/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_acvp.c
 * ===========
 *
 * Known answers from the NIST ACVP SLH-DSA vectors, for every parameter
 * set: the cases of tests/core/acvp-subset.txt (its generator,
 * tests/core/acvp-subset.py, documents the selection and the format).
 *
 *     keygen  the key pair from SK.seed, SK.prf and PK.seed equals the
 *             expected public and secret key
 *     siggen  deterministic signing through the external interface, pure
 *             or pre-hash, reproduces the expected signature byte for byte,
 *             and that signature verifies under the public key held in the
 *             secret key
 *     sigver  verification returns the expected verdict for a signature of
 *             the set's length
 *     hsiggen hedged signing through the external interface with the
 *             case's additionalRandomness as opt_rand reproduces the
 *             expected signature
 *     isiggen slh_sign_internal (FIPS 205 Algorithm 19) with the case's
 *             additionalRandomness as opt_rand reproduces the expected
 *             signature, and slh_verify_internal accepts it
 *
 * The file is built twice. test_acvp links the testing library and runs
 * every case; key generation runs nirapod_slhdsa_testing_keygen with a
 * test random source that returns the case's seeds, so it takes the same
 * path as nirapod_slhdsa_keygen with only the source replaced.
 * test_acvp_production (NIRAPOD_SLHDSA_ACVP_PRODUCTION) links the
 * application library alone and runs the siggen and sigver cases through
 * the functions of nirapod_slhdsa.h; it cannot inject seeds or opt_rand,
 * and has no internal interface, so it reports the keygen, hsiggen and
 * isiggen cases as not run.
 *
 * Every buffer the library is given is allocated for the call at its exact
 * size: the inputs are heap copies of the decoded fields and the outputs
 * fresh blocks, so that a read or write past the end of one leaves its
 * block, where Valgrind's memcheck reports it (make memcheck). The static
 * arrays below only hold the decoded fields.
 *
 * usage: test_acvp <acvp-subset.txt>. Exit status 0 when every case run
 * passes, every parameter set had a keygen, siggen and sigver case, and
 * the file had hsiggen and isiggen cases.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nirapod_slhdsa.h"
#if !defined(NIRAPOD_SLHDSA_ACVP_PRODUCTION)
#include "nirapod_slhdsa_testing.h"
#endif

static int failures;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                        \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

#define MAX_FIELDS  10
#define MAX_MESSAGE 65536

static uint8_t sk[NIRAPOD_SLHDSA_MAX_SECRET_KEY_BYTES];
static uint8_t pk[NIRAPOD_SLHDSA_MAX_PUBLIC_KEY_BYTES];
static uint8_t seeds[3 * 32];
static uint8_t expect_pk[NIRAPOD_SLHDSA_MAX_PUBLIC_KEY_BYTES];
static uint8_t expect_sk[NIRAPOD_SLHDSA_MAX_SECRET_KEY_BYTES];
static uint8_t message[MAX_MESSAGE];
static uint8_t context[NIRAPOD_SLHDSA_MAX_CONTEXT_BYTES];
static uint8_t expect_sig[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t sig[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t opt_rand[32];

/* The buffers of one case, at their exact sizes on the heap. */
typedef struct exact_args {
    uint8_t *sk, *pk, *message, *context, *opt_rand, *sig, *expect_sig;
} exact_args;

/*
 * A block of exactly len bytes holding src[len], or uninitialised when src
 * is NULL (an output). NULL when len is 0: the library takes a NULL
 * message or context of length 0, and the block has nothing a call may
 * touch. Exits on no memory.
 */
static uint8_t *exact(const uint8_t *src, size_t len)
{
    uint8_t *p;

    if (len == 0) {
        return NULL;
    }
    p = malloc(len);
    if (p == NULL) {
        printf("test_acvp: no memory\n");
        exit(2);
    }
    if (src != NULL) {
        memcpy(p, src, len);
    }
    return p;
}

static void exact_free(exact_args *a)
{
    free(a->sk);
    free(a->pk);
    free(a->message);
    free(a->context);
    free(a->opt_rand);
    free(a->sig);
    free(a->expect_sig);
}

/* Cases seen per set (index set - 1) and kind. */
enum { KIND_KEYGEN, KIND_SIGGEN, KIND_SIGVER, KINDS };
static unsigned seen[12][KINDS];

/* Cases with a given opt_rand: hedged external, internal interface. */
static unsigned seen_hedged, seen_internal;

static int nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

/*
 * Decode the hex field into out[cap]; "-" is the empty string. Returns the
 * number of bytes, or (size_t)-1 for a malformed or oversized field.
 */
static size_t unhex(const char *field, uint8_t *out, size_t cap)
{
    size_t len = strlen(field), i;

    if (strcmp(field, "-") == 0) {
        return 0;
    }
    if (len % 2 != 0 || len / 2 > cap) {
        return (size_t)-1;
    }
    for (i = 0; i < len / 2; i++) {
        int hi = nibble(field[2 * i]), lo = nibble(field[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            return (size_t)-1;
        }
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return len / 2;
}

static nirapod_slhdsa_set set_by_name(const char *name)
{
    int s;

    for (s = 1; s <= 12; s++) {
        if (strcmp(nirapod_slhdsa_set_name((nirapod_slhdsa_set)s), name) == 0) {
            return (nirapod_slhdsa_set)s;
        }
    }
    return (nirapod_slhdsa_set)0;
}

/* ACVP hashAlg names (FIPS 205 section 10.2.2) to nirapod_slhdsa_prehash; 0 for "pure". */
static int prehash_by_name(const char *name)
{
    static const char *const names[] = {
        "pure", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA2-512/224",
        "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
        "SHAKE-128", "SHAKE-256"
    };
    int i;

    for (i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        if (strcmp(names[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

#if !defined(NIRAPOD_SLHDSA_ACVP_PRODUCTION)
/* A test random source that returns the case's seeds, once. */
typedef struct seed_source {
    const uint8_t *seeds;
    size_t len;
    unsigned calls;
} seed_source;

static int give_seeds(void *state, uint8_t *buf, size_t len)
{
    seed_source *src = (seed_source *)state;

    src->calls++;
    if (len != src->len) {
        return -1;
    }
    memcpy(buf, src->seeds, len);
    return 0;
}
#endif

static void run_keygen(nirapod_slhdsa_set set, const char *tc, char **f)
{
    int before = failures;
    const char *name = nirapod_slhdsa_set_name(set);
    size_t n = nirapod_slhdsa_public_key_bytes(set) / 2;
    size_t pk_len = 2 * n, sk_len = 4 * n;

    CHECK(unhex(f[3], seeds, n) == n && unhex(f[4], seeds + n, n) == n &&
              unhex(f[5], seeds + 2 * n, n) == n &&
              unhex(f[6], expect_pk, sizeof(expect_pk)) == pk_len &&
              unhex(f[7], expect_sk, sizeof(expect_sk)) == sk_len,
          "%s keygen tcId %s: malformed case", name, tc);
    if (failures != before) {
        return;
    }
#if defined(NIRAPOD_SLHDSA_ACVP_PRODUCTION)
    (void)pk_len;
    (void)sk_len;
    printf("%-20s keygen tcId %-4s NOT RUN (seeds cannot be injected into the application library)\n",
           name, tc);
#else
    {
        seed_source src = { seeds, 3 * n, 0 };
        nirapod_slhdsa_testing_config config = { NULL, give_seeds, NULL, 0 };
        exact_args a = { 0 };
        nirapod_slhdsa_status st;

        a.pk = exact(NULL, pk_len);
        a.sk = exact(NULL, sk_len);
        config.entropy_state = &src;
        st = nirapod_slhdsa_testing_keygen(&config, set, a.pk, pk_len, a.sk, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK && src.calls == 1, "%s keygen tcId %s: status %d", name, tc, st);
        CHECK(memcmp(a.pk, expect_pk, pk_len) == 0, "%s keygen tcId %s: public key differs", name, tc);
        CHECK(memcmp(a.sk, expect_sk, sk_len) == 0, "%s keygen tcId %s: secret key differs", name, tc);
        exact_free(&a);
        printf("%-20s keygen tcId %-4s %s\n", name, tc, failures == before ? "PASS" : "FAIL");
    }
#endif
    seen[set - 1][KIND_KEYGEN]++;
}

static void run_siggen(nirapod_slhdsa_set set, const char *tc, char **f)
{
    int before = failures;
    const char *name = nirapod_slhdsa_set_name(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    size_t n = sk_len / 4, msg_len, ctx_len;
    int prehash = prehash_by_name(f[3]);
    nirapod_slhdsa_status st, vst;
    exact_args a;

    msg_len = unhex(f[5], message, sizeof(message));
    ctx_len = unhex(f[6], context, sizeof(context));
    CHECK(prehash >= 0 && unhex(f[4], sk, sizeof(sk)) == sk_len && msg_len != (size_t)-1 &&
              ctx_len != (size_t)-1 && unhex(f[7], expect_sig, sizeof(expect_sig)) == sig_len,
          "%s siggen tcId %s: malformed case", name, tc);
    if (failures != before) {
        return;
    }

    a = (exact_args){ exact(sk, sk_len), exact(sk + 2 * n, 2 * n), exact(message, msg_len),
                      exact(context, ctx_len), NULL, exact(NULL, sig_len),
                      exact(expect_sig, sig_len) };
    if (prehash == 0) {
        st = nirapod_slhdsa_sign_deterministic(set, a.sig, sig_len, a.message, msg_len,
                                               a.context, ctx_len, a.sk, sk_len);
        vst = nirapod_slhdsa_verify(set, a.expect_sig, sig_len, a.message, msg_len,
                                    a.context, ctx_len, a.pk, 2 * n);
    } else {
        st = nirapod_slhdsa_hash_sign_deterministic(set, (nirapod_slhdsa_prehash)prehash, a.sig,
                                                    sig_len, a.message, msg_len, a.context,
                                                    ctx_len, a.sk, sk_len);
        vst = nirapod_slhdsa_hash_verify(set, (nirapod_slhdsa_prehash)prehash, a.expect_sig,
                                         sig_len, a.message, msg_len, a.context, ctx_len,
                                         a.pk, 2 * n);
    }
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s siggen tcId %s: status %d", name, tc, st);
    CHECK(memcmp(a.sig, expect_sig, sig_len) == 0, "%s siggen tcId %s: signature differs", name, tc);
    exact_free(&a);
    CHECK(vst == NIRAPOD_SLHDSA_OK, "%s siggen tcId %s: expected signature does not verify: %d",
          name, tc, vst);
    printf("%-20s siggen tcId %-4s %-12s %s\n", name, tc, f[3], failures == before ? "PASS" : "FAIL");
    seen[set - 1][KIND_SIGGEN]++;
}

/*
 * hsiggen and isiggen: signing with the case's opt_rand. f holds the
 * fields after the tcId: sk, message, context ("-" for the internal
 * interface), opt_rand, signature.
 */
static void run_given(nirapod_slhdsa_set set, const char *tc, const char *kind, int internal,
                      char **f)
{
    int before = failures;
    const char *name = nirapod_slhdsa_set_name(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    size_t n = sk_len / 4, msg_len, ctx_len;

    msg_len = unhex(f[1], message, sizeof(message));
    ctx_len = unhex(f[2], context, sizeof(context));
    CHECK(unhex(f[0], sk, sizeof(sk)) == sk_len && msg_len != (size_t)-1 &&
              ctx_len != (size_t)-1 && (!internal || ctx_len == 0) &&
              unhex(f[3], opt_rand, sizeof(opt_rand)) == n &&
              unhex(f[4], expect_sig, sizeof(expect_sig)) == sig_len,
          "%s %s tcId %s: malformed case", name, kind, tc);
    if (failures != before) {
        return;
    }
#if defined(NIRAPOD_SLHDSA_ACVP_PRODUCTION)
    printf("%-20s %s tcId %-4s NOT RUN (opt_rand cannot be given to the application library)\n",
           name, kind, tc);
#else
    {
        nirapod_slhdsa_status st, vst;
        exact_args a = { exact(sk, sk_len), exact(sk + 2 * n, 2 * n), exact(message, msg_len),
                         exact(context, ctx_len), exact(opt_rand, n), exact(NULL, sig_len),
                         exact(expect_sig, sig_len) };

        if (internal) {
            st = nirapod_slhdsa_testing_sign_internal(NULL, set, a.sig, sig_len, a.message,
                                                      msg_len, a.sk, sk_len, a.opt_rand, n);
            vst = nirapod_slhdsa_testing_verify_internal(NULL, set, a.expect_sig, sig_len,
                                                         a.message, msg_len, a.pk, 2 * n);
        } else {
            st = nirapod_slhdsa_testing_sign(NULL, set, 0, a.sig, sig_len, a.message, msg_len,
                                             a.context, ctx_len, a.sk, sk_len, a.opt_rand, n);
            vst = nirapod_slhdsa_verify(set, a.expect_sig, sig_len, a.message, msg_len,
                                        a.context, ctx_len, a.pk, 2 * n);
        }
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s %s tcId %s: status %d", name, kind, tc, st);
        CHECK(memcmp(a.sig, expect_sig, sig_len) == 0, "%s %s tcId %s: signature differs",
              name, kind, tc);
        exact_free(&a);
        CHECK(vst == NIRAPOD_SLHDSA_OK, "%s %s tcId %s: expected signature does not verify: %d",
              name, kind, tc, vst);
        printf("%-20s %s tcId %-4s %s\n", name, kind, tc, failures == before ? "PASS" : "FAIL");
    }
#endif
    if (internal) {
        seen_internal++;
    } else {
        seen_hedged++;
    }
}

static void run_sigver(nirapod_slhdsa_set set, const char *tc, char **f)
{
    int before = failures;
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t msg_len, ctx_len, got_sig;
    int prehash = prehash_by_name(f[3]);
    int passed = strcmp(f[4], "1") == 0;
    nirapod_slhdsa_status st;
    exact_args a;

    msg_len = unhex(f[6], message, sizeof(message));
    ctx_len = unhex(f[7], context, sizeof(context));
    got_sig = unhex(f[8], sig, sizeof(sig));
    CHECK(prehash >= 0 && unhex(f[5], pk, sizeof(pk)) == pk_len && msg_len != (size_t)-1 &&
              ctx_len != (size_t)-1 && got_sig != (size_t)-1,
          "%s sigver tcId %s: malformed case", name, tc);
    if (failures != before) {
        return;
    }

    a = (exact_args){ NULL, exact(pk, pk_len), exact(message, msg_len), exact(context, ctx_len),
                      NULL, exact(sig, got_sig), NULL };
    if (prehash == 0) {
        st = nirapod_slhdsa_verify(set, a.sig, got_sig, a.message, msg_len, a.context, ctx_len,
                                   a.pk, pk_len);
    } else {
        st = nirapod_slhdsa_hash_verify(set, (nirapod_slhdsa_prehash)prehash, a.sig, got_sig,
                                        a.message, msg_len, a.context, ctx_len, a.pk, pk_len);
    }
    exact_free(&a);
    CHECK(st == (passed ? NIRAPOD_SLHDSA_OK : NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE),
          "%s sigver tcId %s: status %d, expected %s", name, tc, st, passed ? "valid" : "invalid");
    printf("%-20s sigver tcId %-4s %-12s expected %s, signature of %zu bytes: %s\n", name, tc,
           f[3], passed ? "valid" : "invalid", got_sig, failures == before ? "PASS" : "FAIL");
    seen[set - 1][KIND_SIGVER]++;
}

/* Split line at single spaces into at most MAX_FIELDS fields; returns the count. */
static int split(char *line, char **f)
{
    int k = 0;
    char *p = line;

    while (*p != '\0' && k < MAX_FIELDS) {
        f[k++] = p;
        while (*p != '\0' && *p != ' ') {
            p++;
        }
        if (*p == ' ') {
            *p++ = '\0';
        }
    }
    return *p == '\0' ? k : -1;
}

int main(int argc, char **argv)
{
    FILE *in;
    char *text, *line, *next, *f[MAX_FIELDS];
    long size;
    int s, k, cases = 0;

    if (argc != 2 || (in = fopen(argv[1], "rb")) == NULL) {
        printf("usage: test_acvp <acvp-subset.txt>\n");
        return 2;
    }
    fseek(in, 0, SEEK_END);
    size = ftell(in);
    rewind(in);
    text = malloc((size_t)size + 1);
    if (text == NULL || fread(text, 1, (size_t)size, in) != (size_t)size) {
        printf("test_acvp: cannot read %s\n", argv[1]);
        return 2;
    }
    text[size] = '\0';
    fclose(in);

    for (line = text; line != NULL && *line != '\0'; line = next) {
        nirapod_slhdsa_set set;
        int count;

        next = strchr(line, '\n');
        if (next != NULL) {
            *next++ = '\0';
        }
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        count = split(line, f);
        set = count >= 3 ? set_by_name(f[1]) : (nirapod_slhdsa_set)0;
        CHECK(set != 0, "unknown case line (%d fields)", count);
        if (set == 0) {
            continue;
        }
        if (strcmp(f[0], "keygen") == 0 && count == 8) {
            run_keygen(set, f[2], f);
        } else if (strcmp(f[0], "siggen") == 0 && count == 8) {
            run_siggen(set, f[2], f);
        } else if (strcmp(f[0], "sigver") == 0 && count == 9) {
            run_sigver(set, f[2], f);
        } else if (strcmp(f[0], "hsiggen") == 0 && count == 9 && strcmp(f[3], "pure") == 0) {
            run_given(set, f[2], f[0], 0, f + 4);
        } else if (strcmp(f[0], "isiggen") == 0 && count == 7) {
            char *g[5];

            g[0] = f[3];
            g[1] = f[4];
            g[2] = "-";
            g[3] = f[5];
            g[4] = f[6];
            run_given(set, f[2], f[0], 1, g);
        } else {
            CHECK(0, "%s tcId %s: unknown kind %s with %d fields", f[1], f[2], f[0], count);
        }
        cases++;
    }
    free(text);

    for (s = 0; s < 12; s++) {
        for (k = 0; k < KINDS; k++) {
            CHECK(seen[s][k] != 0, "%s: no case of kind %d",
                  nirapod_slhdsa_set_name((nirapod_slhdsa_set)(s + 1)), k);
        }
    }
    CHECK(seen_hedged != 0 && seen_internal != 0, "no hsiggen or no isiggen case");

#if defined(NIRAPOD_SLHDSA_ACVP_PRODUCTION)
    printf("test_acvp (application library): %s (%d cases read, keygen, hsiggen and isiggen "
           "not run, %d failures)\n", failures == 0 ? "PASS" : "FAIL", cases, failures);
#else
    printf("test_acvp (testing library): %s (%d cases, %d failures)\n",
           failures == 0 ? "PASS" : "FAIL", cases, failures);
#endif
    return failures == 0 ? 0 : 1;
}
