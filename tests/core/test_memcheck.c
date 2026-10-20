/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_memcheck.c
 * ===============
 *
 * The library's exports with every buffer at its exact size on the heap,
 * for the memcheck run (tests/core/memcheck.py, `make memcheck`), linked
 * with the testing library. Under Valgrind's memcheck a read or write
 * past the end of a block, or a read of bytes nobody wrote, is reported;
 * natively this program is an ordinary round-trip test.
 *
 *     exports    for every parameter set and every hash variant this
 *                process may run: slh_keygen_internal, slh_sign
 *                (deterministic, 255-byte context) and slh_verify,
 *                slh_sign_internal (given opt_rand) and
 *                slh_verify_internal, each signature verified, so every
 *                export of every unit the process can select runs once.
 *                The external form rotates through pure signing and the
 *                twelve pre-hash functions, a different one per set and
 *                variant. With twelve sets a variant meets at most twelve
 *                of the thirteen forms: on x86-64, scalar never signs with
 *                SHAKE256 and avx2 never signs pure. test_core runs the
 *                full matrix natively; it is too long to run under
 *                memcheck, which slows a program down many times over.
 *     variants   for every parameter set, each compiled variant and
 *                whether this process may run it. Run natively and under
 *                Valgrind, the two listings show which variants memcheck
 *                did not reach: Valgrind presents a CPU of its own,
 *                without the extensions it does not emulate, and the
 *                library selects its variant from that CPU.
 *     short      the negative control. slh_keygen_internal of
 *                SLH-DSA-SHA2-128f on the scalar variant, into a public
 *                key buffer allocated one byte shorter than the 2n = 32
 *                bytes the call is told it has. The Jasmin export writes
 *                PK.root straight into that buffer (capi/api.c), so its
 *                last store lands past the block, and memcheck must report
 *                it; if it did not, it would not see such an overrun in the
 *                library either, and the clean results would mean nothing.
 *                Outside Valgrind, whose allocator surrounds each block
 *                with an unwritable zone, this is undefined behaviour:
 *                only the memcheck run starts it.
 *
 * Exit status 0 when every check passes (`exports`), the listing was
 * printed (`variants`) or the call returned (`short`); 1 on a failed
 * check, 2 on a usage or allocation error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nirapod_slhdsa.h"
#include "nirapod_slhdsa_testing.h"

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

#define MESSAGE_BYTES 33

/* A block of exactly len bytes, filled from seed when fill is non-zero. Exits on no memory. */
static uint8_t *block(size_t len, int fill, unsigned seed)
{
    uint8_t *p = malloc(len);
    size_t i;

    if (p == NULL) {
        printf("test_memcheck: no memory\n");
        exit(2);
    }
    for (i = 0; fill && i < len; i++) {
        p[i] = (uint8_t)(seed + 131u * i);
    }
    return p;
}

/* Every export of one unit, once, on exact-size heap buffers. */
static void exercise(nirapod_slhdsa_set set, const char *variant, unsigned prehash)
{
    const char *name = nirapod_slhdsa_set_name(set);
    const size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    const size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    const size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    const size_t n = pk_len / 2;
    nirapod_slhdsa_testing_config config = { NULL, NULL, NULL, 0 };
    int before = failures;
    uint8_t *seeds = block(3 * n, 1, (unsigned)set);
    uint8_t *rnd = block(n, 1, 7u * (unsigned)set);
    uint8_t *msg = block(MESSAGE_BYTES, 1, 11u);
    uint8_t *ctx = block(NIRAPOD_SLHDSA_MAX_CONTEXT_BYTES, 1, 13u);
    uint8_t *pk = block(pk_len, 0, 0);
    uint8_t *sk = block(sk_len, 0, 0);
    uint8_t *sig = block(sig_len, 0, 0);
    nirapod_slhdsa_status st;

    config.variant = variant;
    st = nirapod_slhdsa_testing_keygen_internal(&config, set, pk, pk_len, sk, sk_len,
                                                seeds, seeds + n, seeds + 2 * n, n);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s keygen_internal: %d", name, variant, st);

    st = nirapod_slhdsa_testing_sign(&config, set, prehash, sig, sig_len, msg, MESSAGE_BYTES,
                                     ctx, NIRAPOD_SLHDSA_MAX_CONTEXT_BYTES, sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s sign: %d", name, variant, st);
    st = nirapod_slhdsa_testing_verify(&config, set, prehash, sig, sig_len, msg, MESSAGE_BYTES,
                                       ctx, NIRAPOD_SLHDSA_MAX_CONTEXT_BYTES, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s verify: %d", name, variant, st);

    st = nirapod_slhdsa_testing_sign_internal(&config, set, sig, sig_len, msg, MESSAGE_BYTES,
                                              sk, sk_len, rnd, n);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s sign_internal: %d", name, variant, st);
    st = nirapod_slhdsa_testing_verify_internal(&config, set, sig, sig_len, msg, MESSAGE_BYTES,
                                                pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s verify_internal: %d", name, variant, st);

    printf("%-20s %-7s external form %2u: %s\n", name, variant, prehash,
           failures == before ? "PASS" : "FAIL");
    free(sig);
    free(sk);
    free(pk);
    free(ctx);
    free(msg);
    free(rnd);
    free(seeds);
}

static int exercise_all(void)
{
    unsigned runs = 0;
    int s;

    for (s = 1; s <= 12; s++) {
        nirapod_slhdsa_set set = (nirapod_slhdsa_set)s;
        size_t i, count = nirapod_slhdsa_testing_variant_count(set);

        for (i = 0; i < count; i++) {
            const char *v = nirapod_slhdsa_testing_variant_name(set, i);

            if (nirapod_slhdsa_testing_variant_supported(set, v)) {
                /* 0 is pure; 1 to 12 the nirapod_slhdsa_prehash values. */
                exercise(set, v, (unsigned)(s - 1 + i) % 13u);
                runs++;
            }
        }
    }
    printf("test_memcheck: %s (%u set and variant runs, %d failures)\n",
           failures == 0 ? "PASS" : "FAIL", runs, failures);
    return failures == 0 ? 0 : 1;
}

static int list_variants(void)
{
    int s;

    for (s = 1; s <= 12; s++) {
        nirapod_slhdsa_set set = (nirapod_slhdsa_set)s;
        size_t i, count = nirapod_slhdsa_testing_variant_count(set);

        printf("variants: %s", nirapod_slhdsa_set_name(set));
        for (i = 0; i < count; i++) {
            const char *v = nirapod_slhdsa_testing_variant_name(set, i);

            printf(" %s=%d", v, nirapod_slhdsa_testing_variant_supported(set, v));
        }
        printf("\n");
    }
    return 0;
}

static int short_public_key(void)
{
    const nirapod_slhdsa_set set = NIRAPOD_SLHDSA_SHA2_128F;
    const size_t n = 16, pk_len = 2 * n, sk_len = 4 * n;
    nirapod_slhdsa_testing_config config = { "scalar", NULL, NULL, 0 };
    uint8_t *pk = block(pk_len - 1, 0, 0);
    uint8_t *sk = block(sk_len, 0, 0);
    uint8_t *seeds = block(3 * n, 1, 0x5cu);
    nirapod_slhdsa_status st;

    /* pk_len, not pk_len - 1: the size checks pass and the export writes 2n bytes. */
    st = nirapod_slhdsa_testing_keygen_internal(&config, set, pk, pk_len, sk, sk_len,
                                                seeds, seeds + n, seeds + 2 * n, n);
    printf("memcheck control: keygen_internal %s scalar into a %zu-byte public key buffer "
           "given as %zu bytes: status %d\n",
           nirapod_slhdsa_set_name(set), pk_len - 1, pk_len, st);
    free(seeds);
    free(sk);
    free(pk);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "exports") == 0) {
        return exercise_all();
    }
    if (argc == 2 && strcmp(argv[1], "variants") == 0) {
        return list_variants();
    }
    if (argc == 2 && strcmp(argv[1], "short") == 0) {
        return short_public_key();
    }
    printf("usage: test_memcheck exports | variants | short\n");
    return 2;
}
