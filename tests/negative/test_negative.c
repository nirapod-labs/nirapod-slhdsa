/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_negative.c
 * ===============
 *
 * Malformed arguments and invalid signatures, through the public API:
 *
 *     arguments   NULL pointers, unknown sets, wrong key and signature
 *                 buffer lengths, contexts of 256 bytes, pre-hash values
 *                 outside the enum; each with its documented status
 *     failure     after a failure, an output buffer whose length is the
 *                 set's size for it is zero; one whose length is wrong, and
 *                 every output of an unknown set, is not written at all;
 *                 nothing is written past a passed length
 *     precedence  several wrong arguments at once: the status of the first
 *                 failing check in the documented order
 *     tampering   one flipped bit in R, in the FORS part, in the first, a
 *                 middle and the last hypertree layer; a changed
 *                 message, context, public key; truncated and extended
 *                 signatures, also through verify_internal
 *
 * and through the testing API:
 *
 *     fault       a secret key whose PK.root does not belong to its seeds:
 *                 every signing function withholds the signature and
 *                 returns NIRAPOD_SLHDSA_ERROR_FAULT with a zeroed output;
 *                 the testing switch skip_fault_check releases it, and
 *                 production signing still checks after such a call
 *     entropy     a failing random source makes keygen and hedged signing
 *                 return NIRAPOD_SLHDSA_ERROR_ENTROPY with zeroed outputs;
 *                 deterministic signing never calls it
 *     variants    an unknown variant name is refused before anything runs
 *     selector    the Jasmin sign and verify exports of every variant, called
 *                 directly with a pre-hash selector above 12 (which the C
 *                 layer never passes), return a failure and write nothing:
 *                 their own check of the selector, kept as defence in depth
 *     overlap     an output sharing a byte with an input is refused with
 *                 NIRAPOD_SLHDSA_ERROR_OVERLAP and nothing written, before
 *                 every other check (a NULL key included), by keygen, the
 *                 four signing functions and the testing signing and
 *                 key-generation functions
 *
 * The checks run on SLH-DSA-SHAKE-128f and SLH-DSA-SHA2-128f, the fastest
 * set of each hash family. Exit status 0 when every check passes.
 */

#include <stdio.h>
#include <string.h>

#include "internal.h"
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

#define GUARD 64
#define CANARY 0xA5

static uint8_t sigbuf[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES + GUARD];
static uint8_t sig[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES + 1];

static int all_zero(const uint8_t *p, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* A test random source: counts its calls, and fails when told to. */
typedef struct test_source {
    int fail;
    unsigned calls;
} test_source;

static int test_entropy(void *state, uint8_t *buf, size_t len)
{
    test_source *src = (test_source *)state;

    src->calls++;
    if (src->fail) {
        memset(buf, 0xEE, len);  /* garbage the library must not use */
        return -1;
    }
    memset(buf, 0x5A, len);
    return 0;
}

static int all_canary(const uint8_t *p, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (p[i] != CANARY) {
            return 0;
        }
    }
    return 1;
}

static void test_arguments(nirapod_slhdsa_set set, const uint8_t *pk, const uint8_t *sk)
{
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    uint8_t msg[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t ctx[256];
    uint8_t kp[64], ks[128 + GUARD];
    nirapod_slhdsa_status st;

    memset(ctx, 7, sizeof(ctx));

    /* Unknown sets */

    CHECK(nirapod_slhdsa_signature_bytes((nirapod_slhdsa_set)0) == 0, "size of set 0");
    CHECK(nirapod_slhdsa_signature_bytes((nirapod_slhdsa_set)13) == 0, "size of set 13");
    CHECK(nirapod_slhdsa_set_name((nirapod_slhdsa_set)13) == NULL, "name of set 13");
    memset(sigbuf, CANARY, sizeof(sigbuf));
    st = nirapod_slhdsa_sign((nirapod_slhdsa_set)13, sigbuf, sig_len, msg, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SET, "%s sign set 13: %d", name, st);
    CHECK(all_canary(sigbuf, sig_len + GUARD), "%s sign set 13: output not written", name);
    memset(ks, CANARY, sizeof(ks));
    st = nirapod_slhdsa_keygen((nirapod_slhdsa_set)0, kp, pk_len, ks, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SET && all_canary(ks, sk_len + GUARD),
          "%s keygen set 0: %d, output not written", name, st);

    /* NULL pointers */

    CHECK(nirapod_slhdsa_sign(set, NULL, sig_len, msg, 8, NULL, 0, sk, sk_len) ==
              NIRAPOD_SLHDSA_ERROR_NULL_POINTER, "%s sign NULL signature", name);
    memset(sigbuf, CANARY, sizeof(sigbuf));
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len, NULL, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER && all_zero(sigbuf, sig_len),
          "%s sign NULL message with length", name);
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len, msg, 8, NULL, 1, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER, "%s sign NULL context with length", name);
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len, msg, 8, NULL, 0, NULL, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER, "%s sign NULL key", name);
    st = nirapod_slhdsa_verify(set, NULL, sig_len, msg, 8, NULL, 0, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER, "%s verify NULL signature", name);
    memset(ks, CANARY, sizeof(ks));
    st = nirapod_slhdsa_keygen(set, NULL, pk_len, ks, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER && all_zero(ks, sk_len) && all_canary(ks + sk_len, GUARD),
          "%s keygen NULL public key: %d, output state", name, st);

    /* A NULL message or context with length zero is the empty string */

    st = nirapod_slhdsa_sign_deterministic(set, sig, sig_len, NULL, 0, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign empty message: %d", name, st);
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, NULL, 0, NULL, 0, pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s verify empty message", name);

    /*
     * Lengths. A rejected length is not trusted as a buffer size: that
     * output is not written. An output of the right length in the same
     * call is zeroed.
     */

    memset(sigbuf, CANARY, sizeof(sigbuf));
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len - 1, msg, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s sign short buffer: %d", name, st);
    CHECK(all_canary(sigbuf, sig_len + GUARD), "%s sign short buffer: output not written", name);
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len + 1, msg, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH && all_canary(sigbuf, sig_len + GUARD),
          "%s sign long buffer: %d, output not written", name, st);
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len, msg, 8, NULL, 0, sk, sk_len - 1);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s sign short key: %d", name, st);
    CHECK(all_zero(sigbuf, sig_len) && all_canary(sigbuf + sig_len, GUARD),
          "%s sign short key: signature buffer zeroed", name);
    memset(ks, CANARY, sizeof(ks));
    st = nirapod_slhdsa_keygen(set, kp, pk_len + 1, ks, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s keygen long pk: %d", name, st);
    CHECK(all_zero(ks, sk_len) && all_canary(ks + sk_len, GUARD),
          "%s keygen long pk: secret key buffer zeroed", name);
    memset(kp, CANARY, sizeof(kp));
    memset(ks, CANARY, sizeof(ks));
    st = nirapod_slhdsa_keygen(set, kp, pk_len, ks, sk_len + 1);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s keygen long sk: %d", name, st);
    CHECK(all_zero(kp, pk_len) && all_canary(kp + pk_len, sizeof(kp) - pk_len) &&
              all_canary(ks, sizeof(ks)),
          "%s keygen long sk: public key zeroed, secret key not written", name);
    st = nirapod_slhdsa_verify(set, sig, sig_len, msg, 8, NULL, 0, pk, pk_len - 1);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s verify short pk: %d", name, st);

    /* Context of 256 bytes */

    st = nirapod_slhdsa_sign(set, sigbuf, sig_len, msg, 8, ctx, 256, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT && all_zero(sigbuf, sig_len),
          "%s sign ctx 256: %d", name, st);
    st = nirapod_slhdsa_verify(set, sig, sig_len, msg, 8, ctx, 256, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT, "%s verify ctx 256: %d", name, st);

    /* Pre-hash values outside the enum */

    st = nirapod_slhdsa_hash_sign(set, (nirapod_slhdsa_prehash)0, sigbuf, sig_len, msg, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH && all_zero(sigbuf, sig_len),
          "%s hash_sign ph 0: %d", name, st);
    st = nirapod_slhdsa_hash_sign(set, (nirapod_slhdsa_prehash)13, sigbuf, sig_len, msg, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH, "%s hash_sign ph 13: %d", name, st);
    st = nirapod_slhdsa_hash_verify(set, (nirapod_slhdsa_prehash)255, sig, sig_len, msg, 8, NULL, 0, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH, "%s hash_verify ph 255: %d", name, st);
}

/*
 * Offset of SIG_HT, the first byte of hypertree layer 0, in a signature of
 * the set: n bytes of R, then k(1 + a) n bytes of SIG_FORS (FIPS 205
 * section 9.2). The tree parameters are those of FIPS 205 Table 2, per
 * security level and s or f; the function checks them against the
 * library's signature size, n + k(1 + a) n + d (len + h') n with len =
 * 2n + 3, and returns 0 when they disagree.
 */
static size_t ht_offset(nirapod_slhdsa_set set)
{
    static const struct { unsigned k, a, d, hp; } table[6] = {
        { 14, 12, 7, 9 },   /* 128s */
        { 33, 6, 22, 3 },   /* 128f */
        { 17, 14, 7, 9 },   /* 192s */
        { 33, 8, 22, 3 },   /* 192f */
        { 22, 14, 8, 8 },   /* 256s */
        { 35, 9, 17, 4 },   /* 256f */
    };
    size_t n = nirapod_slhdsa_public_key_bytes(set) / 2;
    unsigned row = ((unsigned)set - 1) / 2;
    size_t fors = (size_t)table[row].k * (1 + table[row].a) * n;
    size_t ht = (size_t)table[row].d * (2 * n + 3 + table[row].hp) * n;

    return n + fors + ht == nirapod_slhdsa_signature_bytes(set) ? n + fors : 0;
}

static void test_tampering(nirapod_slhdsa_set set, const uint8_t *pk, const uint8_t *sk)
{
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    size_t n = pk_len / 2;
    uint8_t msg[40], ctx[4] = { 'c', 't', 'x', '!' }, pk2[64];
    size_t positions[7];
    nirapod_slhdsa_status st;
    size_t i;

    memset(msg, 0x42, sizeof(msg));
    st = nirapod_slhdsa_sign_deterministic(set, sig, sig_len, msg, sizeof(msg), ctx, 4, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign: %d", name, st);
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), ctx, 4, pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s verify untouched", name);

    /*
     * R, FORS secret, FORS auth path, the first byte of hypertree layer 0,
     * the middle byte, which falls in a middle layer, and the last byte, in
     * the last layer's authentication path.
     */

    positions[0] = 0;
    positions[1] = n - 1;
    positions[2] = n;
    positions[3] = 2 * n + 3;
    positions[4] = ht_offset(set);
    positions[5] = sig_len / 2;
    positions[6] = sig_len - 1;
    CHECK(positions[4] != 0, "%s Table 2 parameters disagree with the signature size", name);

    for (i = 0; i < 7; i++) {
        sig[positions[i]] ^= 0x10;
        st = nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), ctx, 4, pk, pk_len);
        CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s bit flip at %zu: %d", name, positions[i], st);
        sig[positions[i]] ^= 0x10;
    }

    /* Message, context, key */

    msg[39] ^= 1;
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), ctx, 4, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s changed message", name);
    msg[39] ^= 1;
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg) - 1, ctx, 4, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s truncated message", name);
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), ctx, 3, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s shorter context", name);
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), NULL, 0, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s empty context", name);
    memcpy(pk2, pk, pk_len);
    pk2[pk_len - 1] ^= 0x80;
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), ctx, 4, pk2, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s changed PK.root", name);
    memcpy(pk2, pk, pk_len);
    pk2[0] ^= 0x01;
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), ctx, 4, pk2, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s changed PK.seed", name);

    /*
     * Wrong signature lengths are invalid signatures (FIPS 205 Algorithm
     * 20, line 1), not argument errors.
     */

    CHECK(nirapod_slhdsa_verify(set, sig, sig_len - 1, msg, sizeof(msg), ctx, 4, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s truncated signature", name);
    CHECK(nirapod_slhdsa_verify(set, sig, sig_len + 1, msg, sizeof(msg), ctx, 4, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s extended signature", name);
    CHECK(nirapod_slhdsa_verify(set, sig, 0, msg, sizeof(msg), ctx, 4, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s empty signature", name);

    /* A pure signature is not a HashSLH-DSA signature */

    CHECK(nirapod_slhdsa_hash_verify(set, NIRAPOD_SLHDSA_PREHASH_SHA2_256, sig, sig_len, msg, sizeof(msg),
                                     ctx, 4, pk, pk_len) == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE,
          "%s pure signature under hash_verify", name);
}

static void test_precedence(nirapod_slhdsa_set set, const uint8_t *pk, const uint8_t *sk)
{
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    uint8_t msg[8] = { 0 }, ctx[256] = { 0 };
    nirapod_slhdsa_status st;

    /* NULL before set, set before length, length before context, context before pre-hash */

    st = nirapod_slhdsa_sign((nirapod_slhdsa_set)13, sigbuf, sig_len, msg, 8, NULL, 0, NULL, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER, "%s NULL key + bad set: %d", name, st);
    st = nirapod_slhdsa_sign((nirapod_slhdsa_set)13, sigbuf, sig_len + 1, msg, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SET, "%s bad set + bad length: %d", name, st);
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len + 1, msg, 8, ctx, 256, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s bad length + bad context: %d", name, st);
    st = nirapod_slhdsa_hash_sign(set, (nirapod_slhdsa_prehash)13, sigbuf, sig_len, msg, 8, ctx, 256, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT, "%s bad context + bad pre-hash: %d", name, st);
    st = nirapod_slhdsa_hash_verify(set, (nirapod_slhdsa_prehash)0, sig, sig_len + 1, msg, 8, NULL, 0, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH, "%s bad pre-hash + bad signature length: %d", name, st);
    st = nirapod_slhdsa_verify(set, sig, sig_len + 1, msg, 8, NULL, 0, pk, pk_len + 1);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s bad pk length + bad signature length: %d", name, st);
}

/*
 * The fault check: a signature that does not verify under the key's own
 * PK.seed || PK.root is withheld. A changed PK.root produces exactly that.
 */
static void test_fault_check(nirapod_slhdsa_set set, const uint8_t *sk)
{
    const char *name = nirapod_slhdsa_set_name(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    uint8_t bad[128], msg[4] = { 1, 2, 3, 4 };
    nirapod_slhdsa_status st;
    int k;

    memcpy(bad, sk, sk_len);
    bad[sk_len - 1] ^= 0x01;

    for (k = 0; k < 4; k++) {
        memset(sigbuf, CANARY, sizeof(sigbuf));
        switch (k) {
        case 0:
            st = nirapod_slhdsa_sign(set, sigbuf, sig_len, msg, 4, NULL, 0, bad, sk_len);
            break;
        case 1:
            st = nirapod_slhdsa_sign_deterministic(set, sigbuf, sig_len, msg, 4, NULL, 0, bad, sk_len);
            break;
        case 2:
            st = nirapod_slhdsa_hash_sign_deterministic(set, NIRAPOD_SLHDSA_PREHASH_SHA2_256, sigbuf,
                                                        sig_len, msg, 4, NULL, 0, bad, sk_len);
            break;
        default:
            st = nirapod_slhdsa_testing_sign_internal(NULL, set, sigbuf, sig_len, msg, 4, bad, sk_len,
                                                      NULL, 0);
            break;
        }
        CHECK(st == NIRAPOD_SLHDSA_ERROR_FAULT, "%s fault check, signer %d: %d", name, k, st);
        CHECK(all_zero(sigbuf, sig_len) && all_canary(sigbuf + sig_len, GUARD),
              "%s fault check, signer %d: output state", name, k);
    }

    /*
     * The testing switch skip_fault_check releases the same signature
     * unchecked, and only through the testing library: the production
     * functions above ran with the check whatever any testing call did
     * before them.
     */
    {
        nirapod_slhdsa_testing_config skip = { NULL, NULL, NULL, 1 };

        st = nirapod_slhdsa_testing_sign(&skip, set, 0, sigbuf, sig_len, msg, 4, NULL, 0,
                                         bad, sk_len, NULL, 0);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s skip_fault_check releases: %d", name, st);
        st = nirapod_slhdsa_sign_deterministic(set, sigbuf, sig_len, msg, 4, NULL, 0, bad, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_ERROR_FAULT,
              "%s production signing after a skipping testing call still checks: %d", name, st);
    }
}

static void test_testing_api(nirapod_slhdsa_set set, const uint8_t *pk, const uint8_t *sk)
{
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    uint8_t msg[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
    uint8_t kp[64 + GUARD], ks[128 + GUARD];
    test_source src = { 1, 0 };
    nirapod_slhdsa_testing_config cfg = { NULL, test_entropy, NULL, 0 };
    nirapod_slhdsa_testing_config bogus = { "no-such-variant", NULL, NULL, 0 };
    nirapod_slhdsa_status st;
    unsigned ph;

    cfg.entropy_state = &src;

    /* A failing source: keygen and hedged signing fail closed */

    memset(kp, CANARY, sizeof(kp));
    memset(ks, CANARY, sizeof(ks));
    st = nirapod_slhdsa_testing_keygen(&cfg, set, kp, pk_len, ks, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_ENTROPY, "%s keygen, failing source: %d", name, st);
    CHECK(all_zero(kp, pk_len) && all_canary(kp + pk_len, GUARD) &&
          all_zero(ks, sk_len) && all_canary(ks + sk_len, GUARD),
          "%s keygen, failing source: output state", name);
    CHECK(src.calls == 1, "%s keygen calls the source once (%u)", name, src.calls);

    for (ph = 0; ph <= 12; ph += 12) {
        src.calls = 0;
        memset(sigbuf, CANARY, sizeof(sigbuf));
        st = nirapod_slhdsa_testing_sign_hedged(&cfg, set, ph, sigbuf, sig_len, msg, 8, NULL, 0, sk, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_ERROR_ENTROPY, "%s sign_hedged ph %u, failing source: %d", name, ph, st);
        CHECK(all_zero(sigbuf, sig_len) && all_canary(sigbuf + sig_len, GUARD),
              "%s sign_hedged ph %u, failing source: output state", name, ph);
        CHECK(src.calls == 1, "%s sign_hedged calls the source once (%u)", name, src.calls);
    }

    /* Argument errors are reported before the source is called */

    src.calls = 0;
    st = nirapod_slhdsa_testing_sign_hedged(&cfg, set, 0, sigbuf, sig_len - 1, msg, 8, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH && src.calls == 0,
          "%s length error precedes entropy: %d, %u calls", name, st, src.calls);

    /* Deterministic signing never draws randomness */

    src.calls = 0;
    st = nirapod_slhdsa_testing_sign(&cfg, set, 0, sig, sig_len, msg, 8, NULL, 0, sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_OK && src.calls == 0, "%s deterministic sign with failing source: %d, %u calls",
          name, st, src.calls);

    /* A working test source is what keygen uses */

    src.fail = 0;
    src.calls = 0;
    st = nirapod_slhdsa_testing_keygen(&cfg, set, kp, pk_len, ks, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK && src.calls == 1 && ks[0] == 0x5A && ks[pk_len - 1] == 0x5A,
          "%s keygen takes its seeds from the source: %d", name, st);

    /* Variants */

    CHECK(!nirapod_slhdsa_testing_variant_supported(set, "no-such-variant"), "%s bogus variant supported", name);
    CHECK(!nirapod_slhdsa_testing_variant_supported(set, NULL), "%s NULL variant supported", name);
    CHECK(nirapod_slhdsa_testing_variant_supported(set, "scalar"), "%s scalar not supported", name);
    CHECK(nirapod_slhdsa_testing_variant_name(set, nirapod_slhdsa_testing_variant_count(set)) == NULL,
          "%s variant name past the end", name);
    CHECK(nirapod_slhdsa_testing_variant_count((nirapod_slhdsa_set)13) == 0, "variant count of set 13");
    memset(sigbuf, CANARY, sizeof(sigbuf));
    st = nirapod_slhdsa_testing_sign(&bogus, set, 0, sigbuf, sig_len, msg, 8, NULL, 0, sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SET && all_canary(sigbuf, sig_len + GUARD),
          "%s sign on an unknown variant: %d, output not written", name, st);

    /* keygen_internal: a NULL seed fails at the NULL step, outputs zeroed */

    memset(kp, CANARY, sizeof(kp));
    memset(ks, CANARY, sizeof(ks));
    st = nirapod_slhdsa_testing_keygen_internal(NULL, set, kp, pk_len, ks, sk_len,
                                                sk, NULL, sk, pk_len / 2);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER && all_zero(kp, pk_len) &&
              all_zero(ks, sk_len) && all_canary(ks + sk_len, GUARD),
          "%s keygen_internal NULL seed: %d, output state", name, st);
    st = nirapod_slhdsa_testing_verify(&bogus, set, 0, sig, sig_len, msg, 8, NULL, 0, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SET, "%s verify on an unknown variant: %d", name, st);

    /* verify_internal: wrong signature lengths are invalid signatures */

    st = nirapod_slhdsa_testing_sign_internal(NULL, set, sig, sig_len, msg, 8, sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign_internal: %d", name, st);
    CHECK(nirapod_slhdsa_testing_verify_internal(NULL, set, sig, sig_len, msg, 8, pk, pk_len) ==
              NIRAPOD_SLHDSA_OK, "%s verify_internal", name);
    CHECK(nirapod_slhdsa_testing_verify_internal(NULL, set, sig, sig_len - 1, msg, 8, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s verify_internal short signature", name);
    CHECK(nirapod_slhdsa_testing_verify_internal(NULL, set, sig, sig_len + 1, msg, 8, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s verify_internal long signature", name);
    CHECK(nirapod_slhdsa_testing_verify_internal(NULL, set, sig, sig_len, msg, 8, pk, pk_len - 1) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH, "%s verify_internal short public key", name);
}

/*
 * The Jasmin exports' own selector check. The C layer rejects a selector
 * above 12 with NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH before any export
 * runs, so this calls the exports of the records directly.
 */
static void test_jasmin_selector(nirapod_slhdsa_set set, const uint8_t *pk, const uint8_t *sk)
{
    static const uint8_t SELECTORS[3] = { 13, 128, 255 };
    const char *name = nirapod_slhdsa_set_name(set);
    const nirapod_slhdsa_impl *impl;
    uint8_t domain[NIRAPOD_SLHDSA_DOMAIN_BYTES], msg[8] = { 3, 1, 4, 1, 5, 9, 2, 6 };
    uint8_t opt_rand[NIRAPOD_SLHDSA_MAX_N];
    size_t i, k, sig_len = nirapod_slhdsa_signature_bytes(set);
    uint64_t result;
    int before = failures;

    memset(opt_rand, 0x17, sizeof(opt_rand));
    for (i = 0; (impl = nirapod_slhdsa_impl_variant(set, i)) != NULL; i++) {
        if (!nirapod_slhdsa_testing_variant_supported(set, impl->variant)) {
            continue;
        }
        for (k = 0; k < sizeof(SELECTORS); k++) {
            memset(domain, 0, sizeof(domain));
            domain[0] = SELECTORS[k];
            memset(sigbuf, CANARY, sizeof(sigbuf));
            result = impl->sign(sigbuf, msg, sizeof(msg), domain, sk, opt_rand);
            nirapod_slhdsa_clear_registers(impl->features);
            CHECK(result != 0 && all_canary(sigbuf, sig_len + GUARD),
                  "%s/%s sign export, selector %u: result %llu, %s", name, impl->variant,
                  SELECTORS[k], (unsigned long long)result,
                  all_canary(sigbuf, sig_len + GUARD) ? "nothing written" : "output written");
            result = impl->verify(sig, msg, sizeof(msg), domain, pk);
            nirapod_slhdsa_leave_avx(impl->features);
            CHECK(result != 0, "%s/%s verify export, selector %u: result %llu", name,
                  impl->variant, SELECTORS[k], (unsigned long long)result);
        }
    }
    printf("%-20s Jasmin exports refuse selectors 13, 128, 255: %s\n", name,
           failures == before ? "PASS" : "FAIL");
}

/*
 * Overlapping buffers: an output that shares a byte with an input of the
 * same call is refused with NIRAPOD_SLHDSA_ERROR_OVERLAP before any other
 * check and before anything is written, by every function with an output,
 * also when another argument is wrong too; adjacent buffers are not
 * refused; verification, which has no output, accepts aliased inputs.
 */
typedef nirapod_slhdsa_status (*sign_fn)(nirapod_slhdsa_set, uint8_t *, size_t,
                                         const uint8_t *, size_t, const uint8_t *, size_t,
                                         const uint8_t *, size_t);

static nirapod_slhdsa_status sign_hash_sha256(nirapod_slhdsa_set set, uint8_t *s, size_t s_len,
                                              const uint8_t *m, size_t m_len, const uint8_t *c,
                                              size_t c_len, const uint8_t *k, size_t k_len)
{
    return nirapod_slhdsa_hash_sign(set, NIRAPOD_SLHDSA_PREHASH_SHA2_256, s, s_len, m, m_len,
                                    c, c_len, k, k_len);
}

static nirapod_slhdsa_status sign_hash_det_sha256(nirapod_slhdsa_set set, uint8_t *s, size_t s_len,
                                                  const uint8_t *m, size_t m_len, const uint8_t *c,
                                                  size_t c_len, const uint8_t *k, size_t k_len)
{
    return nirapod_slhdsa_hash_sign_deterministic(set, NIRAPOD_SLHDSA_PREHASH_SHA2_256, s, s_len,
                                                  m, m_len, c, c_len, k, k_len);
}

static uint8_t region[2 * NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t region_copy[2 * NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];

static void test_overlap(nirapod_slhdsa_set set, const uint8_t *pk, const uint8_t *sk)
{
    static const struct {
        const char *name;
        sign_fn fn;
    } SIGNERS[4] = {
        { "sign", nirapod_slhdsa_sign },
        { "sign_deterministic", nirapod_slhdsa_sign_deterministic },
        { "hash_sign", sign_hash_sha256 },
        { "hash_sign_deterministic", sign_hash_det_sha256 },
    };
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    uint8_t *out = region;
    nirapod_slhdsa_status st;
    size_t i;
    int k;

#define REFUSED_UNCHANGED(what)                                                     \
    CHECK(st == NIRAPOD_SLHDSA_ERROR_OVERLAP &&                                     \
              memcmp(region, region_copy, sizeof(region)) == 0,                     \
          "%s %s: status %d, region %s", name, what, st,                            \
          memcmp(region, region_copy, sizeof(region)) == 0 ? "unchanged" : "written")

    for (i = 0; i < sizeof(region); i++) {
        region[i] = (uint8_t)(i * 131 + 7);
    }

    /* keygen: the public key and the secret key */

    memcpy(region_copy, region, sizeof(region));
    st = nirapod_slhdsa_keygen(set, out, pk_len, out + pk_len - 1, sk_len);
    REFUSED_UNCHANGED("keygen, last pk byte = first sk byte");
    st = nirapod_slhdsa_keygen(set, out, pk_len, out, sk_len);
    REFUSED_UNCHANGED("keygen, pk == sk");
    st = nirapod_slhdsa_keygen(set, out + 1, pk_len, out, sk_len);
    REFUSED_UNCHANGED("keygen, pk inside sk");
    st = nirapod_slhdsa_keygen(set, out, pk_len, out + pk_len, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s keygen, adjacent pk and sk: %d", name, st);

    /* signing: the signature against the message, the context, the secret key */

    for (k = 0; k < 4; k++) {
        const char *fn = SIGNERS[k].name;

        memcpy(out + sig_len - 1, sk, sk_len);
        memcpy(region_copy, region, sizeof(region));
        st = SIGNERS[k].fn(set, out, sig_len, (const uint8_t *)"m", 1, NULL, 0,
                           out + sig_len - 1, sk_len);
        REFUSED_UNCHANGED(fn);
        st = SIGNERS[k].fn(set, out + 1, sig_len, (const uint8_t *)"m", 1, NULL, 0, out, sk_len);
        REFUSED_UNCHANGED(fn);
        st = SIGNERS[k].fn(set, out, sig_len, out + 100, 8, NULL, 0, sk, sk_len);
        REFUSED_UNCHANGED(fn);
        st = SIGNERS[k].fn(set, out, sig_len, (const uint8_t *)"m", 1, out + sig_len - 1, 1,
                           sk, sk_len);
        REFUSED_UNCHANGED(fn);
        /* Before the set and length checks. */
        st = SIGNERS[k].fn((nirapod_slhdsa_set)13, out, sig_len + 1, out, 8, NULL, 0, sk, sk_len);
        REFUSED_UNCHANGED(fn);
        /*
         * Before the NULL check, which would zero the output: a NULL key or
         * a NULL message with a length must not cost the caller the input
         * the output overlaps.
         */
        st = SIGNERS[k].fn(set, out, sig_len, out + 100, 8, NULL, 0, NULL, sk_len);
        REFUSED_UNCHANGED(fn);
        st = SIGNERS[k].fn(set, out, sig_len, NULL, 8, NULL, 0, out + sig_len - 1, sk_len);
        REFUSED_UNCHANGED(fn);
        st = SIGNERS[k].fn(set, out, sig_len, out + 100, 8, NULL, 3, sk, sk_len);
        REFUSED_UNCHANGED(fn);
        /* Adjacent buffers are not an overlap. */
        st = SIGNERS[k].fn(set, out, sig_len, out + sig_len, 8, out + sig_len + 8, 3, sk, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s %s, adjacent buffers: %d", name, fn, st);
    }

    /* testing API: sign_internal and keygen_internal refuse the same way */

    memcpy(region_copy, region, sizeof(region));
    st = nirapod_slhdsa_testing_sign_internal(NULL, set, out, sig_len, out + 10, 8, sk, sk_len,
                                              NULL, 0);
    REFUSED_UNCHANGED("testing_sign_internal");
    st = nirapod_slhdsa_testing_sign_internal(NULL, set, out, sig_len, out + 10, 8, NULL, sk_len,
                                              NULL, 0);
    REFUSED_UNCHANGED("testing_sign_internal, NULL key");
    st = nirapod_slhdsa_testing_keygen_internal(NULL, set, out, pk_len, out + 1, sk_len,
                                                sk, sk, sk, pk_len / 2);
    REFUSED_UNCHANGED("testing_keygen_internal");
    st = nirapod_slhdsa_testing_keygen_internal(NULL, set, out, pk_len, out + 1, sk_len,
                                                NULL, sk, sk, pk_len / 2);
    REFUSED_UNCHANGED("testing_keygen_internal, NULL seed");

    /* With no overlap among the non-NULL pointers, the NULL check decides. */

    st = nirapod_slhdsa_sign(set, out, sig_len, out + sig_len, 8, NULL, 0, NULL, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_NULL_POINTER && all_zero(out, sig_len),
          "%s sign, NULL key, adjacent message: %d", name, st);

    /* verification has no output: aliased inputs are judged, not refused */

    st = nirapod_slhdsa_sign_deterministic(set, sig, sig_len, sig, 0, NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign for the aliasing check: %d", name, st);
    st = nirapod_slhdsa_verify(set, sig, sig_len, sig, sig_len, sig, 255, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE,
          "%s verify, message and context aliasing the signature: %d", name, st);

#undef REFUSED_UNCHANGED
    printf("%-20s overlap: keygen, 4 signing functions, testing API refused before writing\n", name);
}

int main(void)
{
    const nirapod_slhdsa_set sets[2] = { NIRAPOD_SLHDSA_SHAKE_128F, NIRAPOD_SLHDSA_SHA2_128F };
    uint8_t seeds[48], pk[32], sk[64];
    size_t i;

    for (i = 0; i < 2; i++) {
        memset(seeds, (int)(0x30 + i), sizeof(seeds));
        if (nirapod_slhdsa_testing_keygen_internal(NULL, sets[i], pk, sizeof(pk), sk, sizeof(sk),
                                                   seeds, seeds + 16, seeds + 32, 16) != NIRAPOD_SLHDSA_OK) {
            printf("FAIL keygen_internal %s\n", nirapod_slhdsa_set_name(sets[i]));
            return 1;
        }
        test_arguments(sets[i], pk, sk);
        test_precedence(sets[i], pk, sk);
        test_tampering(sets[i], pk, sk);
        test_testing_api(sets[i], pk, sk);
        test_fault_check(sets[i], sk);
        test_jasmin_selector(sets[i], pk, sk);
        test_overlap(sets[i], pk, sk);
    }

    printf("test_negative: %s (%d failures)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
