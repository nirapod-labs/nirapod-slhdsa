/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_core.c
 * ===========
 *
 * Functional tests of the library through its public API and the testing
 * API, for every parameter set on the host's architecture, and for every
 * hash variant of the set that this CPU runs (forced through the testing
 * configuration):
 *
 *     sizes        size functions and NIRAPOD_SLHDSA_*_BYTES agree
 *     keygen       keygen_internal lays out sk = SK.seed || SK.prf ||
 *                  PK.seed || PK.root and pk = PK.seed || PK.root;
 *                  keygen (entropy) produces a working key pair
 *     sign         deterministic signatures verify; context lengths 0, 1
 *                  and 255; hedged signatures differ and verify
 *     pre-hash     each of the twelve pre-hash functions signs and
 *                  verifies at every set, and its signature is rejected by
 *                  pure verification and under another pre-hash (every
 *                  other one on the scalar variant)
 *     internal     sign_internal / verify_internal round trip, and the
 *                  external pure signature equals the internal signature
 *                  of the framed message 0x00 || |ctx| || ctx || M
 *     variants     every variant produces the scalar variant's keys and
 *                  deterministic signatures, byte for byte
 *     public API   the functions of nirapod_slhdsa.h produce what the
 *                  testing functions produce on the dispatched variant
 *     dispatch     the variant chosen for each combination of CPU
 *                  features (nirapod_slhdsa_select_for); with
 *                  --require-variants, the public functions run the last
 *                  variant of each set
 *     lengths      messages of 0 to 300 bytes behind a 255-byte context,
 *                  across every hash block and rate boundary, and one of
 *                  4 MiB, at SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192f and
 *                  SLH-DSA-SHAKE-128f
 *
 * Correctness against FIPS 205 itself is checked against NIST's known
 * answers by tests/core/test_acvp.c; these tests check the library's own
 * contracts.
 *
 * With --transcript FILE the deterministic outputs of the scalar variant
 * (keys, deterministic signatures of fixed inputs, internal signatures)
 * are written as hex to FILE. Two hosts that produce byte-identical
 * transcripts agree on every deterministic output covered; the variant
 * checks extend that to the other variants of each host.
 *
 * A compiled variant this CPU cannot run is skipped and reported, or, with
 * --require-variants, counted as a failure: for hosts that are expected
 * to run every variant of their architecture.
 *
 * Exit status 0 when every check passes; each failure is printed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "nirapod_slhdsa.h"
#include "nirapod_slhdsa_testing.h"

static int failures;
static FILE *transcript;
static int require_variants;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                        \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

static const nirapod_slhdsa_set ALL_SETS[] = {
    NIRAPOD_SLHDSA_SHA2_128S, NIRAPOD_SLHDSA_SHAKE_128S,
    NIRAPOD_SLHDSA_SHA2_128F, NIRAPOD_SLHDSA_SHAKE_128F,
    NIRAPOD_SLHDSA_SHA2_192S, NIRAPOD_SLHDSA_SHAKE_192S,
    NIRAPOD_SLHDSA_SHA2_192F, NIRAPOD_SLHDSA_SHAKE_192F,
    NIRAPOD_SLHDSA_SHA2_256S, NIRAPOD_SLHDSA_SHAKE_256S,
    NIRAPOD_SLHDSA_SHA2_256F, NIRAPOD_SLHDSA_SHAKE_256F,
};

static const size_t HEADER_SIZES[][3] = {
    { NIRAPOD_SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_128S_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_128S_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_128S_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHA2_128F_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_128F_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_128F_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHAKE_128F_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_128F_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_128F_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHA2_192S_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_192S_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_192S_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHAKE_192S_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_192S_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_192S_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHA2_192F_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_192F_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_192F_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHAKE_192F_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_192F_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_192F_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHA2_256S_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_256S_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_256S_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHAKE_256S_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_256S_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_256S_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_256F_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHA2_256F_SIGNATURE_BYTES },
    { NIRAPOD_SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_256F_SECRET_KEY_BYTES, NIRAPOD_SLHDSA_SHAKE_256F_SIGNATURE_BYTES },
};

static uint8_t sig_a[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t sig_b[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t sig_ref[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];

static const nirapod_slhdsa_testing_config SCALAR = { "scalar", NULL, NULL, 0 };

/* Deterministic filler: a short linear-congruential byte stream. */
static void fill(uint8_t *buf, size_t len, uint32_t seed)
{
    size_t i;

    for (i = 0; i < len; i++) {
        seed = seed * 1103515245u + 12345u;
        buf[i] = (uint8_t)(seed >> 16);
    }
}

static void record(const char *label, const char *name, const uint8_t *buf, size_t len)
{
    size_t i;

    if (transcript == NULL) {
        return;
    }
    fprintf(transcript, "%s %s ", name, label);
    for (i = 0; i < len; i++) {
        fprintf(transcript, "%02x", buf[i]);
    }
    fprintf(transcript, "\n");
}

/*
 * The tests of one variant of a set. cfg forces the variant; label names
 * it in failure messages; is_ref marks the scalar variant, whose outputs
 * go to the transcript and are the reference for the others.
 */
static void test_variant(size_t index, const nirapod_slhdsa_testing_config *cfg, int is_ref)
{
    nirapod_slhdsa_set set = ALL_SETS[index];
    const char *name = nirapod_slhdsa_set_name(set);
    const char *v = cfg->variant;
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    size_t n = pk_len / 2;
    uint8_t seeds[96], pk[64], sk[128], pk_ref[64], sk_ref[128], pk2[64], sk2[128], rnd[32];
    uint8_t msg[300], ctx[255], framed[2 + 255 + 300];
    size_t ctx_lens[3] = { 0, 1, 255 };
    nirapod_slhdsa_status st;
    unsigned ph, other;
    size_t i;

    printf("%s %s\n", name, v);

    /* keygen_internal layout, and equality with the scalar variant */

    fill(seeds, 3 * n, 1000u + (uint32_t)index);
    st = nirapod_slhdsa_testing_keygen_internal(cfg, set, pk, pk_len, sk, sk_len,
                                                seeds, seeds + n, seeds + 2 * n, n);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s keygen_internal status %d", name, v, st);
    CHECK(memcmp(sk, seeds, 3 * n) == 0, "%s/%s sk seeds", name, v);
    CHECK(memcmp(pk, sk + 2 * n, 2 * n) == 0, "%s/%s pk = sk[2n:4n]", name, v);
    if (is_ref) {
        record("pk", name, pk, pk_len);
    } else {
        st = nirapod_slhdsa_testing_keygen_internal(&SCALAR, set, pk_ref, pk_len, sk_ref, sk_len,
                                                    seeds, seeds + n, seeds + 2 * n, n);
        CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(pk, pk_ref, pk_len) == 0 &&
              memcmp(sk, sk_ref, sk_len) == 0, "%s/%s keys = scalar keys", name, v);
    }

    /* Deterministic pure signing with three context lengths */

    fill(msg, sizeof(msg), 2000u + (uint32_t)index);
    fill(ctx, sizeof(ctx), 3000u + (uint32_t)index);

    for (i = 0; i < 3; i++) {
        st = nirapod_slhdsa_testing_sign(cfg, set, 0, sig_a, sig_len, msg, 33, ctx, ctx_lens[i],
                                         sk, sk_len, NULL, 0);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s deterministic sign ctx %zu", name, v, ctx_lens[i]);
        st = nirapod_slhdsa_testing_verify(cfg, set, 0, sig_a, sig_len, msg, 33, ctx, ctx_lens[i],
                                           pk, pk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s verify deterministic ctx %zu: %d", name, v,
              ctx_lens[i], st);
        if (is_ref) {
            record(i == 0 ? "sig_det_ctx0" : i == 1 ? "sig_det_ctx1" : "sig_det_ctx255",
                   name, sig_a, sig_len);
        } else if (i == 2) {
            st = nirapod_slhdsa_testing_sign(&SCALAR, set, 0, sig_ref, sig_len, msg, 33, ctx,
                                             ctx_lens[i], sk, sk_len, NULL, 0);
            CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(sig_a, sig_ref, sig_len) == 0,
                  "%s/%s deterministic signature = scalar", name, v);
        }
    }

    /* The external pure form is the internal signature of M' */

    framed[0] = 0;
    framed[1] = 1;
    framed[2] = ctx[0];
    memcpy(framed + 3, msg, 33);
    st = nirapod_slhdsa_testing_sign_internal(cfg, set, sig_b, sig_len, framed, 36, sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s sign_internal", name, v);
    st = nirapod_slhdsa_testing_sign(cfg, set, 0, sig_a, sig_len, msg, 33, ctx, 1, sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(sig_a, sig_b, sig_len) == 0,
          "%s/%s pure = internal(M')", name, v);
    st = nirapod_slhdsa_testing_verify_internal(cfg, set, sig_b, sig_len, framed, 36, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s verify_internal", name, v);

    /* Internal signing with given randomness, and the empty message */

    fill(rnd, n, 4000u + (uint32_t)index);
    st = nirapod_slhdsa_testing_sign_internal(cfg, set, sig_a, sig_len, NULL, 0, sk, sk_len, rnd, n);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s sign_internal empty", name, v);
    st = nirapod_slhdsa_testing_verify_internal(cfg, set, sig_a, sig_len, NULL, 0, pk, pk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s verify_internal empty", name, v);
    if (is_ref) {
        record("sig_internal_empty", name, sig_a, sig_len);
    }

    /* Hedged signing: fresh opt_rand, distinct signatures, both valid */

    st = nirapod_slhdsa_testing_sign_hedged(cfg, set, 0, sig_a, sig_len, msg, sizeof(msg), ctx, 7,
                                            sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s hedged sign", name, v);
    st = nirapod_slhdsa_testing_sign_hedged(cfg, set, 0, sig_b, sig_len, msg, sizeof(msg), ctx, 7,
                                            sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s hedged sign 2", name, v);
    CHECK(memcmp(sig_a, sig_b, sig_len) != 0, "%s/%s hedged signatures differ", name, v);
    CHECK(nirapod_slhdsa_testing_verify(cfg, set, 0, sig_a, sig_len, msg, sizeof(msg), ctx, 7,
                                        pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s/%s verify hedged", name, v);
    CHECK(nirapod_slhdsa_testing_verify(cfg, set, 0, sig_b, sig_len, msg, sizeof(msg), ctx, 7,
                                        pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s/%s verify hedged 2", name, v);

    /* Pre-hash: all twelve functions at every set */

    for (ph = 1; ph <= 12; ph++) {
        st = nirapod_slhdsa_testing_sign(cfg, set, ph, sig_a, sig_len, msg, 100, ctx, 3,
                                         sk, sk_len, NULL, 0);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s hash_sign ph %u", name, v, ph);
        CHECK(nirapod_slhdsa_testing_verify(cfg, set, ph, sig_a, sig_len, msg, 100, ctx, 3,
                                            pk, pk_len) == NIRAPOD_SLHDSA_OK,
              "%s/%s hash_verify ph %u", name, v, ph);
        for (other = 1; other <= 12; other++) {
            if (other == ph || (!is_ref && other != (ph == 12 ? 1 : ph + 1))) {
                continue;
            }
            CHECK(nirapod_slhdsa_testing_verify(cfg, set, other, sig_a, sig_len, msg, 100, ctx, 3,
                                                pk, pk_len) == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE,
                  "%s/%s hash_verify ph %u under %u", name, v, ph, other);
        }
        CHECK(nirapod_slhdsa_testing_verify(cfg, set, 0, sig_a, sig_len, msg, 100, ctx, 3,
                                            pk, pk_len) == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE,
              "%s/%s pure verify of ph %u signature", name, v, ph);
        if (is_ref && (ph == NIRAPOD_SLHDSA_PREHASH_SHA2_256 || ph == NIRAPOD_SLHDSA_PREHASH_SHAKE256)) {
            record(ph == 1 ? "sig_ph_sha2_256" : "sig_ph_shake256", name, sig_a, sig_len);
        }
    }

    /* keygen from the operating system's entropy */

    st = nirapod_slhdsa_testing_keygen(cfg, set, pk2, pk_len, sk2, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s keygen", name, v);
    CHECK(memcmp(pk2, sk2 + 2 * n, 2 * n) == 0, "%s/%s keygen pk = sk[2n:4n]", name, v);
    CHECK(memcmp(sk2, sk, sk_len) != 0, "%s/%s keygen fresh", name, v);
    st = nirapod_slhdsa_testing_sign_hedged(cfg, set, 0, sig_a, sig_len, msg, 1, NULL, 0, sk2, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s/%s sign with fresh key", name, v);
    CHECK(nirapod_slhdsa_testing_verify(cfg, set, 0, sig_a, sig_len, msg, 1, NULL, 0,
                                        pk2, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s/%s verify with fresh key", name, v);
    CHECK(nirapod_slhdsa_testing_verify(cfg, set, 0, sig_a, sig_len, msg, 1, NULL, 0,
                                        pk, pk_len) == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE,
          "%s/%s verify under another key", name, v);
}

/*
 * The functions of nirapod_slhdsa.h against the testing functions on the
 * dispatched variant (config NULL): same keys from the same code path,
 * same deterministic signatures, same verdicts.
 */
static void test_public_api(size_t index)
{
    nirapod_slhdsa_set set = ALL_SETS[index];
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    size_t n = pk_len / 2;
    uint8_t pk[64], sk[128], msg[64], ctx[5];
    nirapod_slhdsa_status st;

    printf("%s public API (%s)\n", name, nirapod_slhdsa_testing_variant(set));

    CHECK(pk_len == HEADER_SIZES[index][0], "%s public key size", name);
    CHECK(sk_len == HEADER_SIZES[index][1], "%s secret key size", name);
    CHECK(sig_len == HEADER_SIZES[index][2], "%s signature size", name);

    fill(msg, sizeof(msg), 5000u + (uint32_t)index);
    fill(ctx, sizeof(ctx), 6000u + (uint32_t)index);

    st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(pk, sk + 2 * n, 2 * n) == 0, "%s keygen", name);

    st = nirapod_slhdsa_sign_deterministic(set, sig_a, sig_len, msg, sizeof(msg), ctx, 5, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign_deterministic", name);
    st = nirapod_slhdsa_testing_sign(NULL, set, 0, sig_b, sig_len, msg, sizeof(msg), ctx, 5,
                                     sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(sig_a, sig_b, sig_len) == 0,
          "%s sign_deterministic = testing", name);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, sizeof(msg), ctx, 5, pk, pk_len) ==
              NIRAPOD_SLHDSA_OK, "%s verify", name);

    st = nirapod_slhdsa_hash_sign_deterministic(set, NIRAPOD_SLHDSA_PREHASH_SHA3_256, sig_a, sig_len,
                                                msg, sizeof(msg), ctx, 5, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s hash_sign_deterministic", name);
    st = nirapod_slhdsa_testing_sign(NULL, set, NIRAPOD_SLHDSA_PREHASH_SHA3_256, sig_b, sig_len,
                                     msg, sizeof(msg), ctx, 5, sk, sk_len, NULL, 0);
    CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(sig_a, sig_b, sig_len) == 0,
          "%s hash_sign_deterministic = testing", name);
    CHECK(nirapod_slhdsa_hash_verify(set, NIRAPOD_SLHDSA_PREHASH_SHA3_256, sig_a, sig_len,
                                     msg, sizeof(msg), ctx, 5, pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s hash_verify", name);

    st = nirapod_slhdsa_sign(set, sig_a, sig_len, msg, sizeof(msg), NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign", name);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, sizeof(msg), NULL, 0, pk, pk_len) ==
              NIRAPOD_SLHDSA_OK, "%s verify hedged", name);
    st = nirapod_slhdsa_hash_sign(set, NIRAPOD_SLHDSA_PREHASH_SHAKE128, sig_a, sig_len,
                                  msg, sizeof(msg), NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s hash_sign", name);
    CHECK(nirapod_slhdsa_hash_verify(set, NIRAPOD_SLHDSA_PREHASH_SHAKE128, sig_a, sig_len,
                                     msg, sizeof(msg), NULL, 0, pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s hash_verify hedged", name);
}

/*
 * Dispatch: the variant nirapod_slhdsa_select_for chooses for every
 * combination of the features variants require on this architecture.
 * The expected choice is written out per family: on x86-64 the SHA2 sets
 * take "shani" exactly when the SHA extensions are present, else "avx2"
 * when AVX2 is, the SHAKE sets "avx2" exactly when AVX2 is; on AArch64 the SHA2 sets take "sha2"
 * exactly when Advanced SIMD, FEAT_SHA256 and FEAT_SHA512 are all present,
 * the SHAKE sets "sha3" exactly when Advanced SIMD and FEAT_SHA3 are.
 */
static void test_dispatch(void)
{
#if defined(__x86_64__)
    static const unsigned MASKS[4] = { 0, NIRAPOD_SLHDSA_CPU_AVX2, NIRAPOD_SLHDSA_CPU_SHANI,
                                       NIRAPOD_SLHDSA_CPU_AVX2 | NIRAPOD_SLHDSA_CPU_SHANI };
#elif defined(__aarch64__)
    enum {
        ASIMD = NIRAPOD_SLHDSA_CPU_ASIMD,
        SHA256 = NIRAPOD_SLHDSA_CPU_SHA256,
        SHA512 = NIRAPOD_SLHDSA_CPU_SHA512,
        SHA3 = NIRAPOD_SLHDSA_CPU_SHA3
    };
    /* every combination of the four features */
    static const unsigned MASKS[16] = {
        0, ASIMD, SHA256, ASIMD | SHA256, SHA512, ASIMD | SHA512, SHA256 | SHA512,
        ASIMD | SHA256 | SHA512, SHA3, ASIMD | SHA3, SHA256 | SHA3, ASIMD | SHA256 | SHA3,
        SHA512 | SHA3, ASIMD | SHA512 | SHA3, SHA256 | SHA512 | SHA3,
        ASIMD | SHA256 | SHA512 | SHA3
    };
#else
    static const unsigned MASKS[1] = { 0 };
#endif
    size_t s, m, count;
    int before = failures;

    for (s = 0; s < sizeof(ALL_SETS) / sizeof(ALL_SETS[0]); s++) {
        nirapod_slhdsa_set set = ALL_SETS[s];
        const char *name = nirapod_slhdsa_set_name(set);
        int shake = strncmp(name, "SLH-DSA-SHAKE", 13) == 0;

        for (m = 0; m < sizeof(MASKS) / sizeof(MASKS[0]); m++) {
            const nirapod_slhdsa_impl *impl = nirapod_slhdsa_select_for(set, MASKS[m]);
            const char *expect = "scalar";

#if defined(__x86_64__)
            if (!shake && (MASKS[m] & NIRAPOD_SLHDSA_CPU_SHANI) != 0) {
                expect = "shani";
            } else if ((MASKS[m] & NIRAPOD_SLHDSA_CPU_AVX2) != 0) {
                expect = "avx2";
            }
#elif defined(__aarch64__)
            if (shake && (MASKS[m] & (ASIMD | SHA3)) == (ASIMD | SHA3)) {
                expect = "sha3";
            } else if (!shake && (MASKS[m] & (ASIMD | SHA256 | SHA512)) == (ASIMD | SHA256 | SHA512)) {
                expect = "sha2";
            }
#else
            (void)shake;
#endif
            CHECK(impl != NULL && strcmp(impl->variant, expect) == 0,
                  "%s dispatch for features 0x%x: %s, expected %s", name, MASKS[m],
                  impl != NULL ? impl->variant : "none", expect);
        }

        count = nirapod_slhdsa_testing_variant_count(set);
        if (require_variants) {
            CHECK(strcmp(nirapod_slhdsa_testing_variant(set),
                         nirapod_slhdsa_testing_variant_name(set, count - 1)) == 0,
                  "%s: the public functions run %s, not the last variant %s", name,
                  nirapod_slhdsa_testing_variant(set),
                  nirapod_slhdsa_testing_variant_name(set, count - 1));
        }
    }
    CHECK(nirapod_slhdsa_select_for((nirapod_slhdsa_set)13, 0) == NULL, "dispatch for set 13");
    printf("dispatch: choice for %zu feature combinations%s: %s\n",
           sizeof(MASKS) / sizeof(MASKS[0]),
           require_variants ? ", last variant selected on this host" : "",
           failures == before ? "PASS" : "FAIL");
}

static void test_set(size_t index)
{
    nirapod_slhdsa_set set = ALL_SETS[index];
    size_t count = nirapod_slhdsa_testing_variant_count(set);
    nirapod_slhdsa_testing_config cfg = { NULL, NULL, NULL, 0 };
    size_t i;

    CHECK(count >= 1 && strcmp(nirapod_slhdsa_testing_variant_name(set, 0), "scalar") == 0,
          "%s variant 0 is scalar", nirapod_slhdsa_set_name(set));

    for (i = 0; i < count; i++) {
        cfg.variant = nirapod_slhdsa_testing_variant_name(set, i);
        if (!nirapod_slhdsa_testing_variant_supported(set, cfg.variant)) {
            printf("%s %s: not supported by this CPU, skipped\n",
                   nirapod_slhdsa_set_name(set), cfg.variant);
            CHECK(!require_variants, "%s %s required but not supported",
                  nirapod_slhdsa_set_name(set), cfg.variant);
            continue;
        }
        test_variant(index, &cfg, i == 0);
    }
    test_public_api(index);
}

/*
 * Message lengths. M' is streamed into the hash functions after a prefix
 * (R, PK.seed, PK.root and the 257-byte domain block of a 255-byte
 * context), so its length decides where the hash blocks end: SHA-256 in
 * SHA2-128f, SHA-512 in SHA2-192f (H_msg and PRF_msg of categories 3 and
 * 5), the SHAKE256 rate in SHAKE-128f. Every length from 0 to 300 bytes
 * crosses each of those boundaries; each signs, verifies, and gives the
 * same signature on every variant this CPU runs. Where it runs one variant
 * only, the check is that signing and verification agree; the ACVP cases
 * hold the known answers. One message of 4 MiB signs and verifies pure and
 * with two pre-hash functions.
 */
#define LONG_MESSAGE (4u << 20)

static void test_message_lengths(void)
{
    /* SHA2-192f: H_msg and PRF_msg run on SHA-512 from category 3 on. */
    static const nirapod_slhdsa_set SETS[3] = { NIRAPOD_SLHDSA_SHA2_128F, NIRAPOD_SLHDSA_SHA2_192F,
                                                NIRAPOD_SLHDSA_SHAKE_128F };
    static const nirapod_slhdsa_prehash PREHASH[2] = { NIRAPOD_SLHDSA_PREHASH_SHA2_512,
                                                       NIRAPOD_SLHDSA_PREHASH_SHAKE256 };
    nirapod_slhdsa_testing_config cfg = { NULL, NULL, NULL, 0 };
    uint8_t pk[NIRAPOD_SLHDSA_MAX_PUBLIC_KEY_BYTES], sk[NIRAPOD_SLHDSA_MAX_SECRET_KEY_BYTES];
    uint8_t seeds[3 * NIRAPOD_SLHDSA_MAX_PUBLIC_KEY_BYTES / 2], ctx[255], msg[300];
    uint8_t *big;
    size_t s, n, pk_len, sk_len, len, v, sig_len, count;
    int p, before;
    nirapod_slhdsa_status st;

    fill(seeds, sizeof(seeds), 0x1e57);
    fill(ctx, sizeof(ctx), 0xc7c7);
    fill(msg, sizeof(msg), 0x3e55);
    big = malloc(LONG_MESSAGE);
    CHECK(big != NULL, "message lengths: no memory for the long message");
    if (big == NULL) {
        return;
    }
    fill(big, LONG_MESSAGE, 0xb16);

    for (s = 0; s < sizeof(SETS) / sizeof(SETS[0]); s++) {
        const nirapod_slhdsa_set set = SETS[s];
        const char *name = nirapod_slhdsa_set_name(set);

        before = failures;
        sig_len = nirapod_slhdsa_signature_bytes(set);
        pk_len = nirapod_slhdsa_public_key_bytes(set);
        sk_len = nirapod_slhdsa_secret_key_bytes(set);
        n = pk_len / 2;
        count = nirapod_slhdsa_testing_variant_count(set);
        st = nirapod_slhdsa_testing_keygen_internal(NULL, set, pk, pk_len, sk, sk_len,
                                                    seeds, seeds + n, seeds + 2 * n, n);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s lengths keygen: %d", name, st);

        for (len = 0; len <= sizeof(msg); len++) {
            st = nirapod_slhdsa_sign_deterministic(set, sig_a, sig_len, msg, len, ctx, 255, sk, sk_len);
            CHECK(st == NIRAPOD_SLHDSA_OK, "%s length %zu sign: %d", name, len, st);
            st = nirapod_slhdsa_verify(set, sig_a, sig_len, msg, len, ctx, 255, pk, pk_len);
            CHECK(st == NIRAPOD_SLHDSA_OK, "%s length %zu verify: %d", name, len, st);
            for (v = 0; v < count; v++) {
                cfg.variant = nirapod_slhdsa_testing_variant_name(set, v);
                if (!nirapod_slhdsa_testing_variant_supported(set, cfg.variant) ||
                    strcmp(cfg.variant, nirapod_slhdsa_testing_variant(set)) == 0) {
                    continue;   /* not runnable here, or the one sig_a came from */
                }
                st = nirapod_slhdsa_testing_sign(&cfg, set, 0, sig_b, sig_len, msg, len, ctx, 255,
                                                 sk, sk_len, NULL, 0);
                CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(sig_a, sig_b, sig_len) == 0,
                      "%s length %zu: %s signature differs from the dispatched one", name, len,
                      cfg.variant);
            }
        }

        st = nirapod_slhdsa_sign_deterministic(set, sig_a, sig_len, big, LONG_MESSAGE, ctx, 255,
                                               sk, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK &&
                  nirapod_slhdsa_verify(set, sig_a, sig_len, big, LONG_MESSAGE, ctx, 255, pk, pk_len)
                      == NIRAPOD_SLHDSA_OK,
              "%s 4 MiB pure: %d", name, st);
        for (p = 0; p < 2; p++) {
            st = nirapod_slhdsa_hash_sign_deterministic(set, PREHASH[p], sig_a, sig_len, big,
                                                        LONG_MESSAGE, ctx, 255, sk, sk_len);
            CHECK(st == NIRAPOD_SLHDSA_OK &&
                      nirapod_slhdsa_hash_verify(set, PREHASH[p], sig_a, sig_len, big,
                                                 LONG_MESSAGE, ctx, 255, pk, pk_len)
                          == NIRAPOD_SLHDSA_OK,
                  "%s 4 MiB pre-hash %d: %d", name, (int)PREHASH[p], st);
        }
        printf("%-20s message lengths 0..%zu with a 255-byte context, and 4 MiB: %s\n", name,
               sizeof(msg), failures == before ? "PASS" : "FAIL");
    }
    free(big);
}

int main(int argc, char **argv)
{
    size_t i;
    int a;

    for (a = 1; a < argc; a++) {
        if (strcmp(argv[a], "--transcript") == 0 && a + 1 < argc && transcript == NULL) {
            transcript = fopen(argv[++a], "w");
            if (transcript == NULL) {
                perror(argv[a]);
                return 2;
            }
        } else if (strcmp(argv[a], "--require-variants") == 0) {
            require_variants = 1;
        } else {
            fprintf(stderr, "usage: %s [--transcript FILE] [--require-variants]\n", argv[0]);
            return 2;
        }
    }

    for (i = 0; i < sizeof(ALL_SETS) / sizeof(ALL_SETS[0]); i++) {
        test_set(i);
    }
    test_dispatch();
    test_message_lengths();

    if (transcript != NULL) {
        fclose(transcript);
    }

    printf("test_core: %s (%d failures)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
