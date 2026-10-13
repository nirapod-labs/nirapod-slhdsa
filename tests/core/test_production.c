/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_production.c
 * =================
 *
 * Round trips through the application library, libnirapod_slhdsa.a, linked
 * alone: the objects an application links, with the operating system's
 * random source and the fault check that cannot be switched off. Every
 * other functional test links the testing library, whose C objects are
 * compiled separately; this one is the evidence that the production
 * objects themselves generate keys, sign and verify. For every parameter
 * set:
 *
 *     keygen         two key pairs from the random source differ, and each
 *                    secret key ends with its public key
 *     hedged         two signatures of one message differ (opt_rand is
 *                    drawn per call) and both verify; a changed byte, a
 *                    changed message and a changed context are rejected
 *     deterministic  the signature verifies and a second call repeats it
 *     pre-hash       hash_sign (SHAKE256) and hash_sign_deterministic
 *                    (SHA2-512) verify with hash_verify and not with pure
 *                    verification
 *     fault check    a secret key whose PK.root does not belong to its
 *                    seeds yields NIRAPOD_SLHDSA_ERROR_FAULT and a zeroed
 *                    signature buffer: the check verifies each new
 *                    signature under the key's PK.root, so a key pair that
 *                    signs successfully is also self-consistent
 *
 * The answers themselves are checked against NIST's by test_acvp, whose
 * production build (test_acvp_production) also links this library alone.
 *
 * Exit status 0 when every check passes; each failure is printed.
 */

#include <stdio.h>
#include <string.h>

#include "nirapod_slhdsa.h"

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

static uint8_t pk[NIRAPOD_SLHDSA_MAX_PUBLIC_KEY_BYTES];
static uint8_t sk[NIRAPOD_SLHDSA_MAX_SECRET_KEY_BYTES];
static uint8_t pk2[NIRAPOD_SLHDSA_MAX_PUBLIC_KEY_BYTES];
static uint8_t sk2[NIRAPOD_SLHDSA_MAX_SECRET_KEY_BYTES];
static uint8_t sig_a[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t sig_b[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];

static int all_zero(const uint8_t *p, size_t len)
{
    uint8_t acc = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

static void test_set(nirapod_slhdsa_set set)
{
    static const uint8_t msg[] = "a message signed by the application library";
    static const uint8_t ctx[] = "production";
    const size_t msg_len = sizeof(msg) - 1, ctx_len = sizeof(ctx) - 1;
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    int before = failures;
    nirapod_slhdsa_status st;

    /* keygen */

    st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s keygen: %d", name, st);
    st = nirapod_slhdsa_keygen(set, pk2, pk_len, sk2, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s second keygen: %d", name, st);
    CHECK(memcmp(pk, pk2, pk_len) != 0 && memcmp(sk, sk2, sk_len) != 0,
          "%s two key pairs from the random source are equal", name);
    CHECK(memcmp(sk + sk_len - pk_len, pk, pk_len) == 0,
          "%s secret key does not end with PK.seed || PK.root", name);
    if (failures != before) {
        printf("%-20s production round trips: FAIL\n", name);
        return;
    }

    /* hedged pure signing */

    st = nirapod_slhdsa_sign(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign: %d", name, st);
    st = nirapod_slhdsa_sign(set, sig_b, sig_len, msg, msg_len, ctx, ctx_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s second sign: %d", name, st);
    CHECK(memcmp(sig_a, sig_b, sig_len) != 0, "%s two hedged signatures are equal", name);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len, pk, pk_len) ==
              NIRAPOD_SLHDSA_OK, "%s hedged signature does not verify", name);
    CHECK(nirapod_slhdsa_verify(set, sig_b, sig_len, msg, msg_len, ctx, ctx_len, pk, pk_len) ==
              NIRAPOD_SLHDSA_OK, "%s second hedged signature does not verify", name);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, msg_len - 1, ctx, ctx_len, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s shortened message accepted", name);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, msg_len, NULL, 0, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s empty context accepted", name);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len, pk2, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s another public key accepted", name);
    sig_a[sig_len / 2] ^= 0x01;
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s changed signature accepted", name);

    /* deterministic pure signing */

    st = nirapod_slhdsa_sign_deterministic(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len,
                                           sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign_deterministic: %d", name, st);
    st = nirapod_slhdsa_sign_deterministic(set, sig_b, sig_len, msg, msg_len, ctx, ctx_len,
                                           sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(sig_a, sig_b, sig_len) == 0,
          "%s deterministic signature not repeated: %d", name, st);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len, pk, pk_len) ==
              NIRAPOD_SLHDSA_OK, "%s deterministic signature does not verify", name);

    /* pre-hash signing, hedged and deterministic */

    st = nirapod_slhdsa_hash_sign(set, NIRAPOD_SLHDSA_PREHASH_SHAKE256, sig_a, sig_len,
                                  msg, msg_len, ctx, ctx_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s hash_sign: %d", name, st);
    CHECK(nirapod_slhdsa_hash_verify(set, NIRAPOD_SLHDSA_PREHASH_SHAKE256, sig_a, sig_len,
                                     msg, msg_len, ctx, ctx_len, pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s hash_sign signature does not verify", name);
    CHECK(nirapod_slhdsa_verify(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len, pk, pk_len) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE,
          "%s pre-hash signature accepted by pure verification", name);
    st = nirapod_slhdsa_hash_sign_deterministic(set, NIRAPOD_SLHDSA_PREHASH_SHA2_512, sig_a,
                                                sig_len, msg, msg_len, ctx, ctx_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s hash_sign_deterministic: %d", name, st);
    CHECK(nirapod_slhdsa_hash_verify(set, NIRAPOD_SLHDSA_PREHASH_SHA2_512, sig_a, sig_len,
                                     msg, msg_len, ctx, ctx_len, pk, pk_len) == NIRAPOD_SLHDSA_OK,
          "%s hash_sign_deterministic signature does not verify", name);

    /* the fault check: PK.root that does not belong to the seeds */

    sk[sk_len - 1] ^= 0x01;
    memset(sig_a, 0xa5, sig_len);
    st = nirapod_slhdsa_sign_deterministic(set, sig_a, sig_len, msg, msg_len, ctx, ctx_len,
                                           sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_FAULT && all_zero(sig_a, sig_len),
          "%s key with a foreign PK.root: status %d, signature %s", name, st,
          all_zero(sig_a, sig_len) ? "zeroed" : "released");

    printf("%-20s production round trips: %s\n", name, failures == before ? "PASS" : "FAIL");
}

int main(void)
{
    int s;

    for (s = 1; s <= 12; s++) {
        test_set((nirapod_slhdsa_set)s);
    }
    printf("test_production (application library): %s (12 sets, %d failures)\n",
           failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
