/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_fault.c
 * ============
 *
 * The fault check of the signing functions (capi/api.c, "Fault check"),
 * against an injected fault.
 *
 * Units
 *
 *     <set>-faultfors   signing flips bit 0 of the FORS public key before
 *                       layer 0 signs it
 *     <set>-faultht     signing flips bit 0 of the layer-0 XMSS root before
 *                       layer 1 signs it
 *
 * They are the library's sources compiled with the test hooks of
 * tests/negative/fault/ in place of src/slhdsa/hook/hook.jinc. The
 * test runs them behind the library's own signing code (the operations
 * of api.c in the testing build, internal.h), with the production unit's
 * verification export, for
 * SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f.
 *
 * Checks, per unit
 *
 *     control     the production unit signs and the signature verifies
 *     fault       the faulty signature differs from it exactly from the
 *                 layer whose message was corrupted onwards: the bytes
 *                 before that layer are equal, so the WOTS+ key of that
 *                 layer signed a second message (the tree-grafting
 *                 situation)
 *     released    with the check skipped, signing returns OK and the
 *                 released signature does not verify: the negative
 *                 control, showing what the check withholds
 *     withheld    with the check, pure, pre-hash and internal signing
 *                 return NIRAPOD_SLHDSA_ERROR_FAULT and leave the signature
 *                 buffer zero, with nothing written past it
 *
 * Exit status 0 when every check passes.
 */

#include <stdio.h>
#include <string.h>

#include "internal.h"
#include "jasmin.h"
#include "nirapod_slhdsa.h"
#include "nirapod_slhdsa_testing.h"

NIRAPOD_SLHDSA_JZ_DECLARE(sha2_128f_faultfors)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_128f_faultht)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_128f_faultfors)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_128f_faultht)

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

/*
 * Signature layout of the 128f sets (FIPS 205 Table 2: n = 16, k = 33,
 * a = 6, h' = 3, len = 35): R, the FORS signature, then d XMSS signatures.
 */
#define N_128F        16
#define FORS_128F     (33 * (6 + 1) * N_128F)
#define XMSS_128F     ((35 + 3) * N_128F)

typedef struct {
    nirapod_slhdsa_set set;
    const char *fault;
    /* first signature byte that the fault may change */
    size_t first_changed;
    uint64_t (*sign)(uint8_t *, const uint8_t *, uint64_t, const uint8_t *,
                     const uint8_t *, const uint8_t *);
    void (*sign_internal)(uint8_t *, const uint8_t *, uint64_t, const uint8_t *,
                          const uint8_t *);
} faulty_unit;

#define FAULTY(set_, unit, fault_, first)                                      \
    { set_, fault_, first,                                                     \
      nirapod_slhdsa_jz_##unit##__sign,                                        \
      nirapod_slhdsa_jz_##unit##__sign_internal }

/* faultfors corrupts the message of layer 0; faultht that of layer 1. */
static const faulty_unit UNITS[] = {
    FAULTY(NIRAPOD_SLHDSA_SHA2_128F,  sha2_128f_faultfors,  "fors pk",      N_128F + FORS_128F),
    FAULTY(NIRAPOD_SLHDSA_SHA2_128F,  sha2_128f_faultht,    "layer-0 root", N_128F + FORS_128F + XMSS_128F),
    FAULTY(NIRAPOD_SLHDSA_SHAKE_128F, shake_128f_faultfors, "fors pk",      N_128F + FORS_128F),
    FAULTY(NIRAPOD_SLHDSA_SHAKE_128F, shake_128f_faultht,   "layer-0 root", N_128F + FORS_128F + XMSS_128F),
};

static uint8_t good[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t sigbuf[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES + GUARD];

static int no_entropy(void *state, uint8_t *buf, size_t len)
{
    (void)state;
    (void)buf;
    (void)len;
    return -1;
}

static int zero_with_guard(size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (sigbuf[i] != 0) {
            return 0;
        }
    }
    for (i = 0; i < GUARD; i++) {
        if (sigbuf[len + i] != CANARY) {
            return 0;
        }
    }
    return 1;
}

static void test_unit(const faulty_unit *u)
{
    const nirapod_slhdsa_impl *prod = nirapod_slhdsa_impl_variant(u->set, 0);
    const char *name = nirapod_slhdsa_set_name(u->set);
    nirapod_slhdsa_impl rec = *prod;
    nirapod_slhdsa_env env;
    size_t n = prod->n, sig_len = prod->signature_bytes, i;
    uint8_t seeds[48], pk[32], sk[64], msg[33], ctx[3] = { 'f', 'l', 't' };
    nirapod_slhdsa_status st;
    int k;

    /* The production verification, the faulty signing. */
    rec.sign = u->sign;
    rec.sign_internal = u->sign_internal;
    memset(&env, 0, sizeof(env));
    env.impl = &rec;
    env.entropy = no_entropy;

    for (i = 0; i < sizeof(seeds); i++) {
        seeds[i] = (uint8_t)(7 * i + 1);
    }
    memset(msg, 0x4d, sizeof(msg));
    st = nirapod_slhdsa_testing_keygen_internal(NULL, u->set, pk, 2 * n, sk, 4 * n,
                                                seeds, seeds + n, seeds + 2 * n, n);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s keygen_internal: %d", name, st);

    /* control */

    st = nirapod_slhdsa_sign_deterministic(u->set, good, sig_len, msg, sizeof(msg), ctx, 3, sk, 4 * n);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s production sign: %d", name, st);
    CHECK(nirapod_slhdsa_verify(u->set, good, sig_len, msg, sizeof(msg), ctx, 3, pk, 2 * n) ==
              NIRAPOD_SLHDSA_OK, "%s production signature verifies", name);

    /* released: the check skipped */

    env.skip_fault_check = 1;
    memset(sigbuf, CANARY, sizeof(sigbuf));
    st = nirapod_slhdsa_sign_framed(&env, 0, 0, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                    sigbuf, sig_len, msg, sizeof(msg), ctx, 3, sk, 4 * n);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s %s unchecked sign: %d", name, u->fault, st);
    CHECK(nirapod_slhdsa_verify(u->set, sigbuf, sig_len, msg, sizeof(msg), ctx, 3, pk, 2 * n) ==
              NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE,
          "%s %s: the released faulty signature must not verify", name, u->fault);

    /* fault: where the faulty signature departs from the good one */

    CHECK(memcmp(sigbuf, good, u->first_changed) == 0,
          "%s %s: bytes before the corrupted layer differ", name, u->fault);
    CHECK(memcmp(sigbuf + u->first_changed, good + u->first_changed,
                 sig_len - u->first_changed) != 0,
          "%s %s: no difference from the corrupted layer on", name, u->fault);
    printf("%-20s %-13s faulty signature equal to the good one up to byte %zu, released unchecked: "
           "does not verify\n", name, u->fault, u->first_changed);

    /* withheld: the check on, three signing paths */

    env.skip_fault_check = 0;
    for (k = 0; k < 3; k++) {
        memset(sigbuf, CANARY, sizeof(sigbuf));
        if (k == 0) {
            st = nirapod_slhdsa_sign_framed(&env, 0, 0, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                            sigbuf, sig_len, msg, sizeof(msg), ctx, 3, sk, 4 * n);
        } else if (k == 1) {
            st = nirapod_slhdsa_sign_framed(&env, 1, NIRAPOD_SLHDSA_PREHASH_SHA2_256,
                                            NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                            sigbuf, sig_len, msg, sizeof(msg), ctx, 3, sk, 4 * n);
        } else {
            st = nirapod_slhdsa_sign_internal_env(&env, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                                  sigbuf, sig_len, msg, sizeof(msg), sk, 4 * n);
        }
        CHECK(st == NIRAPOD_SLHDSA_ERROR_FAULT, "%s %s path %d: status %d", name, u->fault, k, st);
        CHECK(zero_with_guard(sig_len), "%s %s path %d: output state", name, u->fault, k);
    }
    printf("%-20s %-13s with the check: withheld (pure, pre-hash, internal)\n", name, u->fault);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(UNITS) / sizeof(UNITS[0]); i++) {
        test_unit(&UNITS[i]);
    }
    printf("test_fault: %s (%d failures)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
