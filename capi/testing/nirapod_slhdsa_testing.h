/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * nirapod_slhdsa_testing.h
 * ========================
 *
 * Test entry points:
 *
 *     the internal functions of FIPS 205 section 9
 *     the external interfaces with caller-supplied randomness
 *     every operation on a chosen hash variant, or with a test source of
 *     randomness in place of the operating system's
 *
 * They exist for known-answer, differential and negative testing: ACVP
 * vectors fix SK.seed, SK.prf, PK.seed and opt_rand, and a test must be
 * able to run each compiled variant and to make the random source fail.
 *
 * Not for applications. FIPS 205 section 9 says the internal functions
 * should not be made available to applications, and caller-chosen key
 * seeds or signing randomness defeat the security of the scheme. The
 * build keeps this interface out of the application library: these
 * functions are defined only in libnirapod_slhdsa_testing.a, and this
 * header is not installed. Nothing here changes the behaviour of the
 * functions of nirapod_slhdsa.h, which keep selecting their variant and
 * drawing randomness as that header describes.
 *
 * Conventions, status codes, check order and the output state on failure
 * are those of nirapod_slhdsa.h.
 */

#ifndef NIRAPOD_SLHDSA_TESTING_H
#define NIRAPOD_SLHDSA_TESTING_H

#include <stddef.h>
#include <stdint.h>

#include "nirapod_slhdsa.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Variants
 * --------
 *
 * Each parameter set is compiled in one or more hash variants, which
 * compute the same function with different kernels: "scalar" on every
 * target, and on x86-64 "avx2" (SHAKE sets) and "shani" (SHA2 sets).
 */

/* The number of variants compiled for set; 0 for an unknown set. */
size_t nirapod_slhdsa_testing_variant_count(nirapod_slhdsa_set set);

/*
 * The name of variant index of set, for index < variant_count(set); index 0
 * is "scalar". NULL otherwise.
 */
const char *nirapod_slhdsa_testing_variant_name(nirapod_slhdsa_set set, size_t index);

/* 1 if variant of set is compiled and runs on this CPU, else 0. */
int nirapod_slhdsa_testing_variant_supported(nirapod_slhdsa_set set, const char *variant);

/* The variant the functions of nirapod_slhdsa.h select for set on this CPU. */
const char *nirapod_slhdsa_testing_variant(nirapod_slhdsa_set set);

/*
 * Configuration
 * -------------
 *
 * Every function below takes a configuration; NULL means the defaults of
 * the production functions.
 *
 * variant   NULL for the variant the production functions select, or the
 *           name of a variant. If set has no variant of that name, or this
 *           CPU cannot run it, the call fails with
 *           NIRAPOD_SLHDSA_ERROR_INVALID_SET at that step of the check
 *           order, and nothing is executed on the variant.
 *
 * entropy   NULL for the operating system's source, or a function that
 *           fills buf with len bytes and returns 0, or returns non-zero to
 *           fail; the call then returns NIRAPOD_SLHDSA_ERROR_ENTROPY. It is
 *           called with entropy_state, at most once per operation, only by
 *           operations that draw randomness (keygen, sign_hedged).
 *
 * skip_fault_check
 *           0 for the production behaviour: every signing function verifies
 *           its signature before releasing it (nirapod_slhdsa.h). Non-zero
 *           releases the signature unchecked, so that benchmarks can report
 *           signing with and without the check.
 */
typedef int (*nirapod_slhdsa_testing_entropy_fn)(void *state, uint8_t *buf, size_t len);

typedef struct nirapod_slhdsa_testing_config {
    const char *variant;
    nirapod_slhdsa_testing_entropy_fn entropy;
    void *entropy_state;
    int skip_fault_check;
} nirapod_slhdsa_testing_config;

/*
 * Operations
 * ----------
 *
 * prehash selects the external interface: 0 for pure SLH-DSA (FIPS 205
 * Algorithms 22 and 24), a nirapod_slhdsa_prehash value for HashSLH-DSA
 * (Algorithms 23 and 25). Any other value fails with
 * NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH.
 */

/* slh_keygen (Algorithm 21): seeds from the configured source. */
nirapod_slhdsa_status nirapod_slhdsa_testing_keygen(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len);

/*
 * slh_keygen_internal (Algorithm 18) on given seeds of n bytes each
 * (seed_len = n).
 */
nirapod_slhdsa_status nirapod_slhdsa_testing_keygen_internal(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *sk_seed, const uint8_t *sk_prf, const uint8_t *pk_seed,
    size_t seed_len);

/*
 * slh_sign or hash_slh_sign with opt_rand given: n bytes, or NULL for the
 * deterministic variant (opt_rand = PK.seed; opt_rand_len is then
 * ignored).
 */
nirapod_slhdsa_status nirapod_slhdsa_testing_sign(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set, unsigned prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *opt_rand, size_t opt_rand_len);

/* slh_sign or hash_slh_sign, hedged: opt_rand from the configured source. */
nirapod_slhdsa_status nirapod_slhdsa_testing_sign_hedged(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set, unsigned prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len);

/* slh_verify or hash_slh_verify. Results as for nirapod_slhdsa_verify. */
nirapod_slhdsa_status nirapod_slhdsa_testing_verify(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set, unsigned prehash,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len);

/*
 * slh_sign_internal (Algorithm 19) on M as given, with opt_rand as for
 * nirapod_slhdsa_testing_sign.
 */
nirapod_slhdsa_status nirapod_slhdsa_testing_sign_internal(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *opt_rand, size_t opt_rand_len);

/*
 * slh_verify_internal (Algorithm 20) on M as given. Results as for
 * nirapod_slhdsa_verify: a signature of the wrong length is
 * NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE.
 */
nirapod_slhdsa_status nirapod_slhdsa_testing_verify_internal(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key, size_t public_key_len);

#ifdef __cplusplus
}
#endif

#endif /* NIRAPOD_SLHDSA_TESTING_H */
