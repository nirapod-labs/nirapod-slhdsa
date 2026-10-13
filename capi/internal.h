/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * internal.h
 * ==========
 *
 * Declarations shared by the C files of the library. Nothing here is part
 * of the public API, and every symbol carries the library prefix.
 *
 *     sets.c      one implementation record per parameter set and variant
 *     dispatch.c  choice of the record for a set on the running CPU
 *     entropy.c   the operating system's random source
 *     timing.c    the data-independent-timing mode around secret work
 *     clear.c     clearing of buffers and registers
 *     api.c       the public functions
 *
 * Two builds
 *
 *     Every C file is compiled twice (Makefile). The production objects
 *     go into libnirapod_slhdsa.a, where the build leaves only the
 *     functions of nirapod_slhdsa.h global and makes every other symbol
 *     local, Jasmin exports included; `make check` fails if any other
 *     global symbol appears (tests/abi/check-exports.sh). The testing
 *     objects are compiled with NIRAPOD_SLHDSA_TESTING defined and go,
 *     with capi/testing, into libnirapod_slhdsa_testing.a. Only that
 *     build contains what the parts marked "testing build" below declare:
 *     the FIPS 205 internal functions, caller-chosen key seeds and
 *     opt_rand, and the switch that skips the fault check. The production
 *     objects have none of them, and their operations are static.
 */

#ifndef NIRAPOD_SLHDSA_INTERNAL_H
#define NIRAPOD_SLHDSA_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "nirapod_slhdsa.h"

/* The largest n of FIPS 205 Table 2. */
#define NIRAPOD_SLHDSA_MAX_N 32

/*
 * The domain block passed to the Jasmin sign and verify exports:
 * selector (0 pure, 1..12 pre-hash), |ctx|, ctx, zero padding to 257.
 */
#define NIRAPOD_SLHDSA_DOMAIN_BYTES 257

/*
 * Where opt_rand comes from (FIPS 205 Algorithm 19, line 2). In the
 * testing build, an environment with given_opt_rand set replaces the
 * entropy source of the hedged variant.
 */
typedef enum nirapod_slhdsa_opt_rand {
    NIRAPOD_SLHDSA_OPT_RAND_ENTROPY = 1,   /* hedged: n fresh bytes */
    NIRAPOD_SLHDSA_OPT_RAND_PK_SEED = 2    /* deterministic: PK.seed */
} nirapod_slhdsa_opt_rand;

/*
 * CPU features a variant may require, as reported by
 * nirapod_slhdsa_cpu_features for the running architecture.
 */
#define NIRAPOD_SLHDSA_CPU_AVX2   0x01u  /* x86-64: AVX2, YMM state enabled */
#define NIRAPOD_SLHDSA_CPU_SHANI  0x02u  /* x86-64: SHA extensions and AVX */
#define NIRAPOD_SLHDSA_CPU_ASIMD  0x10u  /* AArch64: Advanced SIMD */
#define NIRAPOD_SLHDSA_CPU_SHA256 0x20u  /* AArch64: FEAT_SHA256 */
#define NIRAPOD_SLHDSA_CPU_SHA512 0x40u  /* AArch64: FEAT_SHA512 */
#define NIRAPOD_SLHDSA_CPU_SHA3   0x80u  /* AArch64: FEAT_SHA3 */

/*
 * One compiled parameter set: its FIPS 205 sizes and its Jasmin entry
 * points (see jasmin.h for their ABI). Records are const data.
 */
typedef struct nirapod_slhdsa_impl {
    const char *name;
    const char *variant;
    unsigned features;          /* NIRAPOD_SLHDSA_CPU_* the code requires */
    size_t n;
    size_t public_key_bytes;
    size_t secret_key_bytes;
    size_t signature_bytes;
    void (*keygen)(uint8_t *pk, uint8_t *sk, const uint8_t *seeds);
    uint64_t (*sign)(uint8_t *sig, const uint8_t *msg, uint64_t msg_len,
                     const uint8_t *domain, const uint8_t *sk,
                     const uint8_t *opt_rand);
    uint64_t (*verify)(const uint8_t *sig, const uint8_t *msg,
                       uint64_t msg_len, const uint8_t *domain,
                       const uint8_t *pk);
#ifdef NIRAPOD_SLHDSA_TESTING
    /* Testing build: FIPS 205 Algorithms 19 and 20 on M as given. */
    void (*sign_internal)(uint8_t *sig, const uint8_t *msg, uint64_t msg_len,
                          const uint8_t *sk, const uint8_t *opt_rand);
    uint64_t (*verify_internal)(const uint8_t *sig, const uint8_t *msg,
                                uint64_t msg_len, const uint8_t *pk);
#endif
} nirapod_slhdsa_impl;

/*
 * Variant index of a set, from 0 (scalar, always present) to the
 * preferred one; NULL past the last variant or for a value outside
 * nirapod_slhdsa_set. sets.c.
 */
const nirapod_slhdsa_impl *nirapod_slhdsa_impl_variant(nirapod_slhdsa_set set, size_t index);

/*
 * The NIRAPOD_SLHDSA_CPU_* features of the running CPU, read on every
 * call. dispatch.c.
 */
unsigned nirapod_slhdsa_cpu_features(void);

/*
 * The record to run for a set on this CPU: its last variant whose features
 * the CPU has. NULL for an unknown set. Decided on every call; no result
 * is cached. dispatch.c.
 */
const nirapod_slhdsa_impl *nirapod_slhdsa_select(nirapod_slhdsa_set set);

/*
 * The choice nirapod_slhdsa_select makes, for a CPU with the
 * NIRAPOD_SLHDSA_CPU_* features cpu, so that tests can check it for
 * feature sets the host does not have. dispatch.c.
 */
const nirapod_slhdsa_impl *nirapod_slhdsa_select_for(nirapod_slhdsa_set set, unsigned cpu);

/*
 * Fill buf with len bytes from the operating system's random source.
 * Returns 0 on success. On failure returns -1 and buf is zero. len <= 256.
 * entropy.c.
 */
int nirapod_slhdsa_entropy(uint8_t *buf, size_t len);

/*
 * What an operation runs on: the record of its set (NULL for an unknown
 * set or, from the testing library, an unavailable variant) and its
 * source of randomness. The public functions use nirapod_slhdsa_select
 * and the operating system's source.
 *
 * entropy fills buf with len bytes and returns 0, or returns non-zero on
 * failure; the operation then fails with NIRAPOD_SLHDSA_ERROR_ENTROPY.
 *
 * Testing build only:
 *
 *     seeds             key generation: SK.seed || SK.prf || PK.seed,
 *                       seeds_len bytes (3n required), in place of entropy
 *     seeds_null        key generation: the caller of keygen_internal
 *                       passed a NULL seed; fails at the NULL step
 *     given_opt_rand    hedged signing: opt_rand, given_opt_rand_len bytes
 *                       (n required), in place of entropy
 *     skip_fault_check  release a signature without verifying it first
 *
 * A wrong seeds_len or given_opt_rand_len fails at the length step of the
 * check order, as a wrong key length does.
 */
typedef int (*nirapod_slhdsa_entropy_fn)(void *state, uint8_t *buf, size_t len);

typedef struct nirapod_slhdsa_env {
    const nirapod_slhdsa_impl *impl;
    nirapod_slhdsa_entropy_fn entropy;
    void *entropy_state;
#ifdef NIRAPOD_SLHDSA_TESTING
    const uint8_t *seeds;
    size_t seeds_len;
    int seeds_null;
    const uint8_t *given_opt_rand;
    size_t given_opt_rand_len;
    int skip_fault_check;
#endif
} nirapod_slhdsa_env;

/*
 * Data-independent timing around secret-dependent Jasmin calls. enter
 * returns a token holding the previous mode; leave restores it. On
 * targets without such a mode both do nothing. timing.c.
 */
uint64_t nirapod_slhdsa_timing_enter(void);
void nirapod_slhdsa_timing_leave(uint64_t token);

#ifdef NIRAPOD_SLHDSA_TESTING

/*
 * Testing build: the operations of api.c, with external linkage so that
 * capi/testing can run them in an environment of its own. In the
 * production build they are static functions of api.c.
 *
 *     keygen_env     slh_keygen (Algorithm 21), or Algorithm 18 on env->seeds
 *     sign_framed    slh_sign, hash_slh_sign (Algorithms 22, 23)
 *     verify_framed  slh_verify, hash_slh_verify (Algorithms 24, 25)
 *
 * hash_mode 0 is pure SLH-DSA with prehash 0; hash_mode 1 is HashSLH-DSA
 * with a nirapod_slhdsa_prehash value. Contracts as in nirapod_slhdsa.h.
 */
nirapod_slhdsa_status nirapod_slhdsa_keygen_env(
    const nirapod_slhdsa_env *env,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len);

nirapod_slhdsa_status nirapod_slhdsa_sign_framed(
    const nirapod_slhdsa_env *env, int hash_mode, unsigned prehash,
    nirapod_slhdsa_opt_rand source,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len);

nirapod_slhdsa_status nirapod_slhdsa_verify_framed(
    const nirapod_slhdsa_env *env, int hash_mode, unsigned prehash,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len);

/*
 * Testing build: slh_sign_internal and slh_verify_internal (FIPS 205
 * Algorithms 19 and 20) on M as given, with the checks, fault check and
 * output state of sign_framed and verify_framed.
 */
nirapod_slhdsa_status nirapod_slhdsa_sign_internal_env(
    const nirapod_slhdsa_env *env,
    nirapod_slhdsa_opt_rand source,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, size_t secret_key_len);

nirapod_slhdsa_status nirapod_slhdsa_verify_internal_env(
    const nirapod_slhdsa_env *env,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key, size_t public_key_len);

#endif /* NIRAPOD_SLHDSA_TESTING */

/*
 * Overwrite len bytes at p with zeros in a way the compiler may not remove
 * as a dead store: the stores go through a volatile pointer and are
 * followed by a compiler barrier on p. clear.c.
 */
void nirapod_slhdsa_clear(void *p, size_t len);

/*
 * Zero the registers the platform ABI lets a callee leave changed, after a
 * Jasmin export that read the secret key. used_features is the
 * NIRAPOD_SLHDSA_CPU_* set of the variant that ran. clear.c.
 */
void nirapod_slhdsa_clear_registers(unsigned used_features);

/*
 * Clear the upper halves of the AVX registers after an export of a variant
 * with NIRAPOD_SLHDSA_CPU_AVX2 or _SHANI in used_features, where
 * nirapod_slhdsa_clear_registers does not run (verification). clear.c.
 */
void nirapod_slhdsa_leave_avx(unsigned used_features);

#endif /* NIRAPOD_SLHDSA_INTERNAL_H */
