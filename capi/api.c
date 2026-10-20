/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * api.c
 * =====
 *
 * The public functions of nirapod_slhdsa.h. Their contracts are in that
 * header; this file is the boundary between them and the Jasmin exports.
 *
 * Responsibilities
 *
 *     argument checks that need the caller's lengths: NULL pointers,
 *     overlapping buffers, buffer sizes, |ctx| <= 255, the pre-hash selector
 *     the domain block of the Jasmin sign and verify exports (jasmin.h)
 *     opt_rand: fresh entropy (hedged) or PK.seed (deterministic)
 *     key-generation seeds from the entropy boundary
 *     the timing mode around keygen and sign (timing.c)
 *     the check of every new signature against the public key in the
 *     secret key, before it is released (see "Fault check" below)
 *     the output state on failure, and clearing of this file's own secrets
 *     and of the registers after each export that reads the secret key
 *     (clear.c)
 *
 * Everything cryptographic, including the M' framing and the pre-hash,
 * runs in Jasmin.
 *
 * The operations take an environment (internal.h): the record of the set
 * and the source of randomness. The public functions at the end of this
 * file pass the record dispatch.c selects and the operating system's
 * source.
 *
 * This file is compiled twice (internal.h, "Two builds"). In the
 * production build the operations are static and the environment has no
 * test fields. The testing build (NIRAPOD_SLHDSA_TESTING) gives them
 * external linkage for capi/testing and compiles the parts marked
 * "Testing build" below: key seeds and opt_rand from the environment, the
 * switch that skips the fault check, and the internal functions of FIPS
 * 205 section 9. Everything else, the check order included, is the same
 * source in both.
 *
 * Check order
 *
 *     Overlapping buffers (among the non-NULL pointers), then NULL
 *     pointers, then the parameter set, then lengths, then the context
 *     length and the pre-hash selector, then entropy, and for signing the
 *     fault check of the result. The first failing check decides the
 *     status (nirapod_slhdsa.h, "Failure behaviour"). The overlap check
 *     comes first because later failures zero-fill the outputs: an output
 *     that overlaps an input must be refused before any of them can fire.
 *
 * Fault check
 *
 *     Each signature is verified, with the set's verification export, under
 *     PK.seed || PK.root taken from the secret key, and is released only if
 *     it verifies. It withholds the faulty signatures of tree grafting
 *     (a fault while a lower tree is computed makes the WOTS+ key above it
 *     sign a second, faulty root) only when the fault lies on the path from
 *     the signed leaf to the root. A fault in an authentication path, or in
 *     the subtree below one, reaches the signature and the signed root
 *     alike, so the signature verifies and is returned; that is the common
 *     case (docs/SECURITY-MODEL.md, "Faults"). Nor does the check cover a
 *     fault in the check itself or one during key generation (docs/API.md
 *     lists the scope). It also rejects a secret key whose PK.root does not
 *     belong to its seeds. FIPS 205 does not require the check; it costs one
 *     verification per signature. The testing build can skip it
 *     (skip_fault_check) to measure that cost.
 *
 *     The timing mode set for signing stays set during the check, and the
 *     registers are cleared after it: when the check fails, the values it
 *     computed come from a signature that is never released.
 *
 * Output state on failure
 *
 *     An output is zero-filled only over a length this file has checked:
 *     its pointer is not NULL, the set is known, and the length passed for
 *     it is the set's size for that output. Any other output is not
 *     written. A length that failed the check is not evidence of a buffer
 *     of that size: a caller that sized a buffer for one set and passed
 *     the size of another would have the library write past its buffer.
 *     NIRAPOD_SLHDSA_ERROR_OVERLAP writes nothing at all, since zero-filling
 *     an output that overlaps an input would destroy the caller's input (a
 *     secret key, for one). Those checks precede the computation, so an
 *     output left unwritten holds nothing the library computed.
 *
 * Secrets held here
 *
 *     The key-generation seeds (buf) and opt_rand (signing) live in stack
 *     buffers of this file and are cleared with nirapod_slhdsa_clear before
 *     every return. Copies made by the Jasmin code are the Jasmin frame's;
 *     see docs/API.md for what the build clears there.
 */

#include <string.h>

#include "internal.h"

#if SIZE_MAX != UINT64_MAX
#error "nirapod-slhdsa supports 64-bit targets only: lengths pass to Jasmin as u64"
#endif

/* Static in the production build; see internal.h for the testing build. */
#ifdef NIRAPOD_SLHDSA_TESTING
#define OPERATION
#else
#define OPERATION static
#endif

/*
 * Whether [a, a + a_len) and [b, b + b_len) share a byte. Empty ranges and
 * NULL pointers share none: the overlap check runs before the NULL check
 * (check order in the header), so it sees the pointers as passed. The
 * comparison works on the distance between the starts, so no end address
 * is formed and a huge length cannot wrap around.
 */
static int overlap(const void *a, size_t a_len, const void *b, size_t b_len)
{
    uintptr_t pa = (uintptr_t)a, pb = (uintptr_t)b;

    if (a == NULL || b == NULL || a_len == 0 || b_len == 0) {
        return 0;
    }
    return pa >= pb ? pa - pb < b_len : pb - pa < a_len;
}

/*
 * Zero an output after a failure, if its length is the size the set
 * defines for it (size 0 when the set is unknown): see "Output state on
 * failure".
 */
static void zero_output(uint8_t *out, size_t len, size_t size)
{
    if (out != NULL && size != 0 && len == size) {
        nirapod_slhdsa_clear(out, len);
    }
}

/* The verification exports, followed by nirapod_slhdsa_leave_avx (clear.c). */
static uint64_t run_verify(const nirapod_slhdsa_impl *impl, const uint8_t *signature,
                           const uint8_t *message, size_t message_len,
                           const uint8_t *domain, const uint8_t *public_key)
{
    uint64_t result = impl->verify(signature, message, (uint64_t)message_len, domain, public_key);

    nirapod_slhdsa_leave_avx(impl->features);
    return result;
}

/*
 * The size functions read the scalar record: every variant of a set has the
 * same sizes and name, and these need no feature test.
 */
size_t nirapod_slhdsa_public_key_bytes(nirapod_slhdsa_set set)
{
    const nirapod_slhdsa_impl *impl = nirapod_slhdsa_impl_variant(set, 0);

    return impl != NULL ? impl->public_key_bytes : 0;
}

size_t nirapod_slhdsa_secret_key_bytes(nirapod_slhdsa_set set)
{
    const nirapod_slhdsa_impl *impl = nirapod_slhdsa_impl_variant(set, 0);

    return impl != NULL ? impl->secret_key_bytes : 0;
}

size_t nirapod_slhdsa_signature_bytes(nirapod_slhdsa_set set)
{
    const nirapod_slhdsa_impl *impl = nirapod_slhdsa_impl_variant(set, 0);

    return impl != NULL ? impl->signature_bytes : 0;
}

const char *nirapod_slhdsa_set_name(nirapod_slhdsa_set set)
{
    const nirapod_slhdsa_impl *impl = nirapod_slhdsa_impl_variant(set, 0);

    return impl != NULL ? impl->name : NULL;
}

/*
 * The NULL step for what the testing build takes from the environment: a
 * NULL seed passed to its keygen_internal (seeds_null).
 */
static int env_pointers_valid(const nirapod_slhdsa_env *env)
{
#ifdef NIRAPOD_SLHDSA_TESTING
    return !env->seeds_null;
#else
    (void)env;
    return 1;
#endif
}

/*
 * The 3n key-generation seeds SK.seed || SK.prf || PK.seed, into buf:
 * from the entropy source or, in the testing build, from the environment.
 */
static nirapod_slhdsa_status draw_seeds(const nirapod_slhdsa_env *env, uint8_t *buf)
{
    size_t len = 3 * env->impl->n;

#ifdef NIRAPOD_SLHDSA_TESTING
    if (env->seeds != NULL) {
        if (env->seeds_len != len) {
            return NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH;
        }
        memcpy(buf, env->seeds, len);
        return NIRAPOD_SLHDSA_OK;
    }
#endif
    if (env->entropy(env->entropy_state, buf, len) != 0) {
        return NIRAPOD_SLHDSA_ERROR_ENTROPY;
    }
    return NIRAPOD_SLHDSA_OK;
}

OPERATION nirapod_slhdsa_status nirapod_slhdsa_keygen_env(
    const nirapod_slhdsa_env *env,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_impl *impl = env->impl;
    uint8_t buf[3 * NIRAPOD_SLHDSA_MAX_N];
    nirapod_slhdsa_status status = NIRAPOD_SLHDSA_OK;
    uint64_t token;

    if (overlap(public_key, public_key_len, secret_key, secret_key_len)) {
        /* Nothing written: see "Output state on failure". */
        return NIRAPOD_SLHDSA_ERROR_OVERLAP;
    }

    if (public_key == NULL || secret_key == NULL || !env_pointers_valid(env)) {
        status = NIRAPOD_SLHDSA_ERROR_NULL_POINTER;
    } else if (impl == NULL) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_SET;
    } else if (public_key_len != impl->public_key_bytes ||
               secret_key_len != impl->secret_key_bytes) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH;
    }

    if (status == NIRAPOD_SLHDSA_OK) {
        status = draw_seeds(env, buf);
    }

    if (status == NIRAPOD_SLHDSA_OK) {
        token = nirapod_slhdsa_timing_enter();
        impl->keygen(public_key, secret_key, buf);
        nirapod_slhdsa_clear_registers(impl->features);
        nirapod_slhdsa_timing_leave(token);
    }

    nirapod_slhdsa_clear(buf, sizeof(buf));

    if (status != NIRAPOD_SLHDSA_OK) {
        zero_output(public_key, public_key_len, impl != NULL ? impl->public_key_bytes : 0);
        zero_output(secret_key, secret_key_len, impl != NULL ? impl->secret_key_bytes : 0);
    }
    return status;
}

/*
 * Domain block of the Jasmin sign/verify exports: pre-hash selector (0 for
 * pure), |ctx|, ctx, zero padding. ctx_len <= 255 has been checked.
 */
static void build_domain(uint8_t domain[NIRAPOD_SLHDSA_DOMAIN_BYTES],
                         unsigned prehash, const uint8_t *ctx, size_t ctx_len)
{
    memset(domain, 0, NIRAPOD_SLHDSA_DOMAIN_BYTES);
    domain[0] = (uint8_t)prehash;
    domain[1] = (uint8_t)ctx_len;
    if (ctx_len != 0) {
        memcpy(domain + 2, ctx, ctx_len);
    }
}

/*
 * The framing selector: 0 for pure SLH-DSA, or a nirapod_slhdsa_prehash
 * value for HashSLH-DSA. A C enum can carry any integer, so the pre-hash
 * value is checked here.
 */
static int framing_valid(int hash_mode, unsigned prehash)
{
    if (!hash_mode) {
        return prehash == 0;
    }
    return prehash >= NIRAPOD_SLHDSA_PREHASH_SHA2_256 &&
           prehash <= NIRAPOD_SLHDSA_PREHASH_SHAKE256;
}

/*
 * opt_rand for one signature (FIPS 205 Algorithm 19, line 2), into
 * opt_rand[n]: PK.seed for the deterministic variant; for the hedged
 * variant, n bytes from the entropy source or, in the testing build, the
 * environment's given_opt_rand.
 */
static nirapod_slhdsa_status draw_opt_rand(
    const nirapod_slhdsa_env *env, nirapod_slhdsa_opt_rand source,
    const uint8_t *secret_key, uint8_t *opt_rand)
{
    size_t n = env->impl->n;

    if (source == NIRAPOD_SLHDSA_OPT_RAND_PK_SEED) {
        memcpy(opt_rand, secret_key + 2 * n, n);
        return NIRAPOD_SLHDSA_OK;
    }
#ifdef NIRAPOD_SLHDSA_TESTING
    if (env->given_opt_rand != NULL) {
        memcpy(opt_rand, env->given_opt_rand, n);
        return NIRAPOD_SLHDSA_OK;
    }
#endif
    if (env->entropy(env->entropy_state, opt_rand, n) != 0) {
        return NIRAPOD_SLHDSA_ERROR_ENTROPY;
    }
    return NIRAPOD_SLHDSA_OK;
}

/*
 * The length step for what the testing build takes from the environment:
 * a given opt_rand of n bytes, read only by hedged signing.
 */
static int env_lengths_valid(const nirapod_slhdsa_env *env, nirapod_slhdsa_opt_rand source)
{
#ifdef NIRAPOD_SLHDSA_TESTING
    if (source == NIRAPOD_SLHDSA_OPT_RAND_ENTROPY && env->given_opt_rand != NULL) {
        return env->given_opt_rand_len == env->impl->n;
    }
#endif
    (void)env;
    (void)source;
    return 1;
}

/*
 * Whether the fault check runs: always in the production build; the
 * testing build can switch it off to measure its cost.
 */
static int fault_check_on(const nirapod_slhdsa_env *env)
{
#ifdef NIRAPOD_SLHDSA_TESTING
    return !env->skip_fault_check;
#else
    (void)env;
    return 1;
#endif
}

OPERATION nirapod_slhdsa_status nirapod_slhdsa_sign_framed(
    const nirapod_slhdsa_env *env, int hash_mode, unsigned prehash,
    nirapod_slhdsa_opt_rand source,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_impl *impl = env->impl;
    uint8_t domain[NIRAPOD_SLHDSA_DOMAIN_BYTES];
    uint8_t opt_rand[NIRAPOD_SLHDSA_MAX_N];
    nirapod_slhdsa_status status = NIRAPOD_SLHDSA_OK;
    uint64_t token, result, checked = 0;

    if (overlap(signature, signature_len, message, message_len) ||
        overlap(signature, signature_len, context, context_len) ||
        overlap(signature, signature_len, secret_key, secret_key_len)) {
        /* Nothing written: see "Output state on failure". */
        return NIRAPOD_SLHDSA_ERROR_OVERLAP;
    }

    if (signature == NULL || secret_key == NULL ||
        (message == NULL && message_len != 0) ||
        (context == NULL && context_len != 0)) {
        status = NIRAPOD_SLHDSA_ERROR_NULL_POINTER;
    } else if (impl == NULL) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_SET;
    } else if (signature_len != impl->signature_bytes ||
               secret_key_len != impl->secret_key_bytes ||
               !env_lengths_valid(env, source)) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH;
    } else if (context_len > NIRAPOD_SLHDSA_MAX_CONTEXT_BYTES) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT;
    } else if (!framing_valid(hash_mode, prehash)) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH;
    }

    if (status == NIRAPOD_SLHDSA_OK) {
        status = draw_opt_rand(env, source, secret_key, opt_rand);
    }

    if (status == NIRAPOD_SLHDSA_OK) {
        build_domain(domain, prehash, context, context_len);

        token = nirapod_slhdsa_timing_enter();
        result = impl->sign(signature, message, (uint64_t)message_len,
                            domain, secret_key, opt_rand);
        if (result == 0 && fault_check_on(env)) {
            /* The fault check, under PK.seed || PK.root of the secret key. */
            checked = impl->verify(signature, message, (uint64_t)message_len,
                                   domain, secret_key + 2 * impl->n);
        }
        nirapod_slhdsa_clear_registers(impl->features);
        nirapod_slhdsa_timing_leave(token);

        /* The selector was checked above, so Jasmin cannot reject it. */
        if (result != 0) {
            status = NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH;
        } else if (checked != 0) {
            status = NIRAPOD_SLHDSA_ERROR_FAULT;
        }
    }

    nirapod_slhdsa_clear(opt_rand, sizeof(opt_rand));

    if (status != NIRAPOD_SLHDSA_OK) {
        zero_output(signature, signature_len, impl != NULL ? impl->signature_bytes : 0);
    }
    return status;
}

OPERATION nirapod_slhdsa_status nirapod_slhdsa_verify_framed(
    const nirapod_slhdsa_env *env, int hash_mode, unsigned prehash,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len)
{
    const nirapod_slhdsa_impl *impl = env->impl;
    uint8_t domain[NIRAPOD_SLHDSA_DOMAIN_BYTES];

    if (signature == NULL || public_key == NULL ||
        (message == NULL && message_len != 0) ||
        (context == NULL && context_len != 0)) {
        return NIRAPOD_SLHDSA_ERROR_NULL_POINTER;
    }
    if (impl == NULL) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_SET;
    }
    if (public_key_len != impl->public_key_bytes) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH;
    }
    if (context_len > NIRAPOD_SLHDSA_MAX_CONTEXT_BYTES) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT;
    }
    if (!framing_valid(hash_mode, prehash)) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH;
    }

    /*
     * FIPS 205 Algorithm 20, line 1: a signature of any other length is
     * not valid. It is a property of the signature, not a caller error, so
     * it is reported as an invalid signature.
     */
    if (signature_len != impl->signature_bytes) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE;
    }

    build_domain(domain, prehash, context, context_len);

    if (run_verify(impl, signature, message, message_len, domain, public_key) != 0) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE;
    }
    return NIRAPOD_SLHDSA_OK;
}

#ifdef NIRAPOD_SLHDSA_TESTING

/*
 * Testing build: the internal functions of FIPS 205 section 9
 * ---------------------------------------------------------
 *
 * Algorithms 19 and 20 on M as given, with the checks, timing mode, fault
 * check, clearing and output state of the external operations above. The
 * records of the testing build carry the two Jasmin exports they call.
 */

nirapod_slhdsa_status nirapod_slhdsa_sign_internal_env(
    const nirapod_slhdsa_env *env,
    nirapod_slhdsa_opt_rand source,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_impl *impl = env->impl;
    uint8_t opt_rand[NIRAPOD_SLHDSA_MAX_N];
    nirapod_slhdsa_status status = NIRAPOD_SLHDSA_OK;
    uint64_t token, checked = 0;

    if (overlap(signature, signature_len, message, message_len) ||
        overlap(signature, signature_len, secret_key, secret_key_len)) {
        return NIRAPOD_SLHDSA_ERROR_OVERLAP;
    }

    if (signature == NULL || secret_key == NULL || (message == NULL && message_len != 0)) {
        status = NIRAPOD_SLHDSA_ERROR_NULL_POINTER;
    } else if (impl == NULL) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_SET;
    } else if (signature_len != impl->signature_bytes ||
               secret_key_len != impl->secret_key_bytes ||
               !env_lengths_valid(env, source)) {
        status = NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH;
    }

    if (status == NIRAPOD_SLHDSA_OK) {
        status = draw_opt_rand(env, source, secret_key, opt_rand);
    }

    if (status == NIRAPOD_SLHDSA_OK) {
        token = nirapod_slhdsa_timing_enter();
        impl->sign_internal(signature, message, (uint64_t)message_len, secret_key, opt_rand);
        if (fault_check_on(env)) {
            checked = impl->verify_internal(signature, message, (uint64_t)message_len,
                                            secret_key + 2 * impl->n);
        }
        nirapod_slhdsa_clear_registers(impl->features);
        nirapod_slhdsa_timing_leave(token);

        if (checked != 0) {
            status = NIRAPOD_SLHDSA_ERROR_FAULT;
        }
    }

    nirapod_slhdsa_clear(opt_rand, sizeof(opt_rand));

    if (status != NIRAPOD_SLHDSA_OK) {
        zero_output(signature, signature_len, impl != NULL ? impl->signature_bytes : 0);
    }
    return status;
}

nirapod_slhdsa_status nirapod_slhdsa_verify_internal_env(
    const nirapod_slhdsa_env *env,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key, size_t public_key_len)
{
    const nirapod_slhdsa_impl *impl = env->impl;
    uint64_t result;

    if (signature == NULL || public_key == NULL || (message == NULL && message_len != 0)) {
        return NIRAPOD_SLHDSA_ERROR_NULL_POINTER;
    }
    if (impl == NULL) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_SET;
    }
    if (public_key_len != impl->public_key_bytes) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH;
    }
    /* Algorithm 20, line 1, as in nirapod_slhdsa_verify_framed. */
    if (signature_len != impl->signature_bytes) {
        return NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE;
    }
    result = impl->verify_internal(signature, message, (uint64_t)message_len, public_key);
    nirapod_slhdsa_leave_avx(impl->features);
    return result == 0 ? NIRAPOD_SLHDSA_OK : NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE;
}

#endif /* NIRAPOD_SLHDSA_TESTING */

/*
 * The public functions
 * --------------------
 *
 * Each runs one operation in the production environment: the variant
 * dispatch.c selects for the set on this CPU, and the operating system's
 * random source.
 */

static int os_entropy(void *state, uint8_t *buf, size_t len)
{
    (void)state;
    return nirapod_slhdsa_entropy(buf, len);
}

#ifdef NIRAPOD_SLHDSA_TESTING
#define PRODUCTION_ENV(set) { nirapod_slhdsa_select(set), os_entropy, NULL, NULL, 0, 0, NULL, 0, 0 }
#else
#define PRODUCTION_ENV(set) { nirapod_slhdsa_select(set), os_entropy, NULL }
#endif

nirapod_slhdsa_status nirapod_slhdsa_keygen(
    nirapod_slhdsa_set set,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_env env = PRODUCTION_ENV(set);

    return nirapod_slhdsa_keygen_env(&env, public_key, public_key_len,
                                     secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_sign(
    nirapod_slhdsa_set set,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_env env = PRODUCTION_ENV(set);

    return nirapod_slhdsa_sign_framed(&env, 0, 0, NIRAPOD_SLHDSA_OPT_RAND_ENTROPY,
                                      signature, signature_len, message, message_len,
                                      context, context_len, secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_sign_deterministic(
    nirapod_slhdsa_set set,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_env env = PRODUCTION_ENV(set);

    return nirapod_slhdsa_sign_framed(&env, 0, 0, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                      signature, signature_len, message, message_len,
                                      context, context_len, secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_verify(
    nirapod_slhdsa_set set,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len)
{
    const nirapod_slhdsa_env env = PRODUCTION_ENV(set);

    return nirapod_slhdsa_verify_framed(&env, 0, 0, signature, signature_len,
                                        message, message_len, context, context_len,
                                        public_key, public_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_hash_sign(
    nirapod_slhdsa_set set,
    nirapod_slhdsa_prehash prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_env env = PRODUCTION_ENV(set);

    return nirapod_slhdsa_sign_framed(&env, 1, (unsigned)prehash, NIRAPOD_SLHDSA_OPT_RAND_ENTROPY,
                                      signature, signature_len, message, message_len,
                                      context, context_len, secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_hash_sign_deterministic(
    nirapod_slhdsa_set set,
    nirapod_slhdsa_prehash prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_env env = PRODUCTION_ENV(set);

    return nirapod_slhdsa_sign_framed(&env, 1, (unsigned)prehash, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                      signature, signature_len, message, message_len,
                                      context, context_len, secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_hash_verify(
    nirapod_slhdsa_set set,
    nirapod_slhdsa_prehash prehash,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len)
{
    const nirapod_slhdsa_env env = PRODUCTION_ENV(set);

    return nirapod_slhdsa_verify_framed(&env, 1, (unsigned)prehash, signature, signature_len,
                                        message, message_len, context, context_len,
                                        public_key, public_key_len);
}
