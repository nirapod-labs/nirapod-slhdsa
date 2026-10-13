/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * testing.c
 * =========
 *
 * The test entry points of nirapod_slhdsa_testing.h. Each builds an
 * environment (internal.h) from its configuration and runs the operation
 * of api.c that the production functions run, so the argument checks, the
 * output state on failure and the Jasmin calls are the same source. This
 * file is compiled only into libnirapod_slhdsa_testing.a, together with
 * the testing build of the other C files (internal.h, "Two builds"):
 * caller-chosen seeds and opt_rand reach api.c through the environment
 * fields that only that build has.
 *
 * The configuration lives in the caller's memory and is read per call:
 * this library adds no state, and the production functions never see it.
 */

#include <string.h>

#include "../internal.h"
#include "nirapod_slhdsa_testing.h"

size_t nirapod_slhdsa_testing_variant_count(nirapod_slhdsa_set set)
{
    size_t i = 0;

    while (nirapod_slhdsa_impl_variant(set, i) != NULL) {
        i++;
    }
    return i;
}

const char *nirapod_slhdsa_testing_variant_name(nirapod_slhdsa_set set, size_t index)
{
    const nirapod_slhdsa_impl *impl = nirapod_slhdsa_impl_variant(set, index);

    return impl != NULL ? impl->variant : NULL;
}

/* The record of the named variant of set if this CPU can run it, else NULL. */
static const nirapod_slhdsa_impl *find_variant(nirapod_slhdsa_set set, const char *variant)
{
    const nirapod_slhdsa_impl *impl;
    size_t i;

    for (i = 0; (impl = nirapod_slhdsa_impl_variant(set, i)) != NULL; i++) {
        if (strcmp(impl->variant, variant) == 0) {
            return (impl->features & ~nirapod_slhdsa_cpu_features()) == 0 ? impl : NULL;
        }
    }
    return NULL;
}

int nirapod_slhdsa_testing_variant_supported(nirapod_slhdsa_set set, const char *variant)
{
    return variant != NULL && find_variant(set, variant) != NULL;
}

const char *nirapod_slhdsa_testing_variant(nirapod_slhdsa_set set)
{
    const nirapod_slhdsa_impl *impl = nirapod_slhdsa_select(set);

    return impl != NULL ? impl->variant : NULL;
}

static int os_entropy(void *state, uint8_t *buf, size_t len)
{
    (void)state;
    return nirapod_slhdsa_entropy(buf, len);
}

static nirapod_slhdsa_env make_env(const nirapod_slhdsa_testing_config *config,
                                   nirapod_slhdsa_set set)
{
    nirapod_slhdsa_env env;

    memset(&env, 0, sizeof(env));
    env.impl = nirapod_slhdsa_select(set);
    env.entropy = os_entropy;

    if (config != NULL) {
        if (config->variant != NULL) {
            env.impl = find_variant(set, config->variant);
        }
        if (config->entropy != NULL) {
            env.entropy = config->entropy;
            env.entropy_state = config->entropy_state;
        }
        env.skip_fault_check = config->skip_fault_check != 0;
    }
    return env;
}

/*
 * Signing with a caller-given opt_rand: the hedged variant, with the
 * environment's given_opt_rand in place of the entropy source. NULL
 * selects the deterministic variant (opt_rand = PK.seed).
 */
static nirapod_slhdsa_env given_env(const nirapod_slhdsa_testing_config *config,
                                    nirapod_slhdsa_set set,
                                    const uint8_t *opt_rand, size_t opt_rand_len)
{
    nirapod_slhdsa_env env = make_env(config, set);

    env.given_opt_rand = opt_rand;
    env.given_opt_rand_len = opt_rand_len;
    return env;
}

static nirapod_slhdsa_opt_rand source_of(const uint8_t *opt_rand)
{
    return opt_rand != NULL ? NIRAPOD_SLHDSA_OPT_RAND_ENTROPY : NIRAPOD_SLHDSA_OPT_RAND_PK_SEED;
}

/* hash_mode of the framed operations for a testing prehash argument. */
static int hash_mode(unsigned prehash)
{
    return prehash != 0;
}

nirapod_slhdsa_status nirapod_slhdsa_testing_keygen(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_env env = make_env(config, set);

    return nirapod_slhdsa_keygen_env(&env, public_key, public_key_len,
                                     secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_testing_keygen_internal(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *sk_seed, const uint8_t *sk_prf, const uint8_t *pk_seed,
    size_t seed_len)
{
    nirapod_slhdsa_env env = make_env(config, set);
    uint8_t seeds[3 * NIRAPOD_SLHDSA_MAX_N];
    nirapod_slhdsa_status status;

    memset(seeds, 0, sizeof(seeds));
    env.seeds = seeds;

    /*
     * Every case runs keygen_env, so its check order and output state hold
     * here too: a NULL seed fails at the NULL step, after the overlap check,
     * and a seed_len that is not n at the length step.
     */
    if (sk_seed == NULL || sk_prf == NULL || pk_seed == NULL) {
        env.seeds_null = 1;
    } else if (seed_len > NIRAPOD_SLHDSA_MAX_N) {
        env.seeds_len = SIZE_MAX;
    } else {
        memcpy(seeds, sk_seed, seed_len);
        memcpy(seeds + seed_len, sk_prf, seed_len);
        memcpy(seeds + 2 * seed_len, pk_seed, seed_len);
        env.seeds_len = 3 * seed_len;
    }
    status = nirapod_slhdsa_keygen_env(&env, public_key, public_key_len,
                                       secret_key, secret_key_len);

    nirapod_slhdsa_clear(seeds, sizeof(seeds));
    return status;
}

nirapod_slhdsa_status nirapod_slhdsa_testing_sign(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set, unsigned prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *opt_rand, size_t opt_rand_len)
{
    const nirapod_slhdsa_env env = given_env(config, set, opt_rand, opt_rand_len);

    return nirapod_slhdsa_sign_framed(&env, hash_mode(prehash), prehash, source_of(opt_rand),
                                      signature, signature_len, message, message_len,
                                      context, context_len, secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_testing_sign_hedged(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set, unsigned prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len)
{
    const nirapod_slhdsa_env env = make_env(config, set);

    return nirapod_slhdsa_sign_framed(&env, hash_mode(prehash), prehash,
                                      NIRAPOD_SLHDSA_OPT_RAND_ENTROPY,
                                      signature, signature_len, message, message_len,
                                      context, context_len, secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_testing_verify(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set, unsigned prehash,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len)
{
    const nirapod_slhdsa_env env = make_env(config, set);

    return nirapod_slhdsa_verify_framed(&env, hash_mode(prehash), prehash,
                                        signature, signature_len, message, message_len,
                                        context, context_len, public_key, public_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_testing_sign_internal(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *opt_rand, size_t opt_rand_len)
{
    const nirapod_slhdsa_env env = given_env(config, set, opt_rand, opt_rand_len);

    return nirapod_slhdsa_sign_internal_env(&env, source_of(opt_rand),
                                            signature, signature_len, message, message_len,
                                            secret_key, secret_key_len);
}

nirapod_slhdsa_status nirapod_slhdsa_testing_verify_internal(
    const nirapod_slhdsa_testing_config *config,
    nirapod_slhdsa_set set,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key, size_t public_key_len)
{
    const nirapod_slhdsa_env env = make_env(config, set);

    return nirapod_slhdsa_verify_internal_env(&env, signature, signature_len,
                                              message, message_len,
                                              public_key, public_key_len);
}
