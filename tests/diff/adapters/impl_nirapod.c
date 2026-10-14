/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl_nirapod.c
 * ==============
 *
 * Adapter for this library, linked against the testing library
 * (libnirapod_slhdsa_testing.a): the same Jasmin units as the application
 * library and the same C sources, compiled with the testing additions of
 * capi/testing/nirapod_slhdsa_testing.h. Signing and key generation with
 * given seeds or given opt_rand need those additions, because the public
 * API draws them from the operating system.
 *
 * Variants. Without --variant, every call runs the production dispatch:
 * testing calls get a NULL configuration, and external verification calls
 * the public functions of nirapod_slhdsa.h (nirapod_slhdsa_verify,
 * nirapod_slhdsa_hash_verify).
 * With --variant=V, every call goes through the testing library with
 * config->variant = V, which pins that hash variant per call. A variant is
 * built for some parameter sets only (on x86-64, avx2 for the SHAKE sets and
 * shani for the SHA2 sets); a call for a set without it answers
 * IMPL_UNSUPPORTED, so drivers count it NOT RUN and never report it under
 * another variant's name.
 *
 * Status mapping. The library's own contract is checked, not smoothed
 * over: verification maps NIRAPOD_SLHDSA_OK to IMPL_OK and
 * ERROR_INVALID_SIGNATURE to IMPL_REJECT; an over-long context maps to
 * IMPL_REJECT on the external verify, where the header defines
 * ERROR_INVALID_CONTEXT for it. Any other status, for example
 * ERROR_INVALID_LENGTH for a signature of the wrong size, is IMPL_ERROR, so
 * a run fails if the library ever returns it where its header promises
 * ERROR_INVALID_SIGNATURE.
 */

#include <stdio.h>
#include <string.h>

#include "impl.h"
#include "nirapod_slhdsa.h"
#include "nirapod_slhdsa_testing.h"

/* impl.h numbers sets 0..11 in FIPS 205 Table 2 order; the library 1..12. */
#define SET(set) ((nirapod_slhdsa_set)((set) + 1))

static nirapod_slhdsa_testing_config cfg = { NULL, NULL, NULL, 0 };

/* The configuration for one call: NULL means production dispatch. */
static const nirapod_slhdsa_testing_config *config(void)
{
    return cfg.variant != NULL ? &cfg : NULL;
}

/* With a forced variant, a set built without it is not run. */
static int unsupported(int set)
{
    return cfg.variant != NULL &&
           !nirapod_slhdsa_testing_variant_supported(SET(set), cfg.variant);
}

const char *impl_name(void)
{
    return "nirapod-slhdsa";
}

/* Accepted when at least one set has the variant on this CPU. */
int impl_force_variant(const char *name)
{
    for (int i = 0; i < SLH_SET_COUNT; i++) {
        if (nirapod_slhdsa_testing_variant_supported(SET(i), name)) {
            cfg.variant = name;
            return IMPL_OK;
        }
    }
    return IMPL_UNSUPPORTED;
}

/*
 * The default reads the dispatcher's choice from SHA2-128s and SHAKE-128s
 * and reports it for each family. That holds for every set while the
 * library's variant table (capi/sets.c) gives all sets of a family the
 * same accelerator, as it does now; if it ever differs by set, this string
 * must become per set.
 */
const char *impl_variant(void)
{
    static char buf[96];
    const char *sha2 = nirapod_slhdsa_testing_variant(NIRAPOD_SLHDSA_SHA2_128S);
    const char *shake = nirapod_slhdsa_testing_variant(NIRAPOD_SLHDSA_SHAKE_128S);

    if (cfg.variant != NULL)
        snprintf(buf, sizeof buf, "forced[%s]", cfg.variant);
    else
        snprintf(buf, sizeof buf, "default[sha2=%s,shake=%s]", sha2 ? sha2 : "?",
                 shake ? shake : "?");
    return buf;
}

int impl_init(void)
{
    for (int i = 0; i < SLH_SET_COUNT; i++) {
        const char *name = nirapod_slhdsa_set_name(SET(i));
        if (name == NULL || strcmp(name, slh_sets[i].name) != 0 ||
            nirapod_slhdsa_public_key_bytes(SET(i)) != slh_sets[i].pk_bytes ||
            nirapod_slhdsa_secret_key_bytes(SET(i)) != slh_sets[i].sk_bytes ||
            nirapod_slhdsa_signature_bytes(SET(i)) != slh_sets[i].sig_bytes)
            return IMPL_ERROR;
    }
    return IMPL_OK;
}

static int done(nirapod_slhdsa_status st)
{
    return st == NIRAPOD_SLHDSA_OK ? IMPL_OK : IMPL_ERROR;
}

static int verdict(nirapod_slhdsa_status st)
{
    if (st == NIRAPOD_SLHDSA_OK)
        return IMPL_OK;
    return st == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE ? IMPL_REJECT : IMPL_ERROR;
}

int impl_keygen_seed(int set, const uint8_t *sk_seed, const uint8_t *sk_prf,
                     const uint8_t *pk_seed, uint8_t *pk, uint8_t *sk)
{
    if (unsupported(set))
        return IMPL_UNSUPPORTED;
    return done(nirapod_slhdsa_testing_keygen_internal(
        config(), SET(set), pk, slh_sets[set].pk_bytes, sk, slh_sets[set].sk_bytes,
        sk_seed, sk_prf, pk_seed, slh_sets[set].n));
}

int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m,
                       size_t mlen, const uint8_t *addrnd, uint8_t *sig)
{
    if (unsupported(set))
        return IMPL_UNSUPPORTED;
    return done(nirapod_slhdsa_testing_sign_internal(
        config(), SET(set), sig, slh_sets[set].sig_bytes, m, mlen, sk,
        slh_sets[set].sk_bytes, addrnd, addrnd ? slh_sets[set].n : 0));
}

int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m,
                         size_t mlen, const uint8_t *sig, size_t siglen)
{
    if (unsupported(set))
        return IMPL_UNSUPPORTED;
    return verdict(nirapod_slhdsa_testing_verify_internal(
        config(), SET(set), sig, siglen, m, mlen, pk, slh_sets[set].pk_bytes));
}

/* The library's pre-hash value is the final OID arc (nirapod_slhdsa.h). */
static unsigned prehash_id(slh_ph ph)
{
    return ph == PH_NONE ? 0 : slh_ph_table[ph].oid_der[10];
}

int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m,
              size_t mlen, const uint8_t *ctx, size_t ctxlen,
              const uint8_t *addrnd, uint8_t *sig)
{
    if (unsupported(set))
        return IMPL_UNSUPPORTED;
    return done(nirapod_slhdsa_testing_sign(
        config(), SET(set), prehash_id(ph), sig, slh_sets[set].sig_bytes, m, mlen, ctx,
        ctxlen, sk, slh_sets[set].sk_bytes, addrnd, addrnd ? slh_sets[set].n : 0));
}

int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m,
                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, size_t siglen)
{
    nirapod_slhdsa_status st;
    size_t pklen = slh_sets[set].pk_bytes;

    if (unsupported(set))
        return IMPL_UNSUPPORTED;
    if (config() != NULL)
        st = nirapod_slhdsa_testing_verify(config(), SET(set), prehash_id(ph), sig, siglen, m,
                                           mlen, ctx, ctxlen, pk, pklen);
    else if (ph == PH_NONE)
        st = nirapod_slhdsa_verify(SET(set), sig, siglen, m, mlen, ctx, ctxlen, pk, pklen);
    else
        st = nirapod_slhdsa_hash_verify(SET(set), (nirapod_slhdsa_prehash)prehash_id(ph),
                                        sig, siglen, m, mlen, ctx, ctxlen, pk, pklen);

    if (st == NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT && ctxlen > 255)
        return IMPL_REJECT;
    return verdict(st);
}
