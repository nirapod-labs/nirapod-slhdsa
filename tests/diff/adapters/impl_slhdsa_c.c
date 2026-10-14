/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl_slhdsa_c.c
 * ===============
 *
 * Adapter for the PQ Code Package slhdsa-c library, used as an independent
 * baseline. Every call maps one-to-one onto slhdsa-c's public functions;
 * the adapter performs no cryptographic work. slhdsa-c is built from the
 * revision pinned in bench/baselines.lock and is never part of this
 * library.
 *
 * Single failure value. slhdsa-c's verification functions return 1 or 0
 * and nothing else; 0 covers an invalid signature, a signature of the wrong
 * length, a context over 255 bytes and an unknown pre-hash name alike. The
 * adapter passes only names from slh_ph_table and handles an over-long
 * context itself, so the causes of a 0 left are the two that are
 * rejections; an error inside slhdsa-c would still read as a rejection,
 * and that limit is part of this adapter's evidence.
 */

#include <string.h>

#include "impl.h"
#include "slh_dsa.h"
#include "slh_prehash.h"

static const slh_param_t *const params[SLH_SET_COUNT] = {
    &slh_dsa_sha2_128s, &slh_dsa_shake_128s, &slh_dsa_sha2_128f,
    &slh_dsa_shake_128f, &slh_dsa_sha2_192s, &slh_dsa_shake_192s,
    &slh_dsa_sha2_192f, &slh_dsa_shake_192f, &slh_dsa_sha2_256s,
    &slh_dsa_shake_256s, &slh_dsa_sha2_256f, &slh_dsa_shake_256f,
};

const char *impl_name(void)
{
    return "slhdsa-c";
}

/*
 * One code path: C without intrinsics or assembly (the compiler may still
 * auto-vectorise it under the project's -O3).
 */
int impl_force_variant(const char *name)
{
    return strcmp(name, "c") == 0 ? IMPL_OK : IMPL_UNSUPPORTED;
}

const char *impl_variant(void)
{
    return "c;reject=single-value";
}

int impl_init(void)
{
    /* Guard against a table mismatch between this adapter and the library. */
    for (int i = 0; i < SLH_SET_COUNT; i++) {
        if (strcmp(slh_alg_id(params[i]), slh_sets[i].name) != 0 ||
            slh_pk_sz(params[i]) != slh_sets[i].pk_bytes ||
            slh_sk_sz(params[i]) != slh_sets[i].sk_bytes ||
            slh_sig_sz(params[i]) != slh_sets[i].sig_bytes)
            return IMPL_ERROR;
    }
    return IMPL_OK;
}

int impl_keygen_seed(int set, const uint8_t *sk_seed, const uint8_t *sk_prf,
                     const uint8_t *pk_seed, uint8_t *pk, uint8_t *sk)
{
    if (slh_keygen_internal(sk, pk, sk_seed, sk_prf, pk_seed, params[set]) != 0)
        return IMPL_ERROR;
    return IMPL_OK;
}

int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m,
                       size_t mlen, const uint8_t *addrnd, uint8_t *sig)
{
    size_t len = slh_sign_internal(sig, m, mlen, sk, addrnd, params[set]);
    return len == slh_sets[set].sig_bytes ? IMPL_OK : IMPL_ERROR;
}

int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m,
                         size_t mlen, const uint8_t *sig, size_t siglen)
{
    return slh_verify_internal(m, mlen, sig, siglen, pk, params[set]) == 1
               ? IMPL_OK
               : IMPL_REJECT;
}

int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m,
              size_t mlen, const uint8_t *ctx, size_t ctxlen,
              const uint8_t *addrnd, uint8_t *sig)
{
    size_t len;

    if (ctxlen > 255)
        return IMPL_ERROR;
    if (ph == PH_NONE)
        len = slh_sign(sig, m, mlen, ctx, ctxlen, sk, addrnd, params[set]);
    else
        len = hash_slh_sign(sig, m, mlen, ctx, ctxlen, slh_ph_table[ph].name,
                            sk, addrnd, params[set]);
    return len == slh_sets[set].sig_bytes ? IMPL_OK : IMPL_ERROR;
}

int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m,
                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, size_t siglen)
{
    int ok;

    /* FIPS 205 Algorithms 24 and 25 return false for |ctx| > 255. */
    if (ctxlen > 255)
        return IMPL_REJECT;
    if (ph == PH_NONE)
        ok = slh_verify(m, mlen, sig, siglen, ctx, ctxlen, pk, params[set]);
    else
        ok = hash_slh_verify(m, mlen, sig, siglen, ctx, ctxlen,
                             slh_ph_table[ph].name, pk, params[set]);
    return ok == 1 ? IMPL_OK : IMPL_REJECT;
}
