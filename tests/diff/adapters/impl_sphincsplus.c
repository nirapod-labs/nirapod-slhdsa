/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl_sphincsplus.c
 * ==================
 *
 * Adapter for the SPHINCS+ team's optimised implementations (ref,
 * sha2-avx2, shake-avx2, shake-a64), at the FIPS 205 revision pinned in
 * bench/baselines.lock. That code selects one parameter set at compile
 * time, so each build of this adapter serves the single set named by
 * SPX_SET_NAME and answers IMPL_UNSUPPORTED for the others.
 *
 * Mapping onto its api.h:
 *
 *   keygen_seed  crypto_sign_seed_keypair(SK.seed || SK.prf || PK.seed)
 *   internal     crypto_sign_signature_internal / crypto_sign_verify_internal
 *                with an empty prefix, so M reaches slh_sign_internal as is
 *   pure         crypto_sign_signature_derand / crypto_sign_verify
 *   pre-hash     crypto_sign_signature_prehash_derand /
 *                crypto_sign_verify_prehash, which take PH(M) and the OID
 *                and build M' themselves
 *
 * Its HashSLH-DSA entry points take a digest computed by the caller. The
 * adapter computes it with the project's own digest code where the build
 * has it: SHA-256 and SHA-512 (sha2.c) in SHA2 builds, SHAKE256
 * (fips202.c) in SHAKE builds; fips202.h also declares SHAKE128 and
 * SHA3-256/512, but fips202.c does not define them. The project ships no
 * code for the other pre-hash functions, so those are reported unsupported
 * (NOT RUN) rather than computed with another library.
 *
 * Single failure value. crypto_sign_verify* return 0 or -1; -1 covers an
 * invalid signature, a wrong length and a context over 255 bytes alike, so
 * an error inside the code would also read as a rejection. That limit is
 * part of this adapter's evidence.
 */

#include <string.h>

#include "api.h"
#include "impl.h"
#if defined(SPX_FAMILY_SHA2)
#include "context.h"
#include "sha2.h"
#elif defined(SPX_FAMILY_SHAKE)
#include "fips202.h"
#else
#error "SPX_FAMILY_SHA2 or SPX_FAMILY_SHAKE must name the build's hash family"
#endif

#ifndef SPX_SET_NAME
#error "SPX_SET_NAME must name the parameter set this build was compiled for"
#endif

static int built_set = -1;

const char *impl_name(void)
{
    return "sphincsplus";
}

#ifndef SPX_VARIANT_NAME
#define SPX_VARIANT_NAME "unknown"
#endif

/* The variant is the upstream directory this build was compiled from. */
int impl_force_variant(const char *name)
{
    return strcmp(name, SPX_VARIANT_NAME) == 0 ? IMPL_OK : IMPL_UNSUPPORTED;
}

const char *impl_variant(void)
{
    return SPX_VARIANT_NAME ";reject=single-value";
}

int impl_init(void)
{
    built_set = slh_set_index(SPX_SET_NAME);
    if (built_set < 0 ||
        crypto_sign_publickeybytes() != slh_sets[built_set].pk_bytes ||
        crypto_sign_secretkeybytes() != slh_sets[built_set].sk_bytes ||
        crypto_sign_bytes() != slh_sets[built_set].sig_bytes)
        return IMPL_ERROR;
    return IMPL_OK;
}

int impl_keygen_seed(int set, const uint8_t *sk_seed, const uint8_t *sk_prf,
                     const uint8_t *pk_seed, uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[3 * 32];
    size_t n = slh_sets[set].n;

    if (set != built_set)
        return IMPL_UNSUPPORTED;
    memcpy(seed, sk_seed, n);
    memcpy(seed + n, sk_prf, n);
    memcpy(seed + 2 * n, pk_seed, n);
    return crypto_sign_seed_keypair(pk, sk, seed) == 0 ? IMPL_OK : IMPL_ERROR;
}

int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m,
                       size_t mlen, const uint8_t *addrnd, uint8_t *sig)
{
    size_t siglen = 0;

    if (set != built_set)
        return IMPL_UNSUPPORTED;
    if (crypto_sign_signature_internal(sig, &siglen, m, mlen, NULL, 0, sk,
                                       addrnd) != 0 ||
        siglen != slh_sets[set].sig_bytes)
        return IMPL_ERROR;
    return IMPL_OK;
}

int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m,
                         size_t mlen, const uint8_t *sig, size_t siglen)
{
    if (set != built_set)
        return IMPL_UNSUPPORTED;
    return crypto_sign_verify_internal(sig, siglen, m, mlen, NULL, 0, pk) == 0
               ? IMPL_OK
               : IMPL_REJECT;
}

/* PH(M) with the project's own digests; 0 on success, -1 when it has none. */
static int prehash(slh_ph ph, const uint8_t *m, size_t mlen, uint8_t *out)
{
    switch (ph) {
#if defined(SPX_FAMILY_SHA2)
    case PH_SHA2_256: sha256(out, m, mlen); return 0;
    case PH_SHA2_512: sha512(out, m, mlen); return 0;
#else
    case PH_SHAKE_256: shake256(out, 64, m, mlen); return 0;
#endif
    default: return -1;
    }
}

int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m,
              size_t mlen, const uint8_t *ctx, size_t ctxlen,
              const uint8_t *addrnd, uint8_t *sig)
{
    size_t siglen = 0;
    uint8_t digest[64];
    int r;

    if (set != built_set)
        return IMPL_UNSUPPORTED;
    if (ctxlen > 255)
        return IMPL_ERROR;
    if (ph == PH_NONE) {
        r = crypto_sign_signature_derand(sig, &siglen, m, mlen, ctx, ctxlen, sk, addrnd);
    } else {
        if (prehash(ph, m, mlen, digest) != 0)
            return IMPL_UNSUPPORTED;
        r = crypto_sign_signature_prehash_derand(
            sig, &siglen, digest, slh_ph_table[ph].digest_bytes, slh_ph_table[ph].oid_der,
            sizeof slh_ph_table[ph].oid_der, ctx, ctxlen, sk, addrnd);
    }
    return r == 0 && siglen == slh_sets[set].sig_bytes ? IMPL_OK : IMPL_ERROR;
}

int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m,
                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, size_t siglen)
{
    uint8_t digest[64];

    if (set != built_set)
        return IMPL_UNSUPPORTED;
    /* FIPS 205 Algorithms 24 and 25 return false for |ctx| > 255. */
    if (ctxlen > 255)
        return IMPL_REJECT;
    if (ph == PH_NONE)
        return crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk) == 0 ? IMPL_OK
                                                                               : IMPL_REJECT;
    if (prehash(ph, m, mlen, digest) != 0)
        return IMPL_UNSUPPORTED;
    return crypto_sign_verify_prehash(sig, siglen, digest, slh_ph_table[ph].digest_bytes,
                                      slh_ph_table[ph].oid_der,
                                      sizeof slh_ph_table[ph].oid_der, ctx, ctxlen,
                                      pk) == 0
               ? IMPL_OK
               : IMPL_REJECT;
}
