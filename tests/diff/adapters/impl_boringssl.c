/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl_boringssl.c
 * ================
 *
 * Adapter for BoringSSL's SLH-DSA (openssl/slhdsa.h), used as a partial
 * test oracle. BoringSSL implements two parameter
 * sets, SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-256f; the others answer
 * IMPL_UNSUPPORTED.
 *
 * Its public API generates keys from a seed and verifies pure signatures,
 * which this adapter maps directly. Its HashSLH-DSA covers SHA2-128s only:
 * SLHDSA_SHA2_128S_prehash_verify takes SHA-256 digests, and
 * SLHDSA_SHA2_128S_prehash_warning_nonstandard_verify takes SHA-384 (a
 * combination BoringSSL calls non-standard; FIPS 205 and ACVP include it).
 * The adapter computes those digests with BoringSSL's own SHA-256/384 and
 * maps both; other pre-hash functions and sets are unsupported.
 *
 * All its signing functions draw their own randomness, so signing with a
 * given addrnd, deterministic signing and the internal interface are
 * reported unsupported rather than reached through BoringSSL's internal
 * (C++) module functions. ACVP and differential runs therefore cover its
 * key generation and verification only.
 *
 * Single failure value. Its verify functions return 1 or 0; 0 also covers
 * a wrong length, an over-long context and an unsupported hash, so an error
 * inside BoringSSL would read as a rejection. The adapter screens the
 * context length and the hash itself.
 */

#include <string.h>

#include <openssl/nid.h>
#include <openssl/sha.h>
#include <openssl/slhdsa.h>

#include "impl.h"

/* Indices into slh_sets (tables.c). */
#define SHA2_128S 0
#define SHAKE_256F 11

const char *impl_name(void)
{
    return "boringssl";
}

int impl_force_variant(const char *name)
{
    return strcmp(name, "default") == 0 ? IMPL_OK : IMPL_UNSUPPORTED;
}

const char *impl_variant(void)
{
    return "default;reject=single-value";
}

int impl_init(void)
{
    return slh_sets[SHA2_128S].sig_bytes == SLHDSA_SHA2_128S_SIGNATURE_BYTES &&
                   slh_sets[SHAKE_256F].sig_bytes == SLHDSA_SHAKE_256F_SIGNATURE_BYTES
               ? IMPL_OK
               : IMPL_ERROR;
}

int impl_keygen_seed(int set, const uint8_t *sk_seed, const uint8_t *sk_prf,
                     const uint8_t *pk_seed, uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[3 * 32];
    size_t n = slh_sets[set].n;

    if (set != SHA2_128S && set != SHAKE_256F)
        return IMPL_UNSUPPORTED;
    memcpy(seed, sk_seed, n);
    memcpy(seed + n, sk_prf, n);
    memcpy(seed + 2 * n, pk_seed, n);
    if (set == SHA2_128S)
        SLHDSA_SHA2_128S_generate_key_from_seed(pk, sk, seed);
    else
        SLHDSA_SHAKE_256F_generate_key_from_seed(pk, sk, seed);
    return IMPL_OK;
}

int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m,
                       size_t mlen, const uint8_t *addrnd, uint8_t *sig)
{
    (void)set, (void)sk, (void)m, (void)mlen, (void)addrnd, (void)sig;
    return IMPL_UNSUPPORTED;
}

int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m,
                         size_t mlen, const uint8_t *sig, size_t siglen)
{
    (void)set, (void)pk, (void)m, (void)mlen, (void)sig, (void)siglen;
    return IMPL_UNSUPPORTED;
}

int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m,
              size_t mlen, const uint8_t *ctx, size_t ctxlen,
              const uint8_t *addrnd, uint8_t *sig)
{
    (void)set, (void)ph, (void)sk, (void)m, (void)mlen, (void)ctx, (void)ctxlen;
    (void)addrnd, (void)sig;
    return IMPL_UNSUPPORTED;
}

int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m,
                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, size_t siglen)
{
    uint8_t digest[SHA384_DIGEST_LENGTH];
    int ok;

    if (set != SHA2_128S && set != SHAKE_256F)
        return IMPL_UNSUPPORTED;
    if (ph != PH_NONE && (set != SHA2_128S || (ph != PH_SHA2_256 && ph != PH_SHA2_384)))
        return IMPL_UNSUPPORTED;
    /* FIPS 205 Algorithms 24 and 25 return false for |ctx| > 255. */
    if (ctxlen > 255)
        return IMPL_REJECT;
    if (ph == PH_SHA2_256) {
        SHA256(m, mlen, digest);
        ok = SLHDSA_SHA2_128S_prehash_verify(sig, siglen, pk, digest, SHA256_DIGEST_LENGTH,
                                             NID_sha256, ctx, ctxlen);
    } else if (ph == PH_SHA2_384) {
        SHA384(m, mlen, digest);
        ok = SLHDSA_SHA2_128S_prehash_warning_nonstandard_verify(
            sig, siglen, pk, digest, SHA384_DIGEST_LENGTH, NID_sha384, ctx, ctxlen);
    } else if (set == SHA2_128S) {
        ok = SLHDSA_SHA2_128S_verify(sig, siglen, pk, m, mlen, ctx, ctxlen);
    } else {
        ok = SLHDSA_SHAKE_256F_verify(sig, siglen, pk, m, mlen, ctx, ctxlen);
    }
    return ok == 1 ? IMPL_OK : IMPL_REJECT;
}
