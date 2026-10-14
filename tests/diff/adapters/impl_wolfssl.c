/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl_wolfssl.c
 * ==============
 *
 * Adapter for wolfCrypt's SLH-DSA (wc_slhdsa.h), used as an independent
 * baseline. wolfSSL is GPL-licensed: it is built separately from the
 * release pinned in bench/baselines.lock, linked only into these test
 * programs, and never distributed with this library.
 *
 * Mapping:
 *
 *   keygen_seed  wc_SlhDsaKey_MakeKeyWithRandom, then Export{Private,Public}
 *   internal     wc_SlhDsaKey_SignMsg{Deterministic,WithRandom}, VerifyMsg
 *   pure         wc_SlhDsaKey_Sign{Deterministic,WithRandom}, Verify
 *   pre-hash     wc_SlhDsaKey_SignHash{Deterministic,WithRandom}, VerifyHash
 *
 * wolfCrypt's HashSLH-DSA takes PH(M) from the caller; this adapter computes
 * it with wolfCrypt's own digests, and wolfCrypt builds M'. wolfCrypt also
 * refuses a pre-hash function whose collision strength is below the
 * parameter set's (SHA-224 and SHA-512/224 always; SHA-256, SHA-512/256,
 * SHA3-256 and SHAKE128 above category 1; SHA-384 and SHA3-384 at category
 * 5). wolfCrypt attributes that policy to item 2.5 of the CMVP PQC
 * validation worksheet (slhdsa_check_hash_for_n in wc_slhdsa.c). FIPS 205
 * and ACVP permit those combinations, so the adapter reports them as
 * unsupported (NOT RUN), not as failures.
 *
 * Verification results: 0 is valid; SIG_VERIFY_E (the root comparison
 * failed) and BAD_LENGTH_E (the signature is not sigLen bytes; the adapter
 * always passes digests of the right length) are the documented
 * rejections; every other code is an error and fails the case. Parsed keys
 * are cached as in impl_openssl.c.
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#if defined(USE_INTEL_SPEEDUP)
#include <wolfssl/wolfcrypt/cpuid.h>
#endif

#include "impl.h"

static const enum SlhDsaParam params[SLH_SET_COUNT] = {
    SLHDSA_SHA2_128S, SLHDSA_SHAKE128S, SLHDSA_SHA2_128F, SLHDSA_SHAKE128F,
    SLHDSA_SHA2_192S, SLHDSA_SHAKE192S, SLHDSA_SHA2_192F, SLHDSA_SHAKE192F,
    SLHDSA_SHA2_256S, SLHDSA_SHAKE256S, SLHDSA_SHA2_256F, SLHDSA_SHAKE256F,
};

/* wolfCrypt hash identifiers, and the collision strength in bytes (n) it
 * requires of a pre-hash function; 0 marks one it refuses for every set. */
static const struct {
    enum wc_HashType type;
    size_t strength;
} ph_map[PH_COUNT] = {
    [PH_SHA2_256]     = { WC_HASH_TYPE_SHA256, 16 },
    [PH_SHA2_384]     = { WC_HASH_TYPE_SHA384, 24 },
    [PH_SHA2_512]     = { WC_HASH_TYPE_SHA512, 32 },
    [PH_SHA2_224]     = { WC_HASH_TYPE_SHA224, 0 },
    [PH_SHA2_512_224] = { WC_HASH_TYPE_SHA512_224, 0 },
    [PH_SHA2_512_256] = { WC_HASH_TYPE_SHA512_256, 16 },
    [PH_SHA3_224]     = { WC_HASH_TYPE_SHA3_224, 0 },
    [PH_SHA3_256]     = { WC_HASH_TYPE_SHA3_256, 16 },
    [PH_SHA3_384]     = { WC_HASH_TYPE_SHA3_384, 24 },
    [PH_SHA3_512]     = { WC_HASH_TYPE_SHA3_512, 32 },
    [PH_SHAKE_128]    = { WC_HASH_TYPE_SHAKE128, 16 },
    [PH_SHAKE_256]    = { WC_HASH_TYPE_SHAKE256, 32 },
};

typedef struct {
    int set;
    int is_private;
    uint8_t bytes[128];
    SlhDsaKey key;
    int live;
} key_cache;

static key_cache priv_cache = { -1, 1, { 0 }, { 0 }, 0 };
static key_cache pub_cache = { -1, 0, { 0 }, { 0 }, 0 };

const char *impl_name(void)
{
    return "wolfssl-" LIBWOLFSSL_VERSION_STRING;
}

int impl_force_variant(const char *name)
{
    return strcmp(name, "default") == 0 ? IMPL_OK : IMPL_UNSUPPORTED;
}

/* The build's assembly option and, on x86-64, the CPU flags it dispatches on. */
const char *impl_variant(void)
{
    static char buf[64];
#if defined(USE_INTEL_SPEEDUP)
    snprintf(buf, sizeof buf, "default[intelasm,cpuid=0x%lx]",
             (unsigned long)cpuid_get_flags());
#elif defined(WOLFSSL_ARMASM)
    snprintf(buf, sizeof buf, "default[armasm]");
#else
    snprintf(buf, sizeof buf, "default[c]");
#endif
    return buf;
}

int impl_init(void)
{
    for (int i = 0; i < SLH_SET_COUNT; i++) {
        if (wc_SlhDsaKey_PublicSizeFromParam(params[i]) != (int)slh_sets[i].pk_bytes ||
            wc_SlhDsaKey_PrivateSizeFromParam(params[i]) != (int)slh_sets[i].sk_bytes ||
            wc_SlhDsaKey_SigSizeFromParam(params[i]) != (int)slh_sets[i].sig_bytes)
            return IMPL_ERROR;
    }
    return IMPL_OK;
}

static SlhDsaKey *load_key(key_cache *c, int set, const uint8_t *bytes)
{
    size_t len = c->is_private ? slh_sets[set].sk_bytes : slh_sets[set].pk_bytes;
    int ret;

    if (c->live && c->set == set && memcmp(c->bytes, bytes, len) == 0)
        return &c->key;
    if (c->live)
        wc_SlhDsaKey_Free(&c->key);
    c->live = 0;
    if (wc_SlhDsaKey_Init(&c->key, params[set], NULL, INVALID_DEVID) != 0)
        return NULL;
    c->live = 1;
    ret = c->is_private ? wc_SlhDsaKey_ImportPrivate(&c->key, bytes, (word32)len)
                        : wc_SlhDsaKey_ImportPublic(&c->key, bytes, (word32)len);
    if (ret != 0) {
        wc_SlhDsaKey_Free(&c->key);
        c->live = 0;
        return NULL;
    }
    c->set = set;
    memcpy(c->bytes, bytes, len);
    return &c->key;
}

int impl_keygen_seed(int set, const uint8_t *sk_seed, const uint8_t *sk_prf,
                     const uint8_t *pk_seed, uint8_t *pk, uint8_t *sk)
{
    word32 n = (word32)slh_sets[set].n;
    word32 sklen = (word32)slh_sets[set].sk_bytes, pklen = (word32)slh_sets[set].pk_bytes;
    SlhDsaKey key;
    int ok;

    if (wc_SlhDsaKey_Init(&key, params[set], NULL, INVALID_DEVID) != 0)
        return IMPL_ERROR;
    ok = wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed, n, sk_prf, n, pk_seed, n) == 0 &&
         wc_SlhDsaKey_ExportPrivate(&key, sk, &sklen) == 0 &&
         sklen == slh_sets[set].sk_bytes &&
         wc_SlhDsaKey_ExportPublic(&key, pk, &pklen) == 0 &&
         pklen == slh_sets[set].pk_bytes;
    wc_SlhDsaKey_Free(&key);
    return ok ? IMPL_OK : IMPL_ERROR;
}

/* PH(M) of the length FIPS 205 section 10.2.2 fixes, with wolfCrypt's digests. */
static int prehash(slh_ph ph, const uint8_t *m, size_t mlen, uint8_t *out)
{
    word32 dlen = (word32)slh_ph_table[ph].digest_bytes;

    if (ph == PH_SHAKE_128)
        return wc_Shake128Hash(m, (word32)mlen, out, dlen);
    if (ph == PH_SHAKE_256)
        return wc_Shake256Hash(m, (word32)mlen, out, dlen);
    if (wc_HashGetDigestSize(ph_map[ph].type) != (int)dlen)
        return -1;
    return wc_Hash(ph_map[ph].type, m, (word32)mlen, out, dlen);
}

static int verdict(int ret)
{
    if (ret == 0)
        return IMPL_OK;
    return ret == SIG_VERIFY_E || ret == BAD_LENGTH_E ? IMPL_REJECT : IMPL_ERROR;
}

static int ph_refused(int set, slh_ph ph)
{
    return ph_map[ph].strength < slh_sets[set].n;
}

int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m,
                       size_t mlen, const uint8_t *addrnd, uint8_t *sig)
{
    SlhDsaKey *key = load_key(&priv_cache, set, sk);
    word32 siglen = (word32)slh_sets[set].sig_bytes;
    int ret;

    if (key == NULL)
        return IMPL_ERROR;
    ret = addrnd ? wc_SlhDsaKey_SignMsgWithRandom(key, m, (word32)mlen, sig, &siglen, addrnd)
                 : wc_SlhDsaKey_SignMsgDeterministic(key, m, (word32)mlen, sig, &siglen);
    return ret == 0 && siglen == slh_sets[set].sig_bytes ? IMPL_OK : IMPL_ERROR;
}

int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m,
                         size_t mlen, const uint8_t *sig, size_t siglen)
{
    SlhDsaKey *key = load_key(&pub_cache, set, pk);

    if (key == NULL)
        return IMPL_ERROR;
    return verdict(wc_SlhDsaKey_VerifyMsg(key, m, (word32)mlen, sig, (word32)siglen));
}

int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m,
              size_t mlen, const uint8_t *ctx, size_t ctxlen,
              const uint8_t *addrnd, uint8_t *sig)
{
    SlhDsaKey *key;
    word32 siglen = (word32)slh_sets[set].sig_bytes;
    uint8_t digest[64];
    int ret;

    if (ctxlen > 255)
        return IMPL_ERROR;
    if (ph != PH_NONE && ph_refused(set, ph))
        return IMPL_UNSUPPORTED;
    if ((key = load_key(&priv_cache, set, sk)) == NULL)
        return IMPL_ERROR;
    if (ph == PH_NONE) {
        ret = addrnd ? wc_SlhDsaKey_SignWithRandom(key, ctx, (byte)ctxlen, m, (word32)mlen,
                                                   sig, &siglen, addrnd)
                     : wc_SlhDsaKey_SignDeterministic(key, ctx, (byte)ctxlen, m,
                                                      (word32)mlen, sig, &siglen);
    } else {
        word32 dlen = (word32)slh_ph_table[ph].digest_bytes;
        if (prehash(ph, m, mlen, digest) != 0)
            return IMPL_ERROR;
        ret = addrnd ? wc_SlhDsaKey_SignHashWithRandom(key, ctx, (byte)ctxlen, digest, dlen,
                                                       ph_map[ph].type, sig, &siglen, addrnd)
                     : wc_SlhDsaKey_SignHashDeterministic(key, ctx, (byte)ctxlen, digest,
                                                          dlen, ph_map[ph].type, sig,
                                                          &siglen);
    }
    return ret == 0 && siglen == slh_sets[set].sig_bytes ? IMPL_OK : IMPL_ERROR;
}

int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m,
                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, size_t siglen)
{
    SlhDsaKey *key;
    uint8_t digest[64];
    int ret;

    if (ctxlen > 255)
        return IMPL_REJECT;
    if (ph != PH_NONE && ph_refused(set, ph))
        return IMPL_UNSUPPORTED;
    if ((key = load_key(&pub_cache, set, pk)) == NULL)
        return IMPL_ERROR;
    if (ph == PH_NONE) {
        ret = wc_SlhDsaKey_Verify(key, ctx, (byte)ctxlen, m, (word32)mlen, sig,
                                  (word32)siglen);
    } else {
        if (prehash(ph, m, mlen, digest) != 0)
            return IMPL_ERROR;
        ret = wc_SlhDsaKey_VerifyHash(key, ctx, (byte)ctxlen, digest,
                                      (word32)slh_ph_table[ph].digest_bytes,
                                      ph_map[ph].type, sig, (word32)siglen);
    }
    return verdict(ret);
}
