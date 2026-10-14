/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl_openssl.c
 * ==============
 *
 * Adapter for OpenSSL's SLH-DSA provider, used as an independent baseline
 * through the public EVP interface (EVP_PKEY_sign_message_init and
 * EVP_PKEY_verify_message_init with the parameters documented in
 * EVP_SIGNATURE-SLH-DSA(7) and EVP_PKEY-SLH-DSA(7)).
 *
 * Mapping:
 *
 *   keygen_seed      EVP_PKEY_generate with the "seed" parameter
 *                    (SK.seed || SK.prf || PK.seed)
 *   *_internal       "message-encoding" = 0, which passes M unchanged to
 *                    slh_sign_internal / slh_verify_internal
 *   pure             "message-encoding" = 1 and "context-string"
 *   addrnd           "test-entropy"; NULL selects "deterministic" = 1
 *
 * OpenSSL does not implement HashSLH-DSA: the DESCRIPTION of its manual
 * page EVP_SIGNATURE-SLH-DSA(7) (3.6.5 and 4.0.3) says pre-hash signing is
 * not supported and may be done by the user with message-encoding 0. For
 * a pre-hash call this adapter computes PH(M) with OpenSSL's own digest
 * and builds M' = 0x01 || len(ctx) || ctx || OID(PH) || PH(M) as FIPS 205
 * Algorithm 23 specifies, then signs M' through the unframed interface.
 * That framing is the only cryptographic step an adapter performs; results
 * for pre-hash groups therefore cover OpenSSL's digests and SLH-DSA core
 * together with this framing, not an OpenSSL HashSLH-DSA.
 *
 * Parsed keys and fetched algorithms are cached, so consecutive cases on
 * one key import it once, as an application holding an EVP_PKEY would.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "impl.h"

static EVP_SIGNATURE *sigalg[SLH_SET_COUNT];

/* OpenSSL rejects a NULL octet-string parameter even at length 0. */
static const uint8_t empty_ctx[1];

typedef struct {
    int set;
    int is_private;
    uint8_t bytes[128];
    EVP_PKEY *pkey;
} key_cache;

static key_cache priv_cache = { -1, 1, { 0 }, NULL };
static key_cache pub_cache = { -1, 0, { 0 }, NULL };

/* The run-time library version, so 3.x and 4.x results stay distinct. */
const char *impl_name(void)
{
    static char buf[48];

    snprintf(buf, sizeof buf, "openssl-%s", OpenSSL_version(OPENSSL_VERSION_STRING));
    return buf;
}

/*
 * OpenSSL picks its SHA-2 and Keccak code paths itself from the CPU
 * capabilities it detects. Only that default is offered; the capability
 * words it detected (OPENSSL_armcap or OPENSSL_ia32cap) are reported as
 * the variant so a result records which paths were available to it.
 */
int impl_force_variant(const char *name)
{
    return strcmp(name, "default") == 0 ? IMPL_OK : IMPL_UNSUPPORTED;
}

/*
 * The variant names the CPU capability words OpenSSL detected and, because
 * its pre-hash results include this adapter's framing (see the header),
 * says so in every report: "prehash=adapter-framed".
 */
const char *impl_variant(void)
{
    static char buf[200];
    const char *cpu = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS);

    snprintf(buf, sizeof buf, "default[%s;prehash=adapter-framed];reject=single-value",
             cpu != NULL && *cpu ? cpu : "no-cpu-settings");
    for (char *p = buf; *p; p++)
        if (*p == ' ')
            *p = ',';
    return buf;
}

int impl_init(void)
{
    for (int i = 0; i < SLH_SET_COUNT; i++) {
        sigalg[i] = EVP_SIGNATURE_fetch(NULL, slh_sets[i].name, NULL);
        if (sigalg[i] == NULL)
            return IMPL_ERROR;
    }
    return IMPL_OK;
}

static EVP_PKEY *load_key(key_cache *c, int set, const uint8_t *bytes)
{
    size_t len = c->is_private ? slh_sets[set].sk_bytes : slh_sets[set].pk_bytes;
    EVP_PKEY_CTX *kctx;
    OSSL_PARAM prm[2];
    EVP_PKEY *pkey = NULL;

    if (c->pkey != NULL && c->set == set && memcmp(c->bytes, bytes, len) == 0)
        return c->pkey;

    kctx = EVP_PKEY_CTX_new_from_name(NULL, slh_sets[set].name, NULL);
    if (kctx == NULL)
        return NULL;
    prm[0] = OSSL_PARAM_construct_octet_string(
        c->is_private ? OSSL_PKEY_PARAM_PRIV_KEY : OSSL_PKEY_PARAM_PUB_KEY,
        (void *)bytes, len);
    prm[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata_init(kctx) != 1 ||
        EVP_PKEY_fromdata(kctx, &pkey,
                          c->is_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                          prm) != 1)
        pkey = NULL;
    EVP_PKEY_CTX_free(kctx);
    if (pkey == NULL)
        return NULL;

    EVP_PKEY_free(c->pkey);
    c->pkey = pkey;
    c->set = set;
    memcpy(c->bytes, bytes, len);
    return pkey;
}

/* EVP_PKEY_generate from the given 3n-byte seed SK.seed || SK.prf || PK.seed. */
static int keygen(int set, uint8_t *seed, uint8_t *pk, uint8_t *sk)
{
    size_t n = slh_sets[set].n, len;
    EVP_PKEY_CTX *kctx;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM prm[2];
    int ret = IMPL_ERROR;

    kctx = EVP_PKEY_CTX_new_from_name(NULL, slh_sets[set].name, NULL);
    if (kctx == NULL)
        return IMPL_ERROR;
    prm[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, seed, 3 * n);
    prm[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_keygen_init(kctx) == 1 &&
        EVP_PKEY_CTX_set_params(kctx, prm) == 1 &&
        EVP_PKEY_generate(kctx, &pkey) == 1 &&
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pk,
                                        slh_sets[set].pk_bytes, &len) == 1 &&
        len == slh_sets[set].pk_bytes &&
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, sk,
                                        slh_sets[set].sk_bytes, &len) == 1 &&
        len == slh_sets[set].sk_bytes)
        ret = IMPL_OK;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ret;
}

int impl_keygen_seed(int set, const uint8_t *sk_seed, const uint8_t *sk_prf,
                     const uint8_t *pk_seed, uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[3 * 32];
    size_t n = slh_sets[set].n;

    memcpy(seed, sk_seed, n);
    memcpy(seed + n, sk_prf, n);
    memcpy(seed + 2 * n, pk_seed, n);
    return keygen(set, seed, pk, sk);
}

/*
 * M' for HashSLH-DSA (FIPS 205 Algorithm 23): 0x01, the context length as
 * one byte, the context, the DER OID of PH, then PH(M): the full digest, or
 * 256 and 512 output bits for SHAKE128 and SHAKE256. Returns a malloc'd
 * buffer the caller frees, or NULL for ctxlen > 255 or any digest failure.
 */
static uint8_t *prehash_frame(slh_ph ph, const uint8_t *m, size_t mlen,
                              const uint8_t *ctx, size_t ctxlen, size_t *outlen)
{
    static const char *const md_names[PH_COUNT] = {
        [PH_SHA2_256] = "SHA2-256",       [PH_SHA2_384] = "SHA2-384",
        [PH_SHA2_512] = "SHA2-512",       [PH_SHA2_224] = "SHA2-224",
        [PH_SHA2_512_224] = "SHA2-512/224", [PH_SHA2_512_256] = "SHA2-512/256",
        [PH_SHA3_224] = "SHA3-224",       [PH_SHA3_256] = "SHA3-256",
        [PH_SHA3_384] = "SHA3-384",       [PH_SHA3_512] = "SHA3-512",
        [PH_SHAKE_128] = "SHAKE-128",     [PH_SHAKE_256] = "SHAKE-256",
    };
    const slh_ph_info *info = &slh_ph_table[ph];
    size_t dlen = info->digest_bytes;
    size_t total = 2 + ctxlen + sizeof info->oid_der + dlen;
    uint8_t *out, *p;
    EVP_MD *md;
    EVP_MD_CTX *mctx;
    int ok;

    if (ctxlen > 255)
        return NULL;
    out = malloc(total);
    md = EVP_MD_fetch(NULL, md_names[ph], NULL);
    mctx = EVP_MD_CTX_new();
    if (out == NULL || md == NULL || mctx == NULL) {
        free(out);
        EVP_MD_free(md);
        EVP_MD_CTX_free(mctx);
        return NULL;
    }
    p = out;
    *p++ = 1;
    *p++ = (uint8_t)ctxlen;
    if (ctxlen > 0)
        memcpy(p, ctx, ctxlen);
    p += ctxlen;
    memcpy(p, info->oid_der, sizeof info->oid_der);
    p += sizeof info->oid_der;
    ok = EVP_DigestInit_ex2(mctx, md, NULL) == 1 &&
         EVP_DigestUpdate(mctx, m, mlen) == 1 &&
         ((EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF)
              ? EVP_DigestFinalXOF(mctx, p, dlen) == 1
              : (EVP_MD_get_size(md) == (int)dlen &&
                 EVP_DigestFinal_ex(mctx, p, NULL) == 1));
    EVP_MD_free(md);
    EVP_MD_CTX_free(mctx);
    if (!ok) {
        free(out);
        return NULL;
    }
    *outlen = total;
    return out;
}

static int do_sign(int set, int encode, const uint8_t *sk, const uint8_t *m,
                   size_t mlen, const uint8_t *ctx, size_t ctxlen,
                   const uint8_t *addrnd, uint8_t *sig)
{
    EVP_PKEY *pkey = load_key(&priv_cache, set, sk);
    EVP_PKEY_CTX *sctx;
    OSSL_PARAM prm[4], *q = prm;
    int det = 1;
    size_t siglen = slh_sets[set].sig_bytes;
    int ret = IMPL_ERROR;

    if (pkey == NULL)
        return IMPL_ERROR;
    *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    if (encode)
        *q++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)(ctx ? ctx : empty_ctx), ctxlen);
    if (addrnd != NULL)
        *q++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY, (void *)addrnd, slh_sets[set].n);
    else
        *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    *q = OSSL_PARAM_construct_end();

    sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (sctx != NULL &&
        EVP_PKEY_sign_message_init(sctx, sigalg[set], prm) == 1 &&
        EVP_PKEY_sign(sctx, sig, &siglen, m, mlen) == 1 &&
        siglen == slh_sets[set].sig_bytes)
        ret = IMPL_OK;
    EVP_PKEY_CTX_free(sctx);
    return ret;
}

static int do_verify(int set, int encode, const uint8_t *pk, const uint8_t *m,
                     size_t mlen, const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *sig, size_t siglen)
{
    EVP_PKEY *pkey = load_key(&pub_cache, set, pk);
    EVP_PKEY_CTX *vctx;
    OSSL_PARAM prm[3], *q = prm;
    int ret = IMPL_ERROR, r;

    if (pkey == NULL)
        return IMPL_ERROR;
    *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    if (encode)
        *q++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)(ctx ? ctx : empty_ctx), ctxlen);
    *q = OSSL_PARAM_construct_end();

    vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (vctx != NULL && EVP_PKEY_verify_message_init(vctx, sigalg[set], prm) == 1) {
        /*
         * EVP_PKEY_verify(3): 1 = valid, 0 = did not verify, any other value
         * = a more serious error. Only 0 is a rejection. OpenSSL reports a
         * signature of the wrong length as 0 too (crypto/slh_dsa checks the
         * length first), so 0 is a single value for both rejection causes.
         */
        r = EVP_PKEY_verify(vctx, sig, siglen, m, mlen);
        ret = r == 1 ? IMPL_OK : r == 0 ? IMPL_REJECT : IMPL_ERROR;
    } else if (vctx != NULL && encode && ctxlen > 255) {
        /*
         * OpenSSL refuses a context over 255 bytes when the parameters are
         * set; FIPS 205 Algorithm 24 returns false for it, so this is the
         * rejection the interface expects, not an error.
         */
        ret = IMPL_REJECT;
    }
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m,
                       size_t mlen, const uint8_t *addrnd, uint8_t *sig)
{
    return do_sign(set, 0, sk, m, mlen, NULL, 0, addrnd, sig);
}

int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m,
                         size_t mlen, const uint8_t *sig, size_t siglen)
{
    return do_verify(set, 0, pk, m, mlen, NULL, 0, sig, siglen);
}

int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m,
              size_t mlen, const uint8_t *ctx, size_t ctxlen,
              const uint8_t *addrnd, uint8_t *sig)
{
    uint8_t *framed;
    size_t flen;
    int ret;

    if (ph == PH_NONE)
        return do_sign(set, 1, sk, m, mlen, ctx, ctxlen, addrnd, sig);
    framed = prehash_frame(ph, m, mlen, ctx, ctxlen, &flen);
    if (framed == NULL)
        return IMPL_ERROR;
    ret = do_sign(set, 0, sk, framed, flen, NULL, 0, addrnd, sig);
    free(framed);
    return ret;
}

int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m,
                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, size_t siglen)
{
    uint8_t *framed;
    size_t flen;
    int ret;

    if (ph == PH_NONE)
        return do_verify(set, 1, pk, m, mlen, ctx, ctxlen, sig, siglen);
    if (ctxlen > 255)
        return IMPL_REJECT;
    framed = prehash_frame(ph, m, mlen, ctx, ctxlen, &flen);
    if (framed == NULL)
        return IMPL_ERROR;
    ret = do_verify(set, 0, pk, framed, flen, NULL, 0, sig, siglen);
    free(framed);
    return ret;
}
