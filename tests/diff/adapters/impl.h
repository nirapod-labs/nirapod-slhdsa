/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl.h
 * ======
 *
 * The one interface every SLH-DSA implementation under test is reached
 * through: this library, and the independent baselines it is checked
 * against. The ACVP runner and the differential oracle each link exactly
 * one adapter, so the same driver code exercises every implementation and
 * none of them gets a private shortcut.
 *
 * An adapter maps these calls onto the implementation's own public API and
 * does nothing cryptographic itself, with one documented exception: for an
 * implementation without HashSLH-DSA, an adapter may compute PH(M) with
 * that implementation's own digest and build M' as FIPS 205 Algorithm 23
 * (section 10.2.2) specifies, then sign M' through the implementation's
 * unframed entry point. Such an adapter says so in its own header comment,
 * and results for its pre-hash cases cover that framing too.
 *
 * Common contract for every operation below:
 *
 *   set       index into slh_sets, 0 <= set < SLH_SET_COUNT; byte lengths
 *             not passed explicitly are those of slh_sets[set]
 *   buffers   inputs are read only; outputs must not overlap any input
 *   failure   on any status other than IMPL_OK, output buffers hold
 *             unspecified bytes and drivers do not read them
 *   secrets   adapters handle test keys only and make no constant-time,
 *             clearing or secret-lifetime claim of their own
 *
 * Return convention:
 *
 *   IMPL_OK           the operation ran and produced its output, or
 *                     verification ran and accepted
 *   IMPL_REJECT       verification ran and the signature is not valid,
 *                     including a rejection for a malformed length or an
 *                     over-long context string
 *   IMPL_UNSUPPORTED  the implementation does not offer this operation,
 *                     parameter set or variant; drivers report NOT RUN,
 *                     never PASS
 *   IMPL_ERROR        anything else; drivers report FAIL
 */

#ifndef NIRAPOD_SLHDSA_TESTS_IMPL_H
#define NIRAPOD_SLHDSA_TESTS_IMPL_H

#include <stddef.h>
#include <stdint.h>

enum {
    IMPL_OK = 0,
    IMPL_REJECT = 1,
    IMPL_UNSUPPORTED = 2,
    IMPL_ERROR = 3
};

/*
 * The twelve parameter sets of FIPS 205 Table 2. Sizes follow from n:
 * public key 2n, secret key 4n (FIPS 205 Figures 15 and 16); the signature
 * size is the "sig bytes" column of Table 2.
 */
typedef struct {
    const char *name;     /* ACVP and FIPS 205 name, e.g. "SLH-DSA-SHA2-128s" */
    size_t n;
    size_t pk_bytes;
    size_t sk_bytes;
    size_t sig_bytes;
} slh_set;

#define SLH_SET_COUNT 12
extern const slh_set slh_sets[SLH_SET_COUNT];

/* 0 when slh_sets agrees with a derivation from the tree parameters. */
int slh_tables_check(void);

/* Index into slh_sets, or -1 for an unknown name. */
int slh_set_index(const char *name);

/*
 * Pre-hash functions allowed for HashSLH-DSA by ACVP, in the order of the
 * NIST hash-algorithm object identifiers 2.16.840.1.101.3.4.2.x. PH_NONE
 * selects pure SLH-DSA (FIPS 205 Algorithm 22).
 */
typedef enum {
    PH_NONE = 0,
    PH_SHA2_256,
    PH_SHA2_384,
    PH_SHA2_512,
    PH_SHA2_224,
    PH_SHA2_512_224,
    PH_SHA2_512_256,
    PH_SHA3_224,
    PH_SHA3_256,
    PH_SHA3_384,
    PH_SHA3_512,
    PH_SHAKE_128,
    PH_SHAKE_256,
    PH_COUNT
} slh_ph;

typedef struct {
    const char *name;        /* ACVP name, e.g. "SHA2-512/256" */
    uint8_t oid_der[11];     /* DER encoding of the OID, FIPS 205 section 10.2.2 */
    size_t digest_bytes;     /* output length used by HashSLH-DSA */
} slh_ph_info;

extern const slh_ph_info slh_ph_table[PH_COUNT];

/* PH_* for an ACVP name; "none" and "pure" map to PH_NONE; -1 if unknown. */
int slh_ph_index(const char *name);

/* Short name of the linked implementation, for reports. */
const char *impl_name(void);

/*
 * Code-path selection. An implementation may carry several variants of its
 * hash kernels and pick one per CPU. impl_force_variant, called before
 * impl_init, pins one by name and returns IMPL_UNSUPPORTED when this
 * implementation or this CPU lacks it; without it the implementation's own
 * default selection applies. impl_variant, valid after impl_init, names
 * the path actually in use (for a baseline: its build variant and, where it
 * dispatches internally, the CPU capabilities it detected), so every
 * reported result says which code ran.
 */
int impl_force_variant(const char *name);
const char *impl_variant(void);

/*
 * Single failure value. Some libraries' verification returns one value for
 * every way of not accepting (invalid signature, wrong length, internal
 * failure); an adapter for such a library ends impl_variant() with
 * ";reject=single-value", so every verdict line that names the variant
 * also names that limit of its evidence.
 */

/* Called once before any other call; IMPL_OK or IMPL_ERROR. */
int impl_init(void);

/*
 * FIPS 205 Algorithm 18, slh_keygen_internal. sk_seed, sk_prf and pk_seed
 * are n bytes each; writes pk (2n bytes, PK.seed || PK.root) and sk (4n
 * bytes, SK.seed || SK.prf || PK.seed || PK.root).
 */
int impl_keygen_seed(int set, const uint8_t *sk_seed, const uint8_t *sk_prf,
                     const uint8_t *pk_seed, uint8_t *pk, uint8_t *sk);

/*
 * FIPS 205 Algorithm 19, slh_sign_internal, on the message exactly as
 * given. addrnd is n bytes, or NULL for the deterministic variant, in which
 * opt_rand = PK.seed. Writes sig_bytes bytes.
 */
int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m,
                       size_t mlen, const uint8_t *addrnd, uint8_t *sig);

/* FIPS 205 Algorithm 20, slh_verify_internal; siglen may be any length. */
int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m,
                         size_t mlen, const uint8_t *sig, size_t siglen);

/*
 * FIPS 205 Algorithm 22, slh_sign (ph == PH_NONE), or Algorithm 23,
 * hash_slh_sign. ctx may be NULL when ctxlen is 0. addrnd as for
 * impl_sign_internal. Writes sig_bytes bytes. With ctxlen > 255 there is no
 * signature to make (both algorithms fail): the call must return
 * IMPL_ERROR, never IMPL_OK.
 */
int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m,
              size_t mlen, const uint8_t *ctx, size_t ctxlen,
              const uint8_t *addrnd, uint8_t *sig);

/*
 * FIPS 205 Algorithm 24, slh_verify (ph == PH_NONE), or Algorithm 25,
 * hash_slh_verify. ctxlen above 255 must be rejected, as both algorithms
 * return false for it.
 */
int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m,
                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, size_t siglen);

#endif
