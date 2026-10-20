/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * nirapod_slhdsa.h
 * ================
 *
 * SLH-DSA, the stateless hash-based signature scheme of FIPS 205, through
 * the external interfaces of FIPS 205 section 10:
 *
 *     keygen                     slh_keygen         (Algorithm 21)
 *     sign, sign_deterministic   slh_sign           (Algorithm 22)
 *     hash_sign, ...             hash_slh_sign      (Algorithm 23)
 *     verify                     slh_verify         (Algorithm 24)
 *     hash_verify                hash_slh_verify    (Algorithm 25)
 *
 * All twelve parameter sets of FIPS 205 Table 2 are available at run time
 * through nirapod_slhdsa_set. Every cryptographic computation, including
 * the message framing M' of section 10 and the pre-hash of HashSLH-DSA, runs
 * in the Jasmin implementation; this C layer checks arguments, obtains
 * platform entropy, and calls it.
 *
 * Buffers
 * -------
 *
 * Every key and signature buffer is passed with its length, and the length
 * must equal the size FIPS 205 defines for the parameter set exactly (see
 * the size functions and the NIRAPOD_SLHDSA_*_BYTES table below). A message
 * or context pointer may be NULL only when its length is zero.
 *
 * An output buffer must not share any byte with an input buffer of the
 * same call: the public key with the secret key in keygen, the signature
 * with the message, the context or the secret key in signing. The library
 * compares the address ranges, as passed, of the buffers whose pointers are
 * not NULL, before any other check and before it writes anything, and
 * refuses such a call with NIRAPOD_SLHDSA_ERROR_OVERLAP. This check comes
 * first because it decides whether an output may be written at all: a
 * call that is wrong in another way as well still leaves the overlapped
 * input untouched.
 *
 * Failure behaviour
 * -----------------
 *
 * On any status other than NIRAPOD_SLHDSA_OK, the library writes zero
 * bytes over an output buffer if its pointer is not NULL, the set is valid
 * and the length passed for it is the size the set defines for that
 * output. Every other output buffer is left as it was: one whose length is
 * wrong, every output of a call with an invalid set, and every output of a
 * call refused with NIRAPOD_SLHDSA_ERROR_OVERLAP. A length that is not the
 * set's size is never taken as the size of the buffer, and zero-filling an
 * output that overlaps an input would overwrite that input. These checks
 * come before any computation, so a buffer left as it was holds nothing
 * the library computed. The library never writes past a passed length. No
 * partial key or signature is ever left behind.
 *
 * When several arguments are wrong at once, the status is that of the
 * first failing check in this order:
 *
 *     1. NIRAPOD_SLHDSA_ERROR_OVERLAP          an output overlaps an input
 *     2. NIRAPOD_SLHDSA_ERROR_NULL_POINTER     a required pointer is NULL
 *     3. NIRAPOD_SLHDSA_ERROR_INVALID_SET      the set value
 *     4. NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH   key and signing-output lengths
 *     5. NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT  the context length
 *     6. NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH  the pre-hash value
 *     7. NIRAPOD_SLHDSA_ERROR_ENTROPY          the random source
 *     8. NIRAPOD_SLHDSA_ERROR_FAULT            the check of a new signature
 *
 * Verification has no output and so no overlap check. It judges the
 * signature only after checks 2 to 6 pass, so a signature of the
 * wrong length yields NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE only when
 * every argument is otherwise valid.
 *
 * State and concurrency
 * ---------------------
 *
 * The library allocates no heap memory and has no global mutable state.
 * Calls on distinct buffers may run concurrently. Stack use per operation
 * and architecture is documented in docs/API.md.
 *
 * Entropy
 * -------
 *
 * keygen, sign and hash_sign read the operating system's random source
 * (getentropy on macOS, getrandom on Linux). If it fails, the call returns
 * NIRAPOD_SLHDSA_ERROR_ENTROPY; it never falls back to a weaker source.
 * The deterministic variants use no entropy: they sign with opt_rand set to
 * PK.seed, as FIPS 205 section 9.2 specifies. Both modes give valid
 * signatures under one key, but the security theorems of docs/PROOFS.md fix
 * one mode for every signature of a key; to stay within them, use one mode
 * per key (docs/API.md, "Hedged and deterministic signing").
 *
 * Timing
 * ------
 *
 * Key generation and signing are written so that no branch, loop bound or
 * memory address depends on a secret value, apart from the values that
 * docs/DECLASSIFICATION.md lists as released on purpose. This is what the
 * constant-time and speculative constant-time checks of analysis/README.md
 * establish for the Jasmin code, with the scope and conditions stated
 * there. It does not by itself make the running time independent of
 * secrets: the CPU must also execute the instructions used in time
 * independent of their operands.
 *
 *     AArch64 with FEAT_DIT   The library sets PSTATE.DIT (data-independent
 *                             timing) for the duration of keygen and of
 *                             each signing call, the check of the new
 *                             signature included, and restores the
 *                             caller's DIT value before returning. It
 *                             tests for FEAT_DIT on every call.
 *     AArch64 without it      Nothing is set. The caller depends on the
 *                             CPU executing these instructions in
 *                             constant time.
 *     x86-64, Intel           Intel's DOITM mode (data operand independent
 *                             timing) is controlled by a model-specific
 *                             register that the library cannot write from
 *                             user code. Where the CPU enumerates DOITM, the
 *                             caller or the operating system must enable
 *                             it for the guarantee to hold.
 *     x86-64, other CPUs      Where the CPU has no DOITM control (AMD
 *                             processors, for one), the caller depends on
 *                             the CPU executing these instructions in time
 *                             independent of their operands.
 *
 * Verification works on public data and runs with the caller's mode.
 *
 * Known limitations
 * -----------------
 *
 * On x86-64, the compiled code uses rbp, the frame-pointer register, as a
 * general register. Each export saves rbp on entry and restores it before
 * returning, so the caller's frame chain is intact after the call. While
 * an export runs, rbp does not address a frame record: a frame-chain walk
 * taken at that moment, by a sampling profiler, a crash reporter or a
 * debugger, is unreliable, and in key generation and signing it may record
 * data derived from the secret key as if it were a frame address. The
 * cause is the register allocation of the Jasmin compiler, not the source.
 * On AArch64 the compiled code does not use x29.
 *
 * On Linux, the objects compiled from Jasmin carry no GNU property note,
 * and their entry points do not begin with a landing-pad instruction
 * (endbr64 on x86-64, bti c on AArch64). The linker gives a program a
 * control-flow protection property only when every object linked into it
 * has that property, so linking this library into a program removes it:
 * on x86-64, IBT and SHSTK (Intel CET), and the system then runs the
 * program without shadow stacks even where it would enable them; on
 * AArch64, BTI and GCS, for a program otherwise built with them, and the
 * system then runs it without branch target enforcement or a guarded
 * control stack. macOS does not use these properties.
 */

#ifndef NIRAPOD_SLHDSA_H
#define NIRAPOD_SLHDSA_H

#include <stddef.h>
#include <stdint.h>

/*
 * Version of this header, in Semantic Versioning 2.0.0. Before 1.0.0, a
 * new minor version may change the API and the ABI.
 *
 * The values exist at compile time only: the library exports no symbol
 * that reports its version. CI keeps them equal to the version in
 * CITATION.cff, the newest release heading of CHANGELOG.md and the name of
 * a release tag.
 */
#define NIRAPOD_SLHDSA_VERSION_MAJOR  0
#define NIRAPOD_SLHDSA_VERSION_MINOR  1
#define NIRAPOD_SLHDSA_VERSION_PATCH  0
#define NIRAPOD_SLHDSA_VERSION_STRING "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parameter sets, in the order of FIPS 205 Table 2.
 */
typedef enum nirapod_slhdsa_set {
    NIRAPOD_SLHDSA_SHA2_128S  = 1,
    NIRAPOD_SLHDSA_SHAKE_128S = 2,
    NIRAPOD_SLHDSA_SHA2_128F  = 3,
    NIRAPOD_SLHDSA_SHAKE_128F = 4,
    NIRAPOD_SLHDSA_SHA2_192S  = 5,
    NIRAPOD_SLHDSA_SHAKE_192S = 6,
    NIRAPOD_SLHDSA_SHA2_192F  = 7,
    NIRAPOD_SLHDSA_SHAKE_192F = 8,
    NIRAPOD_SLHDSA_SHA2_256S  = 9,
    NIRAPOD_SLHDSA_SHAKE_256S = 10,
    NIRAPOD_SLHDSA_SHA2_256F  = 11,
    NIRAPOD_SLHDSA_SHAKE_256F = 12
} nirapod_slhdsa_set;

/*
 * Pre-hash functions for HashSLH-DSA (FIPS 205 section 10.2).
 *
 * Each value is the final arc of the function's object identifier under
 * 2.16.840.1.101.3.4.2 (NIST hash algorithms). The DER encoding of that
 * identifier is the OID field of M'. SHAKE128 produces a 256-bit digest and
 * SHAKE256 a 512-bit digest, as FIPS 205 Algorithm 23 specifies.
 */
typedef enum nirapod_slhdsa_prehash {
    NIRAPOD_SLHDSA_PREHASH_SHA2_256     = 1,
    NIRAPOD_SLHDSA_PREHASH_SHA2_384     = 2,
    NIRAPOD_SLHDSA_PREHASH_SHA2_512     = 3,
    NIRAPOD_SLHDSA_PREHASH_SHA2_224     = 4,
    NIRAPOD_SLHDSA_PREHASH_SHA2_512_224 = 5,
    NIRAPOD_SLHDSA_PREHASH_SHA2_512_256 = 6,
    NIRAPOD_SLHDSA_PREHASH_SHA3_224     = 7,
    NIRAPOD_SLHDSA_PREHASH_SHA3_256     = 8,
    NIRAPOD_SLHDSA_PREHASH_SHA3_384     = 9,
    NIRAPOD_SLHDSA_PREHASH_SHA3_512     = 10,
    NIRAPOD_SLHDSA_PREHASH_SHAKE128     = 11,
    NIRAPOD_SLHDSA_PREHASH_SHAKE256     = 12
} nirapod_slhdsa_prehash;

/*
 * Status codes. NIRAPOD_SLHDSA_OK is zero; every failure is negative.
 */
typedef enum nirapod_slhdsa_status {
    NIRAPOD_SLHDSA_OK                       =  0,
    /* verify, hash_verify: the signature is not valid for these inputs. */
    NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE  = -1,
    /* The parameter-set value is not one of nirapod_slhdsa_set. */
    NIRAPOD_SLHDSA_ERROR_INVALID_SET        = -2,
    /*
     * A key buffer, or the signature buffer of a signing call, has a length
     * other than the set's size. A signature of the wrong length passed to
     * verification is NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE instead
     * (FIPS 205 Algorithm 20, line 1).
     */
    NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH     = -3,
    /* The context string is longer than 255 bytes. */
    NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT    = -4,
    /* The pre-hash value is not one of nirapod_slhdsa_prehash. */
    NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH    = -5,
    /* A required pointer is NULL. */
    NIRAPOD_SLHDSA_ERROR_NULL_POINTER       = -6,
    /* The operating system's random source failed. */
    NIRAPOD_SLHDSA_ERROR_ENTROPY            = -7,
    /*
     * Signing: the new signature does not verify under the public key held
     * in the secret key, so it was not released. Either a fault occurred
     * while signing, or the secret key's PK.root does not belong to its
     * seeds.
     */
    NIRAPOD_SLHDSA_ERROR_FAULT              = -8,
    /*
     * An output buffer overlaps an input buffer of the same call; nothing
     * was written.
     */
    NIRAPOD_SLHDSA_ERROR_OVERLAP            = -9
} nirapod_slhdsa_status;

/*
 * Sizes in bytes (FIPS 205 Table 2). Public keys are 2n bytes, secret keys
 * 4n bytes, signatures (1 + k(1 + a) + h + d*len) * n bytes.
 */
#define NIRAPOD_SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES    32
#define NIRAPOD_SLHDSA_SHA2_128S_SECRET_KEY_BYTES    64
#define NIRAPOD_SLHDSA_SHA2_128S_SIGNATURE_BYTES     7856
#define NIRAPOD_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES   32
#define NIRAPOD_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES   64
#define NIRAPOD_SLHDSA_SHAKE_128S_SIGNATURE_BYTES    7856
#define NIRAPOD_SLHDSA_SHA2_128F_PUBLIC_KEY_BYTES    32
#define NIRAPOD_SLHDSA_SHA2_128F_SECRET_KEY_BYTES    64
#define NIRAPOD_SLHDSA_SHA2_128F_SIGNATURE_BYTES     17088
#define NIRAPOD_SLHDSA_SHAKE_128F_PUBLIC_KEY_BYTES   32
#define NIRAPOD_SLHDSA_SHAKE_128F_SECRET_KEY_BYTES   64
#define NIRAPOD_SLHDSA_SHAKE_128F_SIGNATURE_BYTES    17088
#define NIRAPOD_SLHDSA_SHA2_192S_PUBLIC_KEY_BYTES    48
#define NIRAPOD_SLHDSA_SHA2_192S_SECRET_KEY_BYTES    96
#define NIRAPOD_SLHDSA_SHA2_192S_SIGNATURE_BYTES     16224
#define NIRAPOD_SLHDSA_SHAKE_192S_PUBLIC_KEY_BYTES   48
#define NIRAPOD_SLHDSA_SHAKE_192S_SECRET_KEY_BYTES   96
#define NIRAPOD_SLHDSA_SHAKE_192S_SIGNATURE_BYTES    16224
#define NIRAPOD_SLHDSA_SHA2_192F_PUBLIC_KEY_BYTES    48
#define NIRAPOD_SLHDSA_SHA2_192F_SECRET_KEY_BYTES    96
#define NIRAPOD_SLHDSA_SHA2_192F_SIGNATURE_BYTES     35664
#define NIRAPOD_SLHDSA_SHAKE_192F_PUBLIC_KEY_BYTES   48
#define NIRAPOD_SLHDSA_SHAKE_192F_SECRET_KEY_BYTES   96
#define NIRAPOD_SLHDSA_SHAKE_192F_SIGNATURE_BYTES    35664
#define NIRAPOD_SLHDSA_SHA2_256S_PUBLIC_KEY_BYTES    64
#define NIRAPOD_SLHDSA_SHA2_256S_SECRET_KEY_BYTES    128
#define NIRAPOD_SLHDSA_SHA2_256S_SIGNATURE_BYTES     29792
#define NIRAPOD_SLHDSA_SHAKE_256S_PUBLIC_KEY_BYTES   64
#define NIRAPOD_SLHDSA_SHAKE_256S_SECRET_KEY_BYTES   128
#define NIRAPOD_SLHDSA_SHAKE_256S_SIGNATURE_BYTES    29792
#define NIRAPOD_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES    64
#define NIRAPOD_SLHDSA_SHA2_256F_SECRET_KEY_BYTES    128
#define NIRAPOD_SLHDSA_SHA2_256F_SIGNATURE_BYTES     49856
#define NIRAPOD_SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES   64
#define NIRAPOD_SLHDSA_SHAKE_256F_SECRET_KEY_BYTES   128
#define NIRAPOD_SLHDSA_SHAKE_256F_SIGNATURE_BYTES    49856

#define NIRAPOD_SLHDSA_MAX_PUBLIC_KEY_BYTES          64
#define NIRAPOD_SLHDSA_MAX_SECRET_KEY_BYTES          128
#define NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES           49856

/* Longest context string FIPS 205 accepts. */
#define NIRAPOD_SLHDSA_MAX_CONTEXT_BYTES             255

/*
 * Sizes for a parameter set, or 0 when set is not a nirapod_slhdsa_set
 * value.
 */
size_t nirapod_slhdsa_public_key_bytes(nirapod_slhdsa_set set);
size_t nirapod_slhdsa_secret_key_bytes(nirapod_slhdsa_set set);
size_t nirapod_slhdsa_signature_bytes(nirapod_slhdsa_set set);

/*
 * The FIPS 205 name of a parameter set, for example "SLH-DSA-SHAKE-128f",
 * or NULL when set is not a nirapod_slhdsa_set value.
 */
const char *nirapod_slhdsa_set_name(nirapod_slhdsa_set set);

/*
 * Key generation (FIPS 205 Algorithm 21)
 *
 * Draws SK.seed, SK.prf and PK.seed (3n bytes) from the operating system
 * and writes
 *
 *     public_key = PK.seed || PK.root
 *     secret_key = SK.seed || SK.prf || PK.seed || PK.root
 *
 * The secret key must be kept confidential by the caller. The library
 * keeps nothing between calls; docs/API.md lists the copies it makes
 * during a call and what clears them.
 */
nirapod_slhdsa_status nirapod_slhdsa_keygen(
    nirapod_slhdsa_set set,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *secret_key, size_t secret_key_len);

/*
 * Pure signing (FIPS 205 Algorithm 22)
 *
 * Signs message with the context string context (at most 255 bytes, may be
 * empty) under secret_key, using the hedged variant: opt_rand is n fresh
 * bytes from the operating system. The signed message is
 *
 *     M' = 0x00 || |context| || context || message
 *
 * Before returning, the library verifies the new signature under the
 * public key held in secret_key (PK.seed || PK.root). If it does not
 * verify, the signature buffer is zeroed and NIRAPOD_SLHDSA_ERROR_FAULT is
 * returned: either a fault occurred while signing, or the key's PK.root
 * does not belong to its seeds. The same check applies to every signing
 * function.
 */
nirapod_slhdsa_status nirapod_slhdsa_sign(
    nirapod_slhdsa_set set,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len);

/*
 * As nirapod_slhdsa_sign, with the deterministic variant: opt_rand = PK.seed.
 * No entropy is used, and equal inputs give equal signatures.
 */
nirapod_slhdsa_status nirapod_slhdsa_sign_deterministic(
    nirapod_slhdsa_set set,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len);

/*
 * Pure verification (FIPS 205 Algorithm 24)
 *
 * Returns NIRAPOD_SLHDSA_OK when signature is a valid signature of message
 * with context under public_key, and NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE
 * when it is not, including when signature_len is not the signature size of
 * the set. A context longer than 255 bytes is rejected with
 * NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT.
 *
 * Verification works on public data only and is not constant-time.
 */
nirapod_slhdsa_status nirapod_slhdsa_verify(
    nirapod_slhdsa_set set,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len);

/*
 * Pre-hash signing (FIPS 205 Algorithm 23), hedged.
 *
 * Computes PH(message) with the function prehash and signs
 *
 *     M' = 0x01 || |context| || context || OID(prehash) || PH(message)
 *
 * FIPS 205 section 10.2 asks for a pre-hash function that provides at
 * least 8n bits of classical security strength for the parameter set. The
 * library does not enforce this: it accepts every function listed in
 * nirapod_slhdsa_prehash with every set, and the choice is the caller's.
 */
nirapod_slhdsa_status nirapod_slhdsa_hash_sign(
    nirapod_slhdsa_set set,
    nirapod_slhdsa_prehash prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len);

/*
 * As nirapod_slhdsa_hash_sign, with opt_rand = PK.seed.
 */
nirapod_slhdsa_status nirapod_slhdsa_hash_sign_deterministic(
    nirapod_slhdsa_set set,
    nirapod_slhdsa_prehash prehash,
    uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *secret_key, size_t secret_key_len);

/*
 * Pre-hash verification (FIPS 205 Algorithm 25). Results as for
 * nirapod_slhdsa_verify.
 */
nirapod_slhdsa_status nirapod_slhdsa_hash_verify(
    nirapod_slhdsa_set set,
    nirapod_slhdsa_prehash prehash,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *public_key, size_t public_key_len);

#ifdef __cplusplus
}
#endif

#endif /* NIRAPOD_SLHDSA_H */
