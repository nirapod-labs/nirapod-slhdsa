/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * sets.c
 * ======
 *
 * The implementation records of the twelve parameter sets, one per
 * compiled variant (the Makefile says which units are built):
 *
 *     scalar   every set, both architectures; no CPU feature required
 *     avx2     x86-64, SHAKE sets: the four-way Keccak kernel in AVX2;
 *              SHA2 sets: the 8-way SHA-256 and 4-way SHA-512 kernels in
 *              AVX2 for the four-way hashes
 *     shani    x86-64, SHA2 sets: the SHA-256 kernel on the SHA extensions
 *     sha3     AArch64, SHAKE sets: Keccak on the SHA-3 instructions
 *     sha2     AArch64, SHA2 sets: SHA-256 and SHA-512 on the SHA-2
 *              instructions
 *
 * Each set lists its variants from the most portable to the preferred
 * one; dispatch.c runs the last one whose features the CPU has. Sizes are
 * those of FIPS 205 Table 2 and must equal the NIRAPOD_SLHDSA_*_BYTES
 * macros of the public header; tests/core checks both against the Jasmin
 * units.
 */

#include "internal.h"
#include "jasmin.h"

/*
 * The testing build adds the two internal-function exports to each
 * record (internal.h); the production records name only keygen, sign and
 * verify, so nothing in the production build refers to the others.
 */
#ifdef NIRAPOD_SLHDSA_TESTING
#define INTERNAL_EXPORTS(unit)                                                 \
        , nirapod_slhdsa_jz_##unit##__sign_internal,                           \
        nirapod_slhdsa_jz_##unit##__verify_internal
#else
#define INTERNAL_EXPORTS(unit)
#endif

#define NIRAPOD_SLHDSA_RECORD(id, var, feat, label, unit, n_)                  \
    static const nirapod_slhdsa_impl id##_##var = {                            \
        label, #var, feat, n_,                                                 \
        NIRAPOD_SLHDSA_##id##_PUBLIC_KEY_BYTES,                                \
        NIRAPOD_SLHDSA_##id##_SECRET_KEY_BYTES,                                \
        NIRAPOD_SLHDSA_##id##_SIGNATURE_BYTES,                                 \
        nirapod_slhdsa_jz_##unit##__keygen,                                    \
        nirapod_slhdsa_jz_##unit##__sign,                                      \
        nirapod_slhdsa_jz_##unit##__verify                                     \
        INTERNAL_EXPORTS(unit)                                                 \
    };

#define SCALAR 0u
#define AVX2   NIRAPOD_SLHDSA_CPU_AVX2
#define SHANI  NIRAPOD_SLHDSA_CPU_SHANI

NIRAPOD_SLHDSA_RECORD(SHA2_128S,  scalar, SCALAR, "SLH-DSA-SHA2-128s",  sha2_128s_scalar,  16)
NIRAPOD_SLHDSA_RECORD(SHAKE_128S, scalar, SCALAR, "SLH-DSA-SHAKE-128s", shake_128s_scalar, 16)
NIRAPOD_SLHDSA_RECORD(SHA2_128F,  scalar, SCALAR, "SLH-DSA-SHA2-128f",  sha2_128f_scalar,  16)
NIRAPOD_SLHDSA_RECORD(SHAKE_128F, scalar, SCALAR, "SLH-DSA-SHAKE-128f", shake_128f_scalar, 16)
NIRAPOD_SLHDSA_RECORD(SHA2_192S,  scalar, SCALAR, "SLH-DSA-SHA2-192s",  sha2_192s_scalar,  24)
NIRAPOD_SLHDSA_RECORD(SHAKE_192S, scalar, SCALAR, "SLH-DSA-SHAKE-192s", shake_192s_scalar, 24)
NIRAPOD_SLHDSA_RECORD(SHA2_192F,  scalar, SCALAR, "SLH-DSA-SHA2-192f",  sha2_192f_scalar,  24)
NIRAPOD_SLHDSA_RECORD(SHAKE_192F, scalar, SCALAR, "SLH-DSA-SHAKE-192f", shake_192f_scalar, 24)
NIRAPOD_SLHDSA_RECORD(SHA2_256S,  scalar, SCALAR, "SLH-DSA-SHA2-256s",  sha2_256s_scalar,  32)
NIRAPOD_SLHDSA_RECORD(SHAKE_256S, scalar, SCALAR, "SLH-DSA-SHAKE-256s", shake_256s_scalar, 32)
NIRAPOD_SLHDSA_RECORD(SHA2_256F,  scalar, SCALAR, "SLH-DSA-SHA2-256f",  sha2_256f_scalar,  32)
NIRAPOD_SLHDSA_RECORD(SHAKE_256F, scalar, SCALAR, "SLH-DSA-SHAKE-256f", shake_256f_scalar, 32)

#if defined(__x86_64__)

NIRAPOD_SLHDSA_RECORD(SHA2_128S,  avx2,   AVX2,   "SLH-DSA-SHA2-128s",  sha2_128s_avx2,    16)
NIRAPOD_SLHDSA_RECORD(SHA2_128F,  avx2,   AVX2,   "SLH-DSA-SHA2-128f",  sha2_128f_avx2,    16)
NIRAPOD_SLHDSA_RECORD(SHA2_192S,  avx2,   AVX2,   "SLH-DSA-SHA2-192s",  sha2_192s_avx2,    24)
NIRAPOD_SLHDSA_RECORD(SHA2_192F,  avx2,   AVX2,   "SLH-DSA-SHA2-192f",  sha2_192f_avx2,    24)
NIRAPOD_SLHDSA_RECORD(SHA2_256S,  avx2,   AVX2,   "SLH-DSA-SHA2-256s",  sha2_256s_avx2,    32)
NIRAPOD_SLHDSA_RECORD(SHA2_256F,  avx2,   AVX2,   "SLH-DSA-SHA2-256f",  sha2_256f_avx2,    32)
NIRAPOD_SLHDSA_RECORD(SHA2_128S,  shani,  SHANI,  "SLH-DSA-SHA2-128s",  sha2_128s_shani,   16)
NIRAPOD_SLHDSA_RECORD(SHAKE_128S, avx2,   AVX2,   "SLH-DSA-SHAKE-128s", shake_128s_avx2,   16)
NIRAPOD_SLHDSA_RECORD(SHA2_128F,  shani,  SHANI,  "SLH-DSA-SHA2-128f",  sha2_128f_shani,   16)
NIRAPOD_SLHDSA_RECORD(SHAKE_128F, avx2,   AVX2,   "SLH-DSA-SHAKE-128f", shake_128f_avx2,   16)
NIRAPOD_SLHDSA_RECORD(SHA2_192S,  shani,  SHANI,  "SLH-DSA-SHA2-192s",  sha2_192s_shani,   24)
NIRAPOD_SLHDSA_RECORD(SHAKE_192S, avx2,   AVX2,   "SLH-DSA-SHAKE-192s", shake_192s_avx2,   24)
NIRAPOD_SLHDSA_RECORD(SHA2_192F,  shani,  SHANI,  "SLH-DSA-SHA2-192f",  sha2_192f_shani,   24)
NIRAPOD_SLHDSA_RECORD(SHAKE_192F, avx2,   AVX2,   "SLH-DSA-SHAKE-192f", shake_192f_avx2,   24)
NIRAPOD_SLHDSA_RECORD(SHA2_256S,  shani,  SHANI,  "SLH-DSA-SHA2-256s",  sha2_256s_shani,   32)
NIRAPOD_SLHDSA_RECORD(SHAKE_256S, avx2,   AVX2,   "SLH-DSA-SHAKE-256s", shake_256s_avx2,   32)
NIRAPOD_SLHDSA_RECORD(SHA2_256F,  shani,  SHANI,  "SLH-DSA-SHA2-256f",  sha2_256f_shani,   32)
NIRAPOD_SLHDSA_RECORD(SHAKE_256F, avx2,   AVX2,   "SLH-DSA-SHAKE-256f", shake_256f_avx2,   32)

/*
 * A CPU with the SHA extensions runs shani even when it also has AVX2.
 * avx2 computes the four-way hashes with the 8-way SHA-256 kernel on four
 * of its eight lanes, where shani runs four SHA-NI compressions
 * (Makefile, TX_<variant>).
 */
#define SHA2_VARIANTS(id)  { &id##_scalar, &id##_avx2, &id##_shani }
#define SHAKE_VARIANTS(id) { &id##_scalar, &id##_avx2, NULL }
#define NIRAPOD_SLHDSA_MAX_VARIANTS 3

#elif defined(__aarch64__)

/*
 * Each AArch64 extension variant also needs Advanced SIMD, whose registers
 * its kernels use. The SHA2 sets need FEAT_SHA512 as well as FEAT_SHA256:
 * every SHA2 unit runs SHA-512 for pre-hashing, and the 192 and 256 sets
 * in H_msg, PRF_msg (HMAC-SHA-512), H and T_l (FIPS 205 section 11.2.2).
 */
#define A64_SHA2 (NIRAPOD_SLHDSA_CPU_ASIMD | NIRAPOD_SLHDSA_CPU_SHA256 | NIRAPOD_SLHDSA_CPU_SHA512)
#define A64_SHA3 (NIRAPOD_SLHDSA_CPU_ASIMD | NIRAPOD_SLHDSA_CPU_SHA3)

NIRAPOD_SLHDSA_RECORD(SHA2_128S,  sha2,   A64_SHA2, "SLH-DSA-SHA2-128s",  sha2_128s_sha2,    16)
NIRAPOD_SLHDSA_RECORD(SHAKE_128S, sha3,   A64_SHA3, "SLH-DSA-SHAKE-128s", shake_128s_sha3,   16)
NIRAPOD_SLHDSA_RECORD(SHA2_128F,  sha2,   A64_SHA2, "SLH-DSA-SHA2-128f",  sha2_128f_sha2,    16)
NIRAPOD_SLHDSA_RECORD(SHAKE_128F, sha3,   A64_SHA3, "SLH-DSA-SHAKE-128f", shake_128f_sha3,   16)
NIRAPOD_SLHDSA_RECORD(SHA2_192S,  sha2,   A64_SHA2, "SLH-DSA-SHA2-192s",  sha2_192s_sha2,    24)
NIRAPOD_SLHDSA_RECORD(SHAKE_192S, sha3,   A64_SHA3, "SLH-DSA-SHAKE-192s", shake_192s_sha3,   24)
NIRAPOD_SLHDSA_RECORD(SHA2_192F,  sha2,   A64_SHA2, "SLH-DSA-SHA2-192f",  sha2_192f_sha2,    24)
NIRAPOD_SLHDSA_RECORD(SHAKE_192F, sha3,   A64_SHA3, "SLH-DSA-SHAKE-192f", shake_192f_sha3,   24)
NIRAPOD_SLHDSA_RECORD(SHA2_256S,  sha2,   A64_SHA2, "SLH-DSA-SHA2-256s",  sha2_256s_sha2,    32)
NIRAPOD_SLHDSA_RECORD(SHAKE_256S, sha3,   A64_SHA3, "SLH-DSA-SHAKE-256s", shake_256s_sha3,   32)
NIRAPOD_SLHDSA_RECORD(SHA2_256F,  sha2,   A64_SHA2, "SLH-DSA-SHA2-256f",  sha2_256f_sha2,    32)
NIRAPOD_SLHDSA_RECORD(SHAKE_256F, sha3,   A64_SHA3, "SLH-DSA-SHAKE-256f", shake_256f_sha3,   32)

#define SHA2_VARIANTS(id)  { &id##_scalar, &id##_sha2 }
#define SHAKE_VARIANTS(id) { &id##_scalar, &id##_sha3 }
#define NIRAPOD_SLHDSA_MAX_VARIANTS 2

#else
#error "sets.c: unsupported architecture"
#endif

/* Indexed by nirapod_slhdsa_set - 1 (FIPS 205 Table 2 order). */
static const nirapod_slhdsa_impl *const VARIANT_TABLE[12][NIRAPOD_SLHDSA_MAX_VARIANTS] = {
    SHA2_VARIANTS(SHA2_128S),
    SHAKE_VARIANTS(SHAKE_128S),
    SHA2_VARIANTS(SHA2_128F),
    SHAKE_VARIANTS(SHAKE_128F),
    SHA2_VARIANTS(SHA2_192S),
    SHAKE_VARIANTS(SHAKE_192S),
    SHA2_VARIANTS(SHA2_192F),
    SHAKE_VARIANTS(SHAKE_192F),
    SHA2_VARIANTS(SHA2_256S),
    SHAKE_VARIANTS(SHAKE_256S),
    SHA2_VARIANTS(SHA2_256F),
    SHAKE_VARIANTS(SHAKE_256F),
};

const nirapod_slhdsa_impl *nirapod_slhdsa_impl_variant(nirapod_slhdsa_set set, size_t index)
{
    if ((int)set < 1 || (int)set > 12 || index >= NIRAPOD_SLHDSA_MAX_VARIANTS) {
        return NULL;
    }
    return VARIANT_TABLE[(int)set - 1][index];
}
