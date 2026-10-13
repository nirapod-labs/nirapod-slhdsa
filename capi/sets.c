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
 *     avx2     x86-64, SHAKE sets: the four-way Keccak kernel in AVX2
 *     shani    x86-64, SHA2 sets: the SHA-256 kernel on the SHA extensions
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

#define VARIANTS(id, accel) { &id##_scalar, &id##_##accel }
#define NIRAPOD_SLHDSA_MAX_VARIANTS 2

#else

#define VARIANTS(id, accel) { &id##_scalar }
#define NIRAPOD_SLHDSA_MAX_VARIANTS 1

#endif

/* Indexed by nirapod_slhdsa_set - 1 (FIPS 205 Table 2 order). */
static const nirapod_slhdsa_impl *const VARIANT_TABLE[12][NIRAPOD_SLHDSA_MAX_VARIANTS] = {
    VARIANTS(SHA2_128S,  shani),
    VARIANTS(SHAKE_128S, avx2),
    VARIANTS(SHA2_128F,  shani),
    VARIANTS(SHAKE_128F, avx2),
    VARIANTS(SHA2_192S,  shani),
    VARIANTS(SHAKE_192S, avx2),
    VARIANTS(SHA2_192F,  shani),
    VARIANTS(SHAKE_192F, avx2),
    VARIANTS(SHA2_256S,  shani),
    VARIANTS(SHAKE_256S, avx2),
    VARIANTS(SHA2_256F,  shani),
    VARIANTS(SHAKE_256F, avx2),
};

const nirapod_slhdsa_impl *nirapod_slhdsa_impl_variant(nirapod_slhdsa_set set, size_t index)
{
    if ((int)set < 1 || (int)set > 12 || index >= NIRAPOD_SLHDSA_MAX_VARIANTS) {
        return NULL;
    }
    return VARIANT_TABLE[(int)set - 1][index];
}
