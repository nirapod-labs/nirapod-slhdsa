/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * jasmin.h
 * ========
 *
 * C declarations of the Jasmin exports, one group per parameter set and
 * hash variant. The Jasmin source of every export, with its contract, is
 * src/slhdsa/api.jinc; this file only restates the ABI.
 *
 * Symbol scheme
 *
 *     nirapod_slhdsa_jz_<set>_<variant>__<op>
 *
 * The unit of a set is compiled inside the Jasmin namespace
 * nirapod_slhdsa_jz_<set>_<variant>, and Jasmin prints the namespace
 * separator as a double underscore. These symbols are internal: no public
 * header declares them, and libnirapod_slhdsa.a holds them as local
 * symbols (Makefile, "Libraries"). Only the testing build refers to
 * sign_internal and verify_internal (sets.c).
 *
 * ABI (both architectures, from the Jasmin calling convention for exports)
 *
 *     Arguments in order in the platform's integer argument registers; an
 *     array argument is a pointer to exactly that many bytes, with no
 *     alignment requirement. A Jasmin export that returns its mutable
 *     arrays returns them in place: C sees void, or the one scalar result.
 *
 *     keygen          (pk[2n], sk[4n], seeds[3n])
 *     sign            (sig[SIG], msg, msg_len, domain[257], sk[4n], opt_rand[n]) -> status
 *     verify          (sig[SIG], msg, msg_len, domain[257], pk[2n])              -> status
 *     sign_internal   (sig[SIG], msg, msg_len, sk[4n], opt_rand[n])
 *     verify_internal (sig[SIG], msg, msg_len, pk[2n])                           -> status
 *
 *     status: 0, or all ones (UINT64_MAX).
 */

#ifndef NIRAPOD_SLHDSA_JASMIN_H
#define NIRAPOD_SLHDSA_JASMIN_H

#include <stdint.h>

#define NIRAPOD_SLHDSA_JZ_DOMAIN_BYTES 257

#define NIRAPOD_SLHDSA_JZ_DECLARE(unit)                                        \
  void nirapod_slhdsa_jz_##unit##__keygen(                                     \
      uint8_t *pk, uint8_t *sk, const uint8_t *seeds);                         \
  uint64_t nirapod_slhdsa_jz_##unit##__sign(                                   \
      uint8_t *sig, const uint8_t *msg, uint64_t msg_len,                      \
      const uint8_t *domain, const uint8_t *sk, const uint8_t *opt_rand);      \
  uint64_t nirapod_slhdsa_jz_##unit##__verify(                                 \
      const uint8_t *sig, const uint8_t *msg, uint64_t msg_len,                \
      const uint8_t *domain, const uint8_t *pk);                               \
  void nirapod_slhdsa_jz_##unit##__sign_internal(                              \
      uint8_t *sig, const uint8_t *msg, uint64_t msg_len,                      \
      const uint8_t *sk, const uint8_t *opt_rand);                             \
  uint64_t nirapod_slhdsa_jz_##unit##__verify_internal(                        \
      const uint8_t *sig, const uint8_t *msg, uint64_t msg_len,                \
      const uint8_t *pk);

NIRAPOD_SLHDSA_JZ_DECLARE(sha2_128s_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_128s_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_128f_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_128f_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_192s_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_192s_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_192f_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_192f_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_256s_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_256s_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_256f_scalar)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_256f_scalar)

/* x86-64 only: the accelerated variants (Makefile, sets.c). */
#if defined(__x86_64__)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_128s_shani)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_128f_shani)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_192s_shani)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_192f_shani)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_256s_shani)
NIRAPOD_SLHDSA_JZ_DECLARE(sha2_256f_shani)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_128s_avx2)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_128f_avx2)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_192s_avx2)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_192f_avx2)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_256s_avx2)
NIRAPOD_SLHDSA_JZ_DECLARE(shake_256f_avx2)
#endif

#endif /* NIRAPOD_SLHDSA_JASMIN_H */
