/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * clear_skip.c
 * ============
 *
 * capi/clear.c with the clearing taken out, for the negative control of
 * test_clearing.c only: linked in place of clear.c, it lets the seeds and
 * opt_rand stay in the C wrapper's buffers and the Jasmin exports' last
 * values stay in the registers. Never part of a library.
 */

#include "internal.h"

void nirapod_slhdsa_clear(void *p, size_t len)
{
    (void)p;
    (void)len;
}

void nirapod_slhdsa_clear_registers(unsigned used_features)
{
    (void)used_features;
}

/* Not a clearing step: kept as in clear.c, so that only the clearing differs. */
void nirapod_slhdsa_leave_avx(unsigned used_features)
{
#if defined(__x86_64__)
    if ((used_features & (NIRAPOD_SLHDSA_CPU_AVX2 | NIRAPOD_SLHDSA_CPU_SHANI)) != 0) {
        __asm__ __volatile__("vzeroupper" : : : "memory");
    }
#else
    (void)used_features;
#endif
}
