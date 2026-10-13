/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * timing.c
 * ========
 *
 * Data-independent timing mode around the secret-dependent Jasmin calls
 * (key generation and signing).
 *
 * AArch64
 *
 *     FEAT_DIT (Armv8.4) adds PSTATE.DIT. While it is set, the instructions
 *     the Arm architecture lists as data-independent-time execute in time
 *     independent of their data operands. EL0 can read and write it as the
 *     system register DIT (op0 3, op1 3, CRn 4, CRm 2, op2 5; the flag is
 *     bit 24). The register is named by its encoding so that the code
 *     assembles without an Armv8.4 target flag.
 *
 *     enter() checks that the CPU reports FEAT_DIT, saves DIT, and sets it;
 *     leave() writes the saved value back, so a caller that had DIT set
 *     keeps it. Writing DIT on a CPU without FEAT_DIT is undefined, hence
 *     the check, made on every call (no cached global):
 *
 *         macOS   sysctl hw.optional.arm.FEAT_DIT
 *         Linux   getauxval(AT_HWCAP) & HWCAP_DIT (bit 24)
 *
 *     Without FEAT_DIT nothing is changed and the instruction-timing
 *     assumption rests on the CPU (nirapod_slhdsa.h, "Timing").
 *
 * x86-64
 *
 *     Intel's DOITM mode is enabled through a model-specific register that
 *     user code cannot write. Enabling it is the caller's or the platform's
 *     obligation, and CPUs without DOITM give no such control;
 *     enter() and leave() do nothing (nirapod_slhdsa.h, "Timing").
 */

#include "internal.h"

#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#endif

#if defined(__aarch64__)

#define DIT_FLAG (UINT64_C(1) << 24)

static int cpu_has_dit(void)
{
#if defined(__APPLE__)
    int value = 0;
    size_t size = sizeof(value);

    if (sysctlbyname("hw.optional.arm.FEAT_DIT", &value, &size, NULL, 0) != 0) {
        return 0;
    }
    return value == 1;
#elif defined(__linux__)
    return (getauxval(AT_HWCAP) & (UINT64_C(1) << 24)) != 0;
#else
    return 0;
#endif
}

uint64_t nirapod_slhdsa_timing_enter(void)
{
    uint64_t saved;

    if (!cpu_has_dit()) {
        return 0;
    }

    __asm__ __volatile__("mrs %0, s3_3_c4_c2_5" : "=r"(saved));
    __asm__ __volatile__("msr s3_3_c4_c2_5, %0" : : "r"(DIT_FLAG) : "memory");

    /* Bit 0 marks a token that must be restored; bit 24 is the old DIT. */
    return (saved & DIT_FLAG) | 1;
}

void nirapod_slhdsa_timing_leave(uint64_t token)
{
    if ((token & 1) == 0) {
        return;
    }
    __asm__ __volatile__("msr s3_3_c4_c2_5, %0" : : "r"(token & DIT_FLAG) : "memory");
}

#else

uint64_t nirapod_slhdsa_timing_enter(void)
{
    return 0;
}

void nirapod_slhdsa_timing_leave(uint64_t token)
{
    (void)token;
}

#endif
