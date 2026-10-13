/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * dispatch.c
 * ==========
 *
 * Chooses the compiled variant of a parameter set for the running CPU.
 *
 * The scalar variant exists for every set and runs on every supported CPU
 * (ARMv8.0-A, x86-64 baseline). A set may also have variants that need
 * instruction-set extensions (sets.c); one is chosen only when the CPU
 * reports every extension it needs and, on x86-64, the operating system
 * has enabled the register state it uses. All variants of a set compute the same
 * function; tests/core runs each one this CPU supports, through the
 * testing library, and checks the choice for every combination of the
 * features (nirapod_slhdsa_select_for).
 *
 * The feature test runs on every call for a set with more than one
 * variant: the library keeps no cached result, in line with its
 * no-global-state contract. Its cost, a few CPUID instructions, is
 * negligible against one SLH-DSA operation.
 */

#include "internal.h"

#if defined(__x86_64__)
#include <cpuid.h>

/*
 * CPUID and XCR0 bits (Intel SDM vol. 2A, CPUID; vol. 1, sections 13.3 and
 * 14.3): an AVX-encoded instruction may run only when the CPU reports AVX
 * and OSXSAVE and the operating system has set XCR0 bits 1 (SSE state)
 * and 2 (AVX state).
 */
#define LEAF1_ECX_OSXSAVE (1u << 27)
#define LEAF1_ECX_AVX     (1u << 28)
#define LEAF7_EBX_AVX2    (1u << 5)
#define LEAF7_EBX_SHA     (1u << 29)
#define XCR0_SSE_AVX      0x6u

unsigned nirapod_slhdsa_cpu_features(void)
{
    unsigned int a, b, c, d;
    unsigned int xcr0_lo, xcr0_hi;
    unsigned features = 0;

    if (__get_cpuid_max(0, NULL) < 7 || !__get_cpuid(1, &a, &b, &c, &d)) {
        return 0;
    }
    if ((c & (LEAF1_ECX_OSXSAVE | LEAF1_ECX_AVX)) != (LEAF1_ECX_OSXSAVE | LEAF1_ECX_AVX)) {
        return 0;
    }
    /* XGETBV with ECX = 0 reads XCR0; it is defined once OSXSAVE is set. */
    __asm__ volatile("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
    (void)xcr0_hi;
    if ((xcr0_lo & XCR0_SSE_AVX) != XCR0_SSE_AVX) {
        return 0;
    }

    __cpuid_count(7, 0, a, b, c, d);
    if ((b & LEAF7_EBX_AVX2) != 0) {
        features |= NIRAPOD_SLHDSA_CPU_AVX2;
    }
    if ((b & LEAF7_EBX_SHA) != 0) {
        features |= NIRAPOD_SLHDSA_CPU_SHANI;
    }
    return features;
}

#elif defined(__aarch64__)

/*
 * AArch64 extensions an extension variant may require: Advanced SIMD and
 * the SHA-256, SHA-512 and SHA-3 instructions (FEAT_SHA256, FEAT_SHA512,
 * FEAT_SHA3). User code cannot read the ID registers portably, so the
 * operating system's report is used:
 *
 *     macOS   sysctl hw.optional.arm.AdvSIMD and hw.optional.arm.FEAT_*
 *     Linux   getauxval(AT_HWCAP): HWCAP_ASIMD (bit 1), HWCAP_SHA2 (bit 6),
 *             HWCAP_SHA3 (bit 17), HWCAP_SHA512 (bit 21)
 */
#if defined(__APPLE__)
#include <sys/sysctl.h>

static int sysctl_flag(const char *name)
{
    int value = 0;
    size_t size = sizeof(value);

    return sysctlbyname(name, &value, &size, NULL, 0) == 0 && value == 1;
}

unsigned nirapod_slhdsa_cpu_features(void)
{
    unsigned features = 0;

    if (sysctl_flag("hw.optional.arm.AdvSIMD")) {
        features |= NIRAPOD_SLHDSA_CPU_ASIMD;
    }
    if (sysctl_flag("hw.optional.arm.FEAT_SHA256")) {
        features |= NIRAPOD_SLHDSA_CPU_SHA256;
    }
    if (sysctl_flag("hw.optional.arm.FEAT_SHA512")) {
        features |= NIRAPOD_SLHDSA_CPU_SHA512;
    }
    if (sysctl_flag("hw.optional.arm.FEAT_SHA3")) {
        features |= NIRAPOD_SLHDSA_CPU_SHA3;
    }
    return features;
}

#elif defined(__linux__)
#include <sys/auxv.h>

#define HWCAP_BIT_ASIMD  (UINT64_C(1) << 1)
#define HWCAP_BIT_SHA2   (UINT64_C(1) << 6)
#define HWCAP_BIT_SHA3   (UINT64_C(1) << 17)
#define HWCAP_BIT_SHA512 (UINT64_C(1) << 21)

unsigned nirapod_slhdsa_cpu_features(void)
{
    uint64_t hwcap = getauxval(AT_HWCAP);
    unsigned features = 0;

    if ((hwcap & HWCAP_BIT_ASIMD) != 0) {
        features |= NIRAPOD_SLHDSA_CPU_ASIMD;
    }
    if ((hwcap & HWCAP_BIT_SHA2) != 0) {
        features |= NIRAPOD_SLHDSA_CPU_SHA256;
    }
    if ((hwcap & HWCAP_BIT_SHA512) != 0) {
        features |= NIRAPOD_SLHDSA_CPU_SHA512;
    }
    if ((hwcap & HWCAP_BIT_SHA3) != 0) {
        features |= NIRAPOD_SLHDSA_CPU_SHA3;
    }
    return features;
}

#else

unsigned nirapod_slhdsa_cpu_features(void)
{
    return 0;
}

#endif

#endif

const nirapod_slhdsa_impl *nirapod_slhdsa_select_for(nirapod_slhdsa_set set, unsigned cpu)
{
    const nirapod_slhdsa_impl *chosen = nirapod_slhdsa_impl_variant(set, 0);
    const nirapod_slhdsa_impl *impl;
    size_t i;

    for (i = 1; (impl = nirapod_slhdsa_impl_variant(set, i)) != NULL; i++) {
        if ((impl->features & ~cpu) == 0) {
            chosen = impl;
        }
    }
    return chosen;
}

const nirapod_slhdsa_impl *nirapod_slhdsa_select(nirapod_slhdsa_set set)
{
    /*
     * The features are read only when the set has a variant besides
     * scalar: on AArch64, where none is built yet, an operation makes no
     * feature query.
     */
    unsigned cpu = nirapod_slhdsa_impl_variant(set, 1) != NULL ? nirapod_slhdsa_cpu_features() : 0;

    return nirapod_slhdsa_select_for(set, cpu);
}
