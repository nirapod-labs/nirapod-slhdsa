/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * dispatch_base.c
 * ===============
 *
 * capi/dispatch.c for a CPU with fewer instruction-set extensions than the
 * host, for test_stack_base and test_stack_avx2 only. The file is compiled
 * from dispatch.c itself, with nirapod_slhdsa_select renamed and replaced
 * by one that makes the choice for the host's features masked by
 * NIRAPOD_SLHDSA_BASE_FEATURES:
 *
 *     0 (default)                  every set runs its scalar variant on any
 *                                  host (test_stack_base)
 *     NIRAPOD_SLHDSA_CPU_AVX2      x86-64: every set runs avx2 where the
 *                                  host has AVX2, as on a CPU without the
 *                                  SHA extensions (test_stack_avx2)
 *
 * The mask only removes features, so no variant the host cannot run is
 * chosen. nirapod_slhdsa_base_variant reports the choice, so that
 * test_stack can fail when it is not the variant the build is named for.
 * The rest of the library is the application library's own objects, so
 * the public functions run through the same C code as on such a CPU, and
 * test_stack measures their stack depth on that path.
 */

#define nirapod_slhdsa_select nirapod_slhdsa_select_on_host
#include "dispatch.c"
#undef nirapod_slhdsa_select

#ifndef NIRAPOD_SLHDSA_BASE_FEATURES
#define NIRAPOD_SLHDSA_BASE_FEATURES 0u
#endif

const nirapod_slhdsa_impl *nirapod_slhdsa_select(nirapod_slhdsa_set set);

const nirapod_slhdsa_impl *nirapod_slhdsa_select(nirapod_slhdsa_set set)
{
#if NIRAPOD_SLHDSA_BASE_FEATURES == 0u
    return nirapod_slhdsa_select_for(set, 0);
#else
    return nirapod_slhdsa_select_for(set, nirapod_slhdsa_cpu_features() & (NIRAPOD_SLHDSA_BASE_FEATURES));
#endif
}

const char *nirapod_slhdsa_base_variant(nirapod_slhdsa_set set);

const char *nirapod_slhdsa_base_variant(nirapod_slhdsa_set set)
{
    const nirapod_slhdsa_impl *impl = nirapod_slhdsa_select(set);

    return impl == NULL ? "none" : impl->variant;
}
