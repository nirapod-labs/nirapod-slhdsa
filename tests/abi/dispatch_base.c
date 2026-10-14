/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * dispatch_base.c
 * ===============
 *
 * capi/dispatch.c for a CPU with no instruction-set extension, for
 * test_stack_base only. The file is compiled from dispatch.c itself, with
 * nirapod_slhdsa_select renamed and replaced by one that makes the choice
 * for an empty feature set, so every set runs its scalar variant on any
 * host. The rest of the library is the application library's own objects,
 * so the public functions run through the same C code as on a CPU without
 * the extensions, and test_stack measures their stack depth on that path.
 */

#define nirapod_slhdsa_select nirapod_slhdsa_select_on_host
#include "dispatch.c"
#undef nirapod_slhdsa_select

const nirapod_slhdsa_impl *nirapod_slhdsa_select(nirapod_slhdsa_set set);

const nirapod_slhdsa_impl *nirapod_slhdsa_select(nirapod_slhdsa_set set)
{
    return nirapod_slhdsa_select_for(set, 0);
}
