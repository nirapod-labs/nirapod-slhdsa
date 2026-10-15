/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * hedged_boringssl.c
 * ==================
 *
 * Hedged signing for BoringSSL, whose public signing functions always draw
 * opt_rand from BoringSSL's own random source and take no addrnd (see
 * tests/diff/adapters/impl_boringssl.c). Linked into its benchmark program
 * only (bench/Makefile, BENCH_HEDGED_OWN). BoringSSL implements two sets;
 * the others answer BACKEND_UNSUPPORTED. The secret key is the one its own
 * key generation wrote, through the adapter.
 */

#include <openssl/slhdsa.h>

#include "backend.h"
#include "impl.h"

int bench_hedged_own(int set, const uint8_t *sk, const uint8_t *m, size_t mlen, uint8_t *sig)
{
    int ok;

    if (set == slh_set_index("SLH-DSA-SHA2-128s")) {
        ok = SLHDSA_SHA2_128S_sign(sig, sk, m, mlen, NULL, 0);
    } else if (set == slh_set_index("SLH-DSA-SHAKE-256f")) {
        ok = SLHDSA_SHAKE_256F_sign(sig, sk, m, mlen, NULL, 0);
    } else {
        return BACKEND_UNSUPPORTED;
    }
    return ok == 1 ? BACKEND_OK : BACKEND_ERROR;
}
