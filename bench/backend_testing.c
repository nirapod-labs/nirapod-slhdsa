/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * backend_testing.c
 * =================
 *
 * This library through its testing library (libnirapod_slhdsa_testing.a,
 * capi/testing/nirapod_slhdsa_testing.h), for the diagnostic rows the
 * public API cannot give:
 *
 *     --variant=V          every call pinned to hash variant V, to show
 *                          what each compiled variant costs on this CPU
 *     sign-unchecked,      signing with skip_fault_check set: the
 *     sign-det-unchecked   signature is released without the verification
 *                          the public functions perform, which isolates
 *                          the cost of that check (docs/API.md)
 *
 * keygen, sign, sign-det and verify map onto the testing functions with
 * the operating system's entropy, so they run the same code as the
 * public functions. These rows are not the delivered API and R is not
 * computed from them.
 */

#include <string.h>

#include "backend.h"
#include "nirapod_slhdsa.h"
#include "nirapod_slhdsa_testing.h"

static nirapod_slhdsa_testing_config checked, unchecked;

int backend_init(const char *variant)
{
    memset(&checked, 0, sizeof(checked));
    checked.variant = variant;
    unchecked = checked;
    unchecked.skip_fault_check = 1;
    return BACKEND_OK;
}

const char *backend_name(void)
{
    return "nirapod-testing";
}

/* The two configurations are fixed by backend_init and only read after it. */
int backend_concurrent(void)
{
    return 1;
}

const char *backend_variant(int set)
{
    if (checked.variant != NULL) {
        return checked.variant;
    }
    return nirapod_slhdsa_testing_variant((nirapod_slhdsa_set)set);
}

int backend_set_index(const char *name)
{
    int set;
    for (set = NIRAPOD_SLHDSA_SHA2_128S; set <= NIRAPOD_SLHDSA_SHAKE_256F; set++) {
        const char *s = nirapod_slhdsa_set_name((nirapod_slhdsa_set)set);
        if (s != NULL && strcmp(s, name) == 0) {
            if (checked.variant != NULL &&
                !nirapod_slhdsa_testing_variant_supported((nirapod_slhdsa_set)set,
                                                          checked.variant)) {
                return -1;
            }
            return set;
        }
    }
    return -1;
}

void backend_sizes(int set, size_t *n, size_t *pk, size_t *sk, size_t *sig)
{
    *pk = nirapod_slhdsa_public_key_bytes((nirapod_slhdsa_set)set);
    *sk = nirapod_slhdsa_secret_key_bytes((nirapod_slhdsa_set)set);
    *sig = nirapod_slhdsa_signature_bytes((nirapod_slhdsa_set)set);
    *n = *pk / 2;
}

static int status(nirapod_slhdsa_status st)
{
    return st == NIRAPOD_SLHDSA_OK ? BACKEND_OK : BACKEND_ERROR;
}

int backend_keygen(int set, uint8_t *pk, uint8_t *sk)
{
    size_t n, pk_len, sk_len, sig_len;
    backend_sizes(set, &n, &pk_len, &sk_len, &sig_len);
    return status(nirapod_slhdsa_testing_keygen(&checked, (nirapod_slhdsa_set)set, pk, pk_len, sk,
                                                sk_len));
}

int backend_sign(int set, sign_mode mode, const uint8_t *sk, const uint8_t *m, size_t mlen,
                 uint8_t *sig)
{
    const nirapod_slhdsa_testing_config *c =
        mode == SIGN_HEDGED || mode == SIGN_DET ? &checked : &unchecked;
    size_t n, pk_len, sk_len, sig_len;

    backend_sizes(set, &n, &pk_len, &sk_len, &sig_len);
    if (mode == SIGN_HEDGED || mode == SIGN_HEDGED_UNCHECKED) {
        return status(nirapod_slhdsa_testing_sign_hedged(c, (nirapod_slhdsa_set)set, 0, sig,
                                                         sig_len, m, mlen, NULL, 0, sk, sk_len));
    }
    /* Deterministic: opt_rand = PK.seed, the third n-byte field of sk. */
    return status(nirapod_slhdsa_testing_sign(c, (nirapod_slhdsa_set)set, 0, sig, sig_len, m,
                                              mlen, NULL, 0, sk, sk_len, sk + 2 * n, n));
}

int backend_verify(int set, const uint8_t *pk, const uint8_t *m, size_t mlen, const uint8_t *sig)
{
    size_t n, pk_len, sk_len, sig_len;
    backend_sizes(set, &n, &pk_len, &sk_len, &sig_len);
    return status(nirapod_slhdsa_testing_verify(&checked, (nirapod_slhdsa_set)set, 0, sig,
                                                sig_len, m, mlen, NULL, 0, pk, pk_len));
}
