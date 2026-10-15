/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * backend_public.c
 * ================
 *
 * This library as applications use it: the functions of
 * include/nirapod_slhdsa.h, linked from the application library
 * (libnirapod_slhdsa.a) and nothing else. These are the rows R is computed
 * from.
 *
 *     keygen     nirapod_slhdsa_keygen (draws its seeds itself)
 *     sign       nirapod_slhdsa_sign (draws opt_rand itself)
 *     sign-det   nirapod_slhdsa_sign_deterministic
 *     verify     nirapod_slhdsa_verify
 *
 * Both signing functions verify the new signature before releasing it
 * (the fault check of nirapod_slhdsa.h), so their times include one
 * verification that the baselines do not perform. The unchecked modes are
 * not part of the public API and answer BACKEND_UNSUPPORTED here; the
 * testing backend measures them.
 *
 * The hash variant is the one the library's dispatch selects for this CPU.
 * The public API does not name it, so backend_variant reports
 * "production"; bench/run.py records the selected variant from the
 * testing build, whose dispatch is the same code.
 */

#include <string.h>

#include "backend.h"
#include "nirapod_slhdsa.h"

int backend_init(const char *variant)
{
    return variant == NULL ? BACKEND_OK : BACKEND_UNSUPPORTED;
}

const char *backend_name(void)
{
    return "nirapod";
}

/* The library is reentrant and keeps no global mutable state (nirapod_slhdsa.h). */
int backend_concurrent(void)
{
    return 1;
}

const char *backend_variant(int set)
{
    (void)set;
    return "production";
}

int backend_set_index(const char *name)
{
    int set;
    for (set = NIRAPOD_SLHDSA_SHA2_128S; set <= NIRAPOD_SLHDSA_SHAKE_256F; set++) {
        const char *s = nirapod_slhdsa_set_name((nirapod_slhdsa_set)set);
        if (s != NULL && strcmp(s, name) == 0) {
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
    return status(nirapod_slhdsa_keygen((nirapod_slhdsa_set)set, pk, pk_len, sk, sk_len));
}

int backend_sign(int set, sign_mode mode, const uint8_t *sk, const uint8_t *m, size_t mlen,
                 uint8_t *sig)
{
    size_t n, pk_len, sk_len, sig_len;
    backend_sizes(set, &n, &pk_len, &sk_len, &sig_len);
    switch (mode) {
    case SIGN_HEDGED:
        return status(nirapod_slhdsa_sign((nirapod_slhdsa_set)set, sig, sig_len, m, mlen, NULL, 0,
                                          sk, sk_len));
    case SIGN_DET:
        return status(nirapod_slhdsa_sign_deterministic((nirapod_slhdsa_set)set, sig, sig_len, m,
                                                        mlen, NULL, 0, sk, sk_len));
    default:
        return BACKEND_UNSUPPORTED;
    }
}

int backend_verify(int set, const uint8_t *pk, const uint8_t *m, size_t mlen, const uint8_t *sig)
{
    size_t n, pk_len, sk_len, sig_len;
    backend_sizes(set, &n, &pk_len, &sk_len, &sig_len);
    return status(nirapod_slhdsa_verify((nirapod_slhdsa_set)set, sig, sig_len, m, mlen, NULL, 0,
                                        pk, pk_len));
}
