/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * impl_stub.c
 * ===========
 *
 * A fake implementation for testing the drivers' verdict rules
 * (tests/diff/controls.py, tests/acvp/verdicts.py), never a result about
 * SLH-DSA. The environment
 * variable SLH_STUB selects one behaviour for every call:
 *
 *   unsupported  every operation answers IMPL_UNSUPPORTED
 *   error        every operation answers IMPL_ERROR
 *   reject       verification answers IMPL_REJECT, everything else
 *                IMPL_ERROR
 *   hang         every call sleeps for a day (timeout handling)
 *   crash        every call aborts the process (death by signal)
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "impl.h"

static int mode_status(int verify)
{
    const char *m = getenv("SLH_STUB");

    if (m != NULL && strcmp(m, "unsupported") == 0)
        return IMPL_UNSUPPORTED;
    if (m != NULL && strcmp(m, "hang") == 0)
        sleep(86400);
    if (m != NULL && strcmp(m, "crash") == 0)
        abort();
    if (m != NULL && strcmp(m, "reject") == 0 && verify)
        return IMPL_REJECT;
    return IMPL_ERROR;
}

const char *impl_name(void) { return "stub"; }
const char *impl_variant(void) { return getenv("SLH_STUB") ? getenv("SLH_STUB") : "error"; }
int impl_force_variant(const char *name) { (void)name; return IMPL_UNSUPPORTED; }
int impl_init(void) { return IMPL_OK; }

int impl_keygen_seed(int set, const uint8_t *a, const uint8_t *b, const uint8_t *c,
                     uint8_t *pk, uint8_t *sk)
{
    (void)set, (void)a, (void)b, (void)c, (void)pk, (void)sk;
    return mode_status(0);
}

int impl_sign_internal(int set, const uint8_t *sk, const uint8_t *m, size_t mlen,
                       const uint8_t *addrnd, uint8_t *sig)
{
    (void)set, (void)sk, (void)m, (void)mlen, (void)addrnd, (void)sig;
    return mode_status(0);
}

int impl_verify_internal(int set, const uint8_t *pk, const uint8_t *m, size_t mlen,
                         const uint8_t *sig, size_t siglen)
{
    (void)set, (void)pk, (void)m, (void)mlen, (void)sig, (void)siglen;
    return mode_status(1);
}

int impl_sign(int set, slh_ph ph, const uint8_t *sk, const uint8_t *m, size_t mlen,
              const uint8_t *ctx, size_t ctxlen, const uint8_t *addrnd, uint8_t *sig)
{
    (void)set, (void)ph, (void)sk, (void)m, (void)mlen, (void)ctx, (void)ctxlen;
    (void)addrnd, (void)sig;
    return mode_status(0);
}

int impl_verify(int set, slh_ph ph, const uint8_t *pk, const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen, const uint8_t *sig, size_t siglen)
{
    (void)set, (void)ph, (void)pk, (void)m, (void)mlen, (void)ctx, (void)ctxlen;
    (void)sig, (void)siglen;
    return mode_status(1);
}
