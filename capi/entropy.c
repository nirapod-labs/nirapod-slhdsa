/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * entropy.c
 * =========
 *
 * The entropy boundary: the only external service the library uses. It
 * supplies SK.seed, SK.prf and PK.seed for key generation (3n bytes) and
 * opt_rand for hedged signing (n bytes), so every request is at most 96
 * bytes.
 *
 *     macOS   getentropy(2): the kernel random source; requests of at most
 *             256 bytes; fails with -1 and errno.
 *     Linux   getrandom(2) with flags 0: blocks until the kernel source is
 *             initialised, then fills the buffer; may return early on a
 *             signal, so the call is repeated for the remainder.
 *
 * Failure behaviour: any error leaves the buffer zero and returns -1; the
 * caller fails the operation with NIRAPOD_SLHDSA_ERROR_ENTROPY. There is
 * no fallback source.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <string.h>

#include "internal.h"

#if defined(__APPLE__)
#include <sys/random.h>
#elif defined(__linux__)
#include <sys/random.h>
#else
#error "entropy.c: no supported random source for this platform"
#endif

int nirapod_slhdsa_entropy(uint8_t *buf, size_t len)
{
    if (len > 256) {
        nirapod_slhdsa_clear(buf, len);
        return -1;
    }

#if defined(__APPLE__)
    if (getentropy(buf, len) != 0) {
        nirapod_slhdsa_clear(buf, len);
        return -1;
    }
    return 0;
#else
    size_t done = 0;

    while (done < len) {
        ssize_t got = getrandom(buf + done, len - done, 0);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            nirapod_slhdsa_clear(buf, len);
            return -1;
        }
        done += (size_t)got;
    }
    return 0;
#endif
}
