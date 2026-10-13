/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_entropy.c
 * ==============
 *
 * The operating system's random source behind the application library
 * (capi/entropy.c), made to fail.
 *
 * Method
 *
 *     This program defines the system call wrapper the library calls,
 *     getrandom on Linux and getentropy on macOS. It links the application
 *     library alone, so the library's reference to that function binds to
 *     this definition when the program is linked, and the test decides
 *     what the source returns:
 *
 *         ok      fills the buffer with a known pattern
 *         fail    returns -1 with errno EIO
 *         eintr   (Linux) -1 with errno EINTR once, then ok
 *         short   (Linux) one byte per call
 *
 * Checks
 *
 *     binding   with the source ok, key generation calls it, and the secret
 *               key starts with the pattern: the library's seeds come from
 *               this definition, or none of the checks below means anything
 *     failure   with the source failing, key generation and hedged signing,
 *               pure and pre-hash, return NIRAPOD_SLHDSA_ERROR_ENTROPY with
 *               the outputs zeroed and nothing written past them;
 *               deterministic signing does not call the source and succeeds
 *     retries   (Linux) a call interrupted by a signal is repeated, and a
 *               short read is completed by further calls
 *
 * Exit status 0 when every check passes.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>

#include "nirapod_slhdsa.h"

static int failures;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                        \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

#define GUARD   64
#define CANARY  0xA5
#define PATTERN 0x6B

enum { SOURCE_OK, SOURCE_FAIL, SOURCE_EINTR, SOURCE_SHORT };

static int source_mode = SOURCE_OK;
static unsigned source_calls;
static int eintr_pending;

/* One request to the source: the number of bytes delivered, or -1. */
static long source(void *buf, size_t len)
{
    source_calls++;
    if (source_mode == SOURCE_FAIL) {
        memset(buf, 0xEE, len);   /* garbage the library must not use */
        errno = EIO;
        return -1;
    }
    if (source_mode == SOURCE_EINTR && eintr_pending) {
        eintr_pending = 0;
        errno = EINTR;
        return -1;
    }
    if (source_mode == SOURCE_SHORT && len > 1) {
        len = 1;
    }
    memset(buf, PATTERN, len);
    return (long)len;
}

#if defined(__linux__)
#define SOURCE_NAME "getrandom"
#define RETRIES ", interrupted and short reads completed"

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    (void)flags;
    return (ssize_t)source(buf, buflen);
}
#elif defined(__APPLE__)
#define SOURCE_NAME "getentropy"
#define RETRIES ""

int getentropy(void *buffer, size_t size)
{
    return source(buffer, size) < 0 ? -1 : 0;
}
#else
#error "test_entropy.c: unsupported platform"
#endif

static uint8_t sigbuf[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES + GUARD];

static int all_bytes(const uint8_t *p, size_t len, uint8_t v)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (p[i] != v) {
            return 0;
        }
    }
    return 1;
}

static void test_set(nirapod_slhdsa_set set)
{
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    size_t n = pk_len / 2;
    uint8_t pk[64 + GUARD], sk[128 + GUARD], msg[16];
    nirapod_slhdsa_status st;
    int before = failures;

    memset(msg, 0x4d, sizeof(msg));

    /* binding */

    source_mode = SOURCE_OK;
    source_calls = 0;
    st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK && source_calls == 1 && all_bytes(sk, 3 * n, PATTERN),
          "%s keygen with the test source: %d, %u calls; the library does not use this "
          "program's " SOURCE_NAME, name, st, source_calls);

    /* failure */

    source_mode = SOURCE_FAIL;
    source_calls = 0;
    memset(pk, CANARY, sizeof(pk));
    memset(sk, CANARY, sizeof(sk));
    st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_ENTROPY && source_calls >= 1, "%s keygen, failing source: %d",
          name, st);
    CHECK(all_bytes(pk, pk_len, 0) && all_bytes(pk + pk_len, GUARD, CANARY) &&
          all_bytes(sk, sk_len, 0) && all_bytes(sk + sk_len, GUARD, CANARY),
          "%s keygen, failing source: output state", name);

    /* The key for signing: SK.seed || SK.prf || PK.seed || PK.root of a real pair */

    source_mode = SOURCE_OK;
    st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK, "%s keygen for signing: %d", name, st);

    source_mode = SOURCE_FAIL;
    source_calls = 0;
    memset(sigbuf, CANARY, sizeof(sigbuf));
    st = nirapod_slhdsa_sign(set, sigbuf, sig_len, msg, sizeof(msg), NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_ENTROPY && source_calls >= 1 &&
          all_bytes(sigbuf, sig_len, 0) && all_bytes(sigbuf + sig_len, GUARD, CANARY),
          "%s sign, failing source: %d, output state", name, st);

    source_calls = 0;
    memset(sigbuf, CANARY, sizeof(sigbuf));
    st = nirapod_slhdsa_hash_sign(set, NIRAPOD_SLHDSA_PREHASH_SHA2_256, sigbuf, sig_len,
                                  msg, sizeof(msg), NULL, 0, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_ERROR_ENTROPY && source_calls >= 1 &&
          all_bytes(sigbuf, sig_len, 0) && all_bytes(sigbuf + sig_len, GUARD, CANARY),
          "%s hash_sign, failing source: %d, output state", name, st);

    source_calls = 0;
    st = nirapod_slhdsa_sign_deterministic(set, sigbuf, sig_len, msg, sizeof(msg), NULL, 0,
                                           sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK && source_calls == 0,
          "%s sign_deterministic, failing source: %d, %u calls", name, st, source_calls);
    CHECK(nirapod_slhdsa_verify(set, sigbuf, sig_len, msg, sizeof(msg), NULL, 0, pk, pk_len) ==
              NIRAPOD_SLHDSA_OK, "%s deterministic signature verifies", name);

#if defined(__linux__)
    /* retries */

    source_mode = SOURCE_EINTR;
    eintr_pending = 1;
    source_calls = 0;
    st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK && source_calls == 2 && all_bytes(sk, 3 * n, PATTERN),
          "%s keygen, interrupted once: %d, %u calls", name, st, source_calls);

    source_mode = SOURCE_SHORT;
    source_calls = 0;
    st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
    CHECK(st == NIRAPOD_SLHDSA_OK && source_calls == 3 * n && all_bytes(sk, 3 * n, PATTERN),
          "%s keygen, one byte per call: %d, %u calls", name, st, source_calls);
#endif

    printf("%-20s entropy source: bound, failure fails closed" RETRIES ": %s\n", name,
           failures == before ? "PASS" : "FAIL");
}

int main(void)
{
    test_set(NIRAPOD_SLHDSA_SHAKE_128F);
    test_set(NIRAPOD_SLHDSA_SHA2_128F);
    printf("test_entropy (application library): %s (%d failures)\n",
           failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
