/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_buffers.c
 * ==============
 *
 * Two promises of the header about buffers, through the application
 * library alone:
 *
 *     threads     "no global mutable state; calls on distinct buffers may
 *                 run concurrently": one thread per parameter set, and a
 *                 second one for each f set, all started together, sign
 *                 deterministically into their own buffers and verify;
 *                 every signature equals the one computed before on a
 *                 single thread, and every verification passes
 *     alignment   keys, message, context and signature at every offset 0
 *                 to 15 from a 16-byte boundary: the same deterministic
 *                 signature as at offset 0, the same verdict, nothing
 *                 written past the signature, and keys generated at that
 *                 offset that sign and verify
 *
 * Each thread runs on a stack of THREAD_STACK bytes, several times the
 * deepest stack docs/API.md documents for any public function, so that
 * the result does not depend on a platform's default thread stack size.
 * Exit status 0 when every check passes.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

#define SETS 12
#define WORKERS (SETS + SETS / 2)
#define THREAD_STACK ((size_t)256 * 1024)
#define CANARY 0xA5
#define GUARD 32

static int is_fast(nirapod_slhdsa_set set)
{
    /* Sets come in pairs per row of FIPS 205 Table 2: 128s, 128f, 192s, ... */
    return (((unsigned)set - 1) / 2) % 2 == 1;
}

/* The keys of each set, and the signature computed on one thread. */
static uint8_t pks[SETS + 1][64];
static uint8_t sks[SETS + 1][128];
static uint8_t expected[SETS + 1][NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];

/*
 * A worker's own signature buffer. The verdicts are written by the worker
 * and read by main only after pthread_join, which orders the accesses.
 */
typedef struct worker {
    nirapod_slhdsa_set set;
    pthread_t thread;
    nirapod_slhdsa_status signed_st, verified_st;
    uint8_t sig[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
} worker;

static worker workers[WORKERS];

static const uint8_t MSG[] = "concurrent use on distinct buffers";
static const uint8_t CTX[] = "threads";

static void *run_worker(void *arg)
{
    worker *w = (worker *)arg;
    size_t pk_len = nirapod_slhdsa_public_key_bytes(w->set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(w->set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(w->set);

    w->signed_st = nirapod_slhdsa_sign_deterministic(w->set, w->sig, sig_len, MSG, sizeof(MSG) - 1,
                                                     CTX, sizeof(CTX) - 1, sks[w->set], sk_len);
    w->verified_st = nirapod_slhdsa_verify(w->set, expected[w->set], sig_len, MSG, sizeof(MSG) - 1,
                                           CTX, sizeof(CTX) - 1, pks[w->set], pk_len);
    return NULL;
}

static void test_threads(void)
{
    pthread_attr_t attr;
    int started[WORKERS] = { 0 };
    unsigned s, n = 0;
    nirapod_slhdsa_status st;
    size_t i;

    /* The reference, on this thread alone. */

    for (s = 1; s <= SETS; s++) {
        nirapod_slhdsa_set set = (nirapod_slhdsa_set)s;
        size_t sig_len = nirapod_slhdsa_signature_bytes(set);

        st = nirapod_slhdsa_keygen(set, pks[s], nirapod_slhdsa_public_key_bytes(set),
                                   sks[s], nirapod_slhdsa_secret_key_bytes(set));
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s keygen: %d", nirapod_slhdsa_set_name(set), st);
        st = nirapod_slhdsa_sign_deterministic(set, expected[s], sig_len, MSG, sizeof(MSG) - 1,
                                               CTX, sizeof(CTX) - 1, sks[s],
                                               nirapod_slhdsa_secret_key_bytes(set));
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s sign: %d", nirapod_slhdsa_set_name(set), st);
        workers[n++].set = set;
        if (is_fast(set)) {
            workers[n++].set = set;
        }
    }

    /* Every worker at once. */

    CHECK(pthread_attr_init(&attr) == 0, "pthread_attr_init");
    CHECK(pthread_attr_setstacksize(&attr, THREAD_STACK) == 0, "pthread_attr_setstacksize");
    for (i = 0; i < n; i++) {
        memset(workers[i].sig, CANARY, sizeof(workers[i].sig));
        started[i] = pthread_create(&workers[i].thread, &attr, run_worker, &workers[i]) == 0;
        CHECK(started[i], "pthread_create %zu", i);
    }
    for (i = 0; i < n; i++) {
        if (started[i]) {
            CHECK(pthread_join(workers[i].thread, NULL) == 0, "pthread_join %zu", i);
        }
    }
    pthread_attr_destroy(&attr);

    for (i = 0; i < n; i++) {
        const worker *w = &workers[i];
        size_t sig_len = nirapod_slhdsa_signature_bytes(w->set);
        const char *name = nirapod_slhdsa_set_name(w->set);

        if (!started[i]) {
            continue;
        }
        CHECK(w->signed_st == NIRAPOD_SLHDSA_OK, "%s worker %zu sign: %d", name, i, w->signed_st);
        CHECK(memcmp(w->sig, expected[w->set], sig_len) == 0,
              "%s worker %zu: signature differs from the single-thread one", name, i);
        CHECK(w->verified_st == NIRAPOD_SLHDSA_OK, "%s worker %zu verify: %d", name, i,
              w->verified_st);
    }
    printf("threads: %u workers over %d sets, signatures equal the single-thread ones\n", n, SETS);
}

/*
 * Regions of 16 + GUARD bytes beyond the largest buffer: at() rounds up to
 * the next 16-byte boundary, then adds the offset.
 */
#define REGION (NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES + 16 + 16 + GUARD)

static uint8_t r_sig[REGION], r_pk[REGION], r_sk[REGION], r_msg[REGION], r_ctx[REGION];

static uint8_t *at(uint8_t *region, size_t offset)
{
    return region + (16 - (size_t)((uintptr_t)region % 16)) % 16 + offset;
}

static int all_canary(const uint8_t *p, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (p[i] != CANARY) {
            return 0;
        }
    }
    return 1;
}

static void test_alignment(nirapod_slhdsa_set set)
{
    const char *name = nirapod_slhdsa_set_name(set);
    size_t pk_len = nirapod_slhdsa_public_key_bytes(set);
    size_t sk_len = nirapod_slhdsa_secret_key_bytes(set);
    size_t sig_len = nirapod_slhdsa_signature_bytes(set);
    size_t offset;
    nirapod_slhdsa_status st;

    for (offset = 0; offset < 16; offset++) {
        uint8_t *sig = at(r_sig, offset), *pk = at(r_pk, offset), *sk = at(r_sk, offset);
        uint8_t *msg = at(r_msg, offset), *ctx = at(r_ctx, offset);

        memcpy(pk, pks[set], pk_len);
        memcpy(sk, sks[set], sk_len);
        memcpy(msg, MSG, sizeof(MSG) - 1);
        memcpy(ctx, CTX, sizeof(CTX) - 1);
        memset(r_sig, CANARY, sizeof(r_sig));

        st = nirapod_slhdsa_sign_deterministic(set, sig, sig_len, msg, sizeof(MSG) - 1,
                                               ctx, sizeof(CTX) - 1, sk, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK && memcmp(sig, expected[set], sig_len) == 0,
              "%s offset %zu: sign %d, or a different signature", name, offset, st);
        CHECK(all_canary(sig + sig_len, GUARD), "%s offset %zu: written past the signature",
              name, offset);
        st = nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(MSG) - 1, ctx, sizeof(CTX) - 1,
                                   pk, pk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s offset %zu: verify %d", name, offset, st);
        sig[sig_len - 1] ^= 0x01;
        st = nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(MSG) - 1, ctx, sizeof(CTX) - 1,
                                   pk, pk_len);
        CHECK(st == NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE, "%s offset %zu: tampered verify %d",
              name, offset, st);

        st = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s offset %zu: keygen %d", name, offset, st);
        st = nirapod_slhdsa_sign(set, sig, sig_len, msg, sizeof(MSG) - 1, ctx, sizeof(CTX) - 1,
                                 sk, sk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s offset %zu: hedged sign %d", name, offset, st);
        st = nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(MSG) - 1, ctx, sizeof(CTX) - 1,
                                   pk, pk_len);
        CHECK(st == NIRAPOD_SLHDSA_OK, "%s offset %zu: verify of the new key %d", name, offset, st);
    }
    printf("%-20s alignment: offsets 0 to 15 of every buffer\n", name);
}

int main(void)
{
    test_threads();
    test_alignment(NIRAPOD_SLHDSA_SHAKE_128F);
    test_alignment(NIRAPOD_SLHDSA_SHA2_128F);

    printf("test_buffers: %s (%d failures)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
