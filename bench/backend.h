/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * backend.h
 * =========
 *
 * The interface bench.c times. Each benchmark program links bench.c with
 * exactly one backend, so every implementation runs under the same timing
 * loop, the same inputs and the same stack probe:
 *
 *     backend_public.c    this library, through include/nirapod_slhdsa.h
 *                         and the application library only
 *     backend_testing.c   this library through its testing library: a
 *                         pinned hash variant, or signing without the
 *                         check of the new signature (diagnostic rows)
 *     backend_adapter.c   a baseline, through the adapter interface of
 *                         tests/diff/adapters/impl.h
 *
 * Workloads. Each operation is the external interface of FIPS 205
 * section 10 with a pure (unhashed) message and an empty context string,
 * including the random bytes the algorithm draws:
 *
 *     keygen     slh_keygen, Algorithm 21: 3n bytes from the operating
 *                system, then slh_keygen_internal
 *     sign       slh_sign, Algorithm 22, hedged: n bytes of opt_rand from
 *                the operating system
 *     sign-det   slh_sign, Algorithm 22, deterministic: opt_rand = PK.seed
 *     verify     slh_verify, Algorithm 24
 *
 * A backend whose implementation draws the random bytes itself does so
 * inside the call; one that takes them as input draws them with the
 * operating system call this library uses (getentropy on macOS, getrandom
 * on Linux) inside the timed call, so every row includes the same
 * entropy work. The unchecked signing modes exist only in the testing
 * backend.
 *
 * Common contract:
 *
 *     set        a backend index from backend_set_index; buffers have the
 *                sizes backend_sizes reports for it
 *     status     BACKEND_OK, BACKEND_UNSUPPORTED (the implementation or
 *                this build lacks the set or mode; reported, never timed)
 *                or BACKEND_ERROR (a failed call; the run stops)
 *     verify     BACKEND_OK only when the signature is accepted
 */

#ifndef NIRAPOD_SLHDSA_BENCH_BACKEND_H
#define NIRAPOD_SLHDSA_BENCH_BACKEND_H

#include <stddef.h>
#include <stdint.h>

enum {
    BACKEND_OK = 0,
    BACKEND_UNSUPPORTED = 1,
    BACKEND_ERROR = 2
};

typedef enum {
    SIGN_HEDGED = 0,
    SIGN_DET,
    SIGN_HEDGED_UNCHECKED,
    SIGN_DET_UNCHECKED
} sign_mode;

/* Called once, first. option is the --variant value or NULL. */
int backend_init(const char *variant);

/* Short name of the implementation, e.g. "nirapod" or "slhdsa-c". */
const char *backend_name(void);

/* The code path used for set, after backend_init (for a report). */
const char *backend_variant(int set);

/* Index of the FIPS 205 set name, or -1 when this backend has no such set. */
int backend_set_index(const char *name);

/*
 * 1 when the backend may be called from several threads at once on
 * distinct buffers: it keeps no mutable state between calls. Throughput
 * with more than one thread runs only then.
 */
int backend_concurrent(void);

/* n and the key and signature sizes of set, in bytes. */
void backend_sizes(int set, size_t *n, size_t *pk, size_t *sk, size_t *sig);

int backend_keygen(int set, uint8_t *pk, uint8_t *sk);
int backend_sign(int set, sign_mode mode, const uint8_t *sk, const uint8_t *m, size_t mlen,
                 uint8_t *sig);
int backend_verify(int set, const uint8_t *pk, const uint8_t *m, size_t mlen,
                   const uint8_t *sig);

/*
 * Fills buf with len bytes from the operating system's random source, the
 * same call this library makes; 0 on success. Defined in bench.c.
 */
int bench_os_entropy(uint8_t *buf, size_t len);

#if defined(BENCH_HEDGED_OWN)
/*
 * Hedged slh_sign with the library's own randomness, for a baseline that
 * takes no opt_rand (backend_adapter.c); BACKEND_* status.
 */
int bench_hedged_own(int set, const uint8_t *sk, const uint8_t *m, size_t mlen, uint8_t *sig);
#endif

#endif
