/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * backend_adapter.c
 * =================
 *
 * A baseline, reached through the adapter it already has for the
 * differential and ACVP tests (tests/diff/adapters/impl.h), so the
 * benchmark calls each baseline's public API exactly as those tests do.
 * The adapters describe their own mappings and limits in their headers.
 *
 *     keygen     3n bytes from the operating system (SK.seed, SK.prf,
 *                PK.seed), then impl_keygen_seed: Algorithm 21
 *     sign       n bytes of addrnd from the operating system, then
 *                impl_sign with that addrnd: Algorithm 22, hedged
 *     sign-det   impl_sign with addrnd NULL: Algorithm 22, deterministic
 *     verify     impl_verify, pure, empty context: Algorithm 24
 *
 * The draws use bench_os_entropy, the operating system call this library
 * makes for the same bytes, and happen inside the timed call, so keygen
 * and hedged signing do the same entropy work on both sides of R.
 *
 * Some adapters draw the randomness themselves or cannot take it as input
 * (BoringSSL signs only with its own randomness, impl_boringssl.c). Built
 * with BENCH_HEDGED_OWN, hedged signing calls bench_hedged_own instead,
 * which the build links from a small file per such library
 * (hedged_boringssl.c); the library then draws opt_rand from its own
 * source, inside the call.
 */

#include <string.h>

#include "backend.h"
#include "impl.h"

int backend_init(const char *variant)
{
    if (variant != NULL && impl_force_variant(variant) != IMPL_OK) {
        return BACKEND_UNSUPPORTED;
    }
    if (slh_tables_check() != 0 || impl_init() != IMPL_OK) {
        return BACKEND_ERROR;
    }
    return BACKEND_OK;
}

const char *backend_name(void)
{
    return impl_name();
}

/*
 * The adapters that keep no mutable state between calls. The OpenSSL and
 * wolfSSL adapters cache the last key object in process-wide variables
 * (impl_openssl.c, impl_wolfssl.c), so their programs measure throughput
 * with one thread only. The SPHINCS+ code's lazily opened random source
 * (randombytes.c) is not reached: the adapter passes every random input.
 */
int backend_concurrent(void)
{
    static const char *const stateless[] = { "slhdsa-c", "sphincsplus", "boringssl" };
    size_t i;

    for (i = 0; i < sizeof(stateless) / sizeof(stateless[0]); i++) {
        if (strcmp(impl_name(), stateless[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

const char *backend_variant(int set)
{
    (void)set;
    return impl_variant();
}

/*
 * A set the adapter does not offer (sphincsplus builds one set, BoringSSL
 * two) answers BACKEND_UNSUPPORTED at its first call rather than here: the
 * adapter interface reports support per call only.
 */
int backend_set_index(const char *name)
{
    return slh_set_index(name);
}

void backend_sizes(int set, size_t *n, size_t *pk, size_t *sk, size_t *sig)
{
    *n = slh_sets[set].n;
    *pk = slh_sets[set].pk_bytes;
    *sk = slh_sets[set].sk_bytes;
    *sig = slh_sets[set].sig_bytes;
}

static int status(int st)
{
    if (st == IMPL_OK) {
        return BACKEND_OK;
    }
    return st == IMPL_UNSUPPORTED ? BACKEND_UNSUPPORTED : BACKEND_ERROR;
}

int backend_keygen(int set, uint8_t *pk, uint8_t *sk)
{
    uint8_t seeds[3 * 32];
    size_t n = slh_sets[set].n;

    if (bench_os_entropy(seeds, 3 * n) != 0) {
        return BACKEND_ERROR;
    }
    return status(impl_keygen_seed(set, seeds, seeds + n, seeds + 2 * n, pk, sk));
}

int backend_sign(int set, sign_mode mode, const uint8_t *sk, const uint8_t *m, size_t mlen,
                 uint8_t *sig)
{
    uint8_t addrnd[32];

    switch (mode) {
    case SIGN_HEDGED:
#if defined(BENCH_HEDGED_OWN)
        (void)addrnd;
        return bench_hedged_own(set, sk, m, mlen, sig);
#else
        if (bench_os_entropy(addrnd, slh_sets[set].n) != 0) {
            return BACKEND_ERROR;
        }
        return status(impl_sign(set, PH_NONE, sk, m, mlen, NULL, 0, addrnd, sig));
#endif
    case SIGN_DET:
        return status(impl_sign(set, PH_NONE, sk, m, mlen, NULL, 0, NULL, sig));
    default:
        return BACKEND_UNSUPPORTED;
    }
}

int backend_verify(int set, const uint8_t *pk, const uint8_t *m, size_t mlen, const uint8_t *sig)
{
    int st = impl_verify(set, PH_NONE, pk, m, mlen, NULL, 0, sig, slh_sets[set].sig_bytes);
    return st == IMPL_REJECT ? BACKEND_ERROR : status(st);
}
