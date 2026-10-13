/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_stack.c
 * ============
 *
 * Stack depth and stack residue of the Jasmin exports, measured by stack
 * painting on the running host.
 *
 * Method
 *
 *     1. Read the stack pointer of the test function (sp).
 *     2. Fill [sp - REGION, sp) with a canary byte, from inside the test
 *        function and without calls, so no frame below sp is live.
 *     3. Call one Jasmin export directly; its frames grow down from sp.
 *     4. Scan the region again:
 *          depth    = sp minus the lowest address whose byte changed;
 *          residue  = changed bytes that are not zero, below the top
 *                     TOP bytes: the return address and the callee-saved
 *                     registers the export saves on entry, which hold
 *                     caller values, not data of the export (x86-64: the
 *                     return address and six registers, 56 bytes;
 *                     AArch64: the saved link register, 16 bytes).
 *
 * The exports are built with stack zeroization, so the expected residue is
 * zero bytes. Depth is the stack use of one call on this host and build.
 *
 * Secret scan and depth of the public functions
 *
 *     The residue count cannot judge the C wrapper's frames, which hold
 *     non-zero public data (pointers, return addresses) by design. For
 *     those the test runs the public functions on the same painted stack
 *     and searches the region for the secret-key seeds: any 8 consecutive
 *     bytes of SK.seed or SK.prf left anywhere below the caller is a
 *     failure. keygen draws the seeds itself, so they are read from the
 *     secret key it returns. Signing with a given opt_rand through the
 *     testing library extends the search to opt_rand, which the library
 *     copies to its own stack. A function of this test that leaves a copy
 *     of SK.prf in its own frame shows that the scan finds such a copy at
 *     that depth; if it does not, the test fails.
 *
 *     This covers copies of the seeds and of opt_rand, not values derived
 *     from them (WOTS+ and FORS secrets, chain values); those are made
 *     only in the Jasmin frames, which the residue scan covers.
 *
 *     The same calls give the stack depth of each public function, C
 *     frames included: the deepest over all sets is printed per function.
 *
 * Builds
 *
 *     test_stack          the testing library: every export of every
 *                         variant, then the public functions
 *     test_stack_control (NIRAPOD_SLHDSA_STACK_CONTROL)
 *                         two units built without stack zeroization, the
 *                         negative control below
 *
 * Usage: test_stack [--expect-residue]
 *
 *     --expect-residue  negative control: the build without stack
 *                       zeroization must leave residue, else the probe
 *                       cannot detect it and the test fails.
 *
 * Reading memory below the stack pointer is outside the C abstract
 * machine. The accesses are volatile byte accesses with no call in
 * between, which the supported compilers emit as written; the test is a
 * measurement of the compiled program, not a portable C property.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "jasmin.h"
#include "nirapod_slhdsa.h"
#include "nirapod_slhdsa_testing.h"

#define REGION (512u * 1024u)
#define CANARY 0x5Au
#if defined(__x86_64__)
#define TOP    56u
#else
#define TOP    16u
#endif

typedef struct {
    const char *name;
    const char *variant;
    unsigned features;
    size_t n, pk, sk, sig;
    void (*keygen)(uint8_t *, uint8_t *, const uint8_t *);
    uint64_t (*sign)(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, const uint8_t *, const uint8_t *);
    uint64_t (*verify)(const uint8_t *, const uint8_t *, uint64_t, const uint8_t *, const uint8_t *);
} unit;

#define UNITV(set, var, feat, label, n_, pk_, sk_, sig_)                       \
    { label, #var, feat, n_, pk_, sk_, sig_,                                   \
      nirapod_slhdsa_jz_##set##_##var##__keygen,                               \
      nirapod_slhdsa_jz_##set##_##var##__sign,                                 \
      nirapod_slhdsa_jz_##set##_##var##__verify }

#define UNIT(set, label, n_, pk_, sk_, sig_) UNITV(set, scalar, 0u, label, n_, pk_, sk_, sig_)

/*
 * The negative-control binary is built from two units compiled without
 * stack zeroization (NIRAPOD_SLHDSA_STACK_CONTROL); the test binary from
 * every unit of the library. A unit whose CPU features this host lacks is
 * reported as skipped.
 */
#if defined(NIRAPOD_SLHDSA_STACK_CONTROL)
static const unit UNITS[] = {
    UNIT(sha2_128f,  "SLH-DSA-SHA2-128f",  16, 32, 64, 17088),
    UNIT(shake_128f, "SLH-DSA-SHAKE-128f", 16, 32, 64, 17088),
};
#else
static const unit UNITS[] = {
    UNIT(sha2_128s,  "SLH-DSA-SHA2-128s",  16, 32, 64, 7856),
    UNIT(shake_128s, "SLH-DSA-SHAKE-128s", 16, 32, 64, 7856),
    UNIT(sha2_128f,  "SLH-DSA-SHA2-128f",  16, 32, 64, 17088),
    UNIT(shake_128f, "SLH-DSA-SHAKE-128f", 16, 32, 64, 17088),
    UNIT(sha2_192s,  "SLH-DSA-SHA2-192s",  24, 48, 96, 16224),
    UNIT(shake_192s, "SLH-DSA-SHAKE-192s", 24, 48, 96, 16224),
    UNIT(sha2_192f,  "SLH-DSA-SHA2-192f",  24, 48, 96, 35664),
    UNIT(shake_192f, "SLH-DSA-SHAKE-192f", 24, 48, 96, 35664),
    UNIT(sha2_256s,  "SLH-DSA-SHA2-256s",  32, 64, 128, 29792),
    UNIT(shake_256s, "SLH-DSA-SHAKE-256s", 32, 64, 128, 29792),
    UNIT(sha2_256f,  "SLH-DSA-SHA2-256f",  32, 64, 128, 49856),
    UNIT(shake_256f, "SLH-DSA-SHAKE-256f", 32, 64, 128, 49856),
#if defined(__x86_64__)
    UNITV(sha2_128s,  shani, NIRAPOD_SLHDSA_CPU_SHANI, "SLH-DSA-SHA2-128s",  16, 32, 64, 7856),
    UNITV(shake_128s, avx2,  NIRAPOD_SLHDSA_CPU_AVX2,  "SLH-DSA-SHAKE-128s", 16, 32, 64, 7856),
    UNITV(sha2_128f,  shani, NIRAPOD_SLHDSA_CPU_SHANI, "SLH-DSA-SHA2-128f",  16, 32, 64, 17088),
    UNITV(shake_128f, avx2,  NIRAPOD_SLHDSA_CPU_AVX2,  "SLH-DSA-SHAKE-128f", 16, 32, 64, 17088),
    UNITV(sha2_192s,  shani, NIRAPOD_SLHDSA_CPU_SHANI, "SLH-DSA-SHA2-192s",  24, 48, 96, 16224),
    UNITV(shake_192s, avx2,  NIRAPOD_SLHDSA_CPU_AVX2,  "SLH-DSA-SHAKE-192s", 24, 48, 96, 16224),
    UNITV(sha2_192f,  shani, NIRAPOD_SLHDSA_CPU_SHANI, "SLH-DSA-SHA2-192f",  24, 48, 96, 35664),
    UNITV(shake_192f, avx2,  NIRAPOD_SLHDSA_CPU_AVX2,  "SLH-DSA-SHAKE-192f", 24, 48, 96, 35664),
    UNITV(sha2_256s,  shani, NIRAPOD_SLHDSA_CPU_SHANI, "SLH-DSA-SHA2-256s",  32, 64, 128, 29792),
    UNITV(shake_256s, avx2,  NIRAPOD_SLHDSA_CPU_AVX2,  "SLH-DSA-SHAKE-256s", 32, 64, 128, 29792),
    UNITV(sha2_256f,  shani, NIRAPOD_SLHDSA_CPU_SHANI, "SLH-DSA-SHA2-256f",  32, 64, 128, 49856),
    UNITV(shake_256f, avx2,  NIRAPOD_SLHDSA_CPU_AVX2,  "SLH-DSA-SHAKE-256f", 32, 64, 128, 49856),
#endif
};
#endif

/* The control binary links only its two scalar units, not the library. */
static unsigned host_features(void)
{
#if defined(NIRAPOD_SLHDSA_STACK_CONTROL)
    return 0;
#else
    return nirapod_slhdsa_cpu_features();
#endif
}

enum { OP_KEYGEN, OP_SIGN, OP_VERIFY };
static const char *OP_NAMES[] = { "keygen", "sign", "verify" };

typedef struct {
    size_t depth;
    size_t residue;
} probe_result;

static uint8_t pk[64], sk[128], seeds[96], sig[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static uint8_t domain[257], opt_rand[32], msg[64];

static uintptr_t stack_pointer(void)
{
    uintptr_t sp;
#if defined(__aarch64__)
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
#elif defined(__x86_64__)
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(sp));
#else
#error "test_stack.c: unsupported architecture"
#endif
    return sp;
}

/*
 * One painted call. noinline keeps the frame of this function, and so sp,
 * fixed while it paints, calls and scans; it makes a call, so the compiler
 * keeps nothing of its own below sp.
 */
__attribute__((noinline))
static probe_result probe(const unit *u, int op)
{
    volatile uint8_t *base;
    uintptr_t sp = stack_pointer();
    probe_result r = { 0, 0 };
    size_t i;

    base = (volatile uint8_t *)(sp - REGION);
    for (i = 0; i < REGION; i++) {
        base[i] = CANARY;
    }

    switch (op) {
    case OP_KEYGEN:
        u->keygen(pk, sk, seeds);
        break;
    case OP_SIGN:
        (void)u->sign(sig, msg, sizeof(msg), domain, sk, opt_rand);
        break;
    default:
        (void)u->verify(sig, msg, sizeof(msg), domain, pk);
        break;
    }

    for (i = 0; i < REGION; i++) {
        if (base[i] != CANARY) {
            r.depth = REGION - i;
            break;
        }
    }
    for (; i < REGION - TOP; i++) {
        if (base[i] != CANARY && base[i] != 0) {
            r.residue++;
        }
    }
    return r;
}

#if !defined(NIRAPOD_SLHDSA_STACK_CONTROL)

/*
 * Public-API operations of the secret scan, in an order in which each
 * verification checks the signature of the call before it. sign_given
 * runs through the testing library only.
 */
enum {
    API_KEYGEN, API_SIGN, API_SIGN_DET, API_VERIFY, API_HASH_SIGN, API_HASH_SIGN_DET,
    API_HASH_VERIFY, API_SIGN_GIVEN, API_LEAK_CONTROL, API_COUNT
};
static const char *API_NAMES[] = { "keygen", "sign", "sign_det", "verify", "hash_sign",
                                   "hash_sign_det", "hash_verify", "sign_given", "control" };

/* opt_rand given to sign_given: a pattern no other input contains. */
static uint8_t given_opt_rand[32];

/*
 * The deliberate leak of the scan's control: SK.prf copied into this
 * frame and left there. volatile keeps the copy.
 */
__attribute__((noinline))
static void leave_copy(const uint8_t *secret, size_t n)
{
    volatile uint8_t copy[64];
    size_t i;

    for (i = 0; i < n; i++) {
        copy[i] = secret[i];
    }
    /* A use of the copy, so that no compiler treats it as dead. */
    __asm__ __volatile__("" : : "r"(copy) : "memory");
}

/* 1 if some 8-byte window of secret[0 .. n) occurs in [base, base + len). */
static int contains_secret(const volatile uint8_t *base, size_t len, const uint8_t *secret, size_t n)
{
    size_t i, w, k;

    for (i = 0; i + 8 <= len; i++) {
        for (w = 0; w + 8 <= n; w++) {
            for (k = 0; k < 8 && base[i + k] == secret[w + k]; k++) {
            }
            if (k == 8) {
                return 1;
            }
        }
    }
    return 0;
}

typedef struct {
    int found;                  /* a secret window below the caller */
    size_t depth;               /* stack used by the call */
    nirapod_slhdsa_status status;
} secret_result;

/*
 * One painted public-API call on set. For keygen the seeds are those of
 * the key it returns; the other operations sign with the key in sk, and
 * sign_given also looks for given_opt_rand.
 */
__attribute__((noinline))
static secret_result secret_probe(nirapod_slhdsa_set set, int op)
{
    volatile uint8_t *base;
    uintptr_t sp = stack_pointer();
    size_t n = nirapod_slhdsa_public_key_bytes(set) / 2;
    size_t pk_len = 2 * n, sk_len = 4 * n, sig_len = nirapod_slhdsa_signature_bytes(set);
    secret_result r = { 0, 0, NIRAPOD_SLHDSA_OK };
    size_t i;

    /*
     * The whole region up to sp is painted and scanned: the C wrapper's
     * frames sit directly below sp. secret_probe makes calls, so no red
     * zone below sp is in use while it paints.
     */
    base = (volatile uint8_t *)(sp - REGION);
    for (i = 0; i < REGION; i++) {
        base[i] = CANARY;
    }

    switch (op) {
    case API_KEYGEN:
        r.status = nirapod_slhdsa_keygen(set, pk, pk_len, sk, sk_len);
        break;
    case API_SIGN:
        r.status = nirapod_slhdsa_sign(set, sig, sig_len, msg, sizeof(msg), msg, 3, sk, sk_len);
        break;
    case API_SIGN_DET:
        r.status = nirapod_slhdsa_sign_deterministic(set, sig, sig_len, msg, sizeof(msg), NULL, 0,
                                                     sk, sk_len);
        break;
    case API_VERIFY:
        r.status = nirapod_slhdsa_verify(set, sig, sig_len, msg, sizeof(msg), NULL, 0, pk, pk_len);
        break;
    case API_HASH_SIGN:
        r.status = nirapod_slhdsa_hash_sign(set, NIRAPOD_SLHDSA_PREHASH_SHA2_512, sig, sig_len,
                                            msg, sizeof(msg), msg, 3, sk, sk_len);
        break;
    case API_HASH_SIGN_DET:
        r.status = nirapod_slhdsa_hash_sign_deterministic(set, NIRAPOD_SLHDSA_PREHASH_SHA2_512, sig,
                                                          sig_len, msg, sizeof(msg), NULL, 0,
                                                          sk, sk_len);
        break;
    case API_HASH_VERIFY:
        r.status = nirapod_slhdsa_hash_verify(set, NIRAPOD_SLHDSA_PREHASH_SHA2_512, sig, sig_len,
                                              msg, sizeof(msg), NULL, 0, pk, pk_len);
        break;
    case API_SIGN_GIVEN:
        r.status = nirapod_slhdsa_testing_sign(NULL, set, 0, sig, sig_len, msg, sizeof(msg), NULL, 0,
                                               sk, sk_len, given_opt_rand, n);
        break;
    default:
        leave_copy(sk + n, n);
        break;
    }

    for (i = 0; i < REGION; i++) {
        if (base[i] != CANARY) {
            r.depth = REGION - i;
            break;
        }
    }
    r.found = contains_secret(base, REGION, sk, n) || contains_secret(base, REGION, sk + n, n) ||
              (op == API_SIGN_GIVEN && contains_secret(base, REGION, given_opt_rand, n));
    return r;
}

static const nirapod_slhdsa_set API_SETS[] = {
    NIRAPOD_SLHDSA_SHA2_128S, NIRAPOD_SLHDSA_SHAKE_128S, NIRAPOD_SLHDSA_SHA2_128F,
    NIRAPOD_SLHDSA_SHAKE_128F, NIRAPOD_SLHDSA_SHA2_192S, NIRAPOD_SLHDSA_SHAKE_192S,
    NIRAPOD_SLHDSA_SHA2_192F, NIRAPOD_SLHDSA_SHAKE_192F, NIRAPOD_SLHDSA_SHA2_256S,
    NIRAPOD_SLHDSA_SHAKE_256S, NIRAPOD_SLHDSA_SHA2_256F, NIRAPOD_SLHDSA_SHAKE_256F,
};

/*
 * The secret scan over every set, with the deepest stack of each public
 * function; returns the number of failures.
 */
static int secret_scan(void)
{
    size_t s, deepest[API_COUNT] = { 0 };
    const char *deepest_set[API_COUNT] = { NULL };
    int op, failures = 0;

    for (s = 0; s < sizeof(given_opt_rand); s++) {
        given_opt_rand[s] = (uint8_t)(0xc5 ^ (37 * s));
    }
    printf("\n%-20s %-14s %8s %s\n", "set", "api", "depth", "secrets found");
    for (s = 0; s < sizeof(API_SETS) / sizeof(API_SETS[0]); s++) {
        const char *name = nirapod_slhdsa_set_name(API_SETS[s]);

        for (op = API_KEYGEN; op < API_COUNT; op++) {
            secret_result r;

            r = secret_probe(API_SETS[s], op);
            printf("%-20s %-14s %8zu %s\n", name, API_NAMES[op], r.depth, r.found ? "yes" : "no");
            if (op == API_LEAK_CONTROL ? !r.found : r.found) {
                printf("FAIL %s %s: %s\n", name, API_NAMES[op],
                       r.found ? "secret left on the stack" : "control copy not detected");
                failures++;
            }
            if (r.status != NIRAPOD_SLHDSA_OK) {
                printf("FAIL %s %s: status %d\n", name, API_NAMES[op], r.status);
                failures++;
            }
            if (op != API_LEAK_CONTROL && r.depth > deepest[op]) {
                deepest[op] = r.depth;
                deepest_set[op] = name;
            }
        }
    }
    printf("\nDeepest stack of the public functions, C frames included:\n");
    for (op = API_KEYGEN; op < API_LEAK_CONTROL; op++) {
        if (deepest_set[op] != NULL) {
            printf("public-depth %-14s %8zu  %s\n", API_NAMES[op], deepest[op], deepest_set[op]);
        }
    }
    return failures;
}

#endif

int main(int argc, char **argv)
{
    int expect_residue = argc == 2 && strcmp(argv[1], "--expect-residue") == 0;
    size_t i;
    int failures = 0;

    for (i = 0; i < sizeof(seeds); i++) {
        seeds[i] = (uint8_t)(0x11 * i + 3);
    }
    memset(msg, 0x6d, sizeof(msg));
    memset(opt_rand, 0x42, sizeof(opt_rand));
    memset(domain, 0, sizeof(domain));

    {
        size_t total_residue = 0, u;
        int op;

        printf("%-20s %-7s %-7s %10s %8s\n", "set", "variant", "op", "depth", "residue");
        for (u = 0; u < sizeof(UNITS) / sizeof(UNITS[0]); u++) {
            if ((UNITS[u].features & ~host_features()) != 0) {
                printf("%-20s %-7s skipped: CPU feature missing\n", UNITS[u].name, UNITS[u].variant);
                continue;
            }
            for (op = OP_KEYGEN; op <= OP_VERIFY; op++) {
                probe_result r = probe(&UNITS[u], op);

                printf("%-20s %-7s %-7s %10zu %8zu\n", UNITS[u].name, UNITS[u].variant,
                       OP_NAMES[op], r.depth, r.residue);
                if (r.depth == 0 || r.depth > REGION - 4096) {
                    printf("FAIL %s %s: depth outside the probed region\n", UNITS[u].name,
                           OP_NAMES[op]);
                    failures++;
                }
                total_residue += r.residue;
                if (!expect_residue && r.residue != 0) {
                    printf("FAIL %s %s: %zu residue bytes\n", UNITS[u].name, OP_NAMES[op],
                           r.residue);
                    failures++;
                }
            }
            if (UNITS[u].verify(sig, msg, sizeof(msg), domain, pk) != 0) {
                printf("FAIL %s: signature from the probed call does not verify\n", UNITS[u].name);
                failures++;
            }
        }
        if (expect_residue && total_residue == 0) {
            printf("FAIL negative control: no residue detected without stack zeroization\n");
            failures++;
        }
    }

#if !defined(NIRAPOD_SLHDSA_STACK_CONTROL)
    failures += secret_scan();
#endif

    printf("test_stack%s: %s\n", expect_residue ? " (negative control)" : "",
           failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
