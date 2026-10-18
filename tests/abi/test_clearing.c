/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_clearing.c
 * ===============
 *
 * What a secret-reading call leaves behind, on the stack and in the
 * caller-saved registers, once it has returned: on the compiled library,
 * through the functions an application or a test calls.
 *
 * Method
 *
 *     A value is secret-dependent if it changes when only the secrets
 *     change. Each operation therefore runs twice, on two inputs that
 *     differ in their secrets alone (SK.seed, SK.prf and opt_rand) and
 *     agree in everything public (PK.seed, the message, the context, the
 *     pre-hash, the buffers and their addresses), from the same stack
 *     depth. Each run:
 *
 *         1. fills [sp - REGION, sp) below this test's frame with CANARY;
 *         2. runs the operation under call_and_dump of call_dump.h, which
 *            fills the registers with a pattern first and records the
 *            stack pointer; the library function is called through
 *            CAPTURED, which stores the caller-saved registers the moment
 *            it returns, before the test's own code runs;
 *         3. copies the region.
 *
 *     Every byte the operation could write, the region below the stack
 *     pointer at the call, and every stored register must be the same in
 *     both runs. Pointers, return addresses, lengths and public data are
 *     the same in both, so a byte that differs depends on a secret. The
 *     inputs sit at the same addresses in both runs, and the trampoline's
 *     pattern replaces whatever its caller left in the callee-saved
 *     registers, which the operation's frames save.
 *     Unlike a search for the secrets themselves (test_stack.c), this
 *     finds values derived from them as well: WOTS+ chain values, FORS
 *     secrets, hash states, in the C frames as in the Jasmin frames.
 *
 *     The first time an operation runs, one more run before the two,
 *     discarded, takes first-call effects out of the comparison: a lazily
 *     bound symbol makes the dynamic linker run on the stack during the
 *     first call only.
 *
 *     PK.root, the public key and the signature are computed from the
 *     secrets and differ between the runs as well. They are public, but a
 *     copy left behind in the region would still count: the library
 *     leaves none, and the check stays simple.
 *
 *     A comparison sees what differs, not everything that depends on a
 *     secret: a secret-dependent value that happens to be equal for the
 *     two inputs passes. For a byte derived by hashing that has
 *     probability 2^-8, and 2^-64 for a register.
 *
 * Operations
 *
 *     testing library (test_clearing): for every set and every variant
 *     this CPU runs, key generation from given seeds and from the
 *     entropy source; signing with a given opt_rand, deterministic,
 *     hedged from the entropy source, with a pre-hash; the same with the
 *     fault check skipped, so that the frame of the signing export is not
 *     overwritten by the check; signing with a key whose PK.root is wrong,
 *     whose signature the check withholds; and the internal signing
 *     function of FIPS 205 section 9, with and without the check.
 *
 *     application library (test_clearing_production): key generation,
 *     hedged, deterministic and pre-hash signing, on the variant the host
 *     dispatches to. The keys come from the library's key generation, so
 *     the two inputs differ in PK.seed as well as in the secrets, and so
 *     does every value the entropy source provides: a difference there
 *     could also come from public data, which makes these runs stricter,
 *     not weaker.
 *
 *     Each build also runs controls on one set: signing followed by a
 *     function of this test that leaves 16 bytes of SK.prf in its frame,
 *     and functions called through CAPTURED that leave bytes of SK.prf in
 *     one register each (AArch64 x8, x9 and v16, and x18 on Linux; x86-64
 *     r11, r10 and xmm15) and return to a wrapper that then stores its
 *     status, as the operations do. Each must be found, or the test fails.
 *
 * Negative controls (--expect-residue)
 *
 *     test_clearing_skip   the testing library with capi/clear.c replaced
 *                          by clear_skip.c, which clears nothing: on the
 *                          two 128f sets, every operation must leave
 *                          residue, and the run as a whole residue on the
 *                          stack and in registers
 *     test_clearing_nozero two units compiled without stack zeroization,
 *                          their exports called directly: every operation
 *                          must leave residue on the stack
 *
 * Not covered: the flags; on macOS x18, the platform's register, which
 * the library does not use; on x86-64 CPUs with AVX-512, the upper halves
 * of the zmm registers, zmm16-zmm31 and the mask registers. The Jasmin
 * code does not use those, but the C library's memory routines may, and
 * the testing library copies the seeds it is given with memcpy: a copy
 * left in zmm16-zmm31 there would not be seen, and
 * nirapod_slhdsa_clear_registers does not clear them. Also not covered:
 * memory outside the region, and copies the operating system makes.
 * Reading below the stack pointer is outside the C abstract machine: as
 * in test_stack.c, the accesses are volatile byte accesses with no call in
 * between, and the test measures the compiled program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nirapod_slhdsa.h"
#if defined(NIRAPOD_SLHDSA_CLEARING_NOZERO)
#include "jasmin.h"
#elif !defined(NIRAPOD_SLHDSA_CLEARING_PRODUCTION)
#include "nirapod_slhdsa_testing.h"
#endif

#include "call_dump.h"

#define REGION (512u * 1024u)
#define CANARY 0x5Au

#define MAX_N 32

/* One input of an operation: the secrets of one run. */
typedef struct {
    uint8_t pk[2 * MAX_N];
    uint8_t sk[4 * MAX_N];
    uint8_t seeds[3 * MAX_N];   /* SK.seed || SK.prf || PK.seed */
    uint8_t opt_rand[MAX_N];
} input;

/* What one run leaves: the region below the caller and the registers. */
typedef struct {
    uint8_t stack[REGION];
    dump regs;
    size_t depth;
    size_t limit;   /* stack[0 .. limit) lies below the stack pointer at the call */
} snapshot;

static snapshot snap[2];
static input inputs[2];
static int failures;

/*
 * The operation the trampoline runs, and what it reads. Each run copies
 * its input into live first, so that both runs pass the same addresses:
 * a pointer to the secret key that differed between them would differ in
 * the frames that hold it.
 */
static input live;
static const input *const cur = &live;
static size_t cur_n;
static uint8_t out_pk[2 * MAX_N], out_sk[4 * MAX_N];
static uint8_t sig[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];
static const uint8_t msg[48] = "test_clearing: the message both runs sign";
static int cur_status;
#if !defined(NIRAPOD_SLHDSA_CLEARING_NOZERO)
static const uint8_t ctx[3] = { 'c', 't', 'x' };
#endif

static uintptr_t stack_pointer(void)
{
    uintptr_t sp;
#if defined(__aarch64__)
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
#else
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(sp));
#endif
    return sp;
}

/*
 * Where the run in progress stores the registers, and where it copies
 * the region afterwards. A pointer that is live across the call sits in a
 * callee-saved register, which the frames below save: the trampoline's
 * dump is therefore one buffer for both runs, and the snapshot is named
 * by a global read only after the call.
 */
static dump live_regs;
static snapshot *out;

/*
 * One painted run of fn into *out. noinline keeps sp fixed while this
 * function paints, calls and copies; the copy loop makes no call.
 */
__attribute__((noinline))
static void run_painted(void (*fn)(void))
{
    volatile uint8_t *base;
    uintptr_t sp = stack_pointer();
    snapshot *s;
    size_t i;

    base = (volatile uint8_t *)(sp - REGION);
    for (i = 0; i < REGION; i++) {
        base[i] = CANARY;
    }

    call_and_dump(fn, &live_regs);
    s = out;
    s->limit = REGION - (size_t)(sp - (uintptr_t)live_regs.sp);

    s->depth = 0;
    for (i = 0; i < REGION; i++) {
        s->stack[i] = base[i];
        if (s->depth == 0 && base[i] != CANARY) {
            s->depth = REGION - i;
        }
    }
    s->regs = live_regs;
}

typedef struct {
    size_t stack;       /* region bytes that differ between the runs */
    size_t regs;        /* register bytes that differ */
    size_t first;       /* distance below sp of the deepest differing byte */
    size_t depth;       /* stack used by the call */
} residue;

/*
 * Run fn on pair[1] and pair[0], after a discarded run on pair[0] when
 * *warm is still 0.
 */
static residue compare_runs(void (*fn)(void), const input pair[2], int *warm)
{
    residue r = { 0, 0, 0, 0 };
    const uint8_t *a, *b;
    size_t i;

    if (!*warm) {
        live = pair[0];
        out = &snap[0];
        run_painted(fn);
        *warm = 1;
    }
    live = pair[1];
    out = &snap[1];
    run_painted(fn);
    live = pair[0];
    out = &snap[0];
    run_painted(fn);

    if (snap[0].limit != snap[1].limit) {
        printf("FAIL the two runs called the operation from different stack pointers\n");
        failures++;
    }
    for (i = 0; i < snap[0].limit && i < snap[1].limit; i++) {
        if (snap[0].stack[i] != snap[1].stack[i]) {
            if (r.stack == 0) {
                r.first = REGION - i;
            }
            r.stack++;
        }
    }
    a = (const uint8_t *)&snap[0].regs;
    b = (const uint8_t *)&snap[1].regs;
    for (i = 0; i < sizeof(dump); i++) {
        r.regs += a[i] != b[i];
    }
    r.depth = snap[0].depth > snap[1].depth ? snap[0].depth : snap[1].depth;
    if (r.depth > REGION - 4096) {
        printf("FAIL the operation used %zu bytes of stack, too close to the %u probed\n",
               r.depth, REGION);
        failures++;
    }
    return r;
}

#if !defined(NIRAPOD_SLHDSA_CLEARING_PRODUCTION)
/* Fill the secrets of the two inputs; the public PK.seed is shared. */
static void make_secrets(size_t n)
{
    size_t i;
    int k;

    for (k = 0; k < 2; k++) {
        for (i = 0; i < 2 * n; i++) {
            inputs[k].seeds[i] = (uint8_t)(0x3b * i + 0x71 * k + 1);
        }
        for (i = 0; i < n; i++) {
            inputs[k].seeds[2 * n + i] = (uint8_t)(0xe1 ^ i);
            inputs[k].opt_rand[i] = (uint8_t)(0x95 * i + 0x2d * k + 7);
        }
    }
}

#endif

#if !defined(NIRAPOD_SLHDSA_CLEARING_NOZERO)
/*
 * Control of the stack scan: a copy of SK.prf left in a frame of this
 * test. volatile keeps the copy. The register controls are the
 * call_dump_leave_* functions of call_dump.h.
 */
__attribute__((noinline))
static void leave_copy(const uint8_t *secret)
{
    volatile uint8_t copy[16];
    size_t i;

    for (i = 0; i < sizeof(copy); i++) {
        copy[i] = secret[i];
    }
    __asm__ __volatile__("" : : "r"(copy) : "memory");
}

static void op_control_gpr(void)
{
    cur_status = CAPTURED(call_dump_leave_gpr)(cur->sk + cur_n);
}

static void op_control_gpr2(void)
{
    cur_status = CAPTURED(call_dump_leave_gpr2)(cur->sk + cur_n);
}

static void op_control_vec(void)
{
    cur_status = CAPTURED(call_dump_leave_vec)(cur->sk + cur_n);
}

#if defined(__aarch64__) && CALL_DUMP_X18
static void op_control_x18(void)
{
    cur_status = CAPTURED(call_dump_leave_x18)(cur->sk + cur_n);
}
#define CONTROL_X18_NAME "control_x18"
#endif

#if defined(__aarch64__)
#define CONTROL_GPR_NAME "control_x8"
#define CONTROL_GPR2_NAME "control_x9"
#define CONTROL_VEC_NAME "control_v16"
#else
#define CONTROL_GPR_NAME "control_r11"
#define CONTROL_GPR2_NAME "control_r10"
#define CONTROL_VEC_NAME "control_xmm15"
#endif
#endif

#if defined(NIRAPOD_SLHDSA_CLEARING_NOZERO)

/* --------------------------------------------------------------------
 * The exports of the two units without stack zeroization, called
 * directly.
 * ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    size_t n, sig;
    void (*keygen)(uint8_t *, uint8_t *, const uint8_t *);
    uint64_t (*sign)(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, const uint8_t *,
                     const uint8_t *);
    void (*sign_internal)(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, const uint8_t *);
} unit;

#define UNIT(set, label, n_, sig_)                                             \
    { label, n_, sig_, nirapod_slhdsa_jz_##set##_scalar__keygen,                \
      nirapod_slhdsa_jz_##set##_scalar__sign,                                  \
      nirapod_slhdsa_jz_##set##_scalar__sign_internal }

static const unit UNITS[] = {
    UNIT(sha2_128f,  "SLH-DSA-SHA2-128f",  16, 17088),
    UNIT(shake_128f, "SLH-DSA-SHAKE-128f", 16, 17088),
};

static const unit *cur_unit;
static uint8_t domain[NIRAPOD_SLHDSA_JZ_DOMAIN_BYTES];

static void op_keygen(void)
{
    CAPTURED(cur_unit->keygen)(out_pk, out_sk, cur->seeds);
}

static void op_sign(void)
{
    cur_status = (int)CAPTURED(cur_unit->sign)(sig, msg, sizeof(msg), domain, cur->sk,
                                               cur->opt_rand);
}

static void op_sign_internal(void)
{
    CAPTURED(cur_unit->sign_internal)(sig, msg, sizeof(msg), cur->sk, cur->opt_rand);
}

typedef struct {
    const char *name;
    void (*fn)(void);
} op;

static const op OPS[] = {
    { "keygen", op_keygen }, { "sign", op_sign }, { "sign_internal", op_sign_internal },
};

static void make_keys(const unit *u)
{
    int k;

    make_secrets(u->n);
    for (k = 0; k < 2; k++) {
        u->keygen(inputs[k].pk, inputs[k].sk, inputs[k].seeds);
    }
}

#elif defined(NIRAPOD_SLHDSA_CLEARING_PRODUCTION)

/* --------------------------------------------------------------------
 * The application library, through the public functions.
 * ------------------------------------------------------------------ */

static nirapod_slhdsa_set cur_set;

static void op_keygen(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_keygen)(cur_set, out_pk, 2 * cur_n, out_sk, 4 * cur_n);
}

static void op_sign(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_sign)(cur_set, sig,
                                               nirapod_slhdsa_signature_bytes(cur_set),
                                               msg, sizeof(msg), ctx, sizeof(ctx),
                                               cur->sk, 4 * cur_n);
}

static void op_sign_det(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_sign_deterministic)(cur_set, sig,
                                                             nirapod_slhdsa_signature_bytes(cur_set),
                                                             msg, sizeof(msg), ctx, sizeof(ctx),
                                                             cur->sk, 4 * cur_n);
}

static void op_hash_sign(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_hash_sign)(cur_set, NIRAPOD_SLHDSA_PREHASH_SHA2_512, sig,
                                                    nirapod_slhdsa_signature_bytes(cur_set),
                                                    msg, sizeof(msg), ctx, sizeof(ctx),
                                                    cur->sk, 4 * cur_n);
}

static void op_hash_sign_det(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_hash_sign_deterministic)(
        cur_set, NIRAPOD_SLHDSA_PREHASH_SHAKE256, sig, nirapod_slhdsa_signature_bytes(cur_set),
        msg, sizeof(msg), ctx, sizeof(ctx), cur->sk, 4 * cur_n);
}

static void op_control_stack(void)
{
    op_sign_det();
    leave_copy(cur->sk + cur_n);
}

typedef struct {
    const char *name;
    void (*fn)(void);
    int control;
} op;

static const op OPS[] = {
    { "keygen", op_keygen, 0 },
    { "sign", op_sign, 0 },
    { "sign_det", op_sign_det, 0 },
    { "hash_sign", op_hash_sign, 0 },
    { "hash_sign_det", op_hash_sign_det, 0 },
    { "control_stack", op_control_stack, 1 },
    { CONTROL_GPR_NAME, op_control_gpr, 1 },
    { CONTROL_GPR2_NAME, op_control_gpr2, 1 },
    { CONTROL_VEC_NAME, op_control_vec, 1 },
#if defined(CONTROL_X18_NAME)
    { CONTROL_X18_NAME, op_control_x18, 1 },
#endif
};

static int make_keys(nirapod_slhdsa_set set)
{
    int k;

    for (k = 0; k < 2; k++) {
        if (nirapod_slhdsa_keygen(set, inputs[k].pk, 2 * cur_n, inputs[k].sk, 4 * cur_n) !=
            NIRAPOD_SLHDSA_OK) {
            return 0;
        }
    }
    return 1;
}

#else

/* --------------------------------------------------------------------
 * The testing library: every variant, the internal functions, the fault
 * check on and off.
 * ------------------------------------------------------------------ */

static nirapod_slhdsa_set cur_set;
static nirapod_slhdsa_testing_config cur_config;

/* The entropy source of the configuration: the seeds, then opt_rand. */
static int given_entropy(void *state, uint8_t *buf, size_t len)
{
    (void)state;
    if (len == 3 * cur_n) {
        memcpy(buf, cur->seeds, len);
    } else if (len == cur_n) {
        memcpy(buf, cur->opt_rand, len);
    } else {
        return -1;
    }
    return 0;
}

static unsigned prehash_of(nirapod_slhdsa_set set)
{
    const char *name = nirapod_slhdsa_set_name(set);

    return strstr(name, "SHAKE") != NULL ? NIRAPOD_SLHDSA_PREHASH_SHAKE256
                                         : NIRAPOD_SLHDSA_PREHASH_SHA2_512;
}

static void op_keygen_internal(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_testing_keygen_internal)(
        &cur_config, cur_set, out_pk, 2 * cur_n, out_sk, 4 * cur_n, cur->seeds,
        cur->seeds + cur_n, cur->seeds + 2 * cur_n, cur_n);
}

static void op_keygen(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_testing_keygen)(&cur_config, cur_set, out_pk, 2 * cur_n,
                                                         out_sk, 4 * cur_n);
}

static void sign_with(unsigned prehash, const uint8_t *opt_rand)
{
    cur_status = CAPTURED(nirapod_slhdsa_testing_sign)(&cur_config, cur_set, prehash, sig,
                                                       nirapod_slhdsa_signature_bytes(cur_set),
                                                       msg, sizeof(msg), ctx, sizeof(ctx),
                                                       cur->sk, 4 * cur_n,
                                                       opt_rand, opt_rand != NULL ? cur_n : 0);
}

static void op_sign(void)
{
    sign_with(0, cur->opt_rand);
}

static void op_sign_det(void)
{
    sign_with(0, NULL);
}

static void op_sign_hedged(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_testing_sign_hedged)(
        &cur_config, cur_set, 0, sig, nirapod_slhdsa_signature_bytes(cur_set),
        msg, sizeof(msg), ctx, sizeof(ctx), cur->sk, 4 * cur_n);
}

static void op_hash_sign(void)
{
    sign_with(prehash_of(cur_set), cur->opt_rand);
}

static void op_sign_internal(void)
{
    cur_status = CAPTURED(nirapod_slhdsa_testing_sign_internal)(
        &cur_config, cur_set, sig, nirapod_slhdsa_signature_bytes(cur_set),
        msg, sizeof(msg), cur->sk, 4 * cur_n, cur->opt_rand, cur_n);
}

/* The secret keys with one bit of PK.root flipped: the check fails. */
static input withheld[2];

static void op_control_stack(void)
{
    op_sign();
    leave_copy(cur->sk + cur_n);
}

/*
 * skip: run with the fault check switched off. bad_root: sign with the
 * keys of withheld. status: what the call must return.
 */
typedef struct {
    const char *name;
    void (*fn)(void);
    int skip;
    int bad_root;
    nirapod_slhdsa_status status;
    int control;
} op;

static const op OPS[] = {
    { "keygen_internal", op_keygen_internal, 0, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "keygen", op_keygen, 0, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "sign", op_sign, 0, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "sign_det", op_sign_det, 0, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "sign_hedged", op_sign_hedged, 0, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "hash_sign", op_hash_sign, 0, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "sign_nocheck", op_sign, 1, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "sign_withheld", op_sign, 0, 1, NIRAPOD_SLHDSA_ERROR_FAULT, 0 },
    { "sign_internal", op_sign_internal, 0, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "sign_internal_nocheck", op_sign_internal, 1, 0, NIRAPOD_SLHDSA_OK, 0 },
    { "control_stack", op_control_stack, 0, 0, NIRAPOD_SLHDSA_OK, 1 },
    { CONTROL_GPR_NAME, op_control_gpr, 0, 0, NIRAPOD_SLHDSA_OK, 1 },
    { CONTROL_GPR2_NAME, op_control_gpr2, 0, 0, NIRAPOD_SLHDSA_OK, 1 },
    { CONTROL_VEC_NAME, op_control_vec, 0, 0, NIRAPOD_SLHDSA_OK, 1 },
#if defined(CONTROL_X18_NAME)
    { CONTROL_X18_NAME, op_control_x18, 0, 0, NIRAPOD_SLHDSA_OK, 1 },
#endif
};

static int make_keys(nirapod_slhdsa_set set)
{
    nirapod_slhdsa_testing_config config = { NULL, NULL, NULL, 0 };
    int k;

    make_secrets(cur_n);
    for (k = 0; k < 2; k++) {
        if (nirapod_slhdsa_testing_keygen_internal(&config, set, inputs[k].pk, 2 * cur_n,
                                                   inputs[k].sk, 4 * cur_n, inputs[k].seeds,
                                                   inputs[k].seeds + cur_n,
                                                   inputs[k].seeds + 2 * cur_n, cur_n) !=
            NIRAPOD_SLHDSA_OK) {
            return 0;
        }
        withheld[k] = inputs[k];
        withheld[k].sk[4 * cur_n - 1] ^= 1;
    }
    return 1;
}

#endif

/* --------------------------------------------------------------------
 * Driver
 * ------------------------------------------------------------------ */

static int expect_residue;
static int warmed[16];
static size_t control_stack_seen, control_regs_seen;

/*
 * Judge one operation's residue. A control operation must show residue;
 * in a negative-control build every operation must.
 */
static void judge(const char *set, const char *variant, const char *name, residue r,
                  int control, int status_ok)
{
    int found = r.stack != 0 || r.regs != 0;

    printf("%-20s %-7s %-22s %8zu %8zu %6zu%s\n", set, variant, name, r.depth, r.stack, r.regs,
           status_ok ? "" : "  unexpected status");
    if (!status_ok) {
        failures++;
    }
    if (expect_residue) {
        control_stack_seen += r.stack != 0;
        control_regs_seen += r.regs != 0;
        if (!found) {
            printf("FAIL %s %s %s: no residue without clearing\n", set, variant, name);
            failures++;
        }
    } else if (control) {
        if (!found) {
            printf("FAIL %s %s %s: control copy not detected\n", set, variant, name);
            failures++;
        }
    } else if (found) {
        printf("FAIL %s %s %s: %zu stack bytes (deepest %zu below the caller) and %zu register "
               "bytes depend on the secrets\n", set, variant, name, r.stack, r.first, r.regs);
        failures++;
    }
}

static void print_header(void)
{
    printf("%-20s %-7s %-22s %8s %8s %6s\n", "set", "variant", "operation", "depth", "stack",
           "regs");
}

#if defined(NIRAPOD_SLHDSA_CLEARING_NOZERO)

static void run_all(void)
{
    size_t u, o;

    print_header();
    memset(domain, 0, sizeof(domain));
    for (u = 0; u < sizeof(UNITS) / sizeof(UNITS[0]); u++) {
        cur_unit = &UNITS[u];
        cur_n = UNITS[u].n;
        make_keys(&UNITS[u]);
        for (o = 0; o < sizeof(OPS) / sizeof(OPS[0]); o++) {
            residue r = compare_runs(OPS[o].fn, inputs, &warmed[o]);

            /* Only the stack counts: these exports clear no register. */
            r.regs = 0;
            judge(UNITS[u].name, "scalar", OPS[o].name, r, 0,
                  OPS[o].fn != op_sign || cur_status == 0);
        }
    }
}

#else

static const nirapod_slhdsa_set SETS[] = {
    NIRAPOD_SLHDSA_SHA2_128S, NIRAPOD_SLHDSA_SHAKE_128S, NIRAPOD_SLHDSA_SHA2_128F,
    NIRAPOD_SLHDSA_SHAKE_128F, NIRAPOD_SLHDSA_SHA2_192S, NIRAPOD_SLHDSA_SHAKE_192S,
    NIRAPOD_SLHDSA_SHA2_192F, NIRAPOD_SLHDSA_SHAKE_192F, NIRAPOD_SLHDSA_SHA2_256S,
    NIRAPOD_SLHDSA_SHAKE_256S, NIRAPOD_SLHDSA_SHA2_256F, NIRAPOD_SLHDSA_SHAKE_256F,
};

/*
 * The controls of the scan run on the first set only, and the negative
 * control on the two 128f sets, as the other negative controls of
 * tests/abi do: showing that residue is found needs no more.
 */
static int skip_op(size_t s, const op *o)
{
    if (expect_residue) {
        return o->control || (SETS[s] != NIRAPOD_SLHDSA_SHA2_128F &&
                              SETS[s] != NIRAPOD_SLHDSA_SHAKE_128F);
    }
    return o->control && s != 0;
}

#if defined(NIRAPOD_SLHDSA_CLEARING_PRODUCTION)

static void run_all(void)
{
    size_t s, o;

    print_header();
    for (s = 0; s < sizeof(SETS) / sizeof(SETS[0]); s++) {
        const char *name = nirapod_slhdsa_set_name(SETS[s]);

        cur_set = SETS[s];
        cur_n = nirapod_slhdsa_public_key_bytes(SETS[s]) / 2;
        if (!make_keys(SETS[s])) {
            printf("FAIL %s: key generation\n", name);
            failures++;
            continue;
        }
        for (o = 0; o < sizeof(OPS) / sizeof(OPS[0]); o++) {
            residue r;

            if (skip_op(s, &OPS[o])) {
                continue;
            }
            r = compare_runs(OPS[o].fn, inputs, &warmed[o]);
            judge(name, "host", OPS[o].name, r, OPS[o].control, cur_status == NIRAPOD_SLHDSA_OK);
        }
    }
}

#else

static void run_all(void)
{
    size_t s, v, o;

    print_header();
    for (s = 0; s < sizeof(SETS) / sizeof(SETS[0]); s++) {
        const char *name = nirapod_slhdsa_set_name(SETS[s]);

        cur_set = SETS[s];
        cur_n = nirapod_slhdsa_public_key_bytes(SETS[s]) / 2;
        if (!make_keys(SETS[s])) {
            printf("FAIL %s: key generation\n", name);
            failures++;
            continue;
        }
        for (v = 0; v < nirapod_slhdsa_testing_variant_count(SETS[s]); v++) {
            const char *variant = nirapod_slhdsa_testing_variant_name(SETS[s], v);

            if (!nirapod_slhdsa_testing_variant_supported(SETS[s], variant)) {
                printf("%-20s %-7s skipped: CPU feature missing\n", name, variant);
                continue;
            }
            for (o = 0; o < sizeof(OPS) / sizeof(OPS[0]); o++) {
                residue r;

                if (skip_op(s, &OPS[o]) || (OPS[o].control && v != 0)) {
                    continue;
                }
                cur_config.variant = variant;
                cur_config.entropy = given_entropy;
                cur_config.entropy_state = NULL;
                cur_config.skip_fault_check = OPS[o].skip;
                r = compare_runs(OPS[o].fn, OPS[o].bad_root ? withheld : inputs,
                                 &warmed[o]);
                judge(name, variant, OPS[o].name, r, OPS[o].control,
                      cur_status == (int)OPS[o].status);
            }
        }
    }
}

#endif
#endif

int main(int argc, char **argv)
{
    expect_residue = argc == 2 && strcmp(argv[1], "--expect-residue") == 0;

#if defined(__x86_64__)
    wide_vectors = __builtin_cpu_supports("avx");
#endif

    run_all();

    if (expect_residue && (control_stack_seen == 0 || control_regs_seen == 0)) {
#if defined(NIRAPOD_SLHDSA_CLEARING_NOZERO)
        if (control_stack_seen == 0) {
            printf("FAIL negative control: no stack residue without stack zeroization\n");
            failures++;
        }
#else
        printf("FAIL negative control: residue on the stack in %zu and in registers in %zu "
               "operations, both must be non-zero\n", control_stack_seen, control_regs_seen);
        failures++;
#endif
    }

    printf("test_clearing%s: %s (%d failures)\n",
#if defined(NIRAPOD_SLHDSA_CLEARING_PRODUCTION)
           " (application library)",
#elif defined(NIRAPOD_SLHDSA_CLEARING_NOZERO)
           expect_residue ? " (negative control, no stack zeroization)" : " (no stack zeroization)",
#else
           expect_residue ? " (negative control, clearing skipped)" : "",
#endif
           failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
