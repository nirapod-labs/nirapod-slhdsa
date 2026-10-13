/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_registers.c
 * ================
 *
 * Register state after the library returns.
 *
 * Method
 *
 *     A trampoline in inline assembly fills the caller-saved registers
 *     with a pattern, calls a function of this test with no arguments,
 *     and stores every caller-saved register to memory the moment control
 *     comes back, before any compiler-generated code runs.
 *
 *     1. mechanism   the function is nirapod_slhdsa_clear_registers: every
 *                    register it promises to zero must be zero (clear.c
 *                    lists them; on AArch64 the low halves of v8-v15 must
 *                    hold the pattern again, being callee-saved)
 *     2. wiring      the function runs an operation of the library (key
 *                    generation, deterministic, hedged and pre-hash
 *                    signing, internal signing) on a record whose exports
 *                    are stubs: each stub loads a marker into every
 *                    register a callee may change, the return-value
 *                    register aside where it must return 0, and returns.
 *                    No register may hold the marker when the operation
 *                    returns. A stub called directly must leave it, or the
 *                    test fails (the control)
 *     3. end to end  the function runs keygen, signing or hash signing
 *                    through the public API: no register may hold 8
 *                    consecutive bytes of SK.seed or SK.prf
 *     4. control     the function loads 8 bytes of SK.prf into a
 *                    caller-saved register and returns: check 3 must find
 *                    them, otherwise the test fails
 *
 *     5. timing      AArch64 with FEAT_DIT: keygen, signing and the check
 *                    of the new signature run with PSTATE.DIT set, read by
 *                    stub exports; verification runs with the caller's
 *                    value; every call leaves the caller's DIT as it found
 *                    it, set or clear
 *     6. AVX state   x86-64 where XGETBV reports which register state is
 *                    in use: after verification and signing on a variant
 *                    that uses AVX, the upper halves of the ymm registers
 *                    are in their initial state (VZEROUPPER, VZEROALL)
 *
 * Check 2 is the one that shows the clearing runs after each export: the
 * Jasmin exports happen not to return with the seeds in registers, so
 * check 3 passes with or without it, and covers copies of the seeds only,
 * not values derived from them. The flags and, on x86-64, the upper halves
 * of the zmm registers and the registers above 15 of AVX-512 CPUs are not
 * inspected; the library does not use them.
 */

#include <stdio.h>
#include <string.h>

#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#endif

#include "internal.h"
#include "nirapod_slhdsa.h"
#include "nirapod_slhdsa_testing.h"

#if defined(__aarch64__)
#define NGPR 18           /* x0-x17 */
#define NVEC 32           /* v0-v31, 16 bytes each */
#define VEC_BYTES 16
#elif defined(__x86_64__)
#define NGPR 9            /* rax rcx rdx rsi rdi r8 r9 r10 r11 */
#define NVEC 16           /* ymm0-ymm15, 32 bytes each (16 without AVX) */
#define VEC_BYTES 32
#else
#error "test_registers.c: unsupported architecture"
#endif

typedef struct {
    uint64_t gpr[NGPR];
    uint8_t vec[NVEC][VEC_BYTES];
} dump;

#define PATTERN 0xA5u

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

#if defined(__x86_64__)
/* Whether the trampoline stores full ymm registers (x86-64 with AVX). */
static int wide_vectors;
#endif

/*
 * Call fn() with the caller-saved registers pre-filled with PATTERN and
 * store them to *d on return. Everything the call can change is declared
 * clobbered, so the compiler keeps nothing live in those registers.
 */
__attribute__((noinline))
static void call_and_dump(void (*fn)(void), dump *d)
{
#if defined(__aarch64__)
    register void (*f)(void) __asm__("x20") = fn;
    register dump *p __asm__("x19") = d;

    __asm__ __volatile__(
        "mov x0, #0xa5a5\n\t"
        "orr x0, x0, x0, lsl #16\n\t"
        "orr x0, x0, x0, lsl #32\n\t"
        "mov x1, x0\n\t"  "mov x2, x0\n\t"  "mov x3, x0\n\t"  "mov x4, x0\n\t"
        "mov x5, x0\n\t"  "mov x6, x0\n\t"  "mov x7, x0\n\t"  "mov x8, x0\n\t"
        "mov x9, x0\n\t"  "mov x10, x0\n\t" "mov x11, x0\n\t" "mov x12, x0\n\t"
        "mov x13, x0\n\t" "mov x14, x0\n\t" "mov x15, x0\n\t" "mov x16, x0\n\t"
        "mov x17, x0\n\t"
        "movi v0.16b, #0xa5\n\t"
        "mov v1.16b, v0.16b\n\t"  "mov v2.16b, v0.16b\n\t"  "mov v3.16b, v0.16b\n\t"
        "mov v4.16b, v0.16b\n\t"  "mov v5.16b, v0.16b\n\t"  "mov v6.16b, v0.16b\n\t"
        "mov v7.16b, v0.16b\n\t"  "mov v8.16b, v0.16b\n\t"  "mov v9.16b, v0.16b\n\t"
        "mov v10.16b, v0.16b\n\t" "mov v11.16b, v0.16b\n\t" "mov v12.16b, v0.16b\n\t"
        "mov v13.16b, v0.16b\n\t" "mov v14.16b, v0.16b\n\t" "mov v15.16b, v0.16b\n\t"
        "mov v16.16b, v0.16b\n\t" "mov v17.16b, v0.16b\n\t" "mov v18.16b, v0.16b\n\t"
        "mov v19.16b, v0.16b\n\t" "mov v20.16b, v0.16b\n\t" "mov v21.16b, v0.16b\n\t"
        "mov v22.16b, v0.16b\n\t" "mov v23.16b, v0.16b\n\t" "mov v24.16b, v0.16b\n\t"
        "mov v25.16b, v0.16b\n\t" "mov v26.16b, v0.16b\n\t" "mov v27.16b, v0.16b\n\t"
        "mov v28.16b, v0.16b\n\t" "mov v29.16b, v0.16b\n\t" "mov v30.16b, v0.16b\n\t"
        "mov v31.16b, v0.16b\n\t"
        "blr x20\n\t"
        "stp x0, x1, [x19, #0]\n\t"     "stp x2, x3, [x19, #16]\n\t"
        "stp x4, x5, [x19, #32]\n\t"    "stp x6, x7, [x19, #48]\n\t"
        "stp x8, x9, [x19, #64]\n\t"    "stp x10, x11, [x19, #80]\n\t"
        "stp x12, x13, [x19, #96]\n\t"  "stp x14, x15, [x19, #112]\n\t"
        "stp x16, x17, [x19, #128]\n\t"
        "stp q0, q1, [x19, #144]\n\t"   "stp q2, q3, [x19, #176]\n\t"
        "stp q4, q5, [x19, #208]\n\t"   "stp q6, q7, [x19, #240]\n\t"
        "stp q8, q9, [x19, #272]\n\t"   "stp q10, q11, [x19, #304]\n\t"
        "stp q12, q13, [x19, #336]\n\t" "stp q14, q15, [x19, #368]\n\t"
        "stp q16, q17, [x19, #400]\n\t" "stp q18, q19, [x19, #432]\n\t"
        "stp q20, q21, [x19, #464]\n\t" "stp q22, q23, [x19, #496]\n\t"
        "stp q24, q25, [x19, #528]\n\t" "stp q26, q27, [x19, #560]\n\t"
        "stp q28, q29, [x19, #592]\n\t" "stp q30, q31, [x19, #624]"
        : "+r"(f), "+r"(p)
        :
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
          "x12", "x13", "x14", "x15", "x16", "x17", "x30",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11",
          "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22",
          "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
          "memory", "cc");
#else
    /*
     * rbx holds d and r12 the caller's rsp across the call; the stack is
     * moved below the red zone and aligned to 32 bytes first.
     */
    if (wide_vectors) {
        __asm__ __volatile__(
            "movq %%rsp, %%r12\n\t"
            "subq $256, %%rsp\n\t"
            "andq $-32, %%rsp\n\t"
            "movq $0xa5a5a5a5a5a5a5a5, %%rcx\n\t"
            "movq %%rcx, %%rdx\n\t" "movq %%rcx, %%rsi\n\t" "movq %%rcx, %%rdi\n\t"
            "movq %%rcx, %%r8\n\t"  "movq %%rcx, %%r9\n\t"  "movq %%rcx, %%r10\n\t"
            "movq %%rcx, %%r11\n\t"
            "vmovq %%rcx, %%xmm0\n\t"
            "vpbroadcastq %%xmm0, %%ymm0\n\t"
            "vmovdqa %%ymm0, %%ymm1\n\t"   "vmovdqa %%ymm0, %%ymm2\n\t"   "vmovdqa %%ymm0, %%ymm3\n\t"
            "vmovdqa %%ymm0, %%ymm4\n\t"   "vmovdqa %%ymm0, %%ymm5\n\t"   "vmovdqa %%ymm0, %%ymm6\n\t"
            "vmovdqa %%ymm0, %%ymm7\n\t"   "vmovdqa %%ymm0, %%ymm8\n\t"   "vmovdqa %%ymm0, %%ymm9\n\t"
            "vmovdqa %%ymm0, %%ymm10\n\t"  "vmovdqa %%ymm0, %%ymm11\n\t"  "vmovdqa %%ymm0, %%ymm12\n\t"
            "vmovdqa %%ymm0, %%ymm13\n\t"  "vmovdqa %%ymm0, %%ymm14\n\t"  "vmovdqa %%ymm0, %%ymm15\n\t"
            "callq *%%rax\n\t"
            "movq %%rax, 0(%%rbx)\n\t"  "movq %%rcx, 8(%%rbx)\n\t"  "movq %%rdx, 16(%%rbx)\n\t"
            "movq %%rsi, 24(%%rbx)\n\t" "movq %%rdi, 32(%%rbx)\n\t" "movq %%r8, 40(%%rbx)\n\t"
            "movq %%r9, 48(%%rbx)\n\t"  "movq %%r10, 56(%%rbx)\n\t" "movq %%r11, 64(%%rbx)\n\t"
            "vmovdqu %%ymm0, 72(%%rbx)\n\t"   "vmovdqu %%ymm1, 104(%%rbx)\n\t"
            "vmovdqu %%ymm2, 136(%%rbx)\n\t"  "vmovdqu %%ymm3, 168(%%rbx)\n\t"
            "vmovdqu %%ymm4, 200(%%rbx)\n\t"  "vmovdqu %%ymm5, 232(%%rbx)\n\t"
            "vmovdqu %%ymm6, 264(%%rbx)\n\t"  "vmovdqu %%ymm7, 296(%%rbx)\n\t"
            "vmovdqu %%ymm8, 328(%%rbx)\n\t"  "vmovdqu %%ymm9, 360(%%rbx)\n\t"
            "vmovdqu %%ymm10, 392(%%rbx)\n\t" "vmovdqu %%ymm11, 424(%%rbx)\n\t"
            "vmovdqu %%ymm12, 456(%%rbx)\n\t" "vmovdqu %%ymm13, 488(%%rbx)\n\t"
            "vmovdqu %%ymm14, 520(%%rbx)\n\t" "vmovdqu %%ymm15, 552(%%rbx)\n\t"
            "vzeroupper\n\t"
            "movq %%r12, %%rsp"
            : "+a"(fn), "+b"(d)
            :
            : "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
              "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
              "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
              "memory", "cc");
    } else {
        __asm__ __volatile__(
            "movq %%rsp, %%r12\n\t"
            "subq $256, %%rsp\n\t"
            "andq $-32, %%rsp\n\t"
            "movq $0xa5a5a5a5a5a5a5a5, %%rcx\n\t"
            "movq %%rcx, %%rdx\n\t" "movq %%rcx, %%rsi\n\t" "movq %%rcx, %%rdi\n\t"
            "movq %%rcx, %%r8\n\t"  "movq %%rcx, %%r9\n\t"  "movq %%rcx, %%r10\n\t"
            "movq %%rcx, %%r11\n\t"
            "movq %%rcx, %%xmm0\n\t"
            "punpcklqdq %%xmm0, %%xmm0\n\t"
            "movdqa %%xmm0, %%xmm1\n\t"   "movdqa %%xmm0, %%xmm2\n\t"   "movdqa %%xmm0, %%xmm3\n\t"
            "movdqa %%xmm0, %%xmm4\n\t"   "movdqa %%xmm0, %%xmm5\n\t"   "movdqa %%xmm0, %%xmm6\n\t"
            "movdqa %%xmm0, %%xmm7\n\t"   "movdqa %%xmm0, %%xmm8\n\t"   "movdqa %%xmm0, %%xmm9\n\t"
            "movdqa %%xmm0, %%xmm10\n\t"  "movdqa %%xmm0, %%xmm11\n\t"  "movdqa %%xmm0, %%xmm12\n\t"
            "movdqa %%xmm0, %%xmm13\n\t"  "movdqa %%xmm0, %%xmm14\n\t"  "movdqa %%xmm0, %%xmm15\n\t"
            "callq *%%rax\n\t"
            "movq %%rax, 0(%%rbx)\n\t"  "movq %%rcx, 8(%%rbx)\n\t"  "movq %%rdx, 16(%%rbx)\n\t"
            "movq %%rsi, 24(%%rbx)\n\t" "movq %%rdi, 32(%%rbx)\n\t" "movq %%r8, 40(%%rbx)\n\t"
            "movq %%r9, 48(%%rbx)\n\t"  "movq %%r10, 56(%%rbx)\n\t" "movq %%r11, 64(%%rbx)\n\t"
            "movdqu %%xmm0, 72(%%rbx)\n\t"   "movdqu %%xmm1, 104(%%rbx)\n\t"
            "movdqu %%xmm2, 136(%%rbx)\n\t"  "movdqu %%xmm3, 168(%%rbx)\n\t"
            "movdqu %%xmm4, 200(%%rbx)\n\t"  "movdqu %%xmm5, 232(%%rbx)\n\t"
            "movdqu %%xmm6, 264(%%rbx)\n\t"  "movdqu %%xmm7, 296(%%rbx)\n\t"
            "movdqu %%xmm8, 328(%%rbx)\n\t"  "movdqu %%xmm9, 360(%%rbx)\n\t"
            "movdqu %%xmm10, 392(%%rbx)\n\t" "movdqu %%xmm11, 424(%%rbx)\n\t"
            "movdqu %%xmm12, 456(%%rbx)\n\t" "movdqu %%xmm13, 488(%%rbx)\n\t"
            "movdqu %%xmm14, 520(%%rbx)\n\t" "movdqu %%xmm15, 552(%%rbx)\n\t"
            "movq %%r12, %%rsp"
            : "+a"(fn), "+b"(d)
            :
            : "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
              "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
              "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
              "memory", "cc");
    }
#endif
}

/* The functions the trampoline calls, and their shared inputs. */

static nirapod_slhdsa_set the_set;
static unsigned the_features;
static uint8_t pk[64], sk[128], msg[32], sig[NIRAPOD_SLHDSA_MAX_SIGNATURE_BYTES];

static void run_clear(void)
{
    nirapod_slhdsa_clear_registers(the_features);
}

static void run_keygen(void)
{
    size_t n = nirapod_slhdsa_public_key_bytes(the_set) / 2;

    (void)nirapod_slhdsa_keygen(the_set, pk, 2 * n, sk, 4 * n);
}

static void run_sign(void)
{
    size_t n = nirapod_slhdsa_public_key_bytes(the_set) / 2;

    (void)nirapod_slhdsa_sign(the_set, sig, nirapod_slhdsa_signature_bytes(the_set),
                              msg, sizeof(msg), NULL, 0, sk, 4 * n);
}

static void run_hash_sign(void)
{
    size_t n = nirapod_slhdsa_public_key_bytes(the_set) / 2;

    (void)nirapod_slhdsa_hash_sign_deterministic(the_set, NIRAPOD_SLHDSA_PREHASH_SHAKE256, sig,
                                                 nirapod_slhdsa_signature_bytes(the_set),
                                                 msg, sizeof(msg), NULL, 0, sk, 4 * n);
}

/* The control: SK.prf[0 .. 8) left in a caller-saved register. */
static void run_leak(void)
{
    size_t n = nirapod_slhdsa_public_key_bytes(the_set) / 2;
    uint64_t v;

    memcpy(&v, sk + n, 8);
#if defined(__aarch64__)
    __asm__ __volatile__("mov x9, %0" : : "r"(v) : "x9");
#else
    __asm__ __volatile__("movq %0, %%r10" : : "r"(v) : "r10");
#endif
}

/* 1 if the dump holds 8 consecutive bytes of secret[0 .. n). */
static int dump_contains(const dump *d, const uint8_t *secret, size_t n)
{
    const uint8_t *b = (const uint8_t *)d;
    size_t i, w;

    for (i = 0; i + 8 <= sizeof(*d); i++) {
        for (w = 0; w + 8 <= n; w++) {
            if (memcmp(b + i, secret + w, 8) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

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

static void test_mechanism(void)
{
    dump d;
    size_t i, low;

    memset(&d, 0x11, sizeof(d));
    call_and_dump(run_clear, &d);

    for (i = 0; i < NGPR; i++) {
        CHECK(d.gpr[i] == 0, "general register %zu not cleared", i);
    }
    for (i = 0; i < NVEC; i++) {
#if defined(__aarch64__)
        low = (i >= 8 && i <= 15) ? 8 : 0;   /* callee-saved low halves */
        CHECK(all_bytes(d.vec[i], low, PATTERN) && all_bytes(d.vec[i] + low, 16 - low, 0),
              "vector register v%zu not as specified", i);
#else
        low = wide_vectors ? 32 : 16;
        CHECK(all_bytes(d.vec[i], low, 0), "vector register %zu not cleared", i);
#endif
    }
    printf("mechanism: %s\n", failures == 0 ? "registers cleared as specified" : "FAIL");
}

/*
 * Wiring of the register clearing (check 2)
 * -----------------------------------------
 *
 * Stub exports in assembly: each loads MARKER into every register the
 * platform ABI lets a callee change and returns. The "zero" entries return
 * 0 in the return-value register (sign: success; verify: valid), so the
 * operation takes its success path, the fault check included; the "void"
 * entries mark that register too.
 *
 *     AArch64   x0-x17 and v0-v7, v16-v31 whole; v8-v15 in their upper
 *               halves only, the low halves being callee-saved
 *     x86-64    rax, rcx, rdx, rsi, rdi, r8-r11, and xmm0-xmm15: whole
 *               ymm registers in the "avx" entries (AVX instructions,
 *               for records whose features imply AVX), the low halves in
 *               the "sse" entries (legacy SSE, for the scalar record)
 *
 * Each entry starts with the landing pad of its architecture (bti c,
 * endbr64), which executes as a no-op where branch protection is off.
 */

#define MARKER UINT64_C(0x5d3c9a1e7b2f4e61)

#if defined(__APPLE__)
#define SYM(name) "_" #name
#else
#define SYM(name) #name
#endif

#define GLOBL(name) ".globl " SYM(name) "\n" SYM(name) ":\n"

#if defined(__aarch64__)

#define MARK_BODY                                                              \
    "hint #34\n"                                                               \
    "movz x16, #0x4e61\n"                                                      \
    "movk x16, #0x7b2f, lsl #16\n"                                             \
    "movk x16, #0x9a1e, lsl #32\n"                                             \
    "movk x16, #0x5d3c, lsl #48\n"                                             \
    "mov x0, x16\n"  "mov x1, x16\n"  "mov x2, x16\n"  "mov x3, x16\n"         \
    "mov x4, x16\n"  "mov x5, x16\n"  "mov x6, x16\n"  "mov x7, x16\n"         \
    "mov x8, x16\n"  "mov x9, x16\n"  "mov x10, x16\n" "mov x11, x16\n"        \
    "mov x12, x16\n" "mov x13, x16\n" "mov x14, x16\n" "mov x15, x16\n"        \
    "mov x17, x16\n"                                                           \
    "dup v0.2d, x16\n"                                                         \
    "mov v1.16b, v0.16b\n"  "mov v2.16b, v0.16b\n"  "mov v3.16b, v0.16b\n"     \
    "mov v4.16b, v0.16b\n"  "mov v5.16b, v0.16b\n"  "mov v6.16b, v0.16b\n"     \
    "mov v7.16b, v0.16b\n"                                                     \
    "mov v8.d[1], x16\n"    "mov v9.d[1], x16\n"    "mov v10.d[1], x16\n"      \
    "mov v11.d[1], x16\n"   "mov v12.d[1], x16\n"   "mov v13.d[1], x16\n"      \
    "mov v14.d[1], x16\n"   "mov v15.d[1], x16\n"                              \
    "mov v16.16b, v0.16b\n" "mov v17.16b, v0.16b\n" "mov v18.16b, v0.16b\n"    \
    "mov v19.16b, v0.16b\n" "mov v20.16b, v0.16b\n" "mov v21.16b, v0.16b\n"    \
    "mov v22.16b, v0.16b\n" "mov v23.16b, v0.16b\n" "mov v24.16b, v0.16b\n"    \
    "mov v25.16b, v0.16b\n" "mov v26.16b, v0.16b\n" "mov v27.16b, v0.16b\n"    \
    "mov v28.16b, v0.16b\n" "mov v29.16b, v0.16b\n" "mov v30.16b, v0.16b\n"    \
    "mov v31.16b, v0.16b\n"

__asm__(
    ".text\n"
    ".p2align 2\n"
    GLOBL(test_mark_keygen)
    GLOBL(test_mark_sign_internal)
    MARK_BODY
    "ret\n"
    ".p2align 2\n"
    GLOBL(test_mark_sign)
    GLOBL(test_mark_verify)
    GLOBL(test_mark_verify_internal)
    MARK_BODY
    "mov x0, xzr\n"
    "ret\n");

#define MARK_STUBS(suffix) MARK_STUBS_1(suffix)
#define MARK_STUBS_1(suffix)                                                   \
    void test_mark_keygen##suffix(uint8_t *, uint8_t *, const uint8_t *);      \
    void test_mark_sign_internal##suffix(uint8_t *, const uint8_t *, uint64_t, \
                                         const uint8_t *, const uint8_t *);    \
    uint64_t test_mark_sign##suffix(uint8_t *, const uint8_t *, uint64_t,      \
                                    const uint8_t *, const uint8_t *,          \
                                    const uint8_t *);                          \
    uint64_t test_mark_verify##suffix(const uint8_t *, const uint8_t *,        \
                                      uint64_t, const uint8_t *,               \
                                      const uint8_t *);                        \
    uint64_t test_mark_verify_internal##suffix(const uint8_t *,                \
                                               const uint8_t *, uint64_t,      \
                                               const uint8_t *);

MARK_STUBS()

#else

#define MARK_GPR                                                               \
    "endbr64\n"                                                                \
    "movabsq $0x5d3c9a1e7b2f4e61, %rcx\n"                                      \
    "movq %rcx, %rdx\n" "movq %rcx, %rsi\n" "movq %rcx, %rdi\n"                \
    "movq %rcx, %r8\n"  "movq %rcx, %r9\n"  "movq %rcx, %r10\n"                \
    "movq %rcx, %r11\n"

#define MARK_AVX                                                               \
    "vmovq %rcx, %xmm0\n"                                                      \
    "vpunpcklqdq %xmm0, %xmm0, %xmm0\n"                                        \
    "vinsertf128 $1, %xmm0, %ymm0, %ymm0\n"                                    \
    "vmovdqa %ymm0, %ymm1\n"  "vmovdqa %ymm0, %ymm2\n"  "vmovdqa %ymm0, %ymm3\n"   \
    "vmovdqa %ymm0, %ymm4\n"  "vmovdqa %ymm0, %ymm5\n"  "vmovdqa %ymm0, %ymm6\n"   \
    "vmovdqa %ymm0, %ymm7\n"  "vmovdqa %ymm0, %ymm8\n"  "vmovdqa %ymm0, %ymm9\n"   \
    "vmovdqa %ymm0, %ymm10\n" "vmovdqa %ymm0, %ymm11\n" "vmovdqa %ymm0, %ymm12\n"  \
    "vmovdqa %ymm0, %ymm13\n" "vmovdqa %ymm0, %ymm14\n" "vmovdqa %ymm0, %ymm15\n"

#define MARK_SSE                                                               \
    "movq %rcx, %xmm0\n"                                                       \
    "punpcklqdq %xmm0, %xmm0\n"                                                \
    "movdqa %xmm0, %xmm1\n"  "movdqa %xmm0, %xmm2\n"  "movdqa %xmm0, %xmm3\n"  \
    "movdqa %xmm0, %xmm4\n"  "movdqa %xmm0, %xmm5\n"  "movdqa %xmm0, %xmm6\n"  \
    "movdqa %xmm0, %xmm7\n"  "movdqa %xmm0, %xmm8\n"  "movdqa %xmm0, %xmm9\n"  \
    "movdqa %xmm0, %xmm10\n" "movdqa %xmm0, %xmm11\n" "movdqa %xmm0, %xmm12\n" \
    "movdqa %xmm0, %xmm13\n" "movdqa %xmm0, %xmm14\n" "movdqa %xmm0, %xmm15\n"

#define MARK_ENTRIES(suffix, VEC)                                              \
    ".p2align 4\n"                                                             \
    GLOBL(test_mark_keygen##suffix)                                            \
    GLOBL(test_mark_sign_internal##suffix)                                     \
    MARK_GPR VEC                                                               \
    "movq %rcx, %rax\n"                                                        \
    "ret\n"                                                                    \
    ".p2align 4\n"                                                             \
    GLOBL(test_mark_sign##suffix)                                              \
    GLOBL(test_mark_verify##suffix)                                            \
    GLOBL(test_mark_verify_internal##suffix)                                   \
    MARK_GPR VEC                                                               \
    "xorl %eax, %eax\n"                                                        \
    "ret\n"

__asm__(
    ".text\n"
    MARK_ENTRIES(_avx, MARK_AVX)
    MARK_ENTRIES(_sse, MARK_SSE));

#define MARK_STUBS(suffix)                                                     \
    void test_mark_keygen##suffix(uint8_t *, uint8_t *, const uint8_t *);      \
    void test_mark_sign_internal##suffix(uint8_t *, const uint8_t *, uint64_t, \
                                         const uint8_t *, const uint8_t *);    \
    uint64_t test_mark_sign##suffix(uint8_t *, const uint8_t *, uint64_t,      \
                                    const uint8_t *, const uint8_t *,          \
                                    const uint8_t *);                          \
    uint64_t test_mark_verify##suffix(const uint8_t *, const uint8_t *,        \
                                      uint64_t, const uint8_t *,               \
                                      const uint8_t *);                        \
    uint64_t test_mark_verify_internal##suffix(const uint8_t *,                \
                                               const uint8_t *, uint64_t,      \
                                               const uint8_t *);

MARK_STUBS(_avx)
MARK_STUBS(_sse)

#endif

/* A test random source: a fixed byte, never failing. */
static int fixed_entropy(void *state, uint8_t *buf, size_t len)
{
    (void)state;
    memset(buf, 0x3c, len);
    return 0;
}

/* The record and environment the wiring operations run on. */
static nirapod_slhdsa_impl stub_rec;
static nirapod_slhdsa_env stub_env;
static nirapod_slhdsa_status wiring_status;

static void wire_keygen(void)
{
    wiring_status = nirapod_slhdsa_keygen_env(&stub_env, pk, stub_rec.public_key_bytes,
                                              sk, stub_rec.secret_key_bytes);
}

static void wire_sign(void)
{
    wiring_status = nirapod_slhdsa_sign_framed(&stub_env, 0, 0, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                               sig, stub_rec.signature_bytes, msg, sizeof(msg),
                                               NULL, 0, sk, stub_rec.secret_key_bytes);
}

static void wire_sign_hedged(void)
{
    wiring_status = nirapod_slhdsa_sign_framed(&stub_env, 0, 0, NIRAPOD_SLHDSA_OPT_RAND_ENTROPY,
                                               sig, stub_rec.signature_bytes, msg, sizeof(msg),
                                               NULL, 0, sk, stub_rec.secret_key_bytes);
}

static void wire_hash_sign(void)
{
    wiring_status = nirapod_slhdsa_sign_framed(&stub_env, 1, NIRAPOD_SLHDSA_PREHASH_SHA2_256,
                                               NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                               sig, stub_rec.signature_bytes, msg, sizeof(msg),
                                               NULL, 0, sk, stub_rec.secret_key_bytes);
}

static void wire_sign_internal(void)
{
    wiring_status = nirapod_slhdsa_sign_internal_env(&stub_env, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED,
                                                     sig, stub_rec.signature_bytes,
                                                     msg, sizeof(msg),
                                                     sk, stub_rec.secret_key_bytes);
}

/* The control: a stub called directly, with nothing after it. */
static void wire_control(void)
{
    stub_rec.keygen(pk, sk, msg);
}

/*
 * One stub record: the sizes of SLH-DSA-SHA2-128f, the stubs given, the
 * features given (they decide how nirapod_slhdsa_clear_registers clears
 * the vector registers).
 */
static void test_wiring_with(const char *label, unsigned features,
                             void (*keygen)(uint8_t *, uint8_t *, const uint8_t *),
                             uint64_t (*sign)(uint8_t *, const uint8_t *, uint64_t,
                                              const uint8_t *, const uint8_t *, const uint8_t *),
                             uint64_t (*verify)(const uint8_t *, const uint8_t *, uint64_t,
                                                const uint8_t *, const uint8_t *),
                             void (*sign_internal)(uint8_t *, const uint8_t *, uint64_t,
                                                   const uint8_t *, const uint8_t *),
                             uint64_t (*verify_internal)(const uint8_t *, const uint8_t *,
                                                         uint64_t, const uint8_t *))
{
    static void (*const ops[])(void) = { wire_keygen, wire_sign, wire_sign_hedged, wire_hash_sign,
                                         wire_sign_internal, wire_control };
    static const char *const names[] = { "keygen", "sign_det", "sign_hedged", "hash_sign_det",
                                         "sign_internal", "control" };
    uint8_t marker[8];
    uint64_t m = MARKER;
    dump d;
    size_t op;
    int found;

    memcpy(marker, &m, 8);
    stub_rec = *nirapod_slhdsa_impl_variant(NIRAPOD_SLHDSA_SHA2_128F, 0);
    stub_rec.features = features;
    stub_rec.keygen = keygen;
    stub_rec.sign = sign;
    stub_rec.verify = verify;
    stub_rec.sign_internal = sign_internal;
    stub_rec.verify_internal = verify_internal;
    memset(&stub_env, 0, sizeof(stub_env));
    stub_env.impl = &stub_rec;
    stub_env.entropy = fixed_entropy;

    for (op = 0; op < sizeof(ops) / sizeof(ops[0]); op++) {
        int control = op == sizeof(ops) / sizeof(ops[0]) - 1;

        wiring_status = NIRAPOD_SLHDSA_OK;
        memset(&d, 0, sizeof(d));
        call_and_dump(ops[op], &d);
        found = dump_contains(&d, marker, 8);
        printf("wiring %-4s %-14s marker in registers: %s\n", label, names[op],
               found ? "yes" : "no");
        CHECK(wiring_status == NIRAPOD_SLHDSA_OK, "wiring %s %s: status %d", label, names[op],
              wiring_status);
        CHECK(control ? found : !found, "wiring %s %s: %s", label, names[op],
              control ? "the marker of a direct stub call was not found"
                      : "registers not cleared after the export");
    }
}

static void test_wiring(void)
{
#if defined(__aarch64__)
    test_wiring_with("simd", 0, test_mark_keygen, test_mark_sign, test_mark_verify,
                     test_mark_sign_internal, test_mark_verify_internal);
#else
    test_wiring_with("sse", 0, test_mark_keygen_sse, test_mark_sign_sse, test_mark_verify_sse,
                     test_mark_sign_internal_sse, test_mark_verify_internal_sse);
    if (wide_vectors) {
        test_wiring_with("avx", NIRAPOD_SLHDSA_CPU_AVX2, test_mark_keygen_avx, test_mark_sign_avx,
                         test_mark_verify_avx, test_mark_sign_internal_avx,
                         test_mark_verify_internal_avx);
    } else {
        printf("wiring avx: SKIP (this CPU has no AVX variant)\n");
    }
#endif
}

static const nirapod_slhdsa_set SETS[] = {
    NIRAPOD_SLHDSA_SHA2_128F, NIRAPOD_SLHDSA_SHAKE_128F,
    NIRAPOD_SLHDSA_SHA2_192F, NIRAPOD_SLHDSA_SHAKE_192F,
    NIRAPOD_SLHDSA_SHA2_256F, NIRAPOD_SLHDSA_SHAKE_256F,
};

static void test_end_to_end(void)
{
    static void (*const ops[])(void) = { run_keygen, run_sign, run_hash_sign, run_leak };
    static const char *const names[] = { "keygen", "sign", "hash_sign_det", "control" };
    dump d;
    size_t s, op, n;
    int found;

    memset(msg, 0x33, sizeof(msg));
    for (s = 0; s < sizeof(SETS) / sizeof(SETS[0]); s++) {
        the_set = SETS[s];
        n = nirapod_slhdsa_public_key_bytes(the_set) / 2;
        for (op = 0; op < 4; op++) {
            memset(&d, 0, sizeof(d));
            call_and_dump(ops[op], &d);
            found = dump_contains(&d, sk, n) || dump_contains(&d, sk + n, n);
            printf("%-20s %-14s seeds in registers: %s\n", nirapod_slhdsa_set_name(the_set),
                   names[op], found ? "yes" : "no");
            CHECK(op == 3 ? found : !found, "%s %s", nirapod_slhdsa_set_name(the_set), names[op]);
        }
    }
}

/*
 * Timing mode (AArch64 with FEAT_DIT)
 *
 * Stub exports written in C record PSTATE.DIT when the library calls
 * them, so the test sees the mode the secret computation actually runs
 * in: keygen, sign, the verification of the fault check, sign_internal
 * and its check must find DIT set; verification through the public path
 * must find the caller's value. The caller's DIT is set before one round
 * and clear before the other; the round with DIT clear is the one that
 * shows the library sets it, and that its FEAT_DIT test found the
 * feature. After every call DIT must be the caller's value again. The
 * production functions run the same round trip on the real exports.
 * Without FEAT_DIT the library must not touch DIT (writing it would be
 * undefined) and the check is skipped.
 */
#if defined(__aarch64__)

#define DIT_FLAG (UINT64_C(1) << 24)

static int host_has_dit(void)
{
#if defined(__APPLE__)
    int value = 0;
    size_t size = sizeof(value);

    return sysctlbyname("hw.optional.arm.FEAT_DIT", &value, &size, NULL, 0) == 0 && value == 1;
#elif defined(__linux__)
    return (getauxval(AT_HWCAP) & (UINT64_C(1) << 24)) != 0;
#else
    return 0;
#endif
}

static uint64_t read_dit(void)
{
    uint64_t v;

    __asm__ __volatile__("mrs %0, s3_3_c4_c2_5" : "=r"(v));
    return v & DIT_FLAG;
}

static void write_dit(uint64_t v)
{
    __asm__ __volatile__("msr s3_3_c4_c2_5, %0" : : "r"(v) : "memory");
}

/* DIT as each stub found it; NOT_CALLED until the stub runs. */
#define NOT_CALLED UINT64_C(2)
enum { AT_KEYGEN, AT_SIGN, AT_VERIFY, AT_SIGN_INTERNAL, AT_VERIFY_INTERNAL, AT_COUNT };
static uint64_t dit_at[AT_COUNT];

static void dit_keygen(uint8_t *p, uint8_t *s, const uint8_t *seeds)
{
    (void)p;
    (void)s;
    (void)seeds;
    dit_at[AT_KEYGEN] = read_dit();
}

static uint64_t dit_sign(uint8_t *out, const uint8_t *m, uint64_t m_len, const uint8_t *domain,
                         const uint8_t *key, const uint8_t *opt)
{
    (void)out;
    (void)m;
    (void)m_len;
    (void)domain;
    (void)key;
    (void)opt;
    dit_at[AT_SIGN] = read_dit();
    return 0;
}

static uint64_t dit_verify(const uint8_t *in, const uint8_t *m, uint64_t m_len,
                           const uint8_t *domain, const uint8_t *key)
{
    (void)in;
    (void)m;
    (void)m_len;
    (void)domain;
    (void)key;
    dit_at[AT_VERIFY] = read_dit();
    return 0;
}

static void dit_sign_internal(uint8_t *out, const uint8_t *m, uint64_t m_len, const uint8_t *key,
                              const uint8_t *opt)
{
    (void)out;
    (void)m;
    (void)m_len;
    (void)key;
    (void)opt;
    dit_at[AT_SIGN_INTERNAL] = read_dit();
}

static uint64_t dit_verify_internal(const uint8_t *in, const uint8_t *m, uint64_t m_len,
                                    const uint8_t *key)
{
    (void)in;
    (void)m;
    (void)m_len;
    (void)key;
    dit_at[AT_VERIFY_INTERNAL] = read_dit();
    return 0;
}

static void reset_dit_at(void)
{
    size_t i;

    for (i = 0; i < AT_COUNT; i++) {
        dit_at[i] = NOT_CALLED;
    }
}

/* The modes the stubs recorded, against the expected one, for one call. */
static void expect_dit(const char *call, uint64_t caller, const uint64_t expect[AT_COUNT],
                       nirapod_slhdsa_status st)
{
    static const char *const AT_NAMES[AT_COUNT] = { "keygen", "sign", "verify", "sign_internal",
                                                    "verify_internal" };
    uint64_t after = read_dit();
    size_t i;

    CHECK(st == NIRAPOD_SLHDSA_OK, "%s with the caller's DIT %d: status %d", call, caller != 0, st);
    for (i = 0; i < AT_COUNT; i++) {
        CHECK(dit_at[i] == expect[i], "%s with the caller's DIT %d: %s ran with DIT %s, expected %s",
              call, caller != 0, AT_NAMES[i],
              dit_at[i] == NOT_CALLED ? "(not called)" : dit_at[i] != 0 ? "1" : "0",
              expect[i] == NOT_CALLED ? "(not called)" : expect[i] != 0 ? "1" : "0");
    }
    CHECK(after == caller, "%s changed the caller's DIT from %d to %d", call, caller != 0, after != 0);
}

static void test_dit(void)
{
    static uint8_t dsig[NIRAPOD_SLHDSA_SHA2_128F_SIGNATURE_BYTES];
    uint8_t dpk[32], dsk[64];
    nirapod_slhdsa_impl rec = *nirapod_slhdsa_impl_variant(NIRAPOD_SLHDSA_SHA2_128F, 0);
    nirapod_slhdsa_env env;
    nirapod_slhdsa_status st;
    uint64_t caller, after, expect[AT_COUNT];
    int round, before = failures;
    size_t i;

    if (!host_has_dit()) {
        printf("timing mode: SKIP (this CPU does not report FEAT_DIT)\n");
        return;
    }

    rec.keygen = dit_keygen;
    rec.sign = dit_sign;
    rec.verify = dit_verify;
    rec.sign_internal = dit_sign_internal;
    rec.verify_internal = dit_verify_internal;
    memset(&env, 0, sizeof(env));
    env.impl = &rec;
    env.entropy = fixed_entropy;
    memset(dsk, 0x21, sizeof(dsk));

    for (round = 0; round < 2; round++) {
        caller = round == 0 ? DIT_FLAG : 0;

        /* Stub exports: the mode each one runs in */

        for (i = 0; i < AT_COUNT; i++) {
            expect[i] = NOT_CALLED;
        }
        reset_dit_at();
        write_dit(caller);
        expect[AT_KEYGEN] = DIT_FLAG;
        st = nirapod_slhdsa_keygen_env(&env, dpk, sizeof(dpk), dsk, sizeof(dsk));
        expect_dit("keygen", caller, expect, st);
        expect[AT_KEYGEN] = NOT_CALLED;

        reset_dit_at();
        write_dit(caller);
        expect[AT_SIGN] = DIT_FLAG;
        expect[AT_VERIFY] = DIT_FLAG;
        st = nirapod_slhdsa_sign_framed(&env, 0, 0, NIRAPOD_SLHDSA_OPT_RAND_ENTROPY, dsig,
                                        sizeof(dsig), dpk, sizeof(dpk), NULL, 0, dsk, sizeof(dsk));
        expect_dit("hedged signing and its check", caller, expect, st);

        reset_dit_at();
        write_dit(caller);
        st = nirapod_slhdsa_sign_framed(&env, 1, NIRAPOD_SLHDSA_PREHASH_SHAKE256,
                                        NIRAPOD_SLHDSA_OPT_RAND_PK_SEED, dsig, sizeof(dsig),
                                        dpk, sizeof(dpk), NULL, 0, dsk, sizeof(dsk));
        expect_dit("deterministic pre-hash signing and its check", caller, expect, st);
        expect[AT_SIGN] = NOT_CALLED;

        reset_dit_at();
        write_dit(caller);
        expect[AT_VERIFY] = caller;
        st = nirapod_slhdsa_verify_framed(&env, 0, 0, dsig, sizeof(dsig), dpk, sizeof(dpk),
                                          NULL, 0, dpk, sizeof(dpk));
        expect_dit("verification", caller, expect, st);
        expect[AT_VERIFY] = NOT_CALLED;

        reset_dit_at();
        write_dit(caller);
        expect[AT_SIGN_INTERNAL] = DIT_FLAG;
        expect[AT_VERIFY_INTERNAL] = DIT_FLAG;
        st = nirapod_slhdsa_sign_internal_env(&env, NIRAPOD_SLHDSA_OPT_RAND_PK_SEED, dsig,
                                              sizeof(dsig), dpk, sizeof(dpk), dsk, sizeof(dsk));
        expect_dit("internal signing and its check", caller, expect, st);

        /* The production functions on the real exports: the caller's DIT kept */

        write_dit(caller);
        st = nirapod_slhdsa_keygen(NIRAPOD_SLHDSA_SHA2_128F, dpk, sizeof(dpk), dsk, sizeof(dsk));
        after = read_dit();
        CHECK(st == NIRAPOD_SLHDSA_OK, "keygen for the DIT check: %d", st);
        CHECK(after == caller, "keygen changed the caller's DIT from %d to %d",
              caller != 0, after != 0);

        write_dit(caller);
        st = nirapod_slhdsa_sign_deterministic(NIRAPOD_SLHDSA_SHA2_128F, dsig, sizeof(dsig),
                                               dpk, sizeof(dpk), NULL, 0, dsk, sizeof(dsk));
        after = read_dit();
        CHECK(st == NIRAPOD_SLHDSA_OK, "signing for the DIT check: %d", st);
        CHECK(after == caller, "signing changed the caller's DIT from %d to %d",
              caller != 0, after != 0);
    }
    write_dit(0);
    printf("timing mode: DIT set in keygen, signing and its check, the caller's in verification; "
           "the caller's DIT kept (set and clear): %s\n", failures == before ? "PASS" : "FAIL");
}

#else

static void test_dit(void)
{
    printf("timing mode: NOT APPLICABLE (no DIT on this architecture)\n");
}

#endif

/*
 * AVX state after a call (x86-64)
 *
 * XGETBV with ECX = 1 returns XINUSE: bit 2 is clear when the upper halves
 * of the ymm registers are in their initial state, as VZEROUPPER and
 * VZEROALL leave them. The library ends verification (and the check of a
 * new signature) with VZEROUPPER and signing with VZEROALL on a variant
 * that uses AVX, so bit 2 must be clear right after such a call. The probe
 * is trusted only if it reports the state: set after an instruction that
 * writes a ymm register, clear after VZEROUPPER; otherwise the check is
 * reported as not applicable. The calls under test reach the probe with
 * no other code that uses AVX in between.
 */
#if defined(__x86_64__)

#include <cpuid.h>

static int xinuse_available(void)
{
    unsigned int a, b, c, d;

    if (__get_cpuid_max(0, NULL) < 0xd || !__get_cpuid(1, &a, &b, &c, &d) ||
        (c & (1u << 27)) == 0) {
        return 0;
    }
    __cpuid_count(0xd, 1, a, b, c, d);
    return (a & (1u << 2)) != 0;
}

static unsigned upper_ymm_in_use(void)
{
    unsigned int lo, hi;

    __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(1));
    (void)hi;
    return (lo >> 2) & 1u;
}

static unsigned dirty_then_probe(void)
{
    __asm__ __volatile__("vpcmpeqd %%ymm0, %%ymm0, %%ymm0" : : : "xmm0");
    return upper_ymm_in_use();
}

static unsigned clean_then_probe(void)
{
    __asm__ __volatile__("vzeroupper" : : : "memory");
    return upper_ymm_in_use();
}

static void test_avx_state(void)
{
    static const nirapod_slhdsa_set AVX_SETS[2] = { NIRAPOD_SLHDSA_SHAKE_128F,
                                                    NIRAPOD_SLHDSA_SHA2_128F };
    uint8_t apk[32], ask[64];
    unsigned dirty, clean, in_use;
    nirapod_slhdsa_status st;
    size_t i;
    int before = failures;

    if (!wide_vectors || !xinuse_available()) {
        printf("AVX state: NOT APPLICABLE (no AVX variant or no XGETBV with ECX = 1)\n");
        return;
    }
    dirty = dirty_then_probe();
    clean = clean_then_probe();
    if (dirty != 1 || clean != 0) {
        printf("AVX state: NOT APPLICABLE (XINUSE does not report the ymm state: %u after a "
               "write, %u after VZEROUPPER)\n", dirty, clean);
        return;
    }
    for (i = 0; i < 2; i++) {
        nirapod_slhdsa_set set = AVX_SETS[i];
        const char *name = nirapod_slhdsa_set_name(set);
        const char *variant = nirapod_slhdsa_testing_variant(set);

        if (strcmp(variant, "scalar") == 0) {
            printf("AVX state: %s runs scalar here, skipped\n", name);
            continue;
        }
        st = nirapod_slhdsa_keygen(set, apk, sizeof(apk), ask, sizeof(ask));
        in_use = upper_ymm_in_use();
        CHECK(st == NIRAPOD_SLHDSA_OK && in_use == 0, "%s %s keygen: %d, upper ymm in use %u",
              name, variant, st, in_use);
        st = nirapod_slhdsa_sign_deterministic(set, sig, nirapod_slhdsa_signature_bytes(set),
                                               msg, sizeof(msg), NULL, 0, ask, sizeof(ask));
        in_use = upper_ymm_in_use();
        CHECK(st == NIRAPOD_SLHDSA_OK && in_use == 0, "%s %s signing: %d, upper ymm in use %u",
              name, variant, st, in_use);
        st = nirapod_slhdsa_verify(set, sig, nirapod_slhdsa_signature_bytes(set),
                                   msg, sizeof(msg), NULL, 0, apk, sizeof(apk));
        in_use = upper_ymm_in_use();
        CHECK(st == NIRAPOD_SLHDSA_OK && in_use == 0, "%s %s verification: %d, upper ymm in use %u",
              name, variant, st, in_use);
    }
    printf("AVX state: upper ymm halves initial after keygen, signing and verification on "
           "the AVX variants: %s\n", failures == before ? "PASS" : "FAIL");
}

#else

static void test_avx_state(void)
{
    printf("AVX state: NOT APPLICABLE (x86-64 only)\n");
}

#endif

int main(void)
{
    unsigned cpu = nirapod_slhdsa_cpu_features();

#if defined(__x86_64__)
    /* Both x86-64 extension features imply AVX (internal.h). */
    wide_vectors = (cpu & (NIRAPOD_SLHDSA_CPU_AVX2 | NIRAPOD_SLHDSA_CPU_SHANI)) != 0;
#endif
    the_features = cpu;

    test_mechanism();
    test_wiring();
    test_end_to_end();
    test_dit();
    test_avx_state();

    printf("test_registers: %s (%d failures)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
