/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * call_dump.h
 * ===========
 *
 * The register capture of the ABI tests: the caller-saved registers as a
 * library function leaves them, stored the moment it returns, before any
 * instruction of the test runs. test_registers.c and test_clearing.c
 * include it; each sets wide_vectors on x86-64 before the first call.
 *
 *     call_and_dump(fn, d)   fills the registers with PATTERN, records the
 *                            stack pointer, and calls fn, a function of the
 *                            test with no arguments
 *     CAPTURED(f)(args)      inside fn: calls f with args through
 *                            call_dump_thunk, which stores the registers to
 *                            the dump as soon as f returns
 *
 * fn must make exactly one CAPTURED call, or call_and_dump stops the test.
 * The capture sits between the library function and the test's code: a
 * wrapper that stores a status after the call, and so overwrites a
 * register on its way, cannot hide what the library left there.
 *
 *     AArch64   x0-x17 and v0-v31 (q registers); x18 on Linux, where the
 *               platform ABI lets a callee use it (on macOS it is the
 *               platform's register and is neither filled nor stored)
 *     x86-64    rax, rcx, rdx, rsi, rdi, r8-r11, and xmm0-xmm15, or the full
 *               ymm0-ymm15 when wide_vectors is set
 *
 * The callee-saved registers the trampoline does not use itself get the
 * pattern too (AArch64 x21-x29, x86-64 rbp and r13-r15): whatever the
 * library's frames save below the recorded stack pointer is then
 * independent of the trampoline's caller.
 *
 * Not stored: the flags; on x86-64 the upper halves of the zmm registers,
 * zmm16-zmm31 and the mask registers of AVX-512 CPUs. The test headers
 * say what that leaves out.
 */

#ifndef NIRAPOD_SLHDSA_TESTS_CALL_DUMP_H
#define NIRAPOD_SLHDSA_TESTS_CALL_DUMP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__aarch64__)
#define NGPR 18           /* x0-x17 */
#define NVEC 32           /* v0-v31, 16 bytes each */
#define VEC_BYTES 16
#if defined(__linux__) && !defined(__ANDROID__)
#define CALL_DUMP_X18 1   /* x18 is an ordinary temporary here */
#else
#define CALL_DUMP_X18 0
#endif
#elif defined(__x86_64__)
#define NGPR 9            /* rax rcx rdx rsi rdi r8 r9 r10 r11 */
#define NVEC 16           /* ymm0-ymm15, 32 bytes each (16 without AVX) */
#define VEC_BYTES 32
#else
#error "call_dump.h: unsupported architecture"
#endif

typedef struct {
    uint64_t gpr[NGPR];
#if defined(__aarch64__)
    uint64_t x18;         /* 0 where CALL_DUMP_X18 is 0 */
    uint64_t pad;         /* keeps vec 16-byte aligned for stp q */
#endif
    uint8_t vec[NVEC][VEC_BYTES];
    uint64_t sp;          /* the stack pointer at the call of fn */
} dump;

/*
 * The state the trampoline and the thunk share. regs comes first, so the
 * thunk stores registers at their offsets in dump.
 */
typedef struct {
    dump regs;
    void (*target)(void); /* the function CAPTURED calls */
    uint64_t saved[2];    /* the caller's x19 and x30 / rbx */
    uint64_t calls;       /* captures since call_and_dump began */
    uint64_t wide;        /* x86-64: store ymm rather than xmm */
} call_dump_shared;

#define PATTERN 0xA5u

/*
 * Offsets used in the assembly below, checked against the structure at
 * compile time.
 */
#if defined(__aarch64__)
#define CD_X18    144
#define CD_VEC    160
#define CD_SP     672
#define CD_TARGET 680
#define CD_SAVED  688
#define CD_SAVED1 696
#define CD_CALLS  704
#else
#define CD_VEC    72
#define CD_SP     584
#define CD_TARGET 592
#define CD_SAVED  600
#define CD_CALLS  616
#define CD_WIDE   624
#endif

#define CD_CHECK(name, cond) typedef char call_dump_check_##name[(cond) ? 1 : -1]
#if defined(__aarch64__)
CD_CHECK(x18, offsetof(dump, x18) == CD_X18);
CD_CHECK(saved1, offsetof(call_dump_shared, saved) + 8 == CD_SAVED1);
#else
CD_CHECK(wide, offsetof(call_dump_shared, wide) == CD_WIDE);
#endif
CD_CHECK(vec, offsetof(dump, vec) == CD_VEC);
CD_CHECK(sp, offsetof(dump, sp) == CD_SP);
CD_CHECK(target, offsetof(call_dump_shared, target) == CD_TARGET);
CD_CHECK(saved, offsetof(call_dump_shared, saved) == CD_SAVED);
CD_CHECK(calls, offsetof(call_dump_shared, calls) == CD_CALLS);

/* Defined here, read and written by name from the assembly. */
call_dump_shared call_dump_state __attribute__((used));

#if defined(__x86_64__)
/* Whether the capture stores full ymm registers (x86-64 with AVX). */
static int wide_vectors;
#endif

#define CD_STR(x) CD_STR_1(x)
#define CD_STR_1(x) #x

#if defined(__APPLE__)
#define CD_SYM(name) "_" #name
#else
#define CD_SYM(name) #name
#endif

/*
 * The thunk, and the controls of the tests that use it: functions that
 * load bytes of their argument into one register and return 0, as a
 * library function that failed to clear it would.
 */
void call_dump_thunk(void);
int call_dump_leave_gpr(const uint8_t *secret);    /* AArch64 x8, x86-64 r11 */
int call_dump_leave_gpr2(const uint8_t *secret);   /* AArch64 x9, x86-64 r10 */
int call_dump_leave_vec(const uint8_t *secret);    /* AArch64 v16, x86-64 xmm15 */
#if defined(__aarch64__) && CALL_DUMP_X18
int call_dump_leave_x18(const uint8_t *secret);
#endif

/*
 * CAPTURED(f)(args...): call f through the thunk. f is a function or a
 * function pointer; the call has f's type.
 */
#define CAPTURED(f)                                                            \
    (call_dump_state.target = (void (*)(void))(f),                             \
     (__typeof__(&*(f)))(void (*)(void))call_dump_thunk)

#if defined(__aarch64__)

#if defined(__APPLE__)
#define CD_STATE_ADDR(reg)                                                     \
    "adrp " reg ", " CD_SYM(call_dump_state) "@PAGE\n"                         \
    "add " reg ", " reg ", " CD_SYM(call_dump_state) "@PAGEOFF\n"
#else
#define CD_STATE_ADDR(reg)                                                     \
    "adrp " reg ", " CD_SYM(call_dump_state) "\n"                              \
    "add " reg ", " reg ", :lo12:" CD_SYM(call_dump_state) "\n"
#endif

#if CALL_DUMP_X18
#define CD_STORE_X18 "str x18, [x19, #" CD_STR(CD_X18) "]\n"
#else
#define CD_STORE_X18
#endif

/*
 * The thunk leaves sp alone, so arguments passed on the stack reach the
 * target where the caller put them. x19 holds the shared state across the
 * call (the target preserves it); the caller's x19 and its return address
 * wait in saved[]. Entry points start with BTI C (hint #34).
 */
__asm__(
    ".text\n"
    ".p2align 2\n"
    ".globl " CD_SYM(call_dump_thunk) "\n"
    CD_SYM(call_dump_thunk) ":\n"
    "hint #34\n"
    CD_STATE_ADDR("x16")
    "str x19, [x16, #" CD_STR(CD_SAVED) "]\n"
    "str x30, [x16, #" CD_STR(CD_SAVED1) "]\n"
    "mov x19, x16\n"
    "ldr x16, [x19, #" CD_STR(CD_TARGET) "]\n"
    "blr x16\n"
    "stp x0, x1, [x19, #0]\n"     "stp x2, x3, [x19, #16]\n"
    "stp x4, x5, [x19, #32]\n"    "stp x6, x7, [x19, #48]\n"
    "stp x8, x9, [x19, #64]\n"    "stp x10, x11, [x19, #80]\n"
    "stp x12, x13, [x19, #96]\n"  "stp x14, x15, [x19, #112]\n"
    "stp x16, x17, [x19, #128]\n"
    CD_STORE_X18
    "stp q0, q1, [x19, #160]\n"   "stp q2, q3, [x19, #192]\n"
    "stp q4, q5, [x19, #224]\n"   "stp q6, q7, [x19, #256]\n"
    "stp q8, q9, [x19, #288]\n"   "stp q10, q11, [x19, #320]\n"
    "stp q12, q13, [x19, #352]\n" "stp q14, q15, [x19, #384]\n"
    "stp q16, q17, [x19, #416]\n" "stp q18, q19, [x19, #448]\n"
    "stp q20, q21, [x19, #480]\n" "stp q22, q23, [x19, #512]\n"
    "stp q24, q25, [x19, #544]\n" "stp q26, q27, [x19, #576]\n"
    "stp q28, q29, [x19, #608]\n" "stp q30, q31, [x19, #640]\n"
    "ldr x16, [x19, #" CD_STR(CD_CALLS) "]\n"
    "add x16, x16, #1\n"
    "str x16, [x19, #" CD_STR(CD_CALLS) "]\n"
    "ldr x30, [x19, #" CD_STR(CD_SAVED1) "]\n"
    "ldr x19, [x19, #" CD_STR(CD_SAVED) "]\n"
    "ret\n"
    ".p2align 2\n"
    ".globl " CD_SYM(call_dump_leave_gpr) "\n"
    CD_SYM(call_dump_leave_gpr) ":\n"
    "hint #34\n"
    "ldr x8, [x0]\n"
    "mov w0, #0\n"
    "ret\n"
    ".p2align 2\n"
    ".globl " CD_SYM(call_dump_leave_gpr2) "\n"
    CD_SYM(call_dump_leave_gpr2) ":\n"
    "hint #34\n"
    "ldr x9, [x0]\n"
    "mov w0, #0\n"
    "ret\n"
    ".p2align 2\n"
    ".globl " CD_SYM(call_dump_leave_vec) "\n"
    CD_SYM(call_dump_leave_vec) ":\n"
    "hint #34\n"
    "ldr q16, [x0]\n"
    "mov w0, #0\n"
    "ret\n"
#if CALL_DUMP_X18
    ".p2align 2\n"
    ".globl " CD_SYM(call_dump_leave_x18) "\n"
    CD_SYM(call_dump_leave_x18) ":\n"
    "hint #34\n"
    "ldr x18, [x0]\n"
    "mov w0, #0\n"
    "ret\n"
#endif
);

#if CALL_DUMP_X18
#define CD_FILL_X18 "mov x18, x0\n\t"
#define CD_CLOBBER_X18 "x18",
#else
#define CD_FILL_X18
#define CD_CLOBBER_X18
#endif

#else /* x86-64 */

#define CD_COPY_ARG(i)                                                         \
    "movq " CD_STR(80 + 8 * i) "(%rsp), %r11\n"                                \
    "movq %r11, " CD_STR(8 * i) "(%rsp)\n"

/*
 * The thunk calls the target with a frame of its own, so that each call
 * returns to the instruction after it. It copies the eight stack slots
 * above its return address, where a caller passes the seventh argument and
 * the ones after it, to the bottom of that frame; the test's calls pass at
 * most seven on the stack. rbx holds the shared state across the call (the
 * target preserves it); the caller's rbx waits in saved[0]. Entry points
 * start with ENDBR64.
 */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".globl " CD_SYM(call_dump_thunk) "\n"
    CD_SYM(call_dump_thunk) ":\n"
    "endbr64\n"
    "movq %rbx, " CD_SYM(call_dump_state) "+" CD_STR(CD_SAVED) "(%rip)\n"
    "leaq " CD_SYM(call_dump_state) "(%rip), %rbx\n"
    "subq $72, %rsp\n"
    CD_COPY_ARG(0) CD_COPY_ARG(1) CD_COPY_ARG(2) CD_COPY_ARG(3)
    CD_COPY_ARG(4) CD_COPY_ARG(5) CD_COPY_ARG(6) CD_COPY_ARG(7)
    "callq *" CD_STR(CD_TARGET) "(%rbx)\n"
    "movq %rax, 0(%rbx)\n"  "movq %rcx, 8(%rbx)\n"  "movq %rdx, 16(%rbx)\n"
    "movq %rsi, 24(%rbx)\n" "movq %rdi, 32(%rbx)\n" "movq %r8, 40(%rbx)\n"
    "movq %r9, 48(%rbx)\n"  "movq %r10, 56(%rbx)\n" "movq %r11, 64(%rbx)\n"
    "cmpq $0, " CD_STR(CD_WIDE) "(%rbx)\n"
    "je 1f\n"
    "vmovdqu %ymm0, 72(%rbx)\n"   "vmovdqu %ymm1, 104(%rbx)\n"
    "vmovdqu %ymm2, 136(%rbx)\n"  "vmovdqu %ymm3, 168(%rbx)\n"
    "vmovdqu %ymm4, 200(%rbx)\n"  "vmovdqu %ymm5, 232(%rbx)\n"
    "vmovdqu %ymm6, 264(%rbx)\n"  "vmovdqu %ymm7, 296(%rbx)\n"
    "vmovdqu %ymm8, 328(%rbx)\n"  "vmovdqu %ymm9, 360(%rbx)\n"
    "vmovdqu %ymm10, 392(%rbx)\n" "vmovdqu %ymm11, 424(%rbx)\n"
    "vmovdqu %ymm12, 456(%rbx)\n" "vmovdqu %ymm13, 488(%rbx)\n"
    "vmovdqu %ymm14, 520(%rbx)\n" "vmovdqu %ymm15, 552(%rbx)\n"
    "jmp 2f\n"
    "1:\n"
    "movdqu %xmm0, 72(%rbx)\n"   "movdqu %xmm1, 104(%rbx)\n"
    "movdqu %xmm2, 136(%rbx)\n"  "movdqu %xmm3, 168(%rbx)\n"
    "movdqu %xmm4, 200(%rbx)\n"  "movdqu %xmm5, 232(%rbx)\n"
    "movdqu %xmm6, 264(%rbx)\n"  "movdqu %xmm7, 296(%rbx)\n"
    "movdqu %xmm8, 328(%rbx)\n"  "movdqu %xmm9, 360(%rbx)\n"
    "movdqu %xmm10, 392(%rbx)\n" "movdqu %xmm11, 424(%rbx)\n"
    "movdqu %xmm12, 456(%rbx)\n" "movdqu %xmm13, 488(%rbx)\n"
    "movdqu %xmm14, 520(%rbx)\n" "movdqu %xmm15, 552(%rbx)\n"
    "2:\n"
    "addq $1, " CD_STR(CD_CALLS) "(%rbx)\n"
    "addq $72, %rsp\n"
    "movq " CD_STR(CD_SAVED) "(%rbx), %rbx\n"
    "ret\n"
    ".p2align 4\n"
    ".globl " CD_SYM(call_dump_leave_gpr) "\n"
    CD_SYM(call_dump_leave_gpr) ":\n"
    "endbr64\n"
    "movq (%rdi), %r11\n"
    "xorl %eax, %eax\n"
    "ret\n"
    ".p2align 4\n"
    ".globl " CD_SYM(call_dump_leave_gpr2) "\n"
    CD_SYM(call_dump_leave_gpr2) ":\n"
    "endbr64\n"
    "movq (%rdi), %r10\n"
    "xorl %eax, %eax\n"
    "ret\n"
    ".p2align 4\n"
    ".globl " CD_SYM(call_dump_leave_vec) "\n"
    CD_SYM(call_dump_leave_vec) ":\n"
    "endbr64\n"
    "movdqu (%rdi), %xmm15\n"
    "xorl %eax, %eax\n"
    "ret\n");

#endif

/*
 * Call fn() with the caller-saved registers pre-filled with PATTERN and
 * store the registers fn's one CAPTURED call leaves to *d. Everything the
 * call can change is declared clobbered, so the compiler keeps nothing
 * live in those registers.
 */
__attribute__((noinline))
static void call_and_dump(void (*fn)(void), dump *d)
{
    call_dump_state.calls = 0;
#if defined(__aarch64__)
    {
        register void (*f)(void) __asm__("x20") = fn;
        register call_dump_shared *p __asm__("x19") = &call_dump_state;

        __asm__ __volatile__(
            "mov x0, #0xa5a5\n\t"
            "orr x0, x0, x0, lsl #16\n\t"
            "orr x0, x0, x0, lsl #32\n\t"
            "mov x1, x0\n\t"  "mov x2, x0\n\t"  "mov x3, x0\n\t"  "mov x4, x0\n\t"
            "mov x5, x0\n\t"  "mov x6, x0\n\t"  "mov x7, x0\n\t"  "mov x8, x0\n\t"
            "mov x9, x0\n\t"  "mov x10, x0\n\t" "mov x11, x0\n\t" "mov x12, x0\n\t"
            "mov x13, x0\n\t" "mov x14, x0\n\t" "mov x15, x0\n\t" "mov x16, x0\n\t"
            "mov x17, x0\n\t"
            CD_FILL_X18
            "str x29, [sp, #-16]!\n\t"
            "mov x21, sp\n\t"
            "str x21, [x19, #" CD_STR(CD_SP) "]\n\t"
            "mov x21, x0\n\t" "mov x22, x0\n\t" "mov x23, x0\n\t" "mov x24, x0\n\t"
            "mov x25, x0\n\t" "mov x26, x0\n\t" "mov x27, x0\n\t" "mov x28, x0\n\t"
            "mov x29, x0\n\t"
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
            "ldr x29, [sp], #16"
            : "+r"(f), "+r"(p)
            :
            : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
              "x12", "x13", "x14", "x15", "x16", "x17", CD_CLOBBER_X18
              "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x30",
              "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11",
              "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22",
              "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
              "memory", "cc");
    }
#else
    /*
     * rbx holds the shared state and r12 the caller's rsp across the
     * call; the stack is moved below the red zone and aligned to 32 bytes
     * first. The ymm fill uses AVX instructions only.
     */
    call_dump_state.wide = (uint64_t)wide_vectors;
    if (wide_vectors) {
        __asm__ __volatile__(
            "movq %%rsp, %%r12\n\t"
            "subq $256, %%rsp\n\t"
            "andq $-32, %%rsp\n\t"
            "pushq %%rbp\n\t"
            "pushq %%rbp\n\t"
            "movq %%rsp, " CD_STR(CD_SP) "(%%rbx)\n\t"
            "movq $0xa5a5a5a5a5a5a5a5, %%rcx\n\t"
            "movq %%rcx, %%rbp\n\t" "movq %%rcx, %%r13\n\t" "movq %%rcx, %%r14\n\t"
            "movq %%rcx, %%r15\n\t"
            "movq %%rcx, %%rdx\n\t" "movq %%rcx, %%rsi\n\t" "movq %%rcx, %%rdi\n\t"
            "movq %%rcx, %%r8\n\t"  "movq %%rcx, %%r9\n\t"  "movq %%rcx, %%r10\n\t"
            "movq %%rcx, %%r11\n\t"
            "vmovq %%rcx, %%xmm0\n\t"
            "vpunpcklqdq %%xmm0, %%xmm0, %%xmm0\n\t"
            "vinsertf128 $1, %%xmm0, %%ymm0, %%ymm0\n\t"
            "vmovdqa %%ymm0, %%ymm1\n\t"   "vmovdqa %%ymm0, %%ymm2\n\t"   "vmovdqa %%ymm0, %%ymm3\n\t"
            "vmovdqa %%ymm0, %%ymm4\n\t"   "vmovdqa %%ymm0, %%ymm5\n\t"   "vmovdqa %%ymm0, %%ymm6\n\t"
            "vmovdqa %%ymm0, %%ymm7\n\t"   "vmovdqa %%ymm0, %%ymm8\n\t"   "vmovdqa %%ymm0, %%ymm9\n\t"
            "vmovdqa %%ymm0, %%ymm10\n\t"  "vmovdqa %%ymm0, %%ymm11\n\t"  "vmovdqa %%ymm0, %%ymm12\n\t"
            "vmovdqa %%ymm0, %%ymm13\n\t"  "vmovdqa %%ymm0, %%ymm14\n\t"  "vmovdqa %%ymm0, %%ymm15\n\t"
            "callq *%%rax\n\t"
            "vzeroupper\n\t"
            "popq %%rbp\n\t"
            "popq %%rbp\n\t"
            "movq %%r12, %%rsp"
            : "+a"(fn)
            : "b"(&call_dump_state)
            : "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
              "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
              "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
              "memory", "cc");
    } else {
        __asm__ __volatile__(
            "movq %%rsp, %%r12\n\t"
            "subq $256, %%rsp\n\t"
            "andq $-32, %%rsp\n\t"
            "pushq %%rbp\n\t"
            "pushq %%rbp\n\t"
            "movq %%rsp, " CD_STR(CD_SP) "(%%rbx)\n\t"
            "movq $0xa5a5a5a5a5a5a5a5, %%rcx\n\t"
            "movq %%rcx, %%rbp\n\t" "movq %%rcx, %%r13\n\t" "movq %%rcx, %%r14\n\t"
            "movq %%rcx, %%r15\n\t"
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
            "popq %%rbp\n\t"
            "popq %%rbp\n\t"
            "movq %%r12, %%rsp"
            : "+a"(fn)
            : "b"(&call_dump_state)
            : "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
              "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
              "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
              "memory", "cc");
    }
#endif
    if (call_dump_state.calls != 1) {
        printf("FAIL call_and_dump: %u captured calls, the test expects exactly one\n",
               (unsigned)call_dump_state.calls);
        exit(2);
    }
    *d = call_dump_state.regs;
}

#endif /* NIRAPOD_SLHDSA_TESTS_CALL_DUMP_H */
