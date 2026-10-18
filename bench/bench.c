/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * bench.c
 * =======
 *
 * Latency and stack depth of one implementation's SLH-DSA operations, for
 * one parameter set per run. bench/run.py starts this program once per
 * implementation, set and round, and computes the statistics; this program
 * only measures and prints raw observations, one JSON object per line.
 *
 * Usage:
 *
 *     bench [--variant=V] --describe
 *     bench [--variant=V] --set=NAME --ops=LIST --warmup=W --samples=N
 *           [--mlen=L]
 *     bench [--variant=V] --stack --set=NAME --ops=LIST
 *     bench --throughput --threads=T --duration-ms=D --set=NAME --ops=LIST
 *           [--warmup=W] [--mlen=L]
 *
 *     LIST is a comma-separated subset of keygen, sign, sign-det, verify,
 *     sign-unchecked and sign-det-unchecked (see backend.h).
 *
 * Inputs. The message is mlen bytes (default 32) of a fixed pattern, the
 * context string is empty. A key pair is made with the backend's own
 * keygen before any timing, and verification checks a signature made
 * with it, deterministic where the backend offers that mode. Every timed
 * call must succeed; the run stops at the first failure, so no row times
 * an error path. The untimed setup (one keygen, one signature, one
 * verification) runs before any timed call.
 *
 * Timing. Each operation runs W times untimed, then N times timed, one
 * call per sample, in the order given by --ops. The clock is read just
 * before and just after each call:
 *
 *     macOS       clock_gettime_nsec_np(CLOCK_UPTIME_RAW): nanoseconds from
 *                 the system's monotonic counter, which does not run while
 *                 the system sleeps and is not slewed
 *     Linux       clock_gettime(CLOCK_MONOTONIC_RAW): nanoseconds, not
 *                 slewed by time adjustment
 *     x86-64      in addition, the time-stamp counter (LFENCE; RDTSC;
 *                 LFENCE): ticks at the counter's fixed rate, which is not
 *                 the core clock under frequency scaling
 *
 * On macOS the program asks for the user-interactive quality-of-service
 * class, under which the scheduler prefers performance cores; macOS offers
 * no core pinning. On Linux, run.py may pin the process to one CPU.
 *
 * The harness reads no core-cycle counter on AArch64: macOS exposes none
 * to unprivileged code, and on Linux one needs perf_event access that
 * virtual machines often lack (CNTVCT_EL0 counts at the fixed system-timer
 * rate). AArch64 results are in nanoseconds. The "timer" line reports the
 * median overhead of one clock read pair, the smallest step the clock
 * showed, measured at startup, and on macOS whether the quality-of-service
 * request was granted; the two times are far below the duration of any
 * operation here.
 *
 * Throughput. --throughput starts T threads, each with its own copy of the
 * key pair, message and signature and its own output buffers. After W
 * untimed calls each, the threads are released together and call the
 * operation until D milliseconds have passed since the release (at least
 * once each). The line reports the calls completed by all threads and the
 * wall time from the release to the end of the last call, so a thread
 * that started late or a last call that overran lowers the rate rather
 * than raising it. T > 1 needs a backend that keeps no mutable state
 * between calls (backend_concurrent).
 *
 * Not run. An operation, set or variant that is not measured gets a line
 * with status "unsupported" and a reason: "not offered" when the backend
 * answers BACKEND_UNSUPPORTED (the implementation or this build lacks the
 * set, mode or variant, as the BoringSSL adapter does for deterministic
 * signing), or "keeps state between calls" when T > 1 and the backend is
 * not concurrent. bench/run.py accepts no other reason.
 *
 * Stack. --stack runs each operation once on a painted stack, the method
 * of tests/abi/test_stack.c: the region below the stack pointer of a
 * non-inlined probe is filled with a canary byte, the operation runs, and
 * the depth is the distance from that stack pointer to the lowest byte
 * that changed. It is done with two canaries (0x5A, 0xA5) and the larger
 * depth is reported, so a frame byte that happens to equal one canary does
 * not shorten the result. The depth covers the user-space stack of the
 * calling thread only: frames of the implementation, of its library code
 * and of the C library it calls, not heap memory and not kernel stacks.
 * A depth equal to the region size means the operation went past it and
 * is reported as a lower bound.
 *
 * Reading memory below the stack pointer is outside the C abstract
 * machine. The accesses are volatile byte accesses with no call in
 * between; this is a measurement of the compiled program.
 */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <pthread.h>

#include "backend.h"

#define MAX_PK 64u
#define MAX_SK 128u
#define MAX_SIG 49856u          /* SLH-DSA-*-256f, FIPS 205 Table 2 */
#define MAX_MSG 4096u
#define MAX_SAMPLES 100000u
#define STACK_REGION (1024u * 1024u)
#define MAX_THREADS 256u
#define THREAD_STACK (8u * 1024u * 1024u)

typedef enum {
    OP_KEYGEN, OP_SIGN, OP_SIGN_DET, OP_VERIFY, OP_SIGN_UNCHECKED, OP_SIGN_DET_UNCHECKED,
    OP_COUNT
} op_id;

static const char *const OP_NAMES[OP_COUNT] = {
    "keygen", "sign", "sign-det", "verify", "sign-unchecked", "sign-det-unchecked"
};

/*
 * The buffers of one caller. The inputs (pk, sk, sig_ref, msg) are made
 * once by the setup and only read by the timed calls, which write the
 * outputs only. The main thread uses main_buf; each throughput thread a
 * copy of its own.
 */
typedef struct {
    uint8_t pk[MAX_PK], sk[MAX_SK], sig_ref[MAX_SIG], msg[MAX_MSG];
    uint8_t pk_out[MAX_PK], sk_out[MAX_SK], sig_out[MAX_SIG];
} buffers;

static buffers main_buf;
static size_t mlen = 32;
static uint64_t ns[MAX_SAMPLES];
#if defined(__x86_64__)
static uint64_t ticks[MAX_SAMPLES];
#endif

int bench_os_entropy(uint8_t *buf, size_t len)
{
#if defined(__APPLE__)
    return getentropy(buf, len) == 0 ? 0 : -1;
#else
    return getrandom(buf, len, 0) == (ssize_t)len ? 0 : -1;
#endif
}

static uint64_t now_ns(void)
{
#if defined(__APPLE__)
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#endif
}

#if defined(__x86_64__)
static uint64_t now_tsc(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__("lfence\n\trdtsc\n\tlfence" : "=a"(lo), "=d"(hi) : : "memory");
    return ((uint64_t)hi << 32) | lo;
}
#endif

static const char *timer_name(void)
{
#if defined(__APPLE__)
    return "clock_gettime_nsec_np(CLOCK_UPTIME_RAW)";
#else
    return "clock_gettime(CLOCK_MONOTONIC_RAW)";
#endif
}

/* One call of op on set with the buffers b; BACKEND_* status. */
static int run_op(int set, op_id op, buffers *b)
{
    switch (op) {
    case OP_KEYGEN:
        return backend_keygen(set, b->pk_out, b->sk_out);
    case OP_SIGN:
        return backend_sign(set, SIGN_HEDGED, b->sk, b->msg, mlen, b->sig_out);
    case OP_SIGN_DET:
        return backend_sign(set, SIGN_DET, b->sk, b->msg, mlen, b->sig_out);
    case OP_SIGN_UNCHECKED:
        return backend_sign(set, SIGN_HEDGED_UNCHECKED, b->sk, b->msg, mlen, b->sig_out);
    case OP_SIGN_DET_UNCHECKED:
        return backend_sign(set, SIGN_DET_UNCHECKED, b->sk, b->msg, mlen, b->sig_out);
    default:
        return backend_verify(set, b->pk, b->msg, mlen, b->sig_ref);
    }
}

/* Inlined, so that it reads the stack pointer of its caller's frame. */
static inline __attribute__((always_inline)) uintptr_t stack_pointer(void)
{
    uintptr_t sp;
#if defined(__aarch64__)
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
#elif defined(__x86_64__)
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(sp));
#else
#error "bench.c: unsupported architecture"
#endif
    return sp;
}

/*
 * One painted call. noinline keeps this frame, and so sp, fixed while it
 * paints, calls and scans; it makes a call, so nothing of its own lives
 * below sp.
 */
__attribute__((noinline))
static size_t painted_depth(int set, op_id op, uint8_t canary, int *status)
{
    volatile uint8_t *base;
    uintptr_t sp = stack_pointer();
    size_t i;

    base = (volatile uint8_t *)(sp - STACK_REGION);
    for (i = 0; i < STACK_REGION; i++) {
        base[i] = canary;
    }
    *status = run_op(set, op, &main_buf);
    for (i = 0; i < STACK_REGION; i++) {
        if (base[i] != canary) {
            return STACK_REGION - i;
        }
    }
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/*
 * Overhead of one read pair (median of 1001) and the smallest non-zero
 * step between consecutive reads.
 */
static void print_timer(const char *qos)
{
    enum { READS = 1001 };
    uint64_t d[READS], step = 0;
    size_t i;

    for (i = 0; i < READS; i++) {
        uint64_t a = now_ns(), b = now_ns();
        d[i] = b - a;
        if (d[i] != 0 && (step == 0 || d[i] < step)) {
            step = d[i];
        }
    }
    qsort(d, READS, sizeof(d[0]), cmp_u64);
    printf("{\"timer\":\"%s\",\"overhead_ns\":%llu,\"step_ns\":%llu,\"tsc\":%s,"
           "\"qos\":\"%s\"}\n",
           timer_name(), (unsigned long long)d[READS / 2], (unsigned long long)step,
#if defined(__x86_64__)
           "true",
#else
           "false",
#endif
           qos);
}

static void print_series(const char *key, const uint64_t *v, size_t count)
{
    size_t i;
    printf(",\"%s\":[", key);
    for (i = 0; i < count; i++) {
        printf(i ? ",%llu" : "%llu", (unsigned long long)v[i]);
    }
    printf("]");
}

static void print_head(int set, const char *set_name, op_id op, const char *status)
{
    printf("{\"impl\":\"%s\",\"variant\":\"%s\",\"set\":\"%s\",\"op\":\"%s\",\"status\":\"%s\"",
           backend_name(), backend_variant(set), set_name, OP_NAMES[op], status);
}

/* The line for an operation that is not run (see "Not run" above). */
static const char NOT_OFFERED[] = "not offered";
static const char KEEPS_STATE[] = "keeps state between calls";

static void print_not_run(int set, const char *set_name, op_id op, const char *reason)
{
    print_head(set, set_name, op, "unsupported");
    printf(",\"reason\":\"%s\"}\n", reason);
}

static int fail(const char *what)
{
    fprintf(stderr, "bench: %s\n", what);
    return 1;
}

static int parse_ops(const char *list, int *ops, size_t *count)
{
    char buf[256];
    char *tok;

    if (strlen(list) >= sizeof(buf)) {
        return -1;
    }
    strcpy(buf, list);
    *count = 0;
    for (tok = strtok(buf, ","); tok != NULL; tok = strtok(NULL, ",")) {
        int k;
        for (k = 0; k < OP_COUNT && strcmp(tok, OP_NAMES[k]) != 0; k++) {
        }
        if (k == OP_COUNT || *count == OP_COUNT) {
            return -1;
        }
        ops[(*count)++] = k;
    }
    return *count ? 0 : -1;
}

static int describe(void)
{
    static const char *const SETS[12] = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f"
    };
    size_t i;

    for (i = 0; i < 12; i++) {
        int set = backend_set_index(SETS[i]);
        if (set >= 0) {
            printf("{\"impl\":\"%s\",\"set\":\"%s\",\"variant\":\"%s\"}\n", backend_name(),
                   SETS[i], backend_variant(set));
        }
    }
    return 0;
}

/*
 * Throughput: the shared start signal and one worker's state. A worker
 * makes its warm-up calls, waits for go, then calls until deadline.
 */
static pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;
static int ready, go;
static uint64_t deadline;

typedef struct {
    pthread_t thread;
    buffers *buf;
    int set, status;
    op_id op;
    unsigned long warmup;
    uint64_t calls, end_ns;
} worker;

static void *work(void *arg)
{
    worker *w = arg;
    unsigned long i;

    w->status = BACKEND_OK;
    for (i = 0; i < w->warmup && w->status == BACKEND_OK; i++) {
        w->status = run_op(w->set, w->op, w->buf);
    }
    pthread_mutex_lock(&start_lock);
    ready++;
    pthread_cond_broadcast(&start_cond);
    while (!go) {
        pthread_cond_wait(&start_cond, &start_lock);
    }
    pthread_mutex_unlock(&start_lock);

    w->calls = 0;
    while (w->status == BACKEND_OK) {
        w->status = run_op(w->set, w->op, w->buf);
        w->end_ns = now_ns();
        if (w->status == BACKEND_OK) {
            w->calls++;
        }
        if (w->end_ns >= deadline) {
            break;
        }
    }
    return NULL;
}

/*
 * threads workers on op for duration_ms; prints one line. 0, or 1 after
 * a failed call or a thread that could not be started.
 */
static int throughput(int set, const char *set_name, op_id op, size_t threads,
                      unsigned long warmup, unsigned long duration_ms)
{
    worker *w = calloc(threads, sizeof(*w));
    buffers *b = calloc(threads, sizeof(*b));
    pthread_attr_t attr;
    uint64_t start, calls = 0, end = 0;
    size_t i, started = 0;
    int st = BACKEND_OK;

    if (w == NULL || b == NULL || pthread_attr_init(&attr) != 0) {
        free(w);
        free(b);
        return fail("throughput: out of memory");
    }
    /* The deepest operation here uses well under 1 MiB of stack. */
    (void)pthread_attr_setstacksize(&attr, THREAD_STACK);
    ready = 0;
    go = 0;
    for (i = 0; i < threads; i++) {
        b[i] = main_buf;
        w[i].buf = &b[i];
        w[i].set = set;
        w[i].op = op;
        w[i].warmup = warmup;
        if (pthread_create(&w[i].thread, &attr, work, &w[i]) != 0) {
            break;
        }
        started++;
    }
    pthread_attr_destroy(&attr);

    pthread_mutex_lock(&start_lock);
    while (ready < (int)started) {
        pthread_cond_wait(&start_cond, &start_lock);
    }
    start = now_ns();
    deadline = start + (uint64_t)duration_ms * 1000000u;
    go = 1;
    pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&start_lock);

    for (i = 0; i < started; i++) {
        pthread_join(w[i].thread, NULL);
        if (w[i].status != BACKEND_OK && st == BACKEND_OK) {
            st = w[i].status;
        }
        calls += w[i].calls;
        end = w[i].end_ns > end ? w[i].end_ns : end;
    }
    if (started == threads && st == BACKEND_UNSUPPORTED) {
        print_not_run(set, set_name, op, NOT_OFFERED);
    } else if (started == threads && st == BACKEND_OK) {
        print_head(set, set_name, op, "ok");
        printf(",\"threads\":%zu,\"duration_ms\":%lu,\"calls\":%llu,\"wall_ns\":%llu,"
               "\"mlen\":%zu,\"warmup\":%lu}\n", threads, duration_ms,
               (unsigned long long)calls, (unsigned long long)(end - start), mlen, warmup);
    }
    free(w);
    free(b);
    if (started != threads) {
        return fail("throughput: a thread could not be started");
    }
    return st == BACKEND_OK || st == BACKEND_UNSUPPORTED ? 0 : fail("a throughput call failed");
}

int main(int argc, char **argv)
{
    const char *variant = NULL, *set_name = NULL, *ops_list = "keygen,sign,sign-det,verify";
    const char *qos = "not applicable";
    unsigned long warmup = 1, samples = 5, threads = 0, duration_ms = 0;
    int describe_only = 0, stack = 0, tput = 0, set, st0, ops[OP_COUNT];
    size_t nops, n, pk_len, sk_len, sig_len, i, k;
    buffers *b = &main_buf;

    for (i = 1; i < (size_t)argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "--variant=", 10) == 0) {
            variant = a + 10;
        } else if (strncmp(a, "--set=", 6) == 0) {
            set_name = a + 6;
        } else if (strncmp(a, "--ops=", 6) == 0) {
            ops_list = a + 6;
        } else if (strncmp(a, "--warmup=", 9) == 0) {
            warmup = strtoul(a + 9, NULL, 10);
        } else if (strncmp(a, "--samples=", 10) == 0) {
            samples = strtoul(a + 10, NULL, 10);
        } else if (strncmp(a, "--mlen=", 7) == 0) {
            mlen = strtoul(a + 7, NULL, 10);
        } else if (strncmp(a, "--threads=", 10) == 0) {
            threads = strtoul(a + 10, NULL, 10);
        } else if (strncmp(a, "--duration-ms=", 14) == 0) {
            duration_ms = strtoul(a + 14, NULL, 10);
        } else if (strcmp(a, "--describe") == 0) {
            describe_only = 1;
        } else if (strcmp(a, "--stack") == 0) {
            stack = 1;
        } else if (strcmp(a, "--throughput") == 0) {
            tput = 1;
        } else {
            return fail("unknown argument (see the header of bench/bench.c)");
        }
    }
    if (samples == 0 || samples > MAX_SAMPLES || mlen > MAX_MSG) {
        return fail("--samples or --mlen out of range");
    }
    if (tput && (threads == 0 || threads > MAX_THREADS || duration_ms == 0 || stack)) {
        return fail("--throughput needs --threads=1..256 and --duration-ms > 0");
    }
#if defined(__APPLE__)
    /*
     * macOS places threads on performance or efficiency cores by quality of
     * service; the highest class asks for performance cores. It is a
     * request, not a pinning; the timer line reports whether it was taken.
     * Throughput threads inherit the class of the thread that creates them.
     */
    qos = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) == 0
              ? "user-interactive" : "request refused";
#endif
    if (parse_ops(ops_list, ops, &nops) != 0) {
        return fail("bad --ops list");
    }
    if (backend_init(variant) != BACKEND_OK) {
        printf("{\"impl\":\"%s\",\"status\":\"unsupported\",\"variant\":\"%s\","
               "\"reason\":\"%s\"}\n", backend_name(), variant ? variant : "", NOT_OFFERED);
        return 0;
    }
    if (describe_only) {
        return describe();
    }
    if (set_name == NULL) {
        return fail("--set is required");
    }
    set = backend_set_index(set_name);
    if (set < 0) {
        printf("{\"impl\":\"%s\",\"set\":\"%s\",\"status\":\"unsupported\",\"reason\":\"%s\"}\n",
               backend_name(), set_name, NOT_OFFERED);
        return 0;
    }
    backend_sizes(set, &n, &pk_len, &sk_len, &sig_len);
    if (pk_len > MAX_PK || sk_len > MAX_SK || sig_len > MAX_SIG) {
        return fail("set sizes exceed the buffers");
    }
    for (i = 0; i < mlen; i++) {
        b->msg[i] = (uint8_t)(0x3b * i + 0x11);
    }
    /* The reference signature is deterministic where the backend offers it. */
    st0 = backend_keygen(set, b->pk, b->sk);
    if (st0 == BACKEND_OK) {
        st0 = backend_sign(set, SIGN_DET, b->sk, b->msg, mlen, b->sig_ref);
        if (st0 == BACKEND_UNSUPPORTED) {
            st0 = backend_sign(set, SIGN_HEDGED, b->sk, b->msg, mlen, b->sig_ref);
        }
    }
    if (st0 == BACKEND_UNSUPPORTED) {
        printf("{\"impl\":\"%s\",\"set\":\"%s\",\"status\":\"unsupported\",\"reason\":\"%s\"}\n",
               backend_name(), set_name, NOT_OFFERED);
        return 0;
    }
    if (st0 != BACKEND_OK || backend_verify(set, b->pk, b->msg, mlen, b->sig_ref) != BACKEND_OK) {
        return fail("setup (keygen, sign, verify) failed");
    }
    if (!stack) {
        print_timer(qos);
    }

    for (k = 0; k < nops; k++) {
        op_id op = (op_id)ops[k];
        int st = BACKEND_OK;

        if (tput) {
            if (threads > 1 && !backend_concurrent()) {
                print_not_run(set, set_name, op, KEEPS_STATE);
                continue;
            }
            if (throughput(set, set_name, op, threads, warmup, duration_ms) != 0) {
                return 1;
            }
            fflush(stdout);
            continue;
        }

        if (stack) {
            size_t d1 = painted_depth(set, op, 0x5A, &st);
            size_t d2 = st == BACKEND_OK ? painted_depth(set, op, 0xA5, &st) : 0;
            if (st == BACKEND_UNSUPPORTED) {
                print_not_run(set, set_name, op, NOT_OFFERED);
                continue;
            }
            if (st != BACKEND_OK) {
                return fail("an operation failed on the painted stack");
            }
            print_head(set, set_name, op, "ok");
            printf(",\"stack_bytes\":%zu,\"region_bytes\":%u,\"lower_bound\":%s}\n",
                   d1 > d2 ? d1 : d2, STACK_REGION,
                   (d1 > d2 ? d1 : d2) >= STACK_REGION ? "true" : "false");
            continue;
        }

        for (i = 0; i < warmup && st == BACKEND_OK; i++) {
            st = run_op(set, op, b);
        }
        if (st == BACKEND_UNSUPPORTED) {
            print_not_run(set, set_name, op, NOT_OFFERED);
            continue;
        }
        for (i = 0; i < samples && st == BACKEND_OK; i++) {
#if defined(__x86_64__)
            uint64_t c0 = now_tsc();
#endif
            uint64_t t0 = now_ns();
            st = run_op(set, op, b);
            uint64_t t1 = now_ns();
#if defined(__x86_64__)
            ticks[i] = now_tsc() - c0;
#endif
            ns[i] = t1 - t0;
        }
        if (st == BACKEND_UNSUPPORTED && i == 1) {
            /* Without warm-up calls, the first timed call is the probe. */
            print_not_run(set, set_name, op, NOT_OFFERED);
            continue;
        }
        if (st != BACKEND_OK) {
            return fail("a timed operation failed");
        }
        print_head(set, set_name, op, "ok");
        printf(",\"mlen\":%zu,\"warmup\":%lu", mlen, warmup);
        print_series("ns", ns, samples);
#if defined(__x86_64__)
        print_series("tsc", ticks, samples);
#endif
        printf("}\n");
        fflush(stdout);
    }
    return 0;
}
