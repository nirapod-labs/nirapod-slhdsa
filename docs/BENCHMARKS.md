# Benchmarks

This page describes how the latency, throughput, stack depth and code size of
this library are measured and compared with other SLH-DSA implementations. It
gives the method only. No result is published yet: results will appear here
with the exact revision, hardware and conditions they were measured under.

The harness lives in `bench/`. Each source file opens with a header that gives
its mechanics in detail; this page is the overview.

Throughput is measured as operations per second across several threads, each
on its own buffers (see "Throughput" below). Baselines whose adapters keep
state between calls (OpenSSL, wolfSSL) are measured with one thread only, so
their multi-threaded throughput is reported as not run.

## What is measured

Four workloads per parameter set, for all twelve sets of FIPS 205 Table 2,
through the external interfaces of FIPS 205 section 10:

| Workload | FIPS 205 | This library |
|---|---|---|
| keygen | Algorithm 21, seeds from the operating system | `nirapod_slhdsa_keygen` |
| sign (hedged) | Algorithm 22, `opt_rand` from the operating system | `nirapod_slhdsa_sign` |
| sign (deterministic) | Algorithm 22, `opt_rand` = PK.seed | `nirapod_slhdsa_sign_deterministic` |
| verify | Algorithm 24 | `nirapod_slhdsa_verify` |

The message is 32 bytes (configurable) and the context string is empty. This
library is measured through `include/nirapod_slhdsa.h`, linked from the
application library alone, with the hash variant its dispatch selects for the
CPU. The record names that variant for every set.

The same workloads run through each implementation pinned in
`bench/baselines.lock`: slhdsa-c, the SPHINCS+ team's code on its FIPS 205
branch (the portable reference and the variants for the host architecture),
OpenSSL 3.6.5 and 4.0.3, wolfSSL 5.9.4, and BoringSSL for the two sets it
implements. `bench/baselines.py` fetches them, checks every pin and builds
them: OpenSSL in its default configuration for the host, wolfSSL with its
assembly for the host enabled, BoringSSL in its release configuration.
slhdsa-c and SPHINCS+ are compiled with the flags of their own Makefiles.
Each is reached through the adapter the differential tests already use
(`tests/diff/adapters/`), so the benchmark calls its public API as those tests
do. The one exception is BoringSSL's hedged signing, which goes through
`bench/hedged_boringssl.c` because its adapter cannot pass `opt_rand`.

## Equivalent work

A comparison is like for like only where both sides do the same work. The
differences that remain are stated, not hidden:

- **Signature check.** Every signing function of this library verifies the new
  signature before releasing it (`docs/API.md`, fault check). Its signing
  times therefore include one verification that no baseline performs. The
  testing build reports signing without the check as separate diagnostic rows,
  so the cost of the check is visible, and the record pairs the two within
  each process to give that cost as a ratio. R is computed from the delivered
  API, check included.
- **Timing mode, feature selection and clearing.** On AArch64 CPUs with
  FEAT_DIT, this library's key generation and signing (the check included)
  run with PSTATE.DIT set, and query the operating system for FEAT_DIT on
  every call (`capi/timing.c`). Every operation also queries the CPU features
  on each call to select its hash variant (`capi/dispatch.c`), and key
  generation and signing clear their secret buffers and the registers they
  used before returning (`capi/api.c`). This is part of the delivered API and
  stays in the timed call. No baseline does any of the three: they run with
  the caller's DIT state, which the harness does not change.
- **Randomness.** Key generation and hedged signing include drawing their
  random bytes. This library draws them inside the call. For a baseline that
  takes them as input, the harness draws them with the same operating-system
  call (`getentropy` on macOS, `getrandom` on Linux) inside the timed call.
  BoringSSL takes no `opt_rand` and signs with its own random source; it has no
  deterministic signing, which is reported as not run.
- **OpenSSL.** The EVP interface. For signing and verification, key objects and
  fetched algorithms are made once and reused across calls, as an application
  holding an `EVP_PKEY` would, and the timed calls exclude key import. Key
  generation includes creating its context by algorithm name and exporting
  both raw keys, which the adapter interface asks of every baseline. Hedged
  `opt_rand` is passed in as test entropy rather than drawn from OpenSSL's
  random generator.
- **wolfSSL.** wolfCrypt's SLH-DSA, with key objects reused across calls.
- **SPHINCS+.** One parameter set per build. On its FIPS 205 branch the
  deterministic variant uses `addrnd` = PK.seed, as FIPS 205 does; its master
  branch implements the earlier SPHINCS+ round-3 scheme and is not used.
- **Keys.** Each process makes its own key pair with fresh randomness, so the
  two sides of a ratio sign and verify with different keys. Verification time
  varies a little with the signature; the variation averages out over rounds
  and is part of the spread the verdict below accounts for.
- **Pre-hash.** HashSLH-DSA is not part of these workloads.

## Timing

One call per sample. The clock is read immediately before and after it:

| Platform | Clock |
|---|---|
| macOS | `clock_gettime_nsec_np(CLOCK_UPTIME_RAW)`, nanoseconds, monotonic, not slewed |
| Linux | `clock_gettime(CLOCK_MONOTONIC_RAW)`, nanoseconds, not slewed |
| x86-64, in addition | the time-stamp counter (`LFENCE; RDTSC; LFENCE`), in ticks of its fixed rate |

The time-stamp counter is not the core clock when the frequency changes, so
nanoseconds are the unit of comparison everywhere. The harness reads no
core-cycle counter on AArch64: macOS exposes none to unprivileged code, and on
Linux one needs perf_event access that virtual machines often lack. AArch64
results are in nanoseconds. Each process measures the clock's read overhead
and smallest step, and the record keeps every process's figures, so they can
be set against the shortest operation.

## Sampling and R

For each parameter set, every implementation runs once per round, each in a
fresh process: warm-up calls, then a fixed number of timed calls of each
operation. Before any of them, each process makes a key pair, a signature and
a verification untimed, which also warms the caches and the clock. The order
of implementations rotates from one round to the next, so none always runs
first or last.

R is the latency of this library divided by the latency of a baseline for the
same workload; lower is better. It is computed by paired median: in each round,
the ratio of the two implementations' round medians, and R is the median of
those ratios over all rounds. Pairing within a round cancels drift that is
slower than a round, such as thermal state or background load.

The verdict uses a 95% sign-test confidence interval for the median of the
per-round ratios. With the n ratios sorted as x(1) to x(n), the interval is
[x(k), x(n+1-k)], where k is the largest integer for which the probability
that a binomial variable with n trials and probability 1/2 is at most k-1 does
not exceed 2.5%. The interval then covers the median with at least 95%
probability whatever the distribution of the ratios: for 6 rounds it is
[x(1), x(6)], for 9 rounds [x(2), x(8)], for 15 rounds [x(4), x(12)]. A
comparison is resolved (R < 1 or R > 1) only when this interval excludes 1,
and is reported as inconclusive otherwise. Fewer than 6 rounds always give an
inconclusive verdict, because no such interval exists below 6. When the two
implementations are equally fast, the rule resolves the comparison in at most
5% of runs; the harness's unit tests check this by simulation.

Every R is reported with its interval, the range of its per-round ratios, the
number of rounds, and the spread of the samples within each round. The table
marks, for each workload, the baseline with the lowest median latency.

## Throughput

With `--threads=LIST`, each process also runs each operation for a fixed time
(`--duration`, one second by default) on T threads at once, for every T in
LIST. Each thread has its own copy of the key pair, message and signature and
its own output buffers. The threads make their warm-up calls, are released
together, and call the operation until the time has passed. Throughput is the
number of calls completed by all threads divided by the wall time from the
release to the end of the last call. These processes are not pinned. Throughput
R is the baseline's rate divided by this library's, so lower is better here
too, and the same rounds, rotation and verdict rule apply.

More than one thread requires a backend that keeps no state between calls.
This library, slhdsa-c, SPHINCS+ and BoringSSL qualify. The OpenSSL and wolfSSL
adapters keep the last key object in process-wide variables, so they are
measured with one thread and their multi-threaded rows are reported as not run.
Every row not run carries the reason the benchmark program gave: "keeps state
between calls" for these, or "not offered" for a set or mode an implementation
lacks, such as BoringSSL's deterministic signing.

## Stack and code size

Maximum stack depth is measured per operation by stack painting, the method of
`tests/abi/test_stack.c`: the region below the stack pointer is filled with a
known byte, the operation runs once, and the depth is the distance to the
lowest byte that changed (done with two fill bytes; the larger depth counts).
It is the touched depth, including the harness's own backend frame, and covers
the calling thread's user-space stack with frames in library and C-library
code. A frame byte that is reserved but never written is not seen. It does not
cover heap memory, which this library does not use but some baselines do.

Code size is read from the section headers of the objects in
`libnirapod_slhdsa.a`: executable code, read-only data, writable data and
zero-filled data, for all twelve sets and every hash variant the library
carries for the architecture.

## Conditions for a measurement

A measurement needs a quiet machine: no other workload, the benchmark itself
not run at lowered priority, on mains power, with no thermal throttling from an
earlier job. The harness checks what it can and records the run as a trial,
not a measurement, when the priority is lowered, low-power mode is on, fewer
than 6 rounds ran, the working tree differs from its commit, the Jasmin
compiler binary is not identified, the programs are older than their sources,
or on Linux the processes are not pinned. A trial is rendered under a banner
with its reasons.

Native execution only: an emulated or cross-architecture result is not a
measurement of that architecture. On Linux, pin the processes to one CPU
(`--cpu`) and record the frequency governor; on macOS, which offers no pinning,
the harness requests the user-interactive quality-of-service class, under which
the scheduler prefers performance cores. Results from different machines or
architectures are never presented as a controlled comparison, and continuous
integration timings are never performance evidence.

## Running it

```sh
python3 -I bench/baselines.py fetch  <workdir>
python3 -I bench/baselines.py verify <workdir>
python3 -I bench/baselines.py build  <workdir>
make bench JASMINC=<jasminc> BASELINES=<workdir> \
    BENCH_ARGS="--rounds=15 --samples=7 --threads=1,4"
python3 -I bench/render.py build/<target>/bench.json
```

`python3 -I bench/run.py --help` lists the options: sets, implementations,
operations, rounds, samples, warm-up calls, message length, CPU pinning,
throughput thread counts and duration. `JASMINC` names the compiler binary so
that its SHA-256 is recorded.
`--smoke` runs two sets for two rounds to check that the harness works; its
record is marked as a smoke run and is not a measurement.

The record (`bench.json`) holds every raw sample and every derived statistic,
together with the revision of this tree and a SHA-256 digest of the working
tree (every tracked file and every untracked file `.gitignore` does not
exclude), next to the same digest of the commit, with each differing path
listed. It also holds the SHA-256 of the library and of every benchmark
program, the compilers and flags, each baseline's pin and build options, the
CPU model (on Linux AArch64, from the Main ID Register fields the kernel
reports), core counts, memory, operating system, kernel, virtualisation,
frequency policy and load. It holds no host name, user name or path.
`bench/render.py` prints it as tables with the workload, this library's median
latency, the baseline and its median latency, R, the variability, the CPU and
the revision, followed by throughput, the cost of the fault check, stack depth,
code size, and the identity of every build: this library's library digest,
compiler, flags and Jasmin compiler pins, and each baseline's pin, build
options, compiler, flags and program digest.
