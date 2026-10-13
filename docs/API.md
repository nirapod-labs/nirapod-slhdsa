# C API

The library's interface is `include/nirapod_slhdsa.h`. This page explains how
to use it. The header owns the contract of every function; where this
page and the header differ, the header is right and this page is a bug.

## Building and linking

```sh
make JASMINC=/path/to/jasminc            # build/<target>/lib/libnirapod_slhdsa.a
make check JASMINC=/path/to/jasminc      # the tests of this host; the Makefile
                                         # lists them
```

`<target>` is `aarch64-macho`, `aarch64-elf` or `x86_64-elf`, chosen from the
host. `JASMINC` is the Jasmin compiler that `toolchain/build.sh` builds from
the pins under `toolchain/`; the build needs it, a C99 compiler, the
assembler and linker of the platform, and `objcopy` on Linux. Link
`libnirapod_slhdsa.a` and include `nirapod_slhdsa.h`. The library has no
other runtime dependency than the C library and the operating system's
random source.

`libnirapod_slhdsa.a` exports the functions of `nirapod_slhdsa.h` and nothing
else: the build links its objects into one relocatable object and makes every
other symbol local, the Jasmin entry points included. `make check` lists the
archive's global symbols with `nm` and fails on any symbol the header does not
declare (`tests/abi/check-exports.sh`), and fails as well if a control archive
with one extra global function passes that check.

`libnirapod_slhdsa_testing.a` and `capi/testing/nirapod_slhdsa_testing.h`
are for tests. They are built from the same sources with the testing parts
compiled in, which the application library does not contain: the internal
functions of FIPS 205 section 9, key generation from given seeds, signing with
caller-chosen randomness or without the fault check, and every operation on a
chosen hash variant or with a test source of randomness. FIPS 205 section 9
says the internal functions should not be made available to applications; do
not link the testing library into one.

The tests link the testing library, whose public functions are compiled from
the same source as the application library's. The ACVP known answers
(`tests/core/test_acvp.c`) check a subset of the NIST vectors,
`tests/core/acvp-subset.txt`, on it.

## Hash variants

Each parameter set is compiled once per hash variant. The variants compute the
same function with different hash kernels; the library picks one per call from
the running CPU's features and caches nothing.

| Target | Variant | Sets | Requires |
|---|---|---|---|
| AArch64, x86-64 | `scalar` | all | nothing beyond the base architecture |
| x86-64 | `avx2` | SHAKE | AVX2, with the YMM state enabled by the operating system |
| x86-64 | `shani` | SHA2 | the SHA extensions and AVX |

On x86-64 a set runs its accelerated variant when the CPU has the feature and
the scalar variant otherwise. `make check` runs every variant the host
supports, and requires the accelerated variants to produce the scalar
variant's keys and deterministic signatures byte for byte.

## Parameter sets and sizes

| Set | `nirapod_slhdsa_set` | public key | secret key | signature |
|---|---|---:|---:|---:|
| SLH-DSA-SHA2-128s  | `NIRAPOD_SLHDSA_SHA2_128S`  | 32 | 64 | 7856 |
| SLH-DSA-SHAKE-128s | `NIRAPOD_SLHDSA_SHAKE_128S` | 32 | 64 | 7856 |
| SLH-DSA-SHA2-128f  | `NIRAPOD_SLHDSA_SHA2_128F`  | 32 | 64 | 17088 |
| SLH-DSA-SHAKE-128f | `NIRAPOD_SLHDSA_SHAKE_128F` | 32 | 64 | 17088 |
| SLH-DSA-SHA2-192s  | `NIRAPOD_SLHDSA_SHA2_192S`  | 48 | 96 | 16224 |
| SLH-DSA-SHAKE-192s | `NIRAPOD_SLHDSA_SHAKE_192S` | 48 | 96 | 16224 |
| SLH-DSA-SHA2-192f  | `NIRAPOD_SLHDSA_SHA2_192F`  | 48 | 96 | 35664 |
| SLH-DSA-SHAKE-192f | `NIRAPOD_SLHDSA_SHAKE_192F` | 48 | 96 | 35664 |
| SLH-DSA-SHA2-256s  | `NIRAPOD_SLHDSA_SHA2_256S`  | 64 | 128 | 29792 |
| SLH-DSA-SHAKE-256s | `NIRAPOD_SLHDSA_SHAKE_256S` | 64 | 128 | 29792 |
| SLH-DSA-SHA2-256f  | `NIRAPOD_SLHDSA_SHA2_256F`  | 64 | 128 | 49856 |
| SLH-DSA-SHAKE-256f | `NIRAPOD_SLHDSA_SHAKE_256F` | 64 | 128 | 49856 |

The same numbers are available as `NIRAPOD_SLHDSA_<SET>_*_BYTES` macros and from
`nirapod_slhdsa_public_key_bytes`, `_secret_key_bytes` and `_signature_bytes`.

## Example

Sign and verify with SLH-DSA-SHAKE-128f and an application context string.
This example is illustrative; `tests/core/test_core.c` exercises the same calls.

```c
#include "nirapod_slhdsa.h"

static const uint8_t context[] = "example.org v1";

int sign_and_check(const uint8_t *msg, size_t msg_len)
{
    uint8_t pk[NIRAPOD_SLHDSA_SHAKE_128F_PUBLIC_KEY_BYTES];
    uint8_t sk[NIRAPOD_SLHDSA_SHAKE_128F_SECRET_KEY_BYTES];
    static uint8_t sig[NIRAPOD_SLHDSA_SHAKE_128F_SIGNATURE_BYTES];

    if (nirapod_slhdsa_keygen(NIRAPOD_SLHDSA_SHAKE_128F, pk, sizeof pk, sk, sizeof sk)
            != NIRAPOD_SLHDSA_OK) {
        return -1;
    }
    if (nirapod_slhdsa_sign(NIRAPOD_SLHDSA_SHAKE_128F, sig, sizeof sig, msg, msg_len,
                            context, sizeof context - 1, sk, sizeof sk) != NIRAPOD_SLHDSA_OK) {
        return -1;
    }
    return nirapod_slhdsa_verify(NIRAPOD_SLHDSA_SHAKE_128F, sig, sizeof sig, msg, msg_len,
                                 context, sizeof context - 1, pk, sizeof pk)
           == NIRAPOD_SLHDSA_OK ? 0 : -1;
}
```

The secret key above lives on the caller's stack; clearing it after use is the
caller's responsibility.

## Status codes

| Status | Value | Returned when |
|---|---:|---|
| `NIRAPOD_SLHDSA_OK` | 0 | success; for verification, the signature is valid |
| `NIRAPOD_SLHDSA_ERROR_INVALID_SIGNATURE` | -1 | verification: the signature is not valid, including a signature of the wrong length (FIPS 205 Algorithm 20, line 1) |
| `NIRAPOD_SLHDSA_ERROR_INVALID_SET` | -2 | the set value is not a `nirapod_slhdsa_set` |
| `NIRAPOD_SLHDSA_ERROR_INVALID_LENGTH` | -3 | a key buffer, or the signature buffer of a signing call, has the wrong length |
| `NIRAPOD_SLHDSA_ERROR_INVALID_CONTEXT` | -4 | the context is longer than 255 bytes |
| `NIRAPOD_SLHDSA_ERROR_INVALID_PREHASH` | -5 | the pre-hash value is not a `nirapod_slhdsa_prehash` |
| `NIRAPOD_SLHDSA_ERROR_NULL_POINTER` | -6 | a required pointer is NULL (a message or context may be NULL only with length 0) |
| `NIRAPOD_SLHDSA_ERROR_ENTROPY` | -7 | the operating system's random source failed |
| `NIRAPOD_SLHDSA_ERROR_FAULT` | -8 | signing: the new signature does not verify under the public key in the secret key, and was withheld |
| `NIRAPOD_SLHDSA_ERROR_OVERLAP` | -9 | an output buffer shares a byte with an input buffer of the same call; nothing was written |

Checks run in this order and the first failure decides the status:
overlapping buffers (among the pointers that are not NULL), NULL pointers,
set, lengths, context length, pre-hash, entropy, and for signing the fault
check of the result. Verification, which has no output, judges the signature,
including its length, only after the others pass.

After a failure, an output buffer is zero if its pointer is not NULL, the set
is valid and the length passed for it is the set's size for that output. Any
other output buffer is not written at all: one passed with a wrong length,
since that length says nothing reliable about the buffer's real size, and
every output of a call with an invalid set or refused for an overlap, since
zeroing an output that overlaps an input would overwrite the input. The
overlap check runs first so that this holds for a call that is also wrong in
another way, a NULL key for example. No check comes after the computation
except the fault check, so a buffer that is not written holds nothing the
library computed.

## Fault check

Every signing function verifies its signature under the public key stored in
the secret key (PK.seed || PK.root) before returning it. A signature that does
not verify is zeroed and the call returns `NIRAPOD_SLHDSA_ERROR_FAULT`.

The published fault attacks on SPHINCS+ signing corrupt the computation of a
tree root inside the hypertree, so that the WOTS+ key one layer up signs a
second value; collecting such faulty signatures leads to forgeries. A faulty
signature of that kind does not verify, so the check withholds it.

Not covered:

- a fault that still yields a valid signature;
- a fault in the check itself, or one that skips it;
- faults during key generation (a faulty key pair is internally consistent and
  passes the check);
- physical side channels (power, electromagnetic emanation).

The check also refuses to sign with a secret key whose PK.root does not belong
to its seeds. FIPS 205 does not ask for it; it costs one verification per
signature, and benchmarks report signing with and without it. For HashSLH-DSA
the verification computes the pre-hash again, so the message is hashed twice
per signature.

A withheld signature is not released, but its computation and its check have
run: their timing shows what a released signature would also show (the FORS
and hypertree indices, the WOTS+ digits of each layer's message, the faulty one
included) and no chain value, FORS secret or authentication path.
`docs/DECLASSIFICATION.md` gives the argument. While the call runs, the
caller's signature buffer holds the signature before it is checked, and a
withheld one until it is zeroed. The signature buffer must therefore not be
readable by anyone else before the call returns: not shared with another
process or a device, for example, while the secret key stays private.

## Timing mode

The contract is in `nirapod_slhdsa.h`, section "Timing". In short: on AArch64
CPUs with FEAT_DIT, key generation and signing (the check of the new signature
included) run with PSTATE.DIT set, and the caller's DIT value is restored on
return. Without FEAT_DIT, and on x86-64, the library changes no mode.
Intel's DOITM is controlled by a model-specific register that user code cannot
write, so enabling it where the CPU has it is the caller's or the operating
system's responsibility. On CPUs without such a control, AMD processors among
them, the caller depends on the CPU executing these instructions in time
independent of their operands. See `capi/timing.c`.

## Known limitations

- On x86-64, the compiled code uses rbp, the frame-pointer register, as a
  general register. Each export saves rbp on entry and restores it before
  returning. While an export runs, rbp does not address a frame record: a
  frame-chain walk taken then (a sampling profiler, a crash reporter, a
  debugger) is unreliable, and in key generation and signing may record a
  value derived from the secret key as if it were a frame address. The cause
  is the compiler's register allocation; `nirapod_slhdsa.h` states it as well.
  On AArch64 the compiled code does not use x29.
- On Linux, linking the library into a program removes the program's
  control-flow protection properties. The objects compiled from Jasmin carry
  no GNU property note, and their entry points do not start with a landing pad
  (`endbr64`, `bti c`). The linker marks a program with a property only when
  every object in it has the property, so a program that links
  `libnirapod_slhdsa.a` loses IBT and SHSTK (Intel CET) on x86-64, and the
  system runs it without shadow stacks even where it would enable them; on
  AArch64, a program otherwise built with them loses BTI and GCS, and runs
  without branch target enforcement or a guarded control stack. `readelf -n`
  on the program shows its properties. macOS does not use these properties.
