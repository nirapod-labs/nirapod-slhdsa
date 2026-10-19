# C API

The library's interface is `include/nirapod_slhdsa.h`. This page explains how
to use it and records the facts about it that change with the build: stack use
and what is cleared. The header owns the contract of every function; where this
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

Most tests link the testing library, whose public functions are compiled from
the same source as the application library's. Five test programs link the
application library alone, as do the two built from `README.md`.
`tests/core/test_production.c` runs key generation, hedged and deterministic
signing, pure and pre-hash, and verification for every set, including the
fault check's refusal of a key whose PK.root does not belong to its seeds. The
ACVP known answers (`tests/core/test_acvp.c`, from the subset
`tests/core/acvp-subset.txt`) run on both libraries; in the application
library key generation cannot take given seeds, nor signing a given opt_rand,
and those cases are not run. A negative control (`tests/core/acvp-control.sh`)
requires the known-answer test to reject a case whose expected signature or
verdict was changed. The stack scan below runs on the application library too,
and `tests/negative/test_entropy.c` makes the operating system's random source
fail behind it. `tests/negative/test_buffers.c` signs with every set on
concurrent threads, and with every buffer at each offset from 0 to 15 from a
16-byte boundary on SLH-DSA-SHAKE-128f and SLH-DSA-SHA2-128f. `make check`
also builds the example of `README.md` against the application library and
requires it to print `valid`, and a copy with one signature bit flipped to
print `invalid` and exit 1 (`tests/core/readme-example.py`).

## Hash variants

Each parameter set is compiled once per hash variant. The variants compute the
same function with different hash kernels; the library picks one per call from
the running CPU's features and caches nothing.

| Target | Variant | Sets | Requires |
|---|---|---|---|
| AArch64, x86-64 | `scalar` | all | nothing beyond the base architecture |
| x86-64 | `avx2` | all | AVX2, with the YMM state enabled by the operating system |
| x86-64 | `shani` | SHA2 | the SHA extensions and AVX |
| AArch64 | `sha3` | SHAKE | Advanced SIMD and FEAT_SHA3 |
| AArch64 | `sha2` | SHA2 | Advanced SIMD, FEAT_SHA256 and FEAT_SHA512 |

`avx2` runs the four-way hashes of the hypertree and FORS on AVX2 kernels:
four-way Keccak for the SHAKE sets; for the SHA2 sets, the 8-way SHA-256
kernel on four of its lanes and the 4-way SHA-512 kernel. `shani` runs
SHA-256 on the SHA extensions. A set runs the last variant, in the order of
the table, whose features the CPU has, as the operating system reports them
(`capi/dispatch.c`), and the scalar variant if there is none: an x86-64 SHA2
set takes `shani` where the SHA extensions are present, with or without
AVX2, and `avx2` where only AVX2 is. `make check` runs every variant the
host supports, and requires the accelerated variants to produce the scalar
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
`tests/negative/test_fault.c` injects such faults (a flipped bit in the FORS
public key, or in a layer-0 XMSS root) and shows the signature withheld, and,
with the check switched off through the testing library, released and not
verifying.

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

## Stack use

The library allocates no heap memory. All working memory is on the caller's
stack: the C wrapper's frames plus the frames of the Jasmin export it calls.

`tests/abi/test_stack.c` measures it by stack painting (its header gives the
method). For the Jasmin exports alone, the deepest stack any export reached,
in bytes, over all parameter sets and variants of the architecture:

| Export | AArch64 (macOS) | x86-64 (Linux) | Deepest set |
|---|---:|---:|---|
| key generation | 17984 | 25904 | SLH-DSA-SHA2-256s |
| signing | 18704 | 26544 | SLH-DSA-SHA2-256s |
| verification | 6096 | 6056 | SLH-DSA-SHA2-256f |

On x86-64 the deepest key generation and signing are those of the `avx2`
variant of the SHA2 sets, whose four-way T_len stages the padded messages
of its four instances (`src/slhdsa/thash_sha2_x4/multi/`); the other
x86-64 variants reach 18024 and 18648 bytes.

Measured on these Jasmin sources with the pinned Jasmin toolchain, on an
Apple M4 (macOS) and an AMD EPYC 7763 (Linux, KVM guest). The figures
change with the Jasmin sources and the compiler, and must be measured again
when either changes; `make check` prints them for the build at hand, one line
per export in the output of `test_stack`.

For the public functions, C frames included, the same test built against the
application library runs every function on the painted stack, once as the
host dispatches it (`test_stack_production`), once with the scalar
variant selected for every set (`test_stack_base`) and, on x86-64, once
with the choice of a CPU that has AVX2 and not the SHA extensions
(`test_stack_avx2`). The deepest stack, in bytes, over all parameter sets
and these runs, so over every variant a CPU of the architecture can select:

| Function | AArch64 (macOS) | x86-64 (Linux) | Deepest set |
|---|---:|---:|---|
| `keygen` | 18160 | 26112 | SLH-DSA-SHA2-256s |
| `sign`, `sign_deterministic` | 19248 | 27136 | SLH-DSA-SHA2-256s |
| `hash_sign`, `hash_sign_deterministic` | 19264 | 27152 | SLH-DSA-SHA2-256s |
| `verify` | 6448 | 6520 | SLH-DSA-SHA2-256f |
| `hash_verify` | 6464 | 6520 | SLH-DSA-SHA2-256f |

Measured on the same hosts. The deepest path is the scalar variant on
AArch64; on x86-64 it is the `avx2` variant for key generation and
signing (`test_stack_avx2`) and `shani` for verification. `make check`
prints the figures of the build at hand in the lines starting with
`public-depth`, those of `test_stack_base` just before the line naming
the scalar variant and those of `test_stack_avx2` just before the line
naming the selection without the SHA extensions. One binary can report
figures 16 bytes apart from run to run, depending on where its stack
starts; the table gives the larger.

## What is cleared

| Copy | Where | Cleared by | Checked by |
|---|---|---|---|
| SK.seed, SK.prf, PK.seed drawn for key generation | `buf` in `nirapod_slhdsa_keygen_env` (C stack) | `nirapod_slhdsa_clear` before return | `tests/abi/test_stack.c` secret scan; `tests/abi/test_clearing.c`, below |
| opt_rand of hedged or deterministic signing | `opt_rand` in `nirapod_slhdsa_sign_framed` (C stack) | `nirapod_slhdsa_clear` before return | `tests/abi/test_stack.c` secret scan; `tests/abi/test_clearing.c`, below |
| Working state of the Jasmin code: hash states, chain values, tree nodes, copies of secret-key parts | the export's stack frames | the compiler's stack zeroization (`jasminc -stack-zero loop -stack-zero-size u64`) at export return | `tests/abi/test_stack.c` residue scan; `tests/abi/test_clearing.c`; `make asm-policy`, below |
| Register contents after an export that reads the secret key (keygen, sign and the check of the new signature) | caller-saved registers | `nirapod_slhdsa_clear_registers` (`capi/clear.c` lists the registers) | `tests/abi/test_registers.c`; `tests/abi/test_clearing.c`, below |

What the checks establish, on the host and build they run on:

- Residue scan: after each Jasmin export returns, internal signing and
  verification included, the stack below the caller holds no byte that is
  neither the paint nor zero, outside the return address and the registers
  the export saves on entry (the top 56 bytes on x86-64, 16 on AArch64). A build without stack zeroization run through the same scan
  must show residue, so the scan can see it.
- Secret scan: after keygen and each signing function through the public API,
  no 8 consecutive bytes of SK.seed or SK.prf remain anywhere in the 512 KiB
  below the caller, the C frames included; after signing with a given opt_rand
  through the testing library, none of opt_rand either. A copy the test leaves
  on purpose is found.
- Register check: `nirapod_slhdsa_clear_registers` zeroes the registers it
  lists. The library calls it after every export that reads the secret key:
  key generation, deterministic, hedged and pre-hash signing, and internal
  signing, run on stub exports that load a marker into every register a
  callee may change, leave no register holding the marker, while a stub
  called directly does. After keygen, sign and deterministic hash_sign
  through the public API, no caller-saved register holds 8 consecutive bytes
  of SK.seed or SK.prf.
- Residue comparison: key generation, every signing path (given,
  deterministic, hedged and pre-hash opt_rand, the fault check on and off, a
  signature the check withholds) and internal signing run twice on inputs
  that differ only in SK.seed, SK.prf and opt_rand, for every set and every
  variant the host runs, and the public functions once more on the
  application library. The registers are stored the moment the library
  function returns, before any code of the test runs. No byte of the stack
  below the call and no stored register may differ between the two runs, so
  no value that differs between two secret inputs is left there, values
  derived from them included, in the C frames as in the Jasmin frames. The
  stored registers are x0-x17 and v0-v31 on AArch64, with x18 on Linux, and
  rax, rcx, rdx, rsi, rdi, r8-r11 and xmm0-xmm15 (ymm0-ymm15 with AVX, and
  all of zmm0-zmm31 with AVX-512) on x86-64. A secret-dependent value that
  happens to be equal for the two inputs is not seen. On the application
  library the two keys come from key generation, so the inputs differ in
  PK.seed too, which can only add differences. The same test with the clearing removed from the C layer,
  and on units built without stack zeroization, must find residue, as must
  a copy of SK.prf the test leaves in a frame, and one a function leaves in
  each of three registers (four on Linux AArch64) before returning to a
  caller that stores its status.
- Epilogue check: `make asm-policy` checks on the assembly that every export
  has one RET and reaches it only through the compiler's stack-zeroing loop
  ([analysis](../analysis/README.md#assembly-policy-asm)).

The secret scan looks for the seeds and opt_rand themselves; the residue
scan and the residue comparison cover values derived from them. Not
covered: the caller's own buffers (the secret key, the
message), copies the operating system or a debugger makes (swap, core dumps,
registers saved on a context switch), the flags register, x18 on macOS (the
platform's register, which the library never writes), and on x86-64 CPUs
with AVX-512 the mask registers k0-k7, which are neither cleared nor
inspected, nor is the register state of later extensions, such as APX's
r16-r31 where the operating system enables it. On AVX-512 CPUs `nirapod_slhdsa_clear_registers` zeroes all of
zmm0-zmm31, whatever the variant: the Jasmin code does not use the
registers AVX-512 adds, but the C library's `memcpy` may copy through them,
and the testing library copies the seeds it is given with `memcpy`. Where
the CPU has no AVX-512, `test_clearing` reports that part NOT APPLICABLE.

## Timing mode

The contract is in `nirapod_slhdsa.h`, section "Timing". In short: on AArch64
CPUs with FEAT_DIT, key generation and signing (the check of the new signature
included) run with PSTATE.DIT set, and the caller's DIT value is restored on
return. `tests/abi/test_registers.c` checks both, with the caller's DIT set and
clear: stub exports record the DIT value they run with, set in key generation,
signing and the check, the caller's in verification, and the real functions
must return with the caller's value. Without FEAT_DIT, and on x86-64, the
library changes no mode.
Intel's DOITM is controlled by a model-specific register that user code cannot
write, so enabling it where the CPU has it is the caller's or the operating
system's responsibility. On CPUs without such a control, AMD processors among
them, the caller depends on the CPU executing these instructions in time
independent of their operands. See `capi/timing.c`.

Which instructions the Jasmin code runs on secrets is checked: `jasmin-ct
--doit` on every unit of both architectures, and, on AArch64, every emitted
instruction against Arm's list of data-independent-time instructions
([SECURITY-MODEL](SECURITY-MODEL.md#instruction-timing) states the scope). The
mode itself, and whether the CPU honours it, stay as described above.

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
- Message lengths are not checked against the input limit of SHA-2 (FIPS
  180-4). The correctness proofs cover, for the SHA2 sets, signing and
  verification of messages under 2^61 - 588 bytes, and for the SHA-2 pre-hash
  functions messages under 2^61 bytes, each in a buffer that does not wrap
  the address space ([PROOFS](PROOFS.md#the-code-against-the-specification),
  Domain). No buffer a process on the supported targets can hold comes near
  these lengths.
