# Security and machine checks

This directory holds the checks that run on the compiled Jasmin units rather
than on their outputs. Each section says what a PASS establishes and what it
does not.

## Constant-time and speculative constant-time (`ct/`)

```sh
make ct JASMINC=... JASMIN_CT=...
```

runs, for every parameter-set unit of the host's target,

- `jasmin-ct`: the constant-time type system. PASS means that no branch
  condition, loop bound or memory address depends on a value typed secret,
  under the security types declared on the exports
  (`src/slhdsa/api.jinc`) and the functions they call. Only those
  observables are in the model; instruction timing is not (see below).
- `jasmin-ct --sct`: the speculative constant-time type system. PASS means the
  same under the model of mispredicted conditional branches (Spectre v1), with
  the misspeculation flag threaded through every function and every value
  reloaded from a spill slot or a stack array protected before it addresses
  memory or decides a branch.
- `jasmin-ct --doit`, after the compiler's `slhlowering` pass: PASS means that
  additionally every instruction that takes a secret operand is one the
  compiler marks data-operand-independent (Intel's DOIT list, Arm's DIT list),
  arithmetic and the speculation operators included. Moves, loads and stores
  are outside this policy, and the marks are the compiler's transcription of
  the vendor lists, not checked here; on AArch64 the emitted code is checked
  against Arm's list directly (`asm/dit.awk`, below). A control file per
  architecture (`ct/controls/`) gives a secret to an unmarked instruction;
  `jasmin-ct` must accept it and `--doit` must reject it.

Scope and limits:

- Both type systems assume a safe program (no out-of-bounds access, no
  division by zero). Safety is a separate check, not run yet (below); until
  it has run, a CT or SCT PASS is conditional on it.
- A declassification is a type escape. The checker accepts it without judging
  it; each one carries its argument at the source site, and
  `docs/DECLASSIFICATION.md` lists them.
- The checks run on the program inside the compiler, not on its output:
  `jasmin-ct` and `--sct` after typing, `--doit` after `slhlowering`. No
  theorem of the pinned compiler carries them to the assembly; its proofs are
  of semantic preservation and state nothing about leakage
  ([TOOLCHAIN](../docs/TOOLCHAIN.md#assurance-boundary-of-the-toolchain)). The passes after `slhlowering` (address
  lowering, stack and register allocation, linearization, stack zeroization,
  assembly generation) are not seen by `--doit`. On AArch64 `asm/dit.awk`
  checks the instructions they emit (below); on x86-64 no check covers them.
  That branches and addresses in the emitted code still depend on no secret
  rests on the type checks and on the compiler, not on a proof.
- Instruction timing: `--doit` restricts which instructions see secrets; that
  they then run in time independent of those secrets needs the CPU's mode. On
  AArch64 the library runs secret computations with PSTATE.DIT set where the
  CPU has FEAT_DIT; on x86-64 the corresponding DOITM mode is the platform's
  responsibility (`capi/timing.c`).

## Stack depth and residue (`tests/abi/test_stack.c`)

Run by `make check`. The test paints the stack below the caller, calls each
of the five exports of every unit, the internal signing and verification
included, and measures the depth it reached and the bytes it left behind that
are neither the paint nor zero. A second binary built from two units compiled
without stack zeroization is the negative control: it must report residue,
otherwise the probe could not detect any. A second scan runs the public
functions on the painted stack and searches it, C frames included, for any
8 consecutive bytes of SK.seed or SK.prf, and of opt_rand where the test
gives it; a copy the test leaves on purpose must be found. A third binary
runs that scan on the application library alone (`test_stack_production`),
so that it judges the code applications link. The method and its limits are
in the test's header.

## Secret-dependent residue (`tests/abi/test_clearing.c`)

Run by `make check`. Each secret-reading operation runs twice from the same
stack depth, on two inputs that differ only in SK.seed, SK.prf and opt_rand,
on a painted stack and through the register capture of
`tests/abi/call_dump.h`, which stores the caller-saved registers the moment
the library function returns. PASS means: no byte below the stack pointer at
the call, C frames and Jasmin frames alike, and no stored register differs
between the two runs, so no value that differs between two secret inputs is
left there, derived values included. A secret-dependent value that happens
to be equal for both inputs is not seen. On the application library the two
inputs differ in PK.seed too (its keys come from key generation), which can
only add differences. It runs key
generation, every signing path (given, deterministic, hedged and pre-hash
opt_rand, the fault check on and off, a signature the check withholds) and
internal signing, for every set and every variant the CPU runs, on the
testing library, and the public functions on the application library. Each
build must find a copy of SK.prf the test leaves in a frame, and copies that
functions called like the library leave in one register each (AArch64 x8,
x9, v16 and, on Linux, x18; x86-64 r11, r10, xmm15 and, with AVX-512,
zmm31) before returning to a caller that stores its status. On x86-64 CPUs
with AVX-512 the stored registers include all of zmm0-zmm31, and the testing
build also checks that `nirapod_slhdsa_clear_registers` removes a copy left
in zmm31; elsewhere the test prints those parts as NOT APPLICABLE. Two
negative controls must find residue in every operation they run: the testing
library with `capi/clear.c` replaced by `tests/abi/clear_skip.c`, which clears
nothing, and the two units compiled without stack zeroization (the latter when
the Jasmin compiler is available). Not inspected: the flags, x18 on macOS, the
AVX-512 mask registers and the state of later x86-64 extensions (APX r16-r31),
and memory outside the probed region.

## Registers after return (`tests/abi/test_registers.c`)

Run by `make check`. An assembly trampoline fills the caller-saved registers
with a pattern, and the capture of `tests/abi/call_dump.h` stores them the
moment the library function returns, before any compiler-generated code of
the test runs. PASS means: the register-clearing routine of `capi/clear.c` zeroes
every register it lists; key generation and every signing path of the C
layer, run on stub exports that leave a marker in every register a callee
may change, return with no register holding it, while a stub called
directly leaves it; no caller-saved register holds 8 consecutive bytes of
SK.seed or SK.prf after key generation or signing through the public API,
while the copies the controls leave in single registers are found.
On AArch64 with FEAT_DIT, stub exports also record PSTATE.DIT: set during
key generation, signing and the check of the new signature, the caller's
value during verification and after every call. On x86-64 CPUs that report
it, the upper ymm state is initial after a call on an AVX variant. It does
not inspect the flags, or registers saved by the operating system.

## Fault check (`tests/negative/test_fault.c`)

Run by `make check` when the Jasmin compiler is available. Test units built
with the hooks of `tests/negative/fault/` flip one bit of the FORS public key
or of a layer-0 XMSS root during signing. PASS means: the faulty signature
departs from the correct one exactly at the layer whose message was
corrupted; released without the check it does not verify; with the check,
pure, pre-hash and internal signing return `NIRAPOD_SLHDSA_ERROR_FAULT` and
leave the output zero. `docs/API.md` states what the check does not cover.

## Memory safety

Not checked by a tool yet. The Jasmin toolchain's safety checker,
`jasmin-checksafety`, establishes the absence of out-of-bounds accesses, reads of
uninitialised values and misaligned accesses by abstract interpretation. It
has not yet reached a verdict on these exports: with its default settings,
a run on key generation of one parameter set went for nearly two hours
without a verdict before it was stopped. This tree therefore has no safety
target, and CI reports the check as NOT RUN.
Until it runs, program safety rests on review and on the tests, and the CT
and SCT results above are conditional on it.

## Assembly policy (`asm/`)

```sh
make asm-policy [JASMINC=...]
```

checks the assembly the library is built from (`asm/check-asm.sh`): every
global symbol is one of the unit's five exports, no division instruction
appears (its timing depends on its operands), and on AArch64 neither the
platform register x18 nor the frame-pointer register x29 is used. The
control-flow rules of `asm/exports.awk` add: every branch and call targets a
label of the unit, none is indirect, and nothing calls out of it; no trap,
system call or, on AArch64, system-register instruction appears, so the
timing mode stays with the C layer; every export runs its speculation
barrier before its first call, and reaches its return only through the
compiler's stack-zeroing epilogue: the export ends at its first RET, every
branch before it lands on a label of the export defined before it, no label
of the export follows it, and no other code branches into the export. No
data directive (`.byte`, `.inst`, `.long` and the like) appears in a code
section, so no instruction escapes these rules as raw bytes. That the
epilogue starts from the entry stack pointer and its size covers the frame
is the compiler's computation, measured by the residue scan of
`tests/abi/test_stack.c`.

On AArch64, `asm/dit.awk` checks every instruction against the list of
data-independent-time instructions of the Arm Architecture Reference Manual
(DDI 0487 M.d, B1.5.6 "About PSTATE.DIT", and the Operational information of
each instruction), form by form, each with the section it comes from. The
only other forms it accepts consume no secret by construction: MOVZ and
MOVN (and MOVK only while it builds such a constant), ADRP, direct branches,
RET, conditional branches, whose flags are public by the constant-time
check, and the barriers DSB, ISB and CSDB. Any other instruction fails the
target, so a new instruction in the emitted code is reviewed against the
manual before it is listed. On the units of this tree every instruction but
those is on Arm's list. Whether the CPU honours DIT is not something the
check can see. x86-64 has no such check of the emitted code; there the
`--doit` result above, on the compiler's marks, is what exists.

Each rule has
negative controls (`asm/check-controls.sh`), files with a single violation of
that rule, and each must be rejected by that rule, or the target fails. An
awk rule that exits with an error fails its file, with a control of its own,
since the lines it did not reach are unchecked. These
are textual checks of the emitted code; they complement, and do not replace,
the constant-time checks above.
