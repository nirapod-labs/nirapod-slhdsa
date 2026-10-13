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

Scope and limits:

- Both type systems assume a safe program (no out-of-bounds access, no
  division by zero). Safety is a separate check, not run yet (below); until
  it has run, a CT or SCT PASS is conditional on it.
- A declassification is a type escape. The checker accepts it without judging
  it; each one carries its argument at the source site, and
  `docs/DECLASSIFICATION.md` lists them.
- The checks run on the source after typing. That the compiler preserves the
  property down to assembly is a claim of the compiler's own proofs for the
  pinned version, not of this check.
- Instruction timing: the default policy treats arithmetic as constant-time.
  On AArch64 the library runs secret computations with PSTATE.DIT set where
  the CPU has FEAT_DIT; on x86-64 the corresponding DOITM mode is the
  platform's responsibility (`capi/timing.c`). The stricter `--doit` policy
  has not been run.

## Stack depth and residue (`tests/abi/test_stack.c`)

Run by `make check`. The test paints the stack below the caller, calls each
export, and measures the depth it reached and the bytes it left behind that
are neither the paint nor zero. A second binary built from two units compiled
without stack zeroization is the negative control: it must report residue,
otherwise the probe could not detect any. A second scan runs the public
functions on the painted stack and searches it, C frames included, for any
8 consecutive bytes of SK.seed or SK.prf, and of opt_rand where the test
gives it; a copy the test leaves on purpose must be found. The method and
its limits are in the test's header.

## Registers after return (`tests/abi/test_registers.c`)

Run by `make check`. An assembly trampoline fills the caller-saved registers
with a pattern, calls, and stores them before any compiler-generated code
runs. PASS means: the register-clearing routine of `capi/clear.c` zeroes
every register it lists; key generation and every signing path of the C
layer, run on stub exports that leave a marker in every register a callee
may change, return with no register holding it, while a stub called
directly leaves it; no caller-saved register holds 8 consecutive bytes of
SK.seed or SK.prf after key generation or signing through the public API.
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
platform register x18 nor the frame-pointer register x29 is used. Each rule has
negative controls (`asm/check-controls.sh`), files with a single violation of
that rule, and each must be rejected by that rule, or the target fails. These
are textual checks of the emitted code; they complement, and do not replace,
the constant-time checks above.
