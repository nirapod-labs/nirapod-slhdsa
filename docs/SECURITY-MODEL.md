# Security model

Which values the library protects, from which observer, by what means, and where
that protection ends. Each section states the scope of a claim and links the check
or argument behind it; [STATUS](STATUS.md) has the current results.

## What is secret

| Value | Secret | Why |
| :-- | :-- | :-- |
| SK.seed, SK.prf | yes | they are the private key |
| `opt_rand` of hedged signing | yes | fresh randomness per signature |
| WOTS+ chain values, FORS secrets and tree nodes not in a signature | yes | derived from SK.seed |
| the FORS indices, `idx_tree`, `idx_leaf`, the WOTS+ digits | released | a verifier recomputes them from the signature |
| PK.seed, PK.root, the message, the context, a signature | public | inputs or outputs of the interface |

Every release of a secret-derived value is a `#declassify` in the source with its
argument beside it; [DECLASSIFICATION](DECLASSIFICATION.md) lists all of them. The
argument covers a signature that the fault check withholds as well as one it
returns.

Verification works on public inputs and is not constant-time by contract
(`nirapod_slhdsa.h`).

## Observer

In scope: an attacker who observes software-visible timing of the process, through
execution time, the cache, branch prediction and conditional-branch speculation,
and who chooses messages and contexts.

Out of scope: power, electromagnetic and other physical side channels. Fault
injection is handled only as far as [Faults](#faults) states.

## Constant time

`jasmin-ct` checks every compilation unit of both architectures, 24 each, the
accelerated variants included (`make ct`, CI check `analysis-units`). A PASS means
that no branch condition, loop bound or memory address depends on a value typed
secret, under the security types of the exports in `src/slhdsa/api.jinc` and of the
functions they call. The hash test exports are checked the same way
(`analysis-hash`).

What the result does not cover:

- It is a property of the Jasmin source after type checking. That compilation
  preserves it rests on the compiler's correctness proof for the pinned version,
  not on this check.
- It assumes a safe program, which has not been checked; see
  [Memory safety](#memory-safety).
- A `#declassify` is accepted without judgement by the checker; its justification
  is the written argument.
- Instruction timing is outside the model; see [Instruction timing](#instruction-timing).

## Speculative constant time

`jasmin-ct --sct` checks the same units under a model of mispredicted conditional
branches (Spectre v1): the misspeculation flag is threaded through every function,
and every value reloaded from a spill slot or stack array, and every released
value, is protected with it before it addresses memory or decides a branch. It has
the same limits as the constant-time check. Speculation through other mechanisms,
such as indirect-branch or store-to-load prediction, is not part of this model,
and the speculative guarantees of barrier instructions are an assumption of it
([TOOLCHAIN](TOOLCHAIN.md#assurance-boundary-of-the-toolchain)).

## Instruction timing

The checks above treat arithmetic as constant-time.

- **AArch64.** On CPUs with FEAT_DIT, key generation and signing, the check of the
  new signature included, run with PSTATE.DIT set, and the caller's value is
  restored on return (`capi/timing.c`). `tests/abi/test_registers.c` checks both.
  Without FEAT_DIT the library changes no mode.
- **x86-64.** Intel's DOITM is a model-specific register that user code cannot
  write; enabling it where the CPU has it is the caller's or the operating
  system's task. On CPUs without such a control, AMD processors among them, the
  caller relies on the CPU executing these instructions in time independent of
  their operands.

The emitted code contains no division instruction (`make asm-policy`). The stricter
`--doit` policy of `jasmin-ct` has not been run.

## Memory safety

Not established. `jasmin-checksafety`, the toolchain's checker for out-of-bounds
accesses, uninitialised reads and misalignment, has reached no verdict on these
exports: with its default settings, one run on key generation of one parameter set
went for nearly two hours without a verdict. The tree therefore has no safety
target, and CI reports the check as NOT RUN.

Until it runs, memory safety rests on review and on the tests, and the
constant-time and speculative results above are conditional on it. The C wrapper
checks every buffer length against the set before any call, and the tests include
malformed inputs, overlapping buffers, and builds that fill the checker's
scratch buffers with 0xa5 bytes instead of zeros ([VALIDATION](VALIDATION.md)).

## Secret lifetime

The library keeps nothing between calls. Within a call, the wrapper clears its own
copies of seeds and `opt_rand`, the compiler zeroes each export's stack frame on
return, and caller-saved registers are cleared after every export that reads the
secret key. [API](API.md#what-is-cleared) lists every copy and the test that checks
it. The caller's buffers, and copies made by the operating system or a debugger,
are outside it.

## Faults

Every signing function verifies its new signature under the public key in the
secret key before it returns it, and withholds a signature that does not verify.
This answers the published attacks that fault a tree root inside the hypertree and
combine the faulty signature with a valid one. `tests/negative/test_fault.c`
injects such faults and shows the signature withheld.

Not covered: a fault that still yields a valid signature, a fault in the check or
one that skips it, and faults during key generation.
[API](API.md#fault-check) gives the details and the cost.

## Platform hardening

Two limitations of the compiled code affect programs that link the library:

- On x86-64 the compiled code uses rbp as a general register, so a frame-chain walk
  taken during a call is unreliable and may record a value derived from the secret
  key.
- On Linux the Jasmin objects carry no GNU property note and their entry points no
  landing pad, so a program that links the library loses IBT and shadow stacks on
  x86-64, and BTI and GCS on AArch64.

[API](API.md#known-limitations) describes both.
