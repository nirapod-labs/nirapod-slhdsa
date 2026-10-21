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

`jasmin-ct` checks every compilation unit, 24 on AArch64 and 30 on x86-64, the
accelerated variants included (`make ct`, CI check `analysis-units`). A PASS means
that no branch condition, loop bound or memory address depends on a value typed
secret, under the security types of the exports in `src/slhdsa/api.jinc` and of the
functions they call. The hash test exports are checked the same way
(`analysis-hash`).

What the result does not cover:

- It is a property of the Jasmin program after type checking. No theorem of the
  pinned compiler carries it to the assembly: the compiler's proofs are of
  semantic preservation and say nothing about leakage
  ([TOOLCHAIN](TOOLCHAIN.md#assurance-boundary-of-the-toolchain)). That the
  emitted code branches and addresses memory as the source does rests on the
  compiler, unproved.
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
the same limits as the constant-time check. The speculative guarantees of barrier
instructions are an assumption of it
([TOOLCHAIN](TOOLCHAIN.md#assurance-boundary-of-the-toolchain)).

Speculation through other mechanisms is not part of this model:

- Return-address prediction (Spectre-RSB). Internal functions are called and
  return with ordinary call and return instructions (`call`/`ret` on x86-64,
  `bl`/`ret` on AArch64), and a return may be mispredicted to a different call
  site. Nothing in the library or in the check prevents this.
- Store-to-load forwarding (Spectre v4): a load may speculatively read a stale
  value before an earlier store to the same address. Speculative store bypass
  disable (SSBD) is the platform's: the library does not set it, and whether a
  process runs with it is up to the operating system and the CPU.
- Indirect-branch prediction. The assembly compiled from Jasmin has no indirect
  branch or call (`make asm-policy`); the C layer is not checked for them, and the
  caller's code and the operating system may have them.

## Instruction timing

The constant-time checks above keep secrets out of branches and addresses.
Which instructions see secrets is checked as follows:

- `jasmin-ct --doit` runs on every unit of both architectures, after the
  compiler has lowered arithmetic and the speculation operators to
  instructions (`make ct`, CI check `analysis-units`). It admits a secret
  operand only in an instruction the compiler marks data-operand-independent,
  after Intel's DOIT and Arm's DIT lists. Moves, loads and stores are outside
  its policy, and the marks are the compiler's, not checked by it. It sees the
  program as it stands after `slhlowering`; what the later passes emit (stack
  and register allocation, linearization, assembly generation) is checked only
  on AArch64, below.
- On AArch64, every instruction of the emitted assembly of every unit is
  checked against the list of data-independent-time instructions in the Arm
  Architecture Reference Manual, DDI 0487 M.d (`analysis/asm/dit.awk`, CI check
  `asm-policy`). All are on that list except MOVZ, MOVN, ADRP, branches, RET and
  the barriers DSB, ISB and CSDB, which read no secret: immediates, addresses,
  public branch conditions and no data. MOVK, listed by DDI 0487 M.d but not by
  Arm's A64 instruction XML, is accepted only while it builds a constant. The
  instructions of the C layer, compiled by the host's C compiler, are not part of
  this check.
- x86-64 has no check of the emitted instructions against Intel's list; the
  `--doit` result rests on the compiler's marks.

That these instructions then run in time independent of their operands is the
CPU's guarantee, under the mode that enables it:

- **AArch64.** On CPUs with FEAT_DIT, key generation and signing, the check of the
  new signature included, run with PSTATE.DIT set, and the caller's value is
  restored on return (`capi/timing.c`). `tests/abi/test_registers.c` checks both.
  Without FEAT_DIT the library changes no mode.
- **x86-64.** Intel's DOITM is a model-specific register that user code cannot
  write; enabling it where the CPU has it is the caller's or the operating
  system's task. On CPUs without such a control, AMD processors among them, the
  caller relies on the CPU executing these instructions in time independent of
  their operands.

The emitted code contains no division instruction and, on AArch64, no
system-register access, so only the C layer sets and restores the timing mode
(`make asm-policy`). What remains with the caller or the platform: a CPU
without FEAT_DIT, where nothing is set and the guarantee is the CPU's alone;
DOITM on Intel CPUs; any x86-64 CPU without such a mode; and whether a given
CPU honours DIT or DOITM as specified, which no check here can observe.

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
On Linux the tests also run under Valgrind's memcheck
([VALIDATION](VALIDATION.md#valgrind-memcheck)), which sees only the accesses
those tests make and does not change the status above.

## Secret lifetime

The library keeps nothing between calls. Within a call, the wrapper clears its own
copies of seeds and `opt_rand`, the compiler zeroes each export's stack frame on
return, and caller-saved registers are cleared after every export that reads the
secret key. [API](API.md#what-is-cleared) lists every copy and the test that checks
it. `tests/abi/test_clearing.c` runs every operation that reads a secret twice, on
inputs that differ only in the secrets, and finds no difference on the stack below
the call or in the caller-saved registers, stored the moment the library function
returns, on every variant of the host. A secret-dependent value that is equal for
the two inputs would not show. The caller's buffers, copies made by the operating
system or a debugger, the flags, and on x86-64 the AVX-512 mask registers and the
state of later extensions such as APX are outside it; on CPUs with AVX-512 the
clearing and the comparison cover all of zmm0-zmm31 ([API](API.md#what-is-cleared)).

## Faults

Every signing function verifies its new signature under the public key in the
secret key before it returns it, and withholds a signature that does not verify.
The check stops a fault only when the fault leaves the signature inconsistent with
the public key, and most faults that enable a forgery do not.

Fault attacks on SPHINCS+ signing, which apply to SLH-DSA unchanged, corrupt the
computation of any tree below the top layer of the hypertree. The WOTS+ key one
layer up then signs a second value, and the faulty signature together with a valid
one under the same WOTS+ key leads to a universal forgery (tree grafting). A. Genêt,
"On Protecting SPHINCS+ Against Fault Attacks", IACR Transactions on Cryptographic
Hardware and Embedded Systems 2023(2), section 4.1, sorts these faults by where they
strike:

- A fault on the path from the signed leaf to the root of a FORS tree or of an
  XMSS tree below the top, the FORS public key and the root included, gives a
  signature that does not verify, and the check withholds it. So it does a fault
  in the message digest, or anywhere in the top XMSS tree, whose root must equal
  PK.root.
- A fault in a node of an authentication path, or anywhere in the subtree below
  one, gives a signature that verifies. The faulty node goes both into the
  authentication path in the signature and into the root that the next layer
  signs, so a verifier recomputes that same root. The check does not stop such a
  signature. It is returned as valid, and it is exploitable: the WOTS+ key above
  has signed a root other than the correct one.

The second kind is the likely outcome. The paper models a fault as making the
output of one hash call, chosen uniformly among all the calls of a signing
operation, random. Under that model a fault gives a signature that verifies with
probability 0.86 to 0.95, and an exploitable one with probability 0.92 to 0.97,
depending on the parameter set (its Table 4, whose parameter sets are those of
FIPS 205).

In this library the undetected kind is somewhat larger than the paper counts. A
tree's signed leaf is computed in the same pass as the tree: the revealed FORS
secret is the value its leaf is hashed from, and each WOTS+ signature value is a
point on the chain that ends in the leaf's public key. A fault in that FORS secret,
or in a WOTS+ chain of the signing key before the position the signature reveals,
also gives a signature that verifies.

`tests/negative/test_fault.c` injects faults of the first kind only, a flipped bit
in the FORS public key or in a layer-0 XMSS root, and shows the signature withheld.

Also not covered: a fault in the check or one that skips it, and faults during key
generation. [API](API.md#fault-check) gives the details and the cost.

The check is the only countermeasure. The library does not compute signatures
redundantly, which is what the paper recommends against faults of the second kind.
Beyond what the check detects, fault injection is outside the threat model,
whether physical (voltage or clock glitches, electromagnetic or laser pulses) or
induced from software (memory disturbance such as Rowhammer, or misuse of
frequency and voltage controls), and so are the physical side channels of
[Observer](#observer).

## Platform hardening

Two limitations of the compiled code affect programs that link the library:

- On x86-64 the compiled code uses rbp as a general register, so a frame-chain walk
  taken during a call is unreliable and may record a value derived from the secret
  key.
- On Linux the Jasmin objects carry no GNU property note and their entry points no
  landing pad, so a program that links the library loses IBT and shadow stacks on
  x86-64, and BTI and GCS on AArch64.

[API](API.md#known-limitations) describes both.
