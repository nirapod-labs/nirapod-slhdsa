# Jasmin patch series: Advanced SIMD for ARMv8-A

These patches add the AArch64 SIMD&FP register file and Advanced SIMD and
cryptographic-extension instructions to Jasmin's `armv8a` target. They are
listed in `SERIES` after the patches of `patches/` (see `PATCHES.md`), with
their SHA-256, and `build.sh` applies them with `git am` on the same pinned
commit. Like that series they modify Jasmin and are distributed under its MIT
licence.

Upstream's `armv8a` target has only general-purpose registers. The vector
register class and the calling convention, lowering, register allocation,
stack allocation and assembly generation it needs are already generic in
Jasmin (the x86-64 target uses them for its XMM/YMM registers); these patches
fill them in for AArch64 and add the instructions.

## Series

All four are project patches, written for this project and not submitted
upstream.

| Patch | Content | Proof status |
|---|---|---|
| 0001 | SIMD&FP registers V0-V31 as 128-bit vector registers; calling convention; MOV (vector), LDR/STR of a Q register, AND, BIC, ORR, EOR, NOT, ADD, SUB, SHL, USHR, SRI, SLI; lowering of u128 moves, loads, stores and operators; saving of callee-saved vector registers | lowering, linearization and assembly generation proved; instruction semantics trusted |
| 0002 | SHA256H, SHA256H2, SHA256SU0, SHA256SU1, SHA512H, SHA512H2, SHA512SU0, SHA512SU1; lemmas relating them to FIPS 180-4; a known-answer test of whole SHA-256 and SHA-512 digests | instruction semantics trusted; the FIPS 180-4 lemmas are proved about those semantics; the known-answer test checks the semantics against published digests |
| 0003 | EOR3, BCAX, RAX1, XAR | instruction semantics trusted |

Intrinsic names: the bitwise instructions, moves and Q-register loads and
stores take no suffix (`#VEOR`, `#VLDR`); the element-wise instructions take
the arrangement as a suffix (`#VADD_4u32` is `ADD Vd.4S`); the cryptographic
instructions keep their assembly name (`#SHA256H`). An instruction whose
destination is also a source takes it as its first argument:
`d = #SHA256SU0(d, n);`.

### What is proved, what is trusted

Proved, by `make -C proofs all` on the patched tree: the compiler correctness
theorem (`it_compile_prog_to_asmP`) with the patched ARMv8-A parameters
(`armv8a_h_params`). This covers the new lowering cases (each lowered u128
expression computes the value of the source expression), the saving and
restoring of 128-bit registers in function prologues and epilogues, and
assembly generation for the new register class and argument conditions.
`Print Assumptions it_compile_prog_to_asmP` and `Print Assumptions
armv8a_h_params` list only the axioms of the unpatched
development: Rocq's primitive 63-bit integers, `eq_rect_eq`,
`proof_irrelevance`, and Jasmin's label encoding. The patches add no
`Admitted` proof and no `Axiom`.

Trusted, as for every instruction of the target:

- The instruction semantics. Each is a transcription of the operational
  pseudocode of the Arm A64 Instruction Set Architecture (DDI 0602, release
  2026-03), cited beside its description in `armv8a_instr_decl.v` with the
  semantics stated in our own words; the
  word-level helpers are in `armv8a_simd.v`. The transcriptions, the
  encodable operand ranges and the data-independent-time classification
  were checked against Arm's machine-readable release of the same version.
- The encodability conditions on immediates and addresses
  (`armv8a_check_CAimm`, `armv8a_check_CAmem`), transcribed from the same
  document. A condition that is too permissive makes the assembler reject
  the output; it cannot change what an accepted instruction means.
- The assembly printer (`pp_arm_v8a.ml`), which prints a vector operand from
  the element size its description pairs with it: `v0.16b`, `v0.8h`,
  `v0.4s`, `v0.2d`, or `q0`, and an element operand of DUP, INS and UMOV as
  `v0.s[1]` from the register and the index that follows it.
- The EasyCrypt operators of `eclib/JModel_armv8a.ec` used by `jasmin2ec`.
  They are written to match the Rocq semantics; no proof relates the two
  for all inputs. They are checked on concrete vectors (see Tests).
- Alignment: Q-register loads and stores are modelled without an alignment
  requirement, as the general-purpose ones are, which matches the hardware
  for Normal memory when alignment checking is disabled (user mode on Linux
  and macOS).

Proved about the semantics (`proofs/compiler/armv8a_simd_facts.v`, outside
the compiler; `Print Assumptions` reports no axiom): the elements of a packed
vector are the packed words; the SHA-2 functions of the Arm pseudocode are
those of FIPS 180-4; SHA256H and SHA256H2 perform four SHA-256 rounds
(FIPS 180-4, 6.2.2 step 3) and SHA256SU0 followed by SHA256SU1 computes four
message-schedule words (step 1); SHA512H, SHA512H2 and an element-wise
addition perform two SHA-512 rounds and SHA512SU0 followed by SHA512SU1
computes two message-schedule words (6.4.2); XAR by 64 - r rotates each
64-bit lane left by r (the ρ step of Keccak-f[1600], FIPS 202, 3.2.2). The
SHA-2 statements are made both about the helper functions and about the
`id_semi` of the instruction descriptions, so the role of each operand is
part of what is proved. The SHA-512 pair packs the state as
`[a; b]`, `[c; d]`, `[e; f]`, `[g; h]`, first element in element 0:
`SHA512H([g + k1; h + k0], [f; g], [d; e])`, then `SHA512H2` of that,
`[c; d]` and `[a; b]`; `[f; g]` and `[d; e]` are `EXT #8` of adjacent state
registers. These lemmas are about the transcribed semantics; they do not
check the transcription against the hardware.

Not implied: anything about the timing of the instructions beyond what the
architecture states (below), and the behaviour of the D, S, H and B views of
the registers, which no instruction of the series writes.

### Assembling

The SHA-2 and SHA-3 instructions need the corresponding architecture
features enabled in the assembler. Apple's assembler enables them for
`arm64-apple-macos`; for Linux, assemble with
`-march=armv8.2-a+sha2+sha3` or an equivalent `.arch` directive. Running
them requires FEAT_SHA256, FEAT_SHA512 and FEAT_SHA3 on the processor.

### Constant time

The operational information of every instruction of the series in DDI 0602
2026-03 classifies it as a data-independent-time instruction (see About
PSTATE.DIT), so `jasmin-ct --doit` accepts them. The constant-time and
speculative constant-time checkers treat them as other operators: their
outputs carry the join of the security levels of their inputs.

The architecture makes these instructions data-independent-time only while
PSTATE.DIT is set. Compiled Jasmin code does not set PSTATE.DIT, and the
series adds no instruction that could. The caller must set it around calls
that handle secret data and restore it afterwards.

### Calling convention

Vector arguments are passed in V0-V7 and results returned in V0-V3, as in the
procedure call standard for 128-bit short vectors; a function returning
several vectors corresponds to a C function returning a homogeneous
short-vector aggregate of that many 128-bit members, which a C compiler
returns in V0 upward (measured with clang for two and four members).
V8-V15 are callee-saved: the standard requires their low 64 bits to be
preserved, the compiler saves and restores all 128 bits. The other vector
registers are caller-saved.

## Tests

By patch: 0001 `simd_moves.jazz`, `simd_ops.jazz` and five programs under
`fail/asmgen/armv8a/` (Q-register address forms, shift amounts); 0002
`simd_sha2.jazz`, `simd_sha2_kat.jazz` and `exec/exec_armv8a.ml`; 0003
`simd_sha3.jazz` and `xar_rotation_range.jazz`; 0004 `simd_lanes.jazz`,
`vext_index_range.jazz` and `vins_index_range.jazz`.

In the Jasmin tree: `compiler/tests/success/armv8a/simd_moves.jazz`,
`simd_ops.jazz`, `simd_sha2.jazz`, `simd_sha2_kat.jazz`, `simd_sha3.jazz` and
`simd_lanes.jazz` compile for Linux and macOS.
`compiler/tests/exec/exec_armv8a.ml` evaluates `simd_sha2_kat.jazz` with the
semantics of the compiler: SHA-256 and SHA-512 digests of the FIPS 180-4
example messages (the empty message, "abc", and a two-block message),
computed with the SHA-2 instructions, must equal the published digests
(`exec_armv8a.expected`). Eight programs under
`compiler/tests/fail/asmgen/armv8a/` with an unencodable address, shift
amount, rotation or element index are rejected at assembly generation
(`negative.expected`).

Run on an Apple M4 (macOS, native), with harnesses that are not yet part of
this repository:

- every test program of `compiler/tests/success/**/armv8a` compiles to the
  same assembly as with the series of `patches/` alone, for Linux and macOS;
- a differential test executes each instruction and each lowered operator
  natively over random and boundary inputs (about 760 cases per seed, three
  seeds) and compares the result with the Jasmin interpreter, which evaluates
  the extracted Rocq semantics, and with an independent model written from
  the same pseudocode; all three agree. Mutating the extracted semantics of
  one instruction (SRI) makes the test fail on that instruction;
- the known-answer test runs natively: the six digests, returned in V0-V1
  and V0-V3 to a C caller, equal the published ones. Mutating the extracted
  semantics of SHA256H or of SHA512H makes the three digests of that
  algorithm differ, and calling SHA512H with the operands `[e; f]`, `[c; d]`
  in place of `[f; g]`, `[d; e]` makes the SHA-512 digests differ;
- a native test of the calling convention: vector arguments and result,
  calls between Jasmin functions, preservation of V8-V15 by a function that
  uses 30 vector registers, vector stack variables and spills, and every
  accepted address form of a Q-register load and store;
- `jasmin-ct`, `jasmin-ct --doit` and `jasmin-ct --sct` accept a program that
  passes secret data through every instruction and reject a secret address;
- `jasmin2ec` extracts that program in the normal, CT and CTG modes and
  EasyCrypt checks the result;
- for each case of the differential test (three seeds, about 2,300 cases,
  every instruction and lowered operator), EasyCrypt proves by computation
  that the operator expression `jasmin2ec` extracts for it, applied to the
  case's inputs, equals the value the processor produced. For each
  instruction, the same statement with one result bit flipped is rejected.

These runs used the same four patches on the previous pin, 2bf326d5,
before their instruction descriptions were rewritten in the descriptor form
of the current pin; they have not been repeated on the current pin. The
tests in the Jasmin tree are run on the current pin by
`toolchain/build.sh test`.
