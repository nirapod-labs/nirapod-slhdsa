# Jasmin patch series

The pinned compiler is upstream Jasmin at the commit in `PIN` with the
patches listed in `SERIES` applied in that order. `toolchain/build.sh jasmin`
applies them with `git am` to a clean checkout of the pin and builds the
result as upstream does: Rocq proofs, extraction of the compiler, OCaml
build.

A patch is either a commit of an upstream pull request, carried unchanged
until the pin includes it, or a patch of this project, written to be proposed
upstream. A carried commit keeps its author, date and message; for #1594 and
#1625, `git cherry-pick -x` appended the upstream commit it was taken from.
The one carried commit that is not byte-identical to its pull request is
listed under "Identity with the pull requests", with the difference.

Upstream Jasmin is distributed under the MIT licence, reproduced in
`jasmin-license.txt` next to this file from the pinned commit. The patches
modify Jasmin and are distributed under the same terms.

The Advanced SIMD and cryptographic-extension patches for `armv8a`, listed in
`SERIES` after these, are described in `PATCHES-SIMD.md`.

## Series

Pin: `e8f59794c92ce1d8dba49cb087173a49f20a691f` (jasmin-lang/jasmin, main,
2026-10-12). It includes #1616 (conditional select) and #1621
(`jasmin-checksafety --slice`), carried by the previous series, and #1565,
which redefined the instruction descriptors. The open pull requests are
carried at their heads of 2026-10-13: #1624 first, whose commits then apply
with no change, then #1594 and #1625, then the patches of this project in
the order of `SERIES`, with #1632 in the place of the project patch it
replaces.

| Patches | Origin | Content | Proof status |
|---|---|---|---|
| 0001-0006 | PR #1624, head `282fcaa4192e` | LDP and STP; architecture-specific conditions on memory arguments | assembly generation and global-load lowering proved; instruction semantics trusted |
| 0007-0008 | PR #1594, head `a30c006246fc` | Mach-O relocation operators in ARMv8-A assembly | printer only (trusted) |
| 0009-0016 | PR #1625, head `02a2330a04c9` | safety checker: unsound verdicts, false alarms, CallTopHeuristic | safety checker (trusted) |
| 0017 | this project: port of PR #1617, head `00e7e972eeb6` | EXTR, BFC, BFI, BFXIL, SBFX, UBFX | instruction semantics trusted |
| 0018 | this project | safety checker for ARMv8-A | safety checker (trusted) |
| 0019-0020 | PR #1632, head `c0006367ca98`; 0019 differs in one generated line | located error for an instruction argument the target cannot express | `check_rexpr`, `check_lexpr`, `check_fexpr` return the new error; same accepted arguments; theorem statements and proofs unchanged |
| 0021 | this project | ARMv8-A: `a & !b` lowered to BIC | lowering proved |
| 0022 | this project | ARMv8-A: store of an immediate through a scratch register | lowering proved |
| 0023 | this project | ARMv8-A: 32-bit load zero-extended to 64 bits (LDRW, written `LDR <Wt>`) | lowering proved; instruction semantics and printing trusted |
| 0024 | this project | safety checker: abstract values and environments shared when unchanged; relational constraints printed sorted | safety checker (trusted) |
| 0025 | this project | safety checker option `array_track_max_bytes` | safety checker (trusted) |

"Proved" means that the Rocq development of the patched tree, checked by
`make -C proofs all`, covers the change: the compiler correctness theorem is
proved again with it. "Trusted" means the change is outside that theorem:
instruction semantics transcribed from the Arm Architecture Reference Manual,
or hand-written OCaml (printers, analysers). `docs/TOOLCHAIN.md` gives the
whole boundary.

The safety-checker options of 0025, 0026 and 0028 are read from the
checker's JSON configuration file. Their defaults keep the analysis of the
pin, and each non-default value can only add alarms, never remove one.

## Why each change is carried

### #1624, LDP and STP

Load and store a register pair in one instruction. The address of a pair
access must be a base register plus a 7-bit offset scaled by the register
size. The first commit adds conditions on memory arguments that assembly
generation enforces, and 0005 checks the range on the scaled offset; an
address outside the form is rejected by the compiler, not the assembler.

0006 removes the assembly printer's rejection of an LDP whose two
destinations are the same register, an encoding the Arm ARM makes
CONSTRAINED UNPREDICTABLE. Register allocation gives the two destinations
of one instruction distinct registers; `ldp_same_dest.jazz`, which loads
both into one variable, compiles. Without the printer check, that test no
longer fails if the two registers are equal.

### #1594, Mach-O relocation operators

At the pin, `jasminc -arch armv8a` prints the address of a global as
`adrp x, sym` and `add x, x, :lo12:sym`, the ELF syntax, whatever `-system`
says. The macOS assembler rejects `:lo12:`; Mach-O needs `sym@PAGE` and
`sym@PAGEOFF`. macOS on AArch64 is a supported platform and the hash kernels
read constant tables, which are globals. The pull request also adds the
`armv8a-macos` category to the compiler's assembly tests.

Reproducer: `compiler/tests/success/armv8a/global_read.jazz` with
`jasminc -arch armv8a -system macosx`, then
`clang -c -x assembler -target arm64-apple-macos` on the output.

### #1625, safety checker fixes

The verdicts of `jasmin-checksafety` are evidence for this project, so its
known defects are fixed before any verdict is used:

- unsound verdicts: a copy at an unknown slice offset kept the destination
  cells initialized although the source cells read may not be; a loop could
  be found stable before an initialization change was propagated; a memory
  range such as `[-1/0; inf]` was reported with a "safe" verdict;
- false alarms on slices of global tables and on pointers offset by a `for`
  counter;
- the CallTopHeuristic call policy aborted on its first use;
- start-up time quadratic in the size of the global tables.

### 0017, EXTR and bit-field instructions (port of #1617)

UBFX and SBFX extract a bit field in one instruction, BFI and BFXIL insert
one, and EXTR extracts a word from a register pair. Used for index
computations on digest bits and multi-word shifts.

The pull request, by Benjamin Gregoire and Côme Le Breton, declares the
instructions in the descriptor form that preceded the pin. At the pin an
instruction has a total semantics, with its safety condition, its
initialization condition and its well-formedness as separate fields
(`id_semi_total`, `id_err`, `id_init`, `id_wf`), and the pull request does
not compile. 0017 is one commit of this project that ports it: the
instructions, argument kinds, printing, tests and changelog entry are those
of the pull request; EXTR takes its semantics unchanged as
`id_semi_total`. The pull request's semantics of BFC, BFI, BFXIL, SBFX and
UBFX asserted the conditions on their immediates that `id_safe` also
states, with lemmas relating the two; the port keeps the same `id_safe`
conditions and removes the assertions and those lemmas, so the semantics is
total and equal to the old one wherever the conditions hold. 0017 is not
the pull request's code and is replaced by upstream's revision when there
is one.

### 0018, safety checker for ARMv8-A (this project)

At the pin, `jasmin-checksafety -arch armv8a` fails with "the safety checker
is not implemented for ARMv8-A" (`compiler/safetylib/safetyMain.ml`), and the
safety test runner skips ARMv8-A. The patch instantiates the analysis with the
abstraction ARMv7-M and RISC-V already use: the outputs of architecture-
specific operators are unknown, and no comparison or conditional-instruction
heuristic is applied. Unknown outputs can only cause alarms, never hide one;
memory and array accesses, initialization and alignment are checked by the
generic analysis, as on the other architectures.

Tests: the common safety tests now also run on ARMv8-A, and
`compiler/tests/safety/{success,fail}/armv8a/` cover 64-bit memory and array
accesses, alignment, the initialization of the memory LDP reads, and an
operator result used as an index with and without a mask. Upstream status:
not yet proposed.

A known limit of the generic analysis, seen on both architectures and not
addressed by this series: an array that two loops fill at run-time indices,
the second starting where the first stopped, is not recognised as
initialized, and reading it raises an `is_init` alarm although every byte is
written first. The alarm is a loss of precision, not of soundness.
Initializing the array in one pass avoids it.

### #1632, invalid instruction operands

An instruction argument, destination or condition that the target cannot
express, such as the zero-extension of a byte read through a pointer in
`x += (64u) d[0];`, failed at linearization with an internal error
(`linearization: check_rexpr`), on x86-64 and ARMv8-A alike (upstream issue
#1126). The program cannot be compiled as written; the byte must be loaded
into a register first. The pull request reports this as an error of the
program, located at the instruction. In `linearization.v` it adds the error
`invalid_operand` and redefines `check_rexpr`, `check_lexpr` and
`check_fexpr` to return it; each succeeds for exactly the arguments it
accepted before, and the statements and proofs of the theorems that use
them are unchanged. Tests: `compiler/tests/fail/common/bug_1126*.jazz`.

The pull request replaces this project's earlier patch for the same error.

0019 differs from the pull request's commit 67ea654b4 in one line: the
`Compile:` count that `compiler/tests/negative.expected` records goes from
235 to 247 here, from 227 to 239 in the pull request, because 0001-0006 add
eight negative tests before it. The count is generated by the test runner;
the negative test suite checks it. 0020 is the pull request's commit
c0006367c.

### 0021, BIC from an AND with a complemented operand (this project)

At the pin, `u = !b & c` on ARMv8-A failed at assembly generation ("invalid
rexpr for oprd"): the lowering of `&` did not recognise a complemented
operand, although BIC computes exactly `Xn AND NOT Xm`. Both operand orders
are now lowered to BIC with the complemented operand second, and a shift or
rotation of that operand is folded into BIC's shifted-register form, as for
AND. The lowering proof (`armv8a_lowering_proof.v`, `lower_Papp2P`) covers
both orders. Before the patch the same code needed the `#BIC` intrinsic.
Tests: `compiler/tests/success/armv8a/bic_lowering.jazz` (both orders,
shifted operands, a complemented constant `a & !C`), and
`compiler/tests/fail/asmgen/armv8a/bic_two_complements.jazz`: with both
operands complemented (`!a & !b`) one complement remains an expression, and
the program is rejected at assembly generation rather than compiled to a
different operation. Upstream status: not yet proposed.

### 0022, store of an immediate (this project)

A64 has no store of an immediate. At the pin, assigning a constant to memory
or to a stack array on ARMv8-A (`buf[i] = 0x80;`, `[:u64 p + 8] = 0;`, any
access size) remained after lowering and was rejected at linearization. The
lowering now moves the constant to a fresh 64-bit variable, `__wtmp__`, that
the program cannot name, and stores its low bytes with STR, STRH or STRB. In
the lowering proof, the lemma `sem_lower_store_imm` states that the two
instructions end in a state equal to the one the source assignment reaches,
except for that variable; `lower_cassgn_wordP` uses it for this case.
Every such store materializes its constant (a MOVZ/MOVK sequence); a
constant stored many times is cheaper held in a register by the source. Test:
`compiler/tests/success/armv8a/store_imm.jazz`. Upstream status: not yet
proposed.

### 0023, LDRW (this project)

At the pin, `x = (64u)[:u32 p];` on ARMv8-A was rejected: zero-extending
loads were lowered for bytes (LDRB) and halfwords (LDRH) only. `LDR <Wt>`
loads a word and, because a write to a W register clears the upper half,
zero-extends it to 64 bits. The patch adds the mnemonic LDRW for that form.
Like LDRSW, it has a 64-bit destination and is valid at that operand size
only; its description gives the printed name `ldr`, used with the W name of
the destination register. The zero-extending word load is lowered to it,
and the Jasmin EasyCrypt library models it (`op LDRW`). LDRW is also listed
as a load (`armv8a_is_load`), so a zero-extending word load from a global
array is lowered to an address computation followed by the load, like the
other loads. Before the patch the source needed a 32-bit load followed by a
separate zero extension (an extra UXTW). The instruction semantics, its
printing and its EasyCrypt model are trusted, like those of the other
instructions. The lowering proof needs no change; `make -C proofs all`
checks it again with the new case. Test:
`compiler/tests/success/armv8a/ldrw.jazz`, with a load from a pointer and
from a global array. Upstream status: not yet proposed.

### 0024, sharing unchanged abstract values (this project)

APRON's `Abstract1.change_environment` copied the abstract value even when
the environment was unchanged, and the environment of an expression was
rebuilt for every evaluation although its variables are nearly always
present already. The patch returns the value or the environment as it is in
those cases, caches the APRON variable of each analysed variable, and builds
array-cell names without `Format`. The checker never modifies an abstract
value in place, so sharing one is safe, and verdicts are unchanged.

Without the copy, APRON can return the constraints of a relational value in
another order, and the safety report printed them in the order returned.
The patch prints them sorted, so the report depends on the value only. The
expected output of the safety tests (`compiler/tests/safety/run.expected`)
changes in that order alone. Upstream status: not yet proposed.

### 0025, `array_track_max_bytes` (this project)

Every byte of every array is a dimension of the numerical abstract state, and
the cost of each operation grows with the number of dimensions. With the
configuration option `"array_track_max_bytes": n`, the cells of arrays of
more than n bytes are not dimensions: an assignment to such a cell is
dropped, and a read gives the full range of the cell's type. Their
initialization and the bounds of indices into them are still checked. The
default, -1, tracks every array as before. Leaving cells out can only add
alarms. Test: the cram test `compiler/tests/safety/arraytrack.t` (a table
lookup, a masked index and an uninitialized read, with and without the
option). Upstream status: not yet proposed.

## Assembly checks

The compiler's own test configuration (`compiler/config/tests.config`) has
an `armv8a-macos` category, added by #1594, that compiles every ARMv8-A
success test, including those the series adds, with `-system macosx` and
assembles the result with `llvm-mc --triple=arm64-apple-macos`. It runs
with `compiler/scripts/runtest` (Python with PyYAML, and `llvm-mc` on
`PATH`); `toolchain/build.sh test` does not run it.

## Identity with the pull requests

- #1624: 0001-0006 are the pull request's six commits at its head,
  282fcaa, which upstream based on the pin. They apply with no conflict.
- #1594, #1625: each commit was compared with the commit named in its
  `cherry picked from` line, at the heads in the table. Author, date and
  message are equal, and `git patch-id --stable` is equal for all ten.
- #1632: 0020 equals c0006367c. 0019 equals 67ea654b4 in author, date,
  message and every changed line but one, the generated test count
  described in its section.

The pull requests apply in this order with no conflict resolution.

## Considered and not carried

- PR #1618 (UMULL, SMULL, UMADDL, SMADDL): SLH-DSA has no multi-word
  multiplication.
- Rotation by zero on x86-64. `x <<r= 0` is printed as `rol $0, r`, an
  instruction that changes neither the value nor the flags; ARMv8-A drops it.
  It costs one instruction and is avoided in the source.
- Encoding checks for single-register loads and stores. Assembly generation
  accepts any base-plus-displacement address for LDR and STR; `[x0, #32768]`
  for an 8-byte load, for instance, is printed although no A64 encoding has
  that offset. The LLVM assembler (Apple clang for Mach-O,
  `clang --target=aarch64-linux-gnu` for ELF) rejects such an address, so
  with it the defect stops the build and cannot produce a different program;
  the GNU assembler was not tested. Addresses that only fit the unscaled form
  (`[x0, #3]`) are assembled by LLVM as LDUR/STUR, with the same meaning.
