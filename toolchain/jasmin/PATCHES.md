# Jasmin patch series

The pinned compiler is upstream Jasmin at the commit in `PIN` with the
patches listed in `SERIES` applied in that order. `toolchain/build.sh jasmin`
applies them with `git am` to a clean checkout of the pin and builds the
result as upstream does: Rocq proofs, extraction of the compiler, OCaml
build.

A patch is either a commit of an upstream pull request, carried unchanged
until the pin includes it, or a patch of this project, written to be proposed
upstream. A carried commit keeps its author, date and message;
`git cherry-pick -x` appended the upstream commit it was taken from. A pull
request merged after the pin is carried as it was merged until the pin moves
past it.

Upstream Jasmin is distributed under the MIT licence, reproduced in
`jasmin-license.txt` next to this file from the pinned commit. The patches
modify Jasmin and are distributed under the same terms.

## Series

Pin: `2bf326d583659c1fbd0e5b90f7c09fe0c0456e35` (jasmin-lang/jasmin, main,
2026-10-12). The six pull requests are applied in pull-request order, as of
2026-10-13, then the project patches. #1621 and #1616 have been merged since
the pin; #1594, #1617, #1624 and #1625 are open. #1616 and #1624 are carried
at an earlier revision of the pull request, written for the pin (see
"Revisions" below).

| Patches | Origin | Content | Proof status |
|---|---|---|---|
| 0001-0002 | PR #1594, head `a30c006246fc` | Mach-O relocation operators in ARMv8-A assembly | printer only (trusted) |
| 0003-0005 | PR #1616, merged as `e8f59794c92c`; carried revision 23c648c, fa89939, abfae7d | CSINC, CSINV, CSNEG, CSET, CSETM; lowering of conditional expressions to them | lowering proved; instruction semantics trusted |
| 0006-0008 | PR #1617, head `00e7e972eeb6` | EXTR, BFC, BFI, BFXIL, SBFX, UBFX | instruction semantics trusted |
| 0009 | PR #1621, merged as `8461b95f2b2f` | `jasmin-checksafety --slice` slices the program | safety checker (trusted) |
| 0010-0015 | PR #1624, head `72c64afbc6cb`; carried revision 34b528f, 10410e0, 72649cd, 61fdb91, 0b1d351, then 72c64af | LDP and STP; architecture-specific conditions on memory arguments | assembly generation and global-load lowering proved; instruction semantics trusted |
| 0016-0023 | PR #1625, head `02a2330a04c9` | safety checker: unsound verdicts, false alarms, CallTopHeuristic | safety checker (trusted) |
| 0024 | this project | safety checker for ARMv8-A | safety checker (trusted) |
| 0025 | this project | located error for an instruction argument that is not an operand | `check_rexpr` redefined to return the new error; same accepted arguments; theorem statements and proofs unchanged |
| 0026 | this project | ARMv8-A: `a & !b` lowered to BIC | lowering proved |

"Proved" means that the Rocq development of the patched tree, checked by
`make -C proofs all`, covers the change: the compiler correctness theorem is
proved again with it. "Trusted" means the change is outside that theorem:
instruction semantics transcribed from the Arm Architecture Reference Manual,
or hand-written OCaml (printers, analysers). `docs/TOOLCHAIN.md` gives the
whole boundary.

## Why each change is carried

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

### #1616, conditional select

CSET and CSETM turn a comparison into 0/1 or 0/-1 without a branch, and a
conditional expression `c ? a : b` on registers is lowered to the CSEL family
instead of needing intrinsics. Used for branch-free results and masks.

### #1617, EXTR and bit-field instructions

UBFX and SBFX extract a bit field in one instruction, BFI and BFXIL insert
one, and EXTR extracts a word from a register pair. Used for index
computations on digest bits and multi-word shifts.

### #1621, `jasmin-checksafety --slice`

At the pin the option only selects which export functions are analysed; the
analysis still runs over the whole program, every global table included. The
patch restricts the program to the selected functions and their dependencies
first, as `jasminc -slice` does. The pull request was squash-merged into main
as 8461b95f2 on 2026-10-12; 0009 is that commit. Its last commit removed the
test it had added, so 0009 adds no test.

### #1624, LDP and STP

Load and store a register pair in one instruction. The address of a pair
access must be a base register plus a 7-bit offset scaled by the register
size. The first commit adds conditions on memory arguments that assembly
generation enforces, and 0014 checks the range on the scaled offset;
an address outside the form is rejected by the compiler, not the assembler.

0015 removes the assembly printer's rejection of an LDP whose two
destinations are the same register, an encoding the Arm ARM makes
CONSTRAINED UNPREDICTABLE. Register allocation gives the two destinations
of one instruction distinct registers; `ldp_same_dest.jazz`, which loads
both into one variable, compiles. Without the printer check, that test no
longer fails if the two registers are equal.

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

### 0024, safety checker for ARMv8-A (this project)

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

### 0025, invalid instruction operands (this project)

An instruction argument that is not an operand of the target, such as the
zero-extension of a byte read through a pointer in `x += (64u) d[0];`, failed
at linearization with the internal error `linearization: check_rexpr`, on
x86-64 and ARMv8-A alike (upstream issue #1126, open). Neither instruction set
has an addition whose operand zero-extends a memory byte, so the program
cannot be compiled as written; the byte must be loaded into a register first.
The patch reports this as an error of the program, located at the
instruction, printing the argument and the fix. In `linearization.v`, the
patch adds the error `invalid_operand` and redefines `check_rexpr` to
return it, built from the argument it rejects. The check succeeds for
exactly the arguments it accepted before and its type is unchanged; the
statements and proofs of the theorems that use it are unchanged.

Tests: `compiler/tests/fail/linearization/{x86-64,armv8a}/zext_load_operand.jazz`;
the expected output of the existing
`fail/stack_allocation/x86-64/reg_var_expected.jazz` changes from the internal
error to the new message. Upstream status: not yet proposed.

### 0026, BIC from an AND with a complemented operand (this project)

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

## Revisions

Between the pin and dd35a2bb, a later commit of main, upstream redefined the
instruction descriptors: an instruction now has a total semantics with its
safety and initialization conditions as separate fields (`id_semi_total`,
`id_err`, `id_init` and `id_wf` replace `id_semi`, `id_semi_errty` and
`id_semi_safe`). On 2026-10-12 #1616 and #1624 were re-committed onto
dd35a2bb in that form, and #1616 was merged so. Instructions declared in
that form do not compile at the pin. This series carries the revision of
each pull request written for the pin's descriptors:

- #1616: 23c648c, fa89939, abfae7d (2026-10-05, on a6daed0). The merged
  commits 2b9b564, 5fd7f8a and e8f5979 equal the last head, b9ef826, commit
  for commit. Against them the carried revision differs in the descriptor
  fields, in four constants written `1%R` and `0%R` instead of `1%w` and
  `0%w`, and in context lines that main changed. A revision of 2026-10-12
  added CNEG in a fourth commit; the merged pull request does not have it.
- #1624: 34b528f, 10410e0, 72649cd, 61fdb91, 0b1d351 (2026-10-07, on the
  pin), then 72c64af from the current head. The current head re-commits
  the first five onto dd35a2bb; the first two differ from the carried ones
  in the descriptor fields and in context only, and the other three are
  equal.

GitHub still serves the carried commits (`git fetch` of
https://github.com/jasmin-lang/jasmin with the full commit id). When the pin
moves past dd35a2bb, the merged commits and current heads replace them.

## Assembly checks

The compiler's own test configuration (`compiler/config/tests.config`) has
an `armv8a-macos` category, added by #1594, that compiles every ARMv8-A
success test, including those the series adds, with `-system macosx` and
assembles the result with `llvm-mc --triple=arm64-apple-macos`. It runs
with `compiler/scripts/runtest` (Python with PyYAML, and `llvm-mc` on
`PATH`); `toolchain/build.sh test` does not run it.

## Conflicts

The pull requests were written against different upstream commits. Where two
of them, or one of them and the pin, change the same lines, the resolution
keeps both changes:

- 0003 (#1616, revision of 2026-10-05): the mnemonic lists of
  `proofs/compiler/armv8a_instr_decl.v`, where the pin already has CMN (from
  #1604, merged after that revision was written): `CMP; CMN; TST` and
  `CSEL; CSINC; CSINV; CSNEG; CSET; CSETM`.
- 0011 (#1624): the same lists, which by then also hold the #1616 and #1617
  entries, gain LDP and STP. In `compiler/src/pp_arm_v8a.ml` the ADR case
  keeps the #1594 form `pp_ADR (pp_asm_arg dst) r`, followed by the LDP case
  of #1624.
- 0015 (#1624): the LDP case it removes follows that ADR case, which keeps
  the #1594 form.

## Identity with the pull requests

Each carried commit was compared with the upstream commit named in its
`cherry picked from` line: for #1621 the merge commit on main, for #1616 and
#1624 the revisions described above, otherwise the head of the pull request.
Author, date, subject and message, co-author lines included, are equal for
all 23. `git patch-id --stable` is equal for 18; for 0003, 0006, 0007, 0011
and 0015 the lines added and removed are equal file by file and only context
differs.

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
