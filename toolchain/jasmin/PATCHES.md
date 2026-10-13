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

No patch is applied yet.

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
