# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial development. No release yet.

### Added

- Advanced SIMD for the ARMv8-A target of the pinned Jasmin compiler
  (`toolchain/jasmin/patches-simd/`): the vector registers V0-V31 and their
  calling convention, basic vector operations, the SHA-256, SHA-512 and SHA-3
  instructions, and lane permutations and element moves. The instruction
  semantics are transcribed from the Arm manual and trusted, and their
  data-independent timing holds only while the caller sets PSTATE.DIT; see
  `toolchain/jasmin/PATCHES-SIMD.md`.

### Fixed

- `toolchain/build.sh` writes `cil.sha256`, `admit-scan.log` and
  `eclib-axioms.log` sorted, so that builds of the same compiler on different
  hosts produce byte-identical records. They used to follow the shell's locale
  and the file system's directory order.
- The admit scans of `toolchain/build.sh` read files byte-wise in the C
  locale. In a UTF-8 locale, GNU grep skipped the matching lines of a file
  holding an invalid byte or a NUL, so an admit there could go unlisted.
