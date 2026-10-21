- SLH-DSA (FIPS 205) in Jasmin for all twelve parameter sets, on AArch64 and
  x86-64 (`src/slhdsa/`). `make ct` runs the constant-time and speculative
  constant-time checkers on every unit, and `make asm-policy` checks its
  emitted assembly. Memory safety of the Jasmin code has no verdict yet: the
  safety checker reaches none on its exports. The C API, and proofs of the
  core's correctness with their scope, are separate entries in this list.
