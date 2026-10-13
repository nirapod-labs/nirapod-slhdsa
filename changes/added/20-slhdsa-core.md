- SLH-DSA (FIPS 205) in Jasmin for all twelve parameter sets, on AArch64 and
  x86-64 (`src/slhdsa/`). `make ct` runs the constant-time and speculative
  constant-time checkers on every unit, and `make asm-policy` checks its
  emitted assembly. Memory safety of the Jasmin code is not checked by a tool
  yet, and no proof of its correctness is in the repository. It has no C API
  yet.
