- EasyCrypt proofs that the Keccak-f[1600] permutation of the single-way
  kernels the scalar variants build, the shared kernel on x86-64 and the
  AArch64 kernel that keeps the state in registers, computes the
  Keccak-f[1600] of the crypto-specs FIPS 202 theories and terminates, on
  the code `jasmin2ec` extracts (`proofs/correctness/hash/`). The AArch64
  kernel is checked on a new model, `proofs/extracted/aarch64/a64scalar/`.
  `ci/kernel_roots.py` checks that the models' kernel roots are those the
  library builds. The kernels on the A64 SHA-3 instructions and the portable
  and AVX2 four-way kernels have no proof yet.
