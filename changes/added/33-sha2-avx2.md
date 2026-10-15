- x86-64 builds an `avx2` variant of the SHA2 parameter sets. It computes
  the four-way hashes of WOTS+ and FORS (PRF, F and T_len, four instances
  at a time) with the AVX2 8-way SHA-256 and 4-way SHA-512 kernels, and is
  selected on CPUs that have AVX2 but not the SHA extensions; CPUs with the
  SHA extensions keep `shani`. Keys and signatures are unchanged. Stack use
  is not: on x86-64, key generation at SLH-DSA-SHA2-256s can now take up
  to 26112 bytes and signing up to 27152, from 18216 and 19240
  (`docs/API.md`). The new code has no proof yet; the `scalar` variant is
  unchanged.
