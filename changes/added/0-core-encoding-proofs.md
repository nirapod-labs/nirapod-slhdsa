- A model of each parameter set's compilation unit for the x86-64 and
  AArch64 scalar variants (`proofs/extracted/<arch>/<variant>/sets/<set>/`),
  with `SetModel.ec` naming the set's FIPS 205 parameters and array
  theories, so that one proof text is checked against all 24 models
  (`make check-sets`). EasyCrypt proofs on these models that the n-byte
  copy and concatenation, the digest decoding into the tree index, leaf
  index and FORS indices (FIPS 205 Algorithms 4 and 19), the WOTS+ digits
  and checksum (Algorithm 7, lines 1 to 7) and, for the SHA2 sets, the
  compressed address of section 11.2 compute what the specification says,
  with termination. Inventory type names are printed in full. For the
  SHAKE sets, proofs that the one-block tweakable hashes F, PRF and H
  compute section 11.1, given that the model's Keccak-f[1600] is correct.
