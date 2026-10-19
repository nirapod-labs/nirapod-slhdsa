- A model of each parameter set's compilation unit for the x86-64 and
  AArch64 scalar variants (`proofs/extracted/<arch>/<variant>/sets/<set>/`),
  with `SetModel.ec` naming the set's FIPS 205 parameters and array
  theories, so that one proof text is checked against all 24 models
  (`make check-sets`). Inventory type names are printed in full.
- EasyCrypt proofs on these models, total correctness, that the core
  computes what FIPS 205 specifies: the n-byte copy and concatenation, the
  digest decoding into the tree index, leaf index and FORS indices
  (Algorithms 4 and 19), the WOTS+ digits and checksum (Algorithm 7, lines
  1 to 7) and, for the SHA2 sets, the compressed address of section 11.2;
  the WOTS+ chain and public key from a signature (Algorithms 5 and 8),
  the four-way WOTS+ leaf (Algorithms 6 and 7), XMSS (Algorithms 9 to 11),
  the hypertree (Algorithms 12 and 13), FORS (Algorithms 14 to 17), the
  internal key generation, signing and verification (Algorithms 18 to 20),
  and the external key generation, signing and verification with the
  context and pre-hash framing of M' (Algorithms 21 to 25; the seeds of key
  generation are the caller's).
- Proofs on the same models of every hash these call: the tweakable hashes
  F, PRF, H, T_len and T_k, single-way and four-way, PRF_msg and H_msg
  (sections 11.1 and 11.2), and the twelve pre-hash functions. The
  theorems of `keygen`, `sign`, `verify`, `sign_internal` and
  `verify_internal` therefore have no premise. They hold for a message
  whose buffer does not wrap the address space and that, where SHA-2
  hashes it, is within the FIPS 180-4 length bound the proofs use; no
  buffer on the supported targets comes near it.
- Not covered: the SIMD and CPU-extension variants, which the library
  selects on CPUs that have the extensions, and the C layer, including
  its argument checks and the entropy draw.
