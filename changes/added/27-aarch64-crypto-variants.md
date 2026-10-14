- AArch64: each parameter set has a second variant on the crypto
  extensions, chosen at run time when the operating system reports them:
  `sha2` for the SHA2 sets (SHA-256 and SHA-512 instructions; needs
  FEAT_SHA256 and FEAT_SHA512) and `sha3` for the SHAKE sets (Keccak on
  EOR3, RAX1, XAR and BCAX; needs FEAT_SHA3). These kernels are not covered
  by the hash correctness proofs; the scalar variant keeps the portable
  SHA-2 kernels, which are.
