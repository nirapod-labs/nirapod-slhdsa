- The hash functions SLH-DSA is built from, in Jasmin for AArch64 and
  x86-64 (`src/hash/`): Keccak-f[1600] and its sponge, SHA3-224,
  SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256 (FIPS 202); SHA-224,
  SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 (FIPS 180-4); HMAC
  and MGF1 over SHA-256 and SHA-512. They are internal to the library; their
  interfaces are in `src/hash/README.md`. `tests/hash/` checks them
  against the NIST CAVP vectors and against OpenSSL. Proofs of the
  functional correctness of some of them, with what they leave out, are
  separate entries in this list.
