- The hash functions SLH-DSA is built from, in Jasmin for AArch64 and
  x86-64 (`src/jasmin/hash/`): Keccak-f[1600] and its sponge, SHA3-224,
  SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256 (FIPS 202); SHA-224,
  SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 (FIPS 180-4); HMAC
  and MGF1 over SHA-256 and SHA-512. They are internal to the library; their
  interfaces are in `src/jasmin/hash/README.md`. `tests/hash/` checks them
  against the NIST CAVP vectors and against OpenSSL. No proof of their
  functional correctness is in the repository yet.
