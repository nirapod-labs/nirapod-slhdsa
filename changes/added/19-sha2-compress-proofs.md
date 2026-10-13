- Proofs that `_sha256_compress` and `_sha512_compress`, the one-block
  entry points of the portable SHA-2 kernels, compute the FIPS 180-4
  compression function and terminate, on the code `jasmin2ec` extracts for
  x86-64 and for AArch64 (`proofs/correctness/hash/`), with EasyCrypt
  specifications of SHA-2, HMAC, MGF1 and FIPS 202 on byte strings
  (`proofs/spec/hash/`; FIPS 202 from formosa-crypto/crypto-specs, imported
  unchanged in `third_party/crypto-specs/`). The entry points that read
  blocks from memory and the rest of the hash layer have no proof yet.
  `make -C proofs check-extraction` fails when the committed models no
  longer match the hash sources, and `make -C proofs check-inventory` when
  an axiom, a claimed theorem statement or a definition changes.
