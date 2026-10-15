- Proofs that `_sha256_compress_one` and `_sha512_compress_one` compress
  one block read from memory, and `_sha256_compress_blocks` and
  `_sha512_compress_blocks` the n consecutive blocks at their pointer, as
  FIPS 180-4 sections 5.2 and 6.2.2 / 6.4.2 specify, with termination, on
  the code `jasmin2ec` extracts for x86-64 and AArch64
  (`proofs/correctness/hash/SHA256_Blocks.ec`, `SHA512_Blocks.ec`). The
  blocks must end below 2^64.
- Proofs of the streaming SHA-2 hashes over those kernels: absorbing bytes
  from memory, padding and finalizing (FIPS 180-4 sections 5.1 and 6), and
  the one-shot SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and
  SHA-512/256 of a buffer in memory, with termination
  (`proofs/correctness/hash/SHA256_Stream.ec`, `SHA512_Stream.ec`). HMAC,
  MGF1 and the Keccak sponge are not proven yet.
