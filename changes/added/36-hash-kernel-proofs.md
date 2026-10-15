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
  (`proofs/correctness/hash/SHA256_Stream.ec`, `SHA512_Stream.ec`).
- Proofs of the HMAC-SHA-256 and HMAC-SHA-512 steps: the keyed initial
  states and the outer hash give HMAC of FIPS 198-1 for keys of at most one
  block (`proofs/correctness/hash/HMAC_SHA256.ec`, `HMAC_SHA512.ec`). The
  key block read from memory is not proven yet.
- Proofs of MGF1 (RFC 8017) for the seed and output lengths of H_msg in
  the SHA2 sets: MGF1-SHA-256 for n = 16 and MGF1-SHA-512 for n = 24 and
  32 (`proofs/correctness/hash/MGF1_SHA256.ec`, `MGF1_SHA512.ec`).
- Proofs that the Keccak sponge absorbs bytes from memory and finalizes
  (padding, permutation) as FIPS 202 specifies, with termination, given
  the Keccak-f[1600] permutation (`proofs/correctness/hash/Sponge.ec`,
  `ShakeSponge.ec`). The squeeze is not proven yet.
