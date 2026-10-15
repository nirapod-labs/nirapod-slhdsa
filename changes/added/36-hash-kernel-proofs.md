- Proofs that `_sha256_compress_one` and `_sha512_compress_one` compress
  one block read from memory, and `_sha256_compress_blocks` and
  `_sha512_compress_blocks` the n consecutive blocks at their pointer, as
  FIPS 180-4 sections 5.2 and 6.2.2 / 6.4.2 specify, with termination, on
  the code `jasmin2ec` extracts for x86-64 and AArch64
  (`proofs/correctness/hash/SHA256_Blocks.ec`, `SHA512_Blocks.ec`). The
  blocks must end below 2^64. Padding, the streaming and one-shot hashes,
  HMAC, MGF1 and the Keccak sponge are not proven yet.
