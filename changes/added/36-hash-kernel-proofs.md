- Proofs that the portable SHA-2 kernels' `_sha256_compress_one` and
  `_sha512_compress_one` compress one block read from memory, and their
  `_sha256_compress_blocks` and `_sha512_compress_blocks` the n
  consecutive blocks at their pointer, as FIPS 180-4 sections 5.2 and
  6.2.2 / 6.4.2 specify, with termination, on the code `jasmin2ec` extracts
  for x86-64 and AArch64 (`proofs/correctness/hash/SHA256_Blocks.ec`,
  `SHA512_Blocks.ec`). The blocks must end below 2^64. The other SHA-2
  kernels (SHA-NI, AVX2, and the A64 instruction and base-ISA kernels),
  some of which define the same entry points, are not proven.
- Proofs of the streaming SHA-2 hashes over the portable kernels:
  absorbing bytes from memory, padding and finalizing (FIPS 180-4 sections
  5.1 and 6), and the one-shot SHA-224, SHA-256, SHA-384, SHA-512,
  SHA-512/224 and SHA-512/256 of a buffer in memory, with termination
  (`proofs/correctness/hash/SHA256_Stream.ec`, `SHA512_Stream.ec`). The
  SHA-512 family is proven for messages under 2^61 bytes.
- Proofs of the HMAC-SHA-256 and HMAC-SHA-512 steps over the portable
  SHA-2 kernels: the keyed initial states and the outer hash, the steps
  from which HMAC of FIPS 198-1 follows for keys of at most one block
  (`proofs/correctness/hash/HMAC_SHA256.ec`, `HMAC_SHA512.ec`). The key
  block read from memory is not proven yet.
- Proofs of MGF1 (RFC 8017) over the portable SHA-2 kernels for the seed
  and output lengths of H_msg in the SHA2 sets: MGF1-SHA-256 for n = 16 and
  MGF1-SHA-512 for n = 24 and 32 (`proofs/correctness/hash/MGF1_SHA256.ec`,
  `MGF1_SHA512.ec`).
- Proofs that the single-way Keccak sponge absorbs bytes from memory,
  finalizes (padding, permutation) and squeezes to memory from any offset
  in its output stream, and that the one-shot SHA3-224, SHA3-256,
  SHA3-384, SHA3-512, SHAKE128 and SHAKE256 of a message in memory compute
  FIPS 202, with termination (`proofs/correctness/hash/Sponge.ec`,
  `ShakeSponge.ec`, `SpongeSqueeze.ec`, `SHA3_SHAKE.ec`). The proofs hold
  for any permutation that computes Keccak-f[1600]; `Sponge_Portable.ec`
  and `aarch64/a64scalar/Sponge_KernelSpec.ec` state them for the two
  proven Keccak-f[1600] kernels, with no premise left. The sponge forms
  over fixed-length arrays and the four-way sponge are not proven yet.
