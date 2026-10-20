<!--
SPDX-FileCopyrightText: nirapod-slhdsa contributors
SPDX-License-Identifier: Apache-2.0
-->

# Proofs

EasyCrypt development for nirapod-slhdsa: a byte-level specification of
FIPS 205 and of the hash functions it uses, lemmas that check parts of that
specification against the standard, its EUF-CMA security, and
functional-correctness proofs that connect it to the Jasmin implementation.

**Status.** The specification, its validation theories and the EUF-CMA
theorems of the specification for all twelve parameter sets are written and
check. The correctness theorems are about the models `jasmin2ec` extracts
from the scalar variant of each architecture (`x86_64/portable` and
`aarch64/a64scalar`). For all twelve parameter sets they state that the five
exports of `src/slhdsa/api.jinc` compute internal and external key
generation, signing and verification (FIPS 205 Algorithms 18 to 25), with
every hash function they call proven too, for a message in the domain stated
under [Assumptions](#assumptions). They do not cover the variants on SIMD
and CPU-extension kernels, which the library selects on CPUs that have the
extensions, nor the C layer; the extraction and the instruction models are
trusted ([Assumptions](#assumptions)). No theorem here composes the security
of the specification with the correctness of the code into one statement
about the library.

## Layout

| Path | Contents |
|---|---|
| `spec/Bytes.ec` | byte strings and the notation of FIPS 205 section 2.3 |
| `spec/hash/` | FIPS 180-4 (SHA-224/256/384/512, SHA-512/224, SHA-512/256), FIPS 198-1 HMAC, RFC 8017 MGF1, and the byte interface to FIPS 202 |
| `spec/slhdsa/` | FIPS 205: parameter sets, Algorithms 1 to 25, addresses, the section 11 hash instantiations, context framing and pre-hash |
| `spec/validation/` | checks of parts of the specification against the standard (below) |
| `security/` | EUF-CMA of the specification, from the imported SPHINCS+ proof |
| `extracted/` | the extraction entries and the models `jasmin2ec` extracts from the Jasmin sources, one directory per (architecture, variant) |
| `correctness/` | functional-correctness proofs of the extracted models |
| `inventory/` | per (architecture, variant): every axiom in scope and the claimed theorem statements, as EasyCrypt prints them |
| `tools/` | the proof-hole scan, the FIPS 180-4 constant derivation, the extraction script, the inventory generator |

Two EasyCrypt developments are imported unchanged, each in
`../third_party/` with its licence and provenance:

- the FIPS 202 bit-level specification of
  [formosa-crypto/crypto-specs](https://github.com/formosa-crypto/crypto-specs),
  in `crypto-specs/`;
- the EUF-CMA security proof of SPHINCS+ of
  [formosa-crypto/formosa-slhdsa](https://github.com/formosa-crypto/formosa-slhdsa)
  (ePrint 2024/910), in `formosa-slhdsa/`.

## The specification

The specification is a set of EasyCrypt operators, one per algorithm of the
standard, each citing its algorithm and the pseudocode lines it transcribes.
Keys and signatures are byte strings in the formats of FIPS 205 Figures 15
to 17, and every function takes its parameter set as an argument. Where the
transcription departs in form from the pseudocode, the theory header says
how and why:

- loops are folds over integer ranges; a `while` loop runs with explicit
  fuel, and the fuel's sufficiency is argued where it is used;
- the recursive tree-hash algorithms (9 and 15) recurse on the list of
  heights still to build;
- addresses are passed by value, which FIPS 205 section 4.2 allows;
- random inputs are arguments (`addrnd = None` selects deterministic
  signing), and a module `SLH_DSA` samples them for the probabilistic
  interface.

The specification covers byte-string messages only. FIPS 180-4 and FIPS 202
also define their functions on bit strings whose length is not a multiple of
eight; FIPS 205 never uses those.

## What the validation theories establish

Each statement below is a machine-checked lemma about the specification.
They check the parts of the transcription listed here against the standard;
they do not prove anything about an implementation.

- `Validate_Params`: every row of Table 2 satisfies the relations the
  standard states between its columns (w, len1, len2 by Algorithm 1,
  Equation 5.3, h = d * h', m, public-key and signature sizes, security
  category).
- `Validate_Encoding`: Algorithms 2 to 4 and the WOTS+ checksum evaluate to
  independently computed values on small inputs, including bit fields that
  cross byte boundaries; sizes and ranges of `toByte` and `base_2b` in
  general.
- `Validate_Address`: an address built with every Table 1 function has the
  byte layout of Figures 2 and 6; the getters read it back; compression
  gives Figure 18; the Table 3 functions agree with compressing the full
  address on that example; every Table 1 function preserves size 32.
- `Validate_Framing`: the pure and pre-hash message framings of section 10.2
  are injective for contexts of at most 255 bytes (the pre-hash one up to
  the digest), and no pure framing equals a pre-hash framing.

Nothing else in the specification is executed. Algorithms 5 to 25 (beyond
the closed forms `security/FIPS205_TreeForms.ec` restates and proves) and
the hash instantiations of section 11 (PRF, PRF_msg, H_msg, F, H and T_l,
their padding and the choice of SHA-256 or SHA-512) are checked by review
against the standard only. The specification itself cannot be run on ACVP
vectors. The correctness theorems below make an indirect check possible:
the scalar exports are proven equal to the specification, so a run of the
ACVP vectors on the scalar variant tests the specification too, under the
conditions `../docs/PROOFS.md` lists
([Testing the specification through the code](../docs/PROOFS.md#testing-the-specification-through-the-code)).
No result of such a run is recorded in this repository.

The FIPS 180-4 constant tables are checked by `make check-constants`, which
re-derives them from their definitions.

The hash functions themselves cannot be evaluated inside EasyCrypt (machine
words are abstract there). They are tested through the code proven equal to
them (below), which `tests/hash` runs on the NIST CAVP vectors: the SHA-2
compression functions, the full SHA-2 hashes with their padding and
truncated variants, and the FIPS 202 byte interface (SHA-3 and SHAKE). HMAC
is tested the same way, but the step that forms its key block is not among
the proven code. MGF1 has no CAVP vectors; `tests/hash` compares it with
MGF1 composed from OpenSSL's SHA-2, at the six sizes FIPS 205 uses.

## Security of the specification

`security/` instantiates the imported SPHINCS+ scheme with the functions of
the specification, proves that its signing and verification compute the
FIPS 205 algorithms byte for byte, and carries its EUF-CMA bound over to
the external interface of FIPS 205. `SPHINCS_Sets.ec` states the results for
each of the twelve parameter sets of Table 2, as `SLH_DSA_<SET>.<lemma>`:

- `slhdsa_euf_cma_spec`: deterministic signing. The scheme is the
  specification's own: key generation by `SLH_DSA.keygen` (Algorithm 21),
  signing by `slh_sign` and `hash_slh_sign` with `addrnd` absent,
  verification by `SLH_DSA.verify` and `SLH_DSA.hash_verify`, with pure
  and pre-hash requests under one key. The success probability of any
  forger is at most the sum of the terms below, each for an explicit
  adversary built from the forger.
- `slhdsa_euf_cma_hedged_spec`: the same for hedged signing
  (`SLH_DSA.sign` and `SLH_DSA.hash_sign`, a fresh `opt_rand` for every
  signature).
- `slhdsa_euf_cma` and `slhdsa_euf_cma_hedged`: the same bounds for the
  internal scheme of section 9 behind the framing of section 10
  (`ExternalFraming.ec`).

The terms of the bound:

- PRF advantage of PRF on (PK.seed, ADRS), with PK.seed chosen by the
  adversary, and of PRF_msg on (opt_rand, M') with opt_rand of n bytes,
  under uniformly drawn n-byte keys;
- interleaved target subset resilience of H_msg on (PK.seed, PK.root, M'),
  with the FIPS 205 split of the digest into FORS indices and instance;
- the multi-target TCR, UD, PRE and DSPR terms of the imported proof, for
  the tweakable hash `thfc` of `SPHINCS_Instance.eca`, which extends F, H
  and T_l to all bit strings. These ask more than the same properties of
  F, H and T_l on the inputs FIPS 205 gives them: a winning pair may use
  byte lengths FIPS 205 never gives a function, and for the SHA2 sets with
  n = 24 or 32 it may mix SHA-256 and SHA-512;
- collision resistance of the pre-hash functions, through an explicit
  collision finder.

Hypotheses: the forger terminates whenever its signing oracle does, and it
does not access the state of the games and reductions (the module
restrictions of each statement). Nothing else is assumed: every property of
a hash function appears as a term of the bound, and every axiom the imported
proof states about its abstract functions is realized for the FIPS 205
functions, `two_encodings` by `WOTS_Encoding.ec`.

Limits:

- The theorems are about the EasyCrypt operators of the specification,
  not about the Jasmin code.
- The adversary is an EasyCrypt module: a classical probabilistic program
  with classical access to its oracles. Security against quantum
  adversaries is not covered by these theorems.
- For the SHA2 sets, the specification's SHA-2 is total
  (`spec/hash/FIPS180_SHA2.ec`): past the input length FIPS 180-4 allows
  (under 2^64 bits for SHA-224 and SHA-256, under 2^128 bits for the
  SHA-512 family), its padding writes the bit length modulo 2^64 or 2^128,
  where FIPS 180-4 defines nothing. FIPS 205 puts no bound on the message,
  so its SHA2 sets are undefined on such messages, and the theorems, which
  have no length bound, are about this extension there. The correctness
  theorems stop inside the FIPS 180-4 domain (`msg_dom` and `ph_dom`,
  under [Assumptions](#assumptions)).
- A key used for both deterministic and hedged signatures is not covered;
  each theorem fixes one mode for every signature.
- The bound is concrete; no numeric security level is derived from it.
- The randomness of key generation and of hedged signing is modelled as
  uniform n-byte strings.
- The signature games type a signature as a byte string, so the error
  indication of `slh_sign` and `hash_slh_sign` is read as the empty string.
- On inputs that are not whole bytes, which FIPS 205 never hashes, `thfc`
  hashes a padded string under address type 7. That this branch makes no
  game easier, although it shares one function across address types and
  ignores the declared length, is argued in the header of
  `SPHINCS_Instance.eca` and not proved.
- Software-visible behaviour only: faults and physical leakage are out of
  scope.

## Extracted models and correctness proofs

`make extract` runs `jasmin2ec` on two entries, once per (architecture,
variant) pair listed in the Makefile (`EXTRACTIONS`):
`extracted/hash.jazz`, which only requires the production hash sources
(SHA-2, HMAC, the sponge, and MGF1 once for each seed and output length of
the SHA2 parameter sets, since `mgf1.jinc` fixes both at compile time) and
is extracted under the include roots that select that pair's kernels, and
`extracted/address.jazz`, which only requires the address code of the
SLH-DSA core (`src/slhdsa/address.jinc`; it depends on no parameter set).
The models are written to `extracted/<arch>/<variant>/` as
`HashExtracted.ec` and `AddressExtracted.ec` plus the array theories they
use, each with a header naming the generator, the command and the SHA-256
of the sources. `make check-extraction` re-extracts into a scratch directory
and fails if any committed model differs: a model can never silently lag
behind its source. Both targets need `JASMIN2EC` (the pinned `jasmin2ec`)
and `JASMIN_SRC` (default `../src`).

Correctness proofs follow one layout:

| Path | Contents | Checked against |
|---|---|---|
| `correctness/<area>/` | proofs written once for all targets | every pair; a proof of one kernel, only the pairs that build it (`KERNEL_PROOFS`) |
| `correctness/<area>/<arch>/` | facts about one architecture's instructions (theory `ArchWord`) | every pair of that architecture |
| `correctness/<area>/<arch>/<variant>/` | proofs of the kernels a variant replaces (theory `KernelSpec`) | that pair |

`make check-correctness` compiles, for each pair, its model, its
architecture and variant theories and the shared proofs that apply to it
(all of them, except that a proof of one kernel is checked only on the
pairs that build that kernel; below), with that pair's directories on the
load path. A shared proof that requires
`HashExtracted` or `ArchWord` is therefore checked against each pair's
model in turn: the shared Jasmin source is proven once and the proof is
replayed on every architecture. The x86-64 and AArch64 models of the
portable code differ only in the instructions behind `__bswap32` and
`__bswap64` (BSWAP against REV), and `ArchWord` proves both to be byte
reversal.

The pairs are `x86_64/portable` and `aarch64/portable`, the models of the
portable kernels, and `aarch64/a64scalar`, the model with the kernels the
AArch64 scalar variant builds in their place: the Keccak-f[1600] kernel that
keeps the state in registers (`src/hash/keccak/aarch64/scalar/`), with the
portable SHA-2 kernels. A shared proof of one kernel holds only for the
pairs that build it, so the Makefile lists each such proof with the kernel
root it needs (`KERNEL_PROOFS`), and a pair checks it only when its
extraction uses that root.

Which library variant each pair models is declared in the Makefile
(`LIBRARY_PAIRS`: `x86_64/portable` for the x86-64 scalar variant,
`aarch64/a64scalar` for the AArch64 one; `LIBRARY_UNMODELLED`: the x86-64
`avx2` and `shani` and the AArch64 `sha2` and `sha3` variants, which have
no model yet). `ci/kernel_roots.py`
compares these with the include roots the top-level Makefile compiles
each unit under (`make kernel-roots`), and fails if a variant is in
neither list or if a pair's kernel roots are not the library's, so the
models cannot drift from the kernels the library builds.

The SLH-DSA core depends on the parameter set: jasmin2ec writes each
`param int` as its value and names each array theory after its size, so
the same procedure has other loop bounds and argument types in each set.
For each pair of `LIBRARY_PAIRS` (`CORE_PAIRS`) and each of the twelve
sets, `extracted/<arch>/<variant>/sets/<set>/CoreExtracted.ec` is the
model of the set's compilation unit `src/slhdsa/sets/<set>.jinc`,
extracted under the include roots the library compiles it with, beside
the array theories it requires that the pair's own models do not. Next to
it, `SetModel.ec` (`tools/set_model.py`) gives the
names a proof uses instead: `P`, the FIPS 205 parameter record of the set,
with one lemma per base parameter (`n_val : P.`n = 16`, proved by
evaluation, so a Jasmin parameter file that disagrees with FIPS 205 does
not check), and aliases of the array theories by role (`Node` for u8[n],
`Digest` for u8[m], ...), each checked to be a theory the model requires.
The per-set proofs in `correctness/core/` refer to the set only through
these names, so one proof text is checked against all 24 models
(`make check-sets PAIR=<pair>`); `correctness/core/sha2/` and
`correctness/core/shake/` hold proofs for one hash family's sets. Each
(pair, set) has its own inventory, `inventory/sets/<arch>-<variant>-<set>.txt`.

Theorems so far, each checked on every pair unless it says otherwise:

- `sha256_rounds_correct` (`correctness/hash/SHA256_Compress.ec`):
  `__sha256_rounds` turns the chaining value `h` and the 16 message words
  in `w` into `compress h w` of FIPS 180-4 section 6.2.2
  (`spec/hash/FIPS180_SHA2.ec`);
- `sha256_compress_correct`: `_sha256_compress` computes `compress` on the
  big-endian words of its 64-byte block;
- `sha256_compress_total`: the same with termination;
- `sha512_rounds_correct`, `sha512_compress_correct`,
  `sha512_compress_total` (`correctness/hash/SHA512_Compress.ec`): the same
  three statements for the SHA-512 kernel, section 6.4.2, on its 128-byte
  block;
- `sha256_compress_one_total`, `sha256_compress_blocks_total`
  (`correctness/hash/SHA256_Blocks.ec`): `_sha256_compress_one` compresses
  the 64 bytes in memory at `p`, and `_sha256_compress_blocks` folds
  `compress` over the `n` blocks at `p`, the parse of section 5.2.1 of
  those `64 n` bytes; memory is read through `memread` of crypto-specs, and
  the blocks must end below 2^64;
- `sha512_compress_one_total`, `sha512_compress_blocks_total`
  (`correctness/hash/SHA512_Blocks.ec`): the same for SHA-512 and 128-byte
  blocks;
- `sha256_absorb_mem_total`, `sha256_finalize_total`, `sha256_mem_total`,
  `sha224_mem_total` (`correctness/hash/SHA256_Stream.ec`): the streaming
  SHA-256 of `src/hash/sha2/sha256.jinc`. The stream state after a message
  `m` from a chaining value `h0` is `stream256 h0 m h buf total`: `total`
  is `|m|`, `h` is `compress` folded from `h0` over the whole blocks of
  `m`, and `buf` begins with the bytes after them. `_sha256_absorb_mem`
  extends `m` by the `l` bytes at `p` (`p + l < 2^64` and
  `|m| + l < 2^64`); `_sha256_finalize` pads as section 5.1.1 says and
  returns the hash of `m` from `h0` (`|m| < 2^61`, so that the bit length
  fits the 64-bit length field); `_sha256_mem` and `_sha224_mem` are the
  one-shot SHA-256 and SHA-224 (its first 28 bytes) of the `l` bytes at
  `p` (`p + l < 2^64`, `l < 2^61`);
- `sha512_absorb_mem_total`, `sha512_finalize_total`, `sha512_mem_total`,
  `sha384_mem_total`, `sha512_224_mem_total`, `sha512_256_mem_total`
  (`correctness/hash/SHA512_Stream.ec`): the same for SHA-512 (section
  5.1.2, 128-byte blocks) and its truncations SHA-384, SHA-512/224 and
  SHA-512/256 (the first 48, 28 and 32 bytes, from their own initial
  values), with the same preconditions. For SHA-512 the bound `|m| < 2^61`
  is narrower than the code: it keeps the upper word of the 128-bit length
  field zero, while `_sha512_finalize` also writes that word, so messages
  of 2^61 bytes or more are outside the theorems;
- `hmac_sha256_blocks`, `hmac_sha256_init_total`,
  `hmac_sha256_finalize_total` (`correctness/hash/HMAC_SHA256.ec`): the
  HMAC-SHA-256 steps of `src/hash/sha2/hmac.jinc`. `__hmac_sha256_init`
  turns a 64-byte key block `K` into the chaining values after the blocks
  `K xor ipad` and `K xor opad`; `__hmac_sha256_finalize`, given the inner
  stream over `ipad block ++ text` (of fewer than 2^61 bytes) and that
  outer chaining value, returns
  `sha256 (opad block ++ sha256 (ipad block ++ text))`; and
  `hmac_sha256_blocks` says that this value is HMAC-SHA-256 of FIPS 198-1
  for a key of at most 64 bytes padded with zeros. The procedure that
  forms the key block from memory (`_hmac_sha256_keyblock_mem`) is not
  covered;
- `hmac_sha512_blocks`, `hmac_sha512_init_total`,
  `hmac_sha512_finalize_total` (`correctness/hash/HMAC_SHA512.ec`): the
  same for HMAC-SHA-512 and 128-byte key blocks;
- `mgf64_30_sha256_total`, `mgf64_34_sha256_total`
  (`correctness/hash/MGF1_SHA256.ec`): `_mgf1_sha256` of
  `src/hash/sha2/mgf1.jinc`, instantiated for a 64-byte seed and 30 or 34
  bytes of output (H_msg of the SHA2 sets with n = 16), returns
  MGF1-SHA-256 of RFC 8017 appendix B.2.1 of the seed. The proof shows
  that the buffer the code lays out once is the FIPS 180-4 padding of
  `seed || I2OSP(c, 4)` for every counter c;
- `mgf112_39_sha512_total`, `mgf112_42_sha512_total`,
  `mgf128_47_sha512_total`, `mgf128_49_sha512_total`
  (`correctness/hash/MGF1_SHA512.ec`): the same for `_mgf1_sha512` and
  MGF1-SHA-512, with a 112-byte seed and 39 or 42 bytes of output (n = 24)
  and a 128-byte seed and 47 or 49 bytes (n = 32);
- `keccak_round_correct`, `keccakf1600_correct`, `keccakf1600_ll`,
  `keccakf1600_total`
  (`correctness/hash/Keccakf1600_Portable.ec`, on the two portable
  pairs): one round of the shared scalar kernel `src/hash/keccak/keccakf1600.jinc`
  computes `keccak_pround_op` (θ, ρ, π and χ), and `_keccakf1600` computes
  `keccak_f1600_op`, the Keccak-f[1600] of the imported FIPS 202
  theories, on the 25 64-bit lanes of its state, then the same with
  termination. crypto-specs proves `keccak_f1600_op` equal to its
  procedure for FIPS 202 sections 3.3 and 3.4 (`keccak_f1600_ph`), which
  `make check-imported` re-checks here. The x86-64 library builds this
  kernel; the AArch64 library does not;
- `keccak_round_regs_correct`, `keccakf1600_correct`, `keccakf1600_ll`,
  `keccakf1600_total`
  (`correctness/hash/aarch64/a64scalar/KernelSpec.ec`, on
  `aarch64/a64scalar`): the same for the AArch64 kernel, whose round
  includes ι. The state facts both Keccak proofs use (the lane view, the
  ρ offsets against FIPS 202 Algorithm 2, the round constants) are in
  `correctness/hash/KeccakState.ec`;
- `keccak_absorb_mem_h`, `keccak_absorb_mem_ll`, `keccak_absorb_mem_total`,
  `keccak_finalize_h`, `keccak_finalize_ll`, `keccak_finalize_total`
  (`correctness/hash/Sponge.ec`, on every pair): absorb from memory and
  finalize (pad, permute) of `src/hash/keccak/sponge.jinc` against FIPS 202
  (`ABSORB1600` of `Keccak1600_Spec`), total correctness, for a rate of
  `r8` bytes with `0 < r8 < 200` (absorb) or `0 < r8 <= 200` (finalize),
  and with the correctness and termination of `_keccakf1600` as premises
  (discharged below). `correctness/hash/ShakeSponge.ec` gives the byte
  view of the absorbing state that these statements use;
- `extract_mem_h`, `extract_mem_ll`, `keccak_squeeze_mem_h`,
  `keccak_squeeze_mem_ll`, `keccak_squeeze_mem_total`
  (`correctness/hash/SpongeSqueeze.ec`, on every pair): squeeze to memory
  (`_keccak_squeeze_mem`, `__keccak_extract_mem`) of
  `src/hash/keccak/sponge.jinc` against FIPS 202 (`SQUEEZE1600` of
  `Keccak1600_Spec`), total correctness, from any start offset in the
  output stream, for `0 < r8 <= 200`, with the same premises
  (`extract_mem_h` and `extract_mem_ll` have none; the bytes copied end
  within the state and below 2^64 in memory);
- `sha3_absorb_all_total`, `sha3_224_mem_total`, `sha3_256_mem_total`,
  `sha3_384_mem_total`, `sha3_512_mem_total`, `shake_mem_total`,
  `shake128_mem_total`, `shake256_mem_total`
  (`correctness/hash/SHA3_SHAKE.ec`, on every pair): the one-shot
  SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256 functions
  of `src/hash/keccak/fips202.jinc`, message read from memory, against
  FIPS 202 (`SHA3_224` to `SHA3_512`, `SHAKE128` and `SHAKE256` of
  `Keccak1600_Spec`), total correctness, with the same premises
  (`sha3_absorb_all_total` and `shake_mem_total` take the rate, with
  `0 < r8 < 200`). The SHAKE functions read the whole message before
  they write output, so the statements need no disjointness of the two
  regions;
- `keccak_absorb_mem_total`, `keccak_finalize_total`,
  `keccak_squeeze_mem_total`, `sha3_absorb_all_total`,
  `sha3_224_mem_total` to `sha3_512_mem_total`, `shake_mem_total`,
  `shake128_mem_total`, `shake256_mem_total`
  (`correctness/hash/Sponge_Portable.ec` on the two portable pairs, with
  `keccakf1600_correct` and `keccakf1600_ll` of
  `Keccakf1600_Portable.ec`; `correctness/hash/aarch64/a64scalar/Sponge_KernelSpec.ec`
  on `aarch64/a64scalar`, with those of `KernelSpec.ec`): the theorems of
  the same names above with both premises discharged, so the sponge,
  SHA-3 and SHAKE results hold on each pair with no premise;
- the eleven `adrs_*_correct` theorems (`correctness/slhdsa/ADRS.ec`):
  every procedure of `src/slhdsa/address.jinc` (zeroing, the setters of
  FIPS 205 Table 1, the key pair copy and the address copy) returns the
  32-byte address the specification operator of
  `spec/slhdsa/FIPS205_Address.ec` gives, read as the bytes of the array,
  for every initial address and argument (setTypeAndClear for a type
  below 256; FIPS 205 uses 0 to 6). They are total-correctness statements:
  the procedure terminates with that result with probability 1. The
  address code is the same for all twelve parameter sets, so they hold
  for each.

Per-set theorems, each checked against the per-set models (`make check-sets`):

- `node_copy_correct` (`correctness/core/Encoding.ec`): `__node_copy`
  of `src/slhdsa/encoding.jinc` returns its n-byte source;
- `node_concat_correct`: `__node_concat` returns the 2n bytes of a
  followed by those of b;
- `digest_tree_leaf_correct` (`correctness/core/DigestIndices.ec`):
  `__digest_tree_leaf` returns idx_tree and idx_leaf, read from the
  message digest as FIPS 205 Algorithm 19 lines 6 to 10 prescribe
  (`split_digest`);
- `fors_indices_correct`: index j of `__fors_indices` is digit j of
  base_2b(md, a, k) (Algorithm 4), md the first field of the digest;
- `wots_digits_correct` (`correctness/core/Wots.ec`): `__wots_digits` of
  `src/slhdsa/wots.jinc` returns the len digits of Algorithm 7, lines 1
  to 7 (`wots_digits`): the 2n base-16 digits of the message, then the
  three digits of its checksum;
- `adrs_compress_into64_correct` and `adrs_compress_into128_correct`
  (`correctness/core/sha2/ADRSc.ec`, on the 12 SHA2 models):
  `__adrs_compress_into64` and `__adrs_compress_into128` of
  `src/slhdsa/thash_sha2.jinc` write ADRS^c, the 22-byte compressed
  address of FIPS 205 section 11.2, into the first 22 bytes of a hash
  block and leave its other bytes unchanged;
- `thash_ctx_init_correct`, `thash_f_correct`, `thash_prf_correct` and
  `thash_h_correct` (`correctness/core/sha2/Thash.ec`, on the 12 SHA2
  models): `_thash_ctx_init` of `src/slhdsa/thash_sha2.jinc` stores in
  the context the chaining values after the PK.seed block (`ctx_ok`), and
  `_thash_f`, `_thash_prf` and `_thash_h` return F, PRF and H of section
  11.2 from a context with that layout, given the premise that the
  model's SHA-256 and SHA-512 compression procedures meet the statements
  the kernel proofs give for the kernel's own model (discharged in
  `sha2/HashKernels.ec`, below);
- `thash_f_correct`, `thash_prf_correct`, `thash_h_correct`,
  `thash_t_len_correct` and `thash_t_k_correct`
  (`correctness/core/shake/Thash.ec`, on the 12 SHAKE models): `_thash_f`,
  `_thash_prf`, `_thash_h`, `_thash_t_len` and `_thash_t_k` of
  `src/slhdsa/thash_shake.jinc` return F, PRF, H, T_len and T_k of FIPS 205
  section 11.1; `shake_absorb_prefix_correct`: `_shake_absorb_prefix`
  absorbs a prefix of up to 332 bytes (`SLH_PREFIX_MAX`) from any position
  within the 136-byte rate; `keccak_finalize_correct`: `_keccak_finalize`
  at rate 136 with domain byte 0x1F pads and permutes as SHAKE256 does
  (FIPS 202, sections 5.1 and 6.2). All under the premise that the model's
  `_keccakf1600` computes Keccak-f[1600] on the lanes of its state
  (discharged in `shake/HashKernels.ec`, below).

The theorems that follow take the tweakable hashes they call as premises,
each in the form of the theorems above: for one fixed PK.seed and context,
the procedure returns the section 11 hash of its arguments, with
probability 1. The four-way procedures `_thash_prf_x4`, `_thash_f_x4` and
`_thash_t_len_x4` enter in the same form, lane by lane. The hash theorems
that discharge all of them, and the theorems that compose the two, follow
this list.

- `wots_chain_correct` (`correctness/core/WotsChain.ec`): `_wots_chain`
  of `src/slhdsa/wots.jinc` computes chain of Algorithm 5 when start +
  steps < 2^32, given F;
- `wots_pk_from_sig_correct` (`correctness/core/WotsPk.ec`):
  `_wots_pk_from_sig` computes wots_pkFromSig of Algorithm 8 for the
  address the standard's caller passes, given F and T_len;
- `wots_leaf_x4_correct` (`correctness/core/WotsLeaf.ec`): `_wots_leaf_x4`
  returns, when kp0 + 3 < 2^32 and every digit is below 16, the WOTS+
  public keys of key pairs kp0 to kp0 + 3 (Algorithm 6) and, for a lane
  below 4, the chain values of Algorithm 7 for key pair kp0 + lane, given
  the four-way PRF, F and T_len;
- `xmss_pk_from_sig_correct` (`correctness/core/XmssPk.ec`):
  `_xmss_pk_from_sig` of `src/slhdsa/xmss.jinc` computes xmss_pkFromSig
  of Algorithm 11, given F, T_len and H;
- `treehash_fold_correct` (`correctness/core/TreeFold.ec`):
  `_treehash_fold` of `src/slhdsa/treehash.jinc` adds leaf i to the
  pending nodes and the target's authentication nodes, for a tree of
  height at most a whose first leaf index is a multiple of 2^height,
  given H;
- `xmss_node_correct` and `xmss_sign_correct` (`correctness/core/Xmss.ec`):
  `_xmss_treehash` returns xmss_node of Algorithm 9 for the whole tree when
  every digit is below 16, and, for a target leaf below 2^h' and the
  digits of M, also xmss_sign of Algorithm 10, given the four-way PRF, F
  and T_len and H;
- `fors_pk_from_sig_correct` (`correctness/core/ForsPk.ec`):
  `_fors_pk_from_sig` of `src/slhdsa/fors.jinc` computes fors_pkFromSig of
  Algorithm 17 when its k indices are base_2b(md, a, k), given F, H and
  T_k;
- `fors_tree_correct` (`correctness/core/ForsTree.ec`): `_fors_tree`
  returns, for tree t < k and a leaf below 2^a, the secret of that leaf
  (Algorithm 14), its authentication path and the root of the tree
  (fors_node, Algorithm 15), given the four-way PRF and F, and H;
- `fors_sign_correct` (`correctness/core/ForsSign.ec`): `_fors_sign`
  writes SIG_FORS of Algorithm 16 after the randomizer, leaves the other
  bytes of the signature unchanged and returns fors_pkFromSig of that
  signature, when its k indices are base_2b(md, a, k), given the premises
  of `_fors_tree` and T_k;
- `ht_sign_correct` and `ht_verify_correct`
  (`correctness/core/Hypertree.ec`): `_ht_sign` of
  `src/slhdsa/hypertree.jinc` writes ht_sign of Algorithm 12 after R and
  SIG_FORS, for an idx_leaf below 2^h', given the premises of
  `_xmss_treehash`; `_ht_verify` returns 0 when ht_verify of Algorithm 13
  holds and -1 otherwise, given F, T_len and H;
- `slh_sign_correct`, `slh_verify_correct` and `slh_keygen_correct`
  (`correctness/core/Internal.ec`), for `src/slhdsa/internal.jinc`, with
  M = prefix[0 : prefix_len] followed by the msg_len bytes at msg, for a
  prefix_len of at most 332 and a message that does not wrap the address
  space: `_slh_sign` returns slh_sign_internal(M, SK, opt_rand) of
  Algorithm 19 (hedged; `sign_deterministic` states that the deterministic
  variant is opt_rand = PK.seed), given that `_thash_ctx_init` returns a
  context for which the hash premises hold, the premises of `_ht_sign`
  and `_fors_sign`, and that `_prf_msg` and `_h_msg` compute PRF_msg and
  H_msg of that M;
  `_slh_verify` returns 0 when slh_verify_internal(M, SIG, PK) of
  Algorithm 20 accepts and all ones otherwise, given F, T_len, H, T_k and
  H_msg; `_slh_keygen` returns the SK and PK of slh_keygen_internal of
  Algorithm 18 for the three seeds it is given, given the four-way PRF, F
  and T_len and H;
- `slh_frame_correct` (`correctness/core/External.ec`): `_slh_frame` of
  `src/slhdsa/external.jinc` reads the caller's 257-byte domain block
  (byte 0 the pre-hash selector, 0 for pure SLH-DSA and 1 to 12 for the
  hash function with OID 2.16.840.1.101.3.4.2.s; byte 1 |ctx|; then ctx)
  and, for a selector of at most 12, returns status 0 with the start of
  M' of Algorithms 22 to 25 in the prefix: toByte(0, 1) || toByte(|ctx|,
  1) || ctx, with the message to follow, or toByte(1, 1) || toByte(|ctx|,
  1) || ctx || OID || PH(M), with nothing to follow; for a larger selector
  it returns status all ones. A context of more than 255 bytes cannot be
  written in the block: rejecting it is the C layer's part;
- `sign_correct`, `verify_correct` and `keygen_correct`, for the exports
  of `src/slhdsa/api.jinc`: `sign` returns slh_sign (Algorithm 22) or
  hash_slh_sign (Algorithm 23) of M, ctx, SK and opt_rand, and leaves the
  signature buffer unchanged and returns all ones for a selector above
  12; `verify` returns 0 when slh_verify (Algorithm 24) or
  hash_slh_verify (Algorithm 25) accepts and all ones otherwise; `keygen`
  returns slh_keygen (Algorithm 21) for the seeds it is given, the draw of
  lines 1 to 3 being the C layer's; `sign_internal_correct` and
  `verify_internal_correct`: `sign_internal` and `verify_internal` are the
  section 9 functions on M. Each takes as premise the theorem of the
  internal function it calls, in the form `Internal.ec` proves it; sign
  and verify also take that `_prehash` terminates and, for M in
  `ph_dom`, returns PH(M) for the function of its selector. sign and
  verify require M in `msg_dom` with the longest prefix (332 bytes) and
  in `ph_dom`; the section 9 exports require M in `msg_dom` with no
  prefix (both below, under Assumptions).

The hash theorems below are the premises above, proved for the
procedures of each set's model. Only those named in `SET_THEOREMS_<family>`
(`Makefile`) are pinned in the inventories; the others reach the pinned
`Theorems.*` through them, so their statements are checked as part of those.

- `keccakf1600_correct`, `keccakf1600_ll` and `keccakf1600_total`
  (`correctness/hash/<arch>/<variant>/Keccakf1600_Pair.ec`): the
  Keccak-f[1600] theorems of the kernel each pair builds under one theory
  name, so that the per-set proofs use them on every pair;
- `sha256_compress_total`, `sha512_compress_total` and
  `thash_ctx_init_total`, `thash_f_total`, `thash_prf_total`,
  `thash_h_total` (`correctness/core/sha2/HashKernels.ec`): the set
  model's compression procedures equal the hash model's, so the kernel
  theorems hold for them, and with them the tweakable hashes of
  `sha2/Thash.ec` hold with no premise;
- `keccakf1600_total`, `thash_ctx_init_correct`, `thash_f_total`,
  `thash_prf_total`, `thash_h_total`, `thash_t_len_total`,
  `thash_t_k_total`, `shake_absorb_prefix_total` and
  `keccak_finalize_total` (`correctness/core/shake/HashKernels.ec`): the
  same for the SHAKE sets, from `Keccakf1600_Pair.ec`;
- `prf_msg_correct` (`correctness/core/sha2/MsgHash.ec`): `_prf_msg`
  returns PRF_msg of section 11.2, HMAC-SHA-256 or HMAC-SHA-512 keyed
  with SK.prf, for M = prefix[0 : prefix_len] || mem[msg : msg + msg_len]
  in `msg_dom`;
- `mgf1_sha256_total` and `mgf1_sha512_total`
  (`correctness/core/sha2/Mgf1.ec`): MGF1 of RFC 8017 for the seed and
  output lengths of the set's H_msg;
- `prf_msg_correct` and `h_msg_correct`
  (`correctness/core/shake/MsgHash.ec`): `_prf_msg` and `_h_msg` return
  PRF_msg and H_msg of section 11.1 for the same M;
- `prehash_ll`, `prehash_h` and `prehash_total`
  (`correctness/core/PreHash.ec`): `_prehash` of
  `src/slhdsa/external.jinc` terminates on every input and, for a
  selector s from 1 to 12 and M in `ph_dom`, the first len bytes of its
  64-byte result are PH(M) for the function of s: the SHA-2 one-shots of
  the hash layer for 1 to 6, and for 7 to 12 the sponge with the rate,
  padding byte and output length of SHA3-224, SHA3-256, SHA3-384,
  SHA3-512, SHAKE128 (256 bits) and SHAKE256 (512 bits);
- `h_msg_correct` (`correctness/core/sha2/HMsg.ec`, on the 12 SHA2
  models): `_h_msg` returns H_msg of FIPS 205 section 11.2 for M =
  prefix[0 : prefix_len] || mem[msg : msg + msg_len] in `msg_dom`;
- `thash_t_len_total` and `thash_t_k_total`
  (`correctness/core/sha2/ThashT.ec`): `_thash_t_len` and `_thash_t_k`
  return T_len and T_k of section 11.2 from a context with the layout of
  `thash_ctx_init_correct`;
- `thash_prf_x4_total`, `thash_f_x4_total` and `thash_t_len_x4_total`
  (`correctness/core/sha2/ThashX4.ec`): lane k of the result of the
  four-way PRF, F and T_len is the section 11.2 hash of lane k of the
  inputs, for k < 4; these sets run the single-way SHA-2 code once per
  lane;
- `keccakf1600_x4_total`, `thash_prf_x4_total`, `thash_f_x4_total` and
  `thash_t_len_x4_total` (`correctness/core/shake/ThashX4.ec`, on the 12
  SHAKE models): the portable four-way `_keccakf1600_x4` applies
  Keccak-f[1600] to each of its four instances, and lane k of the result
  of the four-way PRF, F and T_len is the section 11.1 hash of lane k of
  the inputs;
- `slh_verify_total`, `slh_sign_total`, `slh_keygen_total`,
  `sign_total`, `verify_total`, `keygen_total`, `sign_internal_total`
  and `verify_internal_total` (`correctness/core/sha2/Theorems.ec` and
  `correctness/core/shake/Theorems.ec`): the internal functions and the
  exports above, with every premise discharged by the hash theorems of
  the set's family and by `PreHash.ec`. They have no premise; their only
  conditions are those on the caller's input named above.

The per-set theorems are total-correctness statements about one
procedure each, for every input that meets the conditions stated above.
Their hash premises are about the procedures of the set's model, and the
`Theorems.ec` of each family discharges all of them, so the theorems of
the exports hold for the set's model with no premise. They are about
the extracted model of the scalar variant of each architecture
(`CORE_PAIRS`).

The SHA-2 and Keccak `_correct` theorems are partial-correctness (Hoare)
statements about the extracted model: when the procedure returns, its
result is the specified value. Every loop of the kernels runs over a
constant range, so `_sha256_compress`, `_sha512_compress` and both
`_keccakf1600` terminate from every initial state (`sha256_compress_ll`,
`sha512_compress_ll`, `keccakf1600_ll`), and the `_total` theorems combine
the two: the procedure returns, with the specified result, with
probability 1. Memory safety is a separate obligation.

The address theorems are about the address procedures themselves. That
the rest of the core passes them the values FIPS 205 prescribes is part of
the per-set proofs of the algorithms that call them.

Not proven yet: the multi-way hash functions outside the four-way
tweakable hashes above, the general four-way Keccak sponge among them;
the HMAC key block from memory; the sponge forms over fixed-length
arrays (`src/hash/keccak/sponge_array.jinc`); the four-way
Keccak-f[1600] kernels on AVX2 and on the A64 SHA-3 instructions; the
four-way SHA2 tweakable hashes on the multi-way SHA-2 kernels
(`src/slhdsa/thash_sha2_x4/multi/`) and the AVX2 8-way SHA-256 and 4-way
SHA-512 kernels under them, in the x86-64 `avx2` variant of the SHA2 sets;
and the kernels that replace the portable ones: SHA-NI for SHA-256 in the
x86-64 `shani` variant, the SHA-2 instruction kernels for SHA-256 and
SHA-512 and the single-way Keccak-f[1600] kernel on the SHA-3 instructions
in the AArch64 `sha2` and `sha3` variants, and the A64 base-ISA SHA-2
kernels, which only the hash tests select. The scalar variant of every unit
runs the portable SHA-2 kernels.

`spec/hash/FIPS180_SHA2_Blocks.ec` states, at the level of the
specification, how a hash splits into a first block compressed once and a
tail, for the proofs of code that keeps the chaining value of a fixed
first block (the PK.seed block of FIPS 205 section 11.2).

## Checking

With the EasyCrypt of the pinned toolchain (`toolchain/build.sh`), from the
repository root:

```sh
ci/toolchain.sh exec make -C proofs check check-inventory check-extraction
```

`toolchain.sh exec` runs the command in the toolchain's opam switch, so that
EasyCrypt finds the pinned provers. `check` runs the proof-hole scan and the
constant derivation, then compiles every `.ec` file of this directory and of
the two imported developments on its own, without `.eco` caches, and the
correctness proofs once per extracted model. EasyCrypt does not re-check the
proofs of theories a file loads with `require`, so a run that compiled only
top-level files would not have checked their dependencies; this one does.
Each file is compiled from a copy that ends with a trivial lemma, because
EasyCrypt accepts a file that ends with unrealized obligations of a
`clone ... proof *` and treats them as proven. The scan (`scan-admits`)
rejects, outside comments, `admit` and `admitted` and the commands that let
a file pass without its proofs being checked: `pragma` (`pragma
Proofs:weak` turns checking off), `exit` (ends the file early with success)
and `fail` (expects a command to fail, so a statement it prefixes is never
established). `check-spec` limits the compilation to `spec/`;
`check-formosa` re-checks the imported SPHINCS+ proof alone, the longest
part of `check`. `J=<n>` checks n files at a time, each in its own
EasyCrypt process, and prints each file's time and peak memory. Variables:
`EASYCRYPT`, `EC_PROVERS`, `EC_TIMEOUT`, `JASMIN2EC`, `JASMIN_SRC`,
`PYTHON`, `J`.

CI checks the same files in shards, in parallel jobs (`make list-shards`,
`make check-shard SHARD=<shard>`): the SPHINCS+ proof, the crypto-specs
theories, this directory's specification and security theories, the
correctness proofs of each pair (`<arch>-<variant>`), the inventories of
all pairs (`inventory`), the per-set proofs and inventories of each group
of three sets of one hash family for each pair of `CORE_PAIRS`
(`<arch>-<variant>-<group>`, groups `SET_GROUPS`), and the extraction
check. Each shard loads only the theories under its own load path, so CI
can tell from a change which shards it affects; `make shard-files` lists
every file of every shard, and CI checks that each file belongs to exactly
one, except the shared correctness proofs, which a pair shard of each
architecture checks against its own models, an architecture's facts,
which each of its pairs checks, and the per-set proofs, which every group
of their family checks.

`check-inventory` requires, for each pair, every theory that pair is
checked with, has EasyCrypt print every axiom then in scope, the statement
of each theorem of that pair (those of `THEOREMS` in the Makefile whose
theory the pair loads, plus `KERNEL_THEOREMS_<arch>_<variant>`) and every
definition (type, operator, predicate, abbreviation, module) of the
theories in this directory and in `../third_party`, and fails unless the
result equals `inventory/<arch>-<variant>.txt`. An axiom can enter by an
`axiom` declaration, by an `axiomatized by` definition, or as an axiom a
`clone` leaves unrealized; all three are in EasyCrypt's list. A statement means
what the definitions it names mean, so the definitions are pinned too: no
axiom can be added, and no theorem dropped or weakened, either in its text
or by changing a definition it relies on, without a reviewed change to the
inventory. The extracted models are left out of the definitions because
`check-extraction` already ties them to the Jasmin sources; the EasyCrypt
and Jasmin libraries are part of the pinned toolchain. Proofs and helper
lemmas are not listed. `make inventory` rewrites the files.

The SMT provers are those of the EasyCrypt pin in `../toolchain/easycrypt/`.
Each imported development is checked with the prover selection and timeout
of its own upstream project file.

## Assumptions

Every axiom the proofs can use is listed in `inventory/`, per pair, and
per (pair, set) in `inventory/sets/` for the per-set models; the
x86-64 list is longer only because the x86-64 instruction model loads the
AES axioms and has two of its own. The specification, validation, security
and correctness theories declare no axioms except these: the section
hypotheses on the adversary named above; the section hypotheses of some
correctness theories on the kernel they are written over (for example
`kf_h` and `kf_ll` in `correctness/hash/Sponge.ec`, `keccakf1600_h` in
`correctness/core/shake/Thash.ec`, `sha256_compress_h` and
`sha512_compress_h` in `correctness/core/sha2/Thash.ec`), which become
premises of the theorems when the section closes and are discharged by the
kernel theorems, so that none is left in an inventory; `I_verify_ll` in
`ExternalFraming.ec`, termination of internal verification, discharged for
SLH-DSA by `SLH_verify_ll`; and the parameter-set hypothesis `P_in` of the
abstract theory `SPHINCS_Instance.eca`, realized for every set in
`SPHINCS_Sets.ec`. The per-set theories also carry the four defining axioms
of each EasyCrypt `Subtype` clone (`insubN`, `insubT`, `valP`, `valK` on a
fresh type); they are satisfiable because each clone proves its predicate
inhabited. The imported crypto-specs theory JWordList defines
`stores8` and `stores64` with `axiomatized by`, and states the hypotheses
of its abstract theory `ListEmbedding` as axioms that each of its three
clones realizes. The imported SPHINCS+ proof states the hypotheses on its
abstract parameters, functions and encodings as axioms (for example
`two_encodings`, `ch0`, `chS` and `dist_adrstypes`): its theorem applies to
a concrete scheme only through a clone that realizes them. The rest belong
to the EasyCrypt standard library and the Jasmin EasyCrypt library
(`eclib`) of the pinned toolchain, including the parameters of the array
theories the extracted models clone; `../toolchain/jasmin/ECLIB_AXIOMS` and
`../docs/TOOLCHAIN.md` describe the `eclib` ones. Both libraries belong to
the trusted base together with EasyCrypt itself and its SMT provers.

The theorems of the exports and of the internal functions hold for
every input in their domain, which the theorems state as two conditions
on the caller's message, not as assumptions about the code:

- `msg_dom` (`Internal.ec`): the message buffer [msg, msg + msg_len)
  does not wrap the 64-bit address space and, for the SHA2 sets, the
  hashed message R || PK.seed || PK.root || M' is in the domain of
  FIPS 180-4 and of the one-shot kernels: M' (prefix and message) under
  2^61 - 256 bytes and msg + msg_len below 2^64;
- `ph_dom` (`External.ec`): for the SHA-2 pre-hash selectors 1 to 6,
  M is under 2^61 bytes and msg + msg_len is below 2^64, the domain the
  SHA-2 one-shots are proved for (FIPS 180-4 allows SHA-384 and SHA-512
  longer messages; the proofs stop at 2^61 bytes for all six). For the
  other selectors it is no condition.

No buffer on the supported targets comes near either bound. User
address spaces are at most 57 bits wide, so a buffer is far shorter than
2^61 bytes, and the address of its end is below 2^57; an AArch64 pointer
may carry a tag in its top byte, but the address under the tag ends
below 2^56, so start plus length still stays below 2^64. The library
does not check the bounds at run time.

The correctness theorems are about the models `jasmin2ec` extracts, so the
extraction belongs to the trusted base too, and so do the `eclib` models
of the instructions the kernels use: `BSWAP_32` and `BSWAP_64` in
`JModel_x86`, `REV_32`, `REV_64` and `BIC_64` in `JModel_armv8a`, and
the speculative load hardening operators of `eclib`'s `Jslh` (`init_msf`,
`update_msf`, `protect_32`, `protect_64`, `protect_ptr`): the
`protect_*` operators return their first argument, so the misspeculation
flag that `init_msf` and `update_msf` compute never changes a value in the
sequential semantics the proofs use.
`ArchWord` proves the byte swaps to be byte reversal, and the AArch64
register kernel's `KernelSpec.ec` proves `BIC_64` to be and-not; that
these models match the compiler's semantics of the instructions is not
proven here.
