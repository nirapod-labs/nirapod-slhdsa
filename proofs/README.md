<!--
SPDX-FileCopyrightText: nirapod-slhdsa contributors
SPDX-License-Identifier: Apache-2.0
-->

# Proofs

EasyCrypt development for nirapod-slhdsa: a byte-level specification of
FIPS 205 and of the hash functions it uses, lemmas that check parts of that
specification against the standard, its EUF-CMA security, and the start of
the functional-correctness proofs that are to connect it to the Jasmin
implementation.

**Status.** The specification, its validation theories and the EUF-CMA
theorems of the specification for all twelve parameter sets are written and
check. The implementation theorems so far cover the entry points of the
portable SHA-256 and SHA-512 kernels (one block from an array, one block
and n blocks from memory) and their round functions, the streaming and
one-shot SHA-2 hashes built on them, the steps of HMAC and the MGF1
instances over them, the Keccak-f[1600] permutation of the single-way
Keccak kernels of the scalar variants, the single-way sponge (absorb,
finalize, squeeze) and the one-shot SHA-3 and SHAKE functions over it, and
the hash address (ADRS) setters of the SLH-DSA core (below).
Nothing in this directory supports a claim that the SLH-DSA implementation
is verified.

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
against the standard only. The specification has not been run on ACVP
vectors; that check is open, and is planned through the equivalence with
the implementation, once the implementation is tested on them.

The FIPS 180-4 constant tables are checked by `make check-constants`, which
re-derives them from their definitions.

The hash functions themselves cannot be evaluated inside EasyCrypt (machine
words are abstract there). Of the hash specifications, only the two SHA-2
compression functions are tested against vectors, through the kernels proven
equal to them, which pass the CAVP tests of `tests/hash`. Padding, the full
hashes and their truncated variants, HMAC, MGF1 and the FIPS 202 byte
interface are checked by review only, until proofs of the code that
implements them reach them.

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
- `keccak_round_correct`, `keccakf1600_correct`, `keccakf1600_total`
  (`correctness/hash/Keccakf1600_Portable.ec`, on the two portable
  pairs): one round of the shared scalar kernel `src/hash/keccak/keccakf1600.jinc`
  computes `keccak_pround_op` (θ, ρ, π and χ), and `_keccakf1600` computes
  `keccak_f1600_op`, the Keccak-f[1600] of the imported FIPS 202
  theories, on the 25 64-bit lanes of its state, then the same with
  termination. crypto-specs proves `keccak_f1600_op` equal to its
  procedure for FIPS 202 sections 3.3 and 3.4 (`keccak_f1600_ph`), which
  `make check-imported` re-checks here. The x86-64 library builds this
  kernel; the AArch64 library does not;
- `keccak_round_regs_correct`, `keccakf1600_correct`, `keccakf1600_total`
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
  and with the correctness and termination of `_keccakf1600` as premises.
  `correctness/hash/ShakeSponge.ec` gives the byte view of the absorbing
  state that these statements use;
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
the proofs of the algorithms that call them, which do not exist yet.

Not proven yet: the multi-way functions, the four-way Keccak sponge among
them; the HMAC key block from memory; the sponge forms over fixed-length
arrays (`src/hash/keccak/sponge_array.jinc`); the four-way Keccak-f[1600]
kernels (portable, AVX2 and A64 SHA-3) the multi-way code uses; the
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
theories, this directory's specification and security theories, each
architecture's correctness proofs with its inventory, and the extraction
check. Each shard loads only the theories under its own load path, so CI
can tell from a change which shards it affects; `make shard-files` lists
every file of every shard, and CI checks that each file belongs to exactly
one, except the shared correctness proofs, which each architecture's shard
checks against its own models.

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

Every axiom the proofs can use is listed in `inventory/`, per pair; the
x86-64 list is longer only because the x86-64 instruction model loads the
AES axioms and has two of its own. The specification, validation, security
and correctness theories declare no axioms except these: the section
hypotheses on the adversary named above; `I_verify_ll` in
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

The correctness theorems are about the models `jasmin2ec` extracts, so the
extraction belongs to the trusted base too, and so do the `eclib` models
of the instructions the kernels use: `BSWAP_32` and `BSWAP_64` in
`JModel_x86`, `REV_32` and `REV_64` in `JModel_armv8a`. `ArchWord` proves
these definitions to be byte reversal; that they match the compiler's
semantics of the instructions is not proven here.
