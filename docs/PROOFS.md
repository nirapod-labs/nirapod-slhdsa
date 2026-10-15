# Proofs

What is machine-checked, about which artifact, and what remains open. This page is
the overview; [`proofs/README.md`](../proofs/README.md) states every theorem
precisely, with its file, hypotheses and limits, and is the authority where the two
differ.

## The chain

Three separate results are needed for the claim that the compiled library is a
secure FIPS 205 signature. They are different obligations, and only the first and
last hold today.

| Link | From | To | Status |
| :-- | :-- | :-- | :-- |
| Security | the SPHINCS+ security proof | the EasyCrypt specification of FIPS 205 | **PROVEN** for all 12 sets |
| Correctness | the Jasmin code, as `jasmin2ec` extracts it | that specification | open; some components **PROVEN** |
| Compilation | the Jasmin program | the assembly program | **PROVEN** for the compiler, per target |

Memory safety, constant time and speculative constant time are further
obligations, covered by analysis rather than proof; see
[SECURITY-MODEL](SECURITY-MODEL.md).

## Security of the specification

EUF-CMA security of the FIPS 205 specification is proved in EasyCrypt from the
SPHINCS+ proof of ePrint 2024/910, imported unchanged; `make -C proofs check`
re-checks both.

- **Object.** The specification, not the Jasmin code. The specification is checked
  against FIPS 205 by review and by the lemmas of `proofs/spec/validation/`, and has
  not been run on ACVP vectors.
- **Scope.** All 12 parameter sets, pure and pre-hash, deterministic and hedged
  signing.
- **Bound.** Concrete, in PRF, ITSR, tweakable-hash and pre-hash collision terms;
  no numeric security level is derived from it.
- **Limits.** Hypotheses and limits, such as a key used for both deterministic and
  hedged signing being outside the theorems, are in
  [`proofs/README.md`](../proofs/README.md#security-of-the-specification).

## The code against the specification

Open. Parts of the SLH-DSA core and of the hash layer are proved in EasyCrypt on
the code `jasmin2ec` extracts. Of the FIPS 205 algorithms, only the WOTS+ chain
(Algorithm 5) and the WOTS+ public key from a signature (Algorithm 8) are covered,
and only given the tweakable hashes they call; key generation, signing and
verification are not.

Proven, on the x86-64 and AArch64 models, total correctness:

- **Addresses.** The hash address procedures of `src/slhdsa/address.jinc` compute
  the address setters of FIPS 205 Table 1, for all 12 parameter sets (the code
  depends on none).
- **SHA-2.** The entry points of the portable SHA-2 kernels, with their round
  functions, against FIPS 180-4: one block from an array (`_sha*_compress`), one
  block from memory (`_sha*_compress_one`) and n consecutive blocks from memory
  (`_sha*_compress_blocks`, used by the streaming hash); and the streaming SHA-224,
  SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 (absorb from memory,
  padding, finalize) and their one-shot functions over memory; the HMAC-SHA-256 and
  HMAC-SHA-512 steps (keyed initial states and the outer hash) against FIPS 198-1,
  for keys up to one block; and MGF1 against RFC 8017 for the seed and output
  lengths of H_msg in the SHA2 sets: MGF1-SHA-256 for n = 16 (64-byte seed, 30 or
  34 bytes), MGF1-SHA-512 for n = 24 (112-byte seed, 39 or 42 bytes) and n = 32
  (128-byte seed, 47 or 49 bytes).
- **Keccak.** The Keccak-f[1600] permutation of the single-way kernels the scalar
  variants build (the portable kernel on x86-64, the kernel that keeps the state in
  registers on AArch64), against FIPS 202; and, over each of those kernels,
  the single-way Keccak sponge's absorb from memory, finalize (padding and the
  permutation) and squeeze to memory, and the one-shot SHA3-224, SHA3-256,
  SHA3-384, SHA3-512, SHAKE128 and SHAKE256 of a message in memory, against
  FIPS 202.
- **SHAKE tweakable hashes.** For the six SHAKE sets, `_thash_f`, `_thash_prf`,
  `_thash_h`, `_thash_t_len` and `_thash_t_k` of `src/slhdsa/thash_shake.jinc`
  compute F, PRF, H, T_len and T_k of section 11.1, for every input. The premise is
  that the Keccak-f[1600] procedure of the set's model is correct; the Keccak
  proofs above are about the kernel's own model, and joining the two is open.
  Under the same premise, two sponge steps of the message hashes are proved for
  every input: `_shake_absorb_prefix` (`src/slhdsa/thash_shake.jinc`) absorbs a
  prefix of up to 332 bytes from any position within the 136-byte rate, permuting
  at each full block, and `_keccak_finalize` (`src/hash/keccak/sponge.jinc`), at
  rate 136 with domain byte 0x1F, pads the absorbed message and permutes as
  SHAKE256 does (FIPS 202, sections 5.1 and 6.2). PRF_msg and H_msg are not.
- **SHA2 tweakable hashes.** For the six SHA2 sets, in `src/slhdsa/thash_sha2.jinc`:
  - `_thash_ctx_init` compresses the PK.seed block once and stores the SHA-256
    chaining value (and, for n = 24 and 32, the SHA-512 one) in the context;
  - `_thash_f`, `_thash_prf` and `_thash_h` compute F, PRF and H of section 11.2
    from a context in that layout, which `_thash_ctx_init` establishes.

  The premise is that the SHA-256 and SHA-512 compression procedures of the set's
  model meet the statements the kernel proofs above give for the kernel's own
  model; joining the two is open. The SHA2 T_len and T_k are not proved; lemmas
  on the SHA-2 specification for their multi-block inputs are
  (`proofs/correctness/core/sha2/ThashBlocks.ec`).

- **Core encodings.** For each of the 12 parameter sets, on the models of that
  set (the core's code depends on the set, so it is extracted once per set and
  architecture):
  - `__node_copy` of `src/slhdsa/encoding.jinc` returns its n-byte source;
  - `__node_concat` returns the 2n bytes of its first argument followed by those of its second;
  - on the six SHA2 sets, `__adrs_compress_into64` and `__adrs_compress_into128` of
    `src/slhdsa/thash_sha2.jinc` write ADRS^c, the 22-byte compressed address of
    section 11.2, into a hash block and leave its other bytes unchanged;
  - `__digest_tree_leaf` and `__fors_indices` split the message digest into idx_tree,
    idx_leaf (Algorithm 19, lines 6 to 10) and the FORS indices (base_2b, Algorithm 4);
  - `__wots_digits` of `src/slhdsa/wots.jinc` returns the len digits of Algorithm 7,
    lines 1 to 7: the base-16 digits of the message, then those of its checksum.
- **WOTS+.** For each of the 12 parameter sets, in `src/slhdsa/wots.jinc`:
  - `_wots_chain` computes chain of Algorithm 5 when start + steps < 2^32, and
    returns an address whose bytes 0 to 27 are those of its input;
  - `_wots_pk_from_sig` computes wots_pkFromSig of Algorithm 8, for the address
    the standard's caller passes (the caller's address with type WOTS_HASH and the
    given key pair).

  Both take as premises that `_thash_f` (and, for Algorithm 8, `_thash_t_len`)
  compute F (T_len) for one fixed PK.seed and context: the form of the tweakable
  hash theorems above, so for the SHAKE sets the two compose, and for the SHA2 sets
  T_len is still open.

Not proven:

- the HMAC step that forms the key block from memory;
- the kernels that replace the portable ones: SHA-NI in the x86-64 `shani` variant
  and the SHA-2 instruction kernels in the AArch64 `sha2` variant (the scalar
  variant runs the portable SHA-2 kernels on both architectures);
- the x86-64 `avx2` variant of the SHA2 sets: its four-way tweakable hashes
  (`src/slhdsa/thash_sha2_x4/multi/`) and the AVX2 8-way SHA-256 and 4-way
  SHA-512 kernels under them;
- the single-way and four-way kernels on the A64 SHA-3 instructions (AArch64 `sha3`
  variant), and the portable and AVX2 four-way kernels;
- the sponge forms over fixed-length arrays and the four-way sponge;
- the SHAKE PRF_msg and H_msg, and the SHA2 T_len, T_k, PRF_msg and H_msg;
- every FIPS 205 algorithm other than Algorithms 5 and 8; the rest is open.

`capi/dispatch.c` selects a set's `shani`, `avx2`, `sha2` or `sha3` variant
wherever the CPU has the extensions it needs, so on such CPUs the library runs
kernels these proofs do not cover. The proven kernels are those of the scalar
variant, which every set has.

The details are in
[`proofs/README.md`](../proofs/README.md#extracted-models-and-correctness-proofs).
`make check-extraction` fails if a committed model differs from a fresh extraction,
so a proof cannot silently refer to old code.

## Compilation

The Jasmin compiler is proved correct in Rocq, from the Jasmin abstract syntax to
the assembly semantics, per target; `toolchain/build.sh` re-checks the proofs from
scratch. The front end, the assembly printer, the assembler and the linker are
outside the theorem. Its assumptions are printed by every build and must equal
[`toolchain/jasmin/ASSUMPTIONS`](../toolchain/jasmin/ASSUMPTIONS);
[TOOLCHAIN](TOOLCHAIN.md#assurance-boundary-of-the-toolchain) lists what is trusted.

## Assumptions and trusted base

Every axiom a proof can use is listed per (architecture, variant) in
`proofs/inventory/`, together with each claimed theorem statement and every
definition it relies on; `make check-inventory` fails when any of them changes
without a reviewed update. The trusted base of the EasyCrypt results is EasyCrypt,
Why3 and the pinned SMT provers, the Jasmin EasyCrypt library and its instruction
models, and `jasmin2ec` itself. No proof contains an admitted step: the proof-hole
scan rejects `admit`, `admitted` and the commands that would let a file pass
unchecked.

## Checking

With the pinned toolchain, from the repository root:

```sh
ci/toolchain.sh exec make -C proofs check check-inventory check-extraction
```

CI runs the same files in 16 shards on every change that can affect them
([STATUS](STATUS.md#proofs)).
