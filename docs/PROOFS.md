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
the code `jasmin2ec` extracts. Of the FIPS 205 algorithms, those of WOTS+, XMSS,
FORS and the hypertree (Algorithms 5 to 17), the internal key generation,
signing and verification (Algorithms 18 to 20) and the external ones with
their context and pre-hash framing (Algorithms 21 to 25) are covered. On the
models of the scalar variant of each architecture, the exports are proved with
every hash they call proved too, so their theorems have no premise; their only
conditions are on the length and placement of the caller's message (Domain,
below).

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
  compute F, PRF, H, T_len and T_k of section 11.1, for every input, with the
  Keccak-f[1600] theorem of the kernel's own model carried over to the set's model.
  Two sponge steps of the message hashes are proved for every input: `_shake_absorb_prefix` (`src/slhdsa/thash_shake.jinc`) absorbs a
  prefix of up to 332 bytes from any position within the 136-byte rate, permuting
  at each full block, and `_keccak_finalize` (`src/hash/keccak/sponge.jinc`), at
  rate 136 with domain byte 0x1F, pads the absorbed message and permutes as
  SHAKE256 does (FIPS 202, sections 5.1 and 6.2); with them, `_prf_msg` and
  `_h_msg` compute PRF_msg and H_msg. The four-way `_thash_prf_x4`, `_thash_f_x4`
  and `_thash_t_len_x4` compute PRF, F and T_len for each of their four lanes, on
  the portable four-way Keccak-f[1600], which is proved to permute each of its four
  instances.
- **SHA2 tweakable hashes.** For the six SHA2 sets, in `src/slhdsa/thash_sha2.jinc`:
  - `_thash_ctx_init` compresses the PK.seed block once and stores the SHA-256
    chaining value (and, for n = 24 and 32, the SHA-512 one) in the context;
  - `_thash_f`, `_thash_prf` and `_thash_h` compute F, PRF and H of section 11.2
    from a context in that layout, which `_thash_ctx_init` establishes.

  - `_thash_t_len` and `_thash_t_k` compute T_len and T_k of section 11.2 from that
    context;
  - the four-way `_thash_prf_x4`, `_thash_f_x4` and `_thash_t_len_x4`, which run
    the single-way code once per lane, compute PRF, F and T_len for each lane;
  - `_prf_msg` and `_h_msg` compute PRF_msg (HMAC) and H_msg (MGF1 over SHA-256
    or SHA-512) of section 11.2 for a message in the SHA-2 domain (Domain, below).

  The kernel theorems above are carried over to the set's model.

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
  hash theorems above, which discharge them for both families.

  `_wots_leaf_x4` computes, when kp0 + 3 < 2^32 and every digit is below 16, the
  public keys of the four key pairs kp0 to kp0 + 3 (Algorithm 6) and, when its lane
  argument is below 4, the chain values of Algorithm 7 for the caller's digits and
  key pair kp0 + lane; for a lane of 4 or more it leaves the signature buffer
  unchanged. Its premises are that `_thash_prf_x4`, `_thash_f_x4` and
  `_thash_t_len_x4` compute PRF, F and T_len lane by lane, for one fixed PK.seed
  and context, which the four-way theorems above discharge for both families.
- **XMSS.** For each of the 12 parameter sets, in `src/slhdsa/xmss.jinc` and
  `src/slhdsa/treehash.jinc`:
  - `_xmss_pk_from_sig` computes xmss_pkFromSig of Algorithm 11, given F, T_len
    and H in the form of the WOTS+ premises;
  - `_treehash_fold` adds one leaf to the treehash fold: from the pending nodes and
    the target's authentication nodes after the leaves before i, it establishes them
    after leaf i, given H, for a tree of height t <= a whose nodes are H of their two
    children and whose first leaf index is a multiple of 2^t (XMSS and FORS trees);
  - `_xmss_treehash` returns xmss_node(SK.seed, 0, h', PK.seed, ADRS) of
    Algorithm 9 when every digit is below 16, and leaves the signature buffer
    unchanged for a target of 2^h' or more; for a target below 2^h' and the digits
    of M (Algorithm 7, lines 1 to 7) it also returns xmss_sign of Algorithm 10.
    Its premises are the four-way PRF, F and T_len of `_wots_leaf_x4`, and H.
- **FORS.** For each of the 12 parameter sets, in `src/slhdsa/fors.jinc`:
  - `_fors_tree` returns, for tree t < k and a selected leaf tg < 2^a, the secret of
    leaf t 2^a + tg (Algorithm 14), its authentication path and the root of the tree,
    fors_node of Algorithm 15, given the four-way PRF and F of `_wots_leaf_x4`, and H;
  - `_fors_sign` writes SIG_FORS of Algorithm 16 after the randomizer, leaving the
    other bytes of the signature buffer unchanged, and returns fors_pkFromSig of that
    signature, when the k indices it is given are base_2b(md, a, k), given the same
    premises and T_k;
  - `_fors_pk_from_sig` computes fors_pkFromSig of Algorithm 17, when the k indices
    it is given are base_2b(md, a, k), given F, H and T_k in the same form.
- **Hypertree.** For each of the 12 parameter sets, in `src/slhdsa/hypertree.jinc`:
  - `_ht_sign` writes ht_sign of Algorithm 12 after R and SIG_FORS, for an idx_leaf
    below 2^h', and returns the root of the top tree, given the premises of
    `_xmss_treehash`;
  - `_ht_verify` returns 0 when ht_verify of Algorithm 13 holds and -1 otherwise,
    given F, T_len and H in the form of the WOTS+ premises.
- **Internal functions.** For each of the 12 parameter sets, in
  `src/slhdsa/internal.jinc`, for the message M = prefix[0 : prefix_len] followed
  by the msg_len bytes at msg, with prefix_len at most 332 and a message that does
  not wrap the address space:
  - `_slh_sign` returns slh_sign_internal(M, SK, opt_rand) of Algorithm 19; the
    deterministic variant is opt_rand = PK.seed;
  - `_slh_verify` returns 0 when slh_verify_internal(M, SIG, PK) of Algorithm 20
    accepts and all ones otherwise;
  - `_slh_keygen` returns the SK and PK of slh_keygen_internal of Algorithm 18 for
    the seeds SK.seed, SK.prf and PK.seed it is given.

  The premises are that `_thash_ctx_init` returns a context for which the
  tweakable hashes compute their section 11 functions in the form above (the
  four-way PRF, F and T_len, and H and T_k, for signing and key generation; F,
  T_len, H and T_k for verification), and that `_prf_msg` and `_h_msg` compute
  PRF_msg and H_msg of M. The hash theorems above discharge all of them: the three
  functions are proved with no premise.
- **External functions.** For each of the 12 parameter sets, in
  `src/slhdsa/external.jinc` and the exports of `src/slhdsa/api.jinc`, with the
  caller's 257-byte domain block (pre-hash selector, |ctx|, ctx):
  - `_slh_frame` returns M' of Algorithms 22 to 25 for a selector of at most 12
    (pure SLH-DSA or one of the 12 pre-hash functions), and status all ones
    otherwise; a context of more than 255 bytes cannot be written in the block,
    and rejecting it is the C layer's part;
  - `sign` returns slh_sign (Algorithm 22) or hash_slh_sign (Algorithm 23);
    `verify` returns 0 when slh_verify (Algorithm 24) or hash_slh_verify
    (Algorithm 25) accepts and all ones otherwise; `keygen` returns slh_keygen
    (Algorithm 21) for the seeds it is given; `sign_internal` and
    `verify_internal` are the section 9 functions.

  The premises are the theorems of the internal functions, and that `_prehash`
  terminates and returns PH(M) for the function of its selector. `_prehash` is
  proved for all 12 functions: the six SHA-2 one-shots, and the sponge with the
  parameters of SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 (256 bits) and
  SHAKE256 (512 bits). With these, the exports are proved with no premise.

- **Domain.** The theorems of the internal functions and of the exports hold for
  every input that meets two conditions on the caller's message: its buffer does
  not wrap the 64-bit address space, and the SHA-2 hashes stay in the domain they
  are proved for, which is that of FIPS 180-4. For the SHA2 sets, 332 + |M| is
  under 2^61 - 256 for `sign` and `verify` (332 bytes being the most framing M'
  puts before M), and |M| is under 2^61 - 256 for `sign_internal` and
  `verify_internal`. For the SHA-2 pre-hash functions, M is under 2^61 bytes
  (FIPS 180-4 allows SHA-384 and SHA-512 longer messages; the proofs stop at 2^61
  bytes). In both cases the buffer ends below 2^64. No buffer that a process on
  the supported targets can hold comes near these bounds, and the library does not
  check them.

Not proven:

- the HMAC step that forms the key block from memory;
- the kernels that replace the portable ones: SHA-NI in the x86-64 `shani` variant
  and the SHA-2 instruction kernels in the AArch64 `sha2` variant (the scalar
  variant runs the portable SHA-2 kernels on both architectures);
- the x86-64 `avx2` variant of the SHA2 sets: its four-way tweakable hashes
  (`src/slhdsa/thash_sha2_x4/multi/`) and the AVX2 8-way SHA-256 and 4-way
  SHA-512 kernels under them;
- the single-way and four-way kernels on the A64 SHA-3 instructions (AArch64 `sha3`
  variant), and the AVX2 four-way kernel;
- the sponge forms over fixed-length arrays and the general four-way sponge;
- the FIPS 205 algorithms other than 5 and 8 to 25 on their own: Algorithms 1 to 4
  only as the proven ones use them (base_2b in `__fors_indices`, the digits of
  Algorithm 7 in `__wots_digits`), and Algorithms 6 and 7 only as `_wots_leaf_x4`
  computes them;
- the C layer (`capi/`): its checks of sizes, NULL pointers, overlapping buffers
  and |ctx| at most 255, the variant dispatch, and the entropy draw of
  Algorithm 21. The theorems take the signature, keys and domain block of an
  export as values apart from the message in memory; for a call through the C
  API, its overlap check is what makes that so.

`capi/dispatch.c` selects a set's `shani`, `avx2`, `sha2` or `sha3` variant
wherever the CPU has the extensions it needs, so on such CPUs the library runs
kernels these proofs do not cover. The proven kernels are those of the scalar
variant, which every set has; [the next section](#which-variant-a-cpu-runs) lists
which variant each CPU runs.

The details are in
[`proofs/README.md`](../proofs/README.md#extracted-models-and-correctness-proofs).
`make check-extraction` fails if a committed model differs from a fresh extraction,
so a proof cannot silently refer to old code.

## Which variant a CPU runs

Each parameter set is compiled once per hash variant (`Makefile`, `capi/sets.c`).
At every call the library runs the last variant in the order below whose CPU
features the operating system reports, and the scalar variant when there is none
(`capi/dispatch.c`). On x86-64 no extension is used unless the CPU reports AVX and
the operating system has enabled the AVX register state. "Proven" means the
correctness theorems of [the previous section](#the-code-against-the-specification)
hold for the variant's model; they never cover the C layer.

| Architecture | Variant | Sets | Selected on | Proven |
| :-- | :-- | :-- | :-- | :-- |
| x86-64 | `scalar` | all 12 | SHAKE sets: CPUs without AVX2. SHA2 sets: CPUs with neither AVX2 nor the SHA extensions | yes, model `x86_64/portable` |
| x86-64 | `avx2` | all 12 | SHAKE sets: CPUs with AVX2. SHA2 sets: CPUs with AVX2 and without the SHA extensions | no |
| x86-64 | `shani` | 6 SHA2 | CPUs with the SHA extensions, with or without AVX2 | no |
| AArch64 | `scalar` | all 12 | SHAKE sets: CPUs that lack FEAT_SHA3 or Advanced SIMD. SHA2 sets: CPUs that lack FEAT_SHA256, FEAT_SHA512 or Advanced SIMD | yes, model `aarch64/a64scalar` |
| AArch64 | `sha3` | 6 SHAKE | CPUs with Advanced SIMD and FEAT_SHA3 | no |
| AArch64 | `sha2` | 6 SHA2 | CPUs with Advanced SIMD, FEAT_SHA256 and FEAT_SHA512 | no |

The variants differ in their hash kernels only: `avx2` runs the four-way Keccak
kernel on AVX2 for the SHAKE sets, and the four-way tweakable hashes on the AVX2
8-way SHA-256 and 4-way SHA-512 kernels for the SHA2 sets; `shani` runs SHA-256 on
the SHA extensions; `sha3` runs single-way and four-way Keccak on the A64 SHA-3
instructions; `sha2` runs SHA-256 and SHA-512 on the A64 SHA-2 instructions. The
SLH-DSA code above the kernels is the same source in every variant, but only the
scalar models are extracted and proven.

So on a CPU that has the extensions of a set's accelerated variant, no call for
that set through the library runs proven code. All three CI runners
([VALIDATION](VALIDATION.md#where-tests-run)) are such CPUs for every set. The
application library has no way to request the scalar variant. The testing library
can pin a variant per call, but it also exposes the internal functions of FIPS 205
section 9 and must not be linked into an application
([API](API.md#building-and-linking)).

## Compilation

The Jasmin compiler is proved correct in Rocq, from the Jasmin abstract syntax to
the assembly semantics, per target; `toolchain/build.sh` re-checks the proofs from
scratch. The front end, the assembly printer, the assembler and the linker are
outside the theorem. Its assumptions are printed by every build and must equal
[`toolchain/jasmin/ASSUMPTIONS`](../toolchain/jasmin/ASSUMPTIONS);
[TOOLCHAIN](TOOLCHAIN.md#assurance-boundary-of-the-toolchain) lists what is trusted.

## Assumptions and trusted base

Every axiom a proof can use is listed per (architecture, variant), and per
parameter set for the per-set models, in `proofs/inventory/`, together with each
claimed theorem statement and every definition it relies on; `make
check-inventory` fails when any of them changes without a reviewed update. The trusted base of the EasyCrypt results is EasyCrypt,
Why3 and the pinned SMT provers, the Jasmin EasyCrypt library and its instruction
models, and `jasmin2ec` itself; for calls through the C API, the C layer as
well (Not proven, above). No proof contains an admitted step: the proof-hole
scan rejects `admit`, `admitted` and the commands that would let a file pass
unchecked.

## Checking

With the pinned toolchain, from the repository root:

```sh
ci/toolchain.sh exec make -C proofs check check-inventory check-extraction
```

CI runs the same files in 16 shards on every change that can affect them
([STATUS](STATUS.md#proofs)).
