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
check. The implementation theorems so far cover the one-block entry points
`_sha256_compress` and `_sha512_compress` of the portable SHA-256 and
SHA-512 kernels, and their round functions (below). The kernels' other
entry points, `_sha256_compress_blocks` and `_sha512_compress_blocks`, which
the streaming hash uses for every whole block of input in memory, and
`_sha256_compress_one` and `_sha512_compress_one`, have no proof yet.
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
`extracted/hash.jazz`, which only requires the production hash sources and
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
| `correctness/<area>/` | proofs written once for all targets | every pair |
| `correctness/<area>/<arch>/` | facts about one architecture's instructions (theory `ArchWord`) | every pair of that architecture |
| `correctness/<area>/<arch>/<variant>/` | proofs of the kernels a variant replaces (theory `KernelSpec`) | that pair |

`make check-correctness` compiles, for each pair, its model, its
architecture and variant theories and every shared proof, with that pair's
directories on the load path. A shared proof that requires
`HashExtracted` or `ArchWord` is therefore checked against each pair's
model in turn: the shared Jasmin source is proven once and the proof is
replayed on every architecture. The x86-64 and AArch64 models of the
portable code differ only in the instructions behind `__bswap32` and
`__bswap64` (BSWAP against REV), and `ArchWord` proves both to be byte
reversal.

Theorems so far, each checked on `x86_64/portable` and
`aarch64/portable`, the models of the portable kernels:

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
  block.

The `_correct` theorems are partial-correctness (Hoare) statements about
the extracted model: when the procedure returns, its result is the
specified value. Every loop of the kernels runs over a constant range, so
`_sha256_compress` and `_sha512_compress` terminate from every initial
state (`sha256_compress_ll`, `sha512_compress_ll`), and the `_total`
theorems combine the two: the procedure returns, with the specified result,
with probability 1. Memory safety is a separate obligation.

Not proven yet: the memory entry points `_sha256_compress_one`,
`_sha256_compress_blocks`, `_sha512_compress_one` and
`_sha512_compress_blocks`; padding, the one-shot and multi-way functions,
HMAC, MGF1, SHA-3 and SHAKE; and the kernels that replace the portable ones
(SHA-NI on x86-64, the A64 kernels on AArch64), which the x86-64 and
AArch64 test configurations select for SHA-256, and on AArch64 also for
SHA-512.

`spec/hash/FIPS180_SHA2_Blocks.ec` states, at the level of the
specification, how a hash splits into a first block compressed once and a
tail, for the proofs of code that keeps the chaining value of a fixed
first block (the PK.seed block of FIPS 205 section 11.2).

## Checking

With the EasyCrypt of the pinned toolchain (`toolchain/build.sh`), from the
repository root:

```sh
tools/ci/toolchain.sh exec make -C proofs check check-inventory check-extraction
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
part of `check`. Variables: `EASYCRYPT`, `EC_PROVERS`, `EC_TIMEOUT`,
`JASMIN2EC`, `JASMIN_SRC`, `PYTHON`.

`check-inventory` requires, for each pair, every theory that pair is
checked with, has EasyCrypt print every axiom then in scope, the statement
of each theorem in `THEOREMS` (Makefile) and every definition (type,
operator, predicate, abbreviation, module) of the theories in this
directory and in `../third_party`, and fails unless the result equals
`inventory/<arch>-<variant>.txt`. An axiom can enter by an `axiom`
declaration, by an `axiomatized by` definition, or as an axiom a `clone`
leaves unrealized; all three are in EasyCrypt's list. A statement means
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
