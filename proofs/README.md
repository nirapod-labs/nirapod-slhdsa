<!--
SPDX-FileCopyrightText: nirapod-slhdsa contributors
SPDX-License-Identifier: Apache-2.0
-->

# Proofs

EasyCrypt development for nirapod-slhdsa. So far it holds byte-level
specifications of the hash functions FIPS 205 uses, models of the Jasmin
hash code extracted with `jasmin2ec`, and proofs that parts of that code
compute the specified functions.

**Status.** The implementation theorems cover the one-block entry points
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
| `extracted/` | the extraction entry and the models `jasmin2ec` extracts from the Jasmin sources, one directory per (architecture, variant) |
| `correctness/` | functional-correctness proofs of the extracted models |
| `inventory/` | per (architecture, variant): every axiom in scope and the claimed theorem statements, as EasyCrypt prints them |
| `tools/` | the proof-hole scan, the FIPS 180-4 constant derivation, the extraction script, the inventory generator |

The FIPS 202 bit-level specification is imported unchanged from
[formosa-crypto/crypto-specs](https://github.com/formosa-crypto/crypto-specs)
and lives in `../third_party/crypto-specs/` with its licence and
provenance.

## The hash specifications

Each function is an EasyCrypt operator on byte strings that cites the
section of its standard. The specifications cover byte-string messages
only: FIPS 180-4 and FIPS 202 also define their functions on bit strings
whose length is not a multiple of eight, which FIPS 205 never uses. The
FIPS 180-4 constant tables are checked by `make check-constants`, which
re-derives them from their definitions. The hash functions themselves
cannot be evaluated inside EasyCrypt (machine words are abstract there).
Of the specifications, only the two compression functions are tested
against vectors, through the kernels proven equal to them, which pass the
CAVP tests of `tests/hash`. Padding, the full hashes and their truncated
variants, HMAC, MGF1 and the FIPS 202 byte interface are checked by review
only, until proofs of the code that implements them reach them.

## Extracted models and correctness proofs

`make extract` runs `jasmin2ec` on `extracted/hash.jazz`, an entry that only
requires the production hash sources, once per (architecture, variant)
pair listed in the Makefile (`EXTRACTIONS`), under the include roots that
select that pair's kernels. Each model is written to
`extracted/<arch>/<variant>/` as `HashExtracted.ec` plus the array theories
it uses, with a header naming the generator, the command and the SHA-256 of
the sources. `make check-extraction` re-extracts into a scratch directory
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
`../third_party/crypto-specs` on its own, without `.eco` caches, and the
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
established). `check-spec` limits the compilation to `spec/`. Variables:
`EASYCRYPT`, `EC_PROVERS`, `EC_TIMEOUT`, `JASMIN2EC`, `JASMIN_SRC`, `PYTHON`.

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
The imported theories are checked with the prover selection of their own
upstream project file.

## Assumptions

Every axiom the proofs can use is listed in `inventory/`, per pair; the
x86-64 list is longer only because the x86-64 instruction model loads the
AES axioms and has two of its own. None comes from the specification or
correctness theories. The imported crypto-specs theory JWordList defines
`stores8` and `stores64` with `axiomatized by`, and states the hypotheses
of its abstract theory `ListEmbedding` as axioms that each of its three
clones realizes. The rest belong to the EasyCrypt standard library and the
Jasmin EasyCrypt library (`eclib`) of the pinned toolchain, including the
parameters of the array theories the extracted models clone;
`../toolchain/jasmin/ECLIB_AXIOMS` and `../docs/TOOLCHAIN.md` describe the
`eclib` ones. Both libraries belong to the trusted base together with
EasyCrypt itself and its SMT provers.

The correctness theorems are about the models `jasmin2ec` extracts, so the
extraction belongs to the trusted base too, and so do the `eclib` models
of the instructions the kernels use: `BSWAP_32` and `BSWAP_64` in
`JModel_x86`, `REV_32` and `REV_64` in `JModel_armv8a`. `ArchWord` proves
these definitions to be byte reversal; that they match the compiler's
semantics of the instructions is not proven here.
