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

Open. One component of the SLH-DSA core and parts of the hash layer are proved in
EasyCrypt on the code `jasmin2ec` extracts; no FIPS 205 algorithm is covered yet.

Proven, on the x86-64 and AArch64 models, total correctness:

- **Addresses.** The hash address procedures of `src/slhdsa/address.jinc` compute
  the address setters of FIPS 205 Table 1, for all 12 parameter sets (the code
  depends on none).
- **SHA-2.** `_sha256_compress` and `_sha512_compress`, the one-block entry points
  of the portable SHA-2 kernels, with their round functions, against FIPS 180-4.
- **Keccak.** The Keccak-f[1600] permutation of the single-way kernels the scalar
  variants build (the portable kernel on x86-64, the kernel that keeps the state in
  registers on AArch64), against FIPS 202.

Not proven:

- the SHA-2 entry points that read blocks from memory (`_sha*_compress_blocks`,
  used by the streaming hash);
- the kernels that replace the portable ones: SHA-NI in the x86-64 `shani` variant
  and the SHA-2 instruction kernels in the AArch64 `sha2` variant (the scalar
  variant runs the portable SHA-2 kernels on both architectures);
- the single-way and four-way kernels on the A64 SHA-3 instructions (AArch64 `sha3`
  variant), and the portable and AVX2 four-way kernels;
- the sponge, SHA-3 and SHAKE, and every FIPS 205 algorithm; the rest is open.

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

CI runs the same files in six shards on every change that can affect them
([STATUS](STATUS.md#proofs)).
