# nirapod-slhdsa

SLH-DSA (FIPS 205) written in [Jasmin](https://github.com/jasmin-lang/jasmin)
for AArch64 and x86-64, with machine-checked proofs in
[EasyCrypt](https://github.com/EasyCrypt/easycrypt).

> **Status: under development. Not for production use.**
> Nothing in this repository is complete yet, and no security or
> correctness property is claimed. Status is reported per feature, parameter
> set and architecture in `docs/STATUS.md` as work lands.

## Scope

- All twelve FIPS 205 parameter sets (SHA2 and SHAKE; 128, 192, 256; s and f).
- Key generation, signing and verification through the external interfaces
  of FIPS 205 section 10: pure SLH-DSA with context strings and HashSLH-DSA,
  with deterministic and hedged signing.
- The internal functions of FIPS 205 section 9, for testing and validation
  only.
- A C-callable API that runs the Jasmin implementation end to end, with no
  heap allocation and no global mutable state.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
