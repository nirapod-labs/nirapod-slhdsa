- An EasyCrypt specification of FIPS 205 (`proofs/spec/slhdsa/`):
  Algorithms 1 to 25 for the twelve parameter sets of Table 2, the address
  layout, the SHA2 and SHAKE instantiations of section 11, and context
  framing and pre-hash. Table 2, Algorithms 2 to 4, the address layout and
  the framings are checked by lemmas; the rest is checked by review only and
  has not been run on ACVP vectors.
- EUF-CMA theorems for that specification (`proofs/security/`), for every
  parameter set, pure and pre-hash signing, deterministic and hedged: a
  concrete bound in PRF, ITSR, tweakable-hash and pre-hash collision terms,
  from the SPHINCS+ proof of formosa-crypto/formosa-slhdsa (ePrint
  2024/910), imported unchanged in `third_party/formosa-slhdsa/` and
  re-checked on this copy. They are about the specification, not the
  Jasmin code; `proofs/README.md` states their hypotheses and limits.
