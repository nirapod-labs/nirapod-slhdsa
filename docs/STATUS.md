# Status

Every result the project has, per parameter set, interface and platform. Each
table names the CI run on `main` it comes from; a result moves only with a check in
the repository and a run that reproduces it.

The tables are rendered from [`status.toml`](status.toml) by `ci/status.py`, and
CI fails when they and the record disagree. To change a result, edit the record
and run `python3 -I ci/status.py write`.

Two vocabularies are used, and kept apart. A **check status** says how a check
ended: PASS, FAIL, INCONCLUSIVE, NOT RUN, NOT APPLICABLE. An **evidence label**
says what kind of evidence supports a claim: PROVEN (a named theorem was
machine-checked), VERIFIED (a test or analysis ran and met its criterion, which is
not a proof), UNKNOWN (not established). A PASS on a proof check means the proofs
that exist were re-checked; it does not widen what they state.

## Parameter sets

<!-- begin status:sets (rendered from docs/status.toml by ci/status.py; edit that file) -->
| SLH-DSA set | [x86-64 Linux](VALIDATION.md) | [AArch64 Linux](VALIDATION.md) | [AArch64 macOS](VALIDATION.md) | [CT](SECURITY-MODEL.md#constant-time) | [SCT](SECURITY-MODEL.md#speculative-constant-time) | [Memory safety](SECURITY-MODEL.md#memory-safety) | [Spec security](PROOFS.md#security-of-the-specification) | [Code = spec](PROOFS.md#the-code-against-the-specification) |
| :-- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| SHA2‑128s | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHA2‑128f | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHA2‑192s | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHA2‑192f | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHA2‑256s | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHA2‑256f | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHAKE‑128s | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHAKE‑128f | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHAKE‑192s | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHAKE‑192f | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHAKE‑256s | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |
| SHAKE‑256f | PASS | PASS | PASS | PASS | PASS | NOT RUN | PROVEN | UNKNOWN |

From CI run [38680243373](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38680243373) on `main` at `de27e6a`.
<!-- end status:sets -->

The three platform columns are the tests: `test-core`, `test-acvp` and
`differential` below, run natively on that platform. *CT* and *SCT*, constant time and speculative constant
time, cover every compilation unit of the set, the accelerated variants included,
and are conditional on memory safety, which has no result yet. *Spec security* is a theorem about the
EasyCrypt specification of the set, not about the code. *Code = spec* is open for
every set: the parts proven so far are listed in [PROOFS](PROOFS.md).

## Interfaces

<!-- begin status:interfaces (rendered from docs/status.toml by ci/status.py; edit that file) -->
| Interface (FIPS 205) | Linux x86-64 | Linux AArch64 | macOS AArch64 |
| :-- | :-: | :-: | :-: |
| `slh_keygen` (Algorithm 21) | PASS | PASS | PASS |
| `slh_sign`, hedged and deterministic (Algorithm 22) | PASS | PASS | PASS |
| `slh_verify` (Algorithm 24) | PASS | PASS | PASS |
| `hash_slh_sign`, 12 pre-hash functions (Algorithm 23) | PASS | PASS | PASS |
| `hash_slh_verify`, 12 pre-hash functions (Algorithm 25) | PASS | PASS | PASS |
| `slh_keygen_internal` (Algorithm 18), testing build | PASS | PASS | PASS |
| `slh_sign_internal` (Algorithm 19), testing build | PASS | PASS | PASS |
| `slh_verify_internal` (Algorithm 20), testing build | PASS | PASS | PASS |

From CI run [38680243373](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38680243373) on `main` at `de27e6a`.
<!-- end status:interfaces -->

The ACVP vectors exercise key generation from given seeds, signing pure and
pre-hash, deterministic and with a given `opt_rand`, and verification, through the
testing build; the round-trip tests run the same interfaces through the application
library. The twelve pre-hash functions are those of `nirapod_slhdsa_prehash`:
SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256,
SHA3-384, SHA3-512, SHAKE128 and SHAKE256. FIPS 205 section 10.2 allows any approved
hash function or XOF; choosing one strong enough for the parameter set is the
caller's, and the library does not check it.

## Checks

<!-- begin status:checks (rendered from docs/status.toml by ci/status.py; edit that file) -->
| Check | Linux x86-64 | Linux AArch64 | macOS AArch64 | What a PASS covers |
| :-- | :-: | :-: | :-: | :-- |
| `test-core` | PASS | PASS | PASS | `make check`: round trips of every set, ACVP subset, negative, fault, stack, register and export tests |
| `test-acvp` | PASS | PASS | PASS | 1248 of 1248 NIST ACVP cases, and the runner's negative controls |
| `test-acvp-scalar` | NOT RUN | NOT RUN | NOT RUN | 1248 of 1248 NIST ACVP cases on the scalar variant, forced for every set |
| `differential` | PASS | PASS | PASS | 336 of 336 cases against slhdsa-c `174c02e`, and the comparison controls |
| `test-hash` | PASS | PASS | PASS | CAVP, differential and negative tests of the hash layer |
| `analysis-units` | PASS | PASS | PASS | `jasmin-ct` and `jasmin-ct --sct` on every unit of the architecture |
| `analysis-hash` | PASS | PASS | PASS | the same on the hash test exports |
| `asm-policy` | PASS | PASS | PASS | exported symbols, no division, reserved AArch64 registers, with controls |
| `safety` | NOT RUN | NOT RUN | NOT RUN | `jasmin-checksafety`; there is no safety target yet |
| `memcheck` | NOT RUN | NOT RUN | NOT APPLICABLE | Valgrind memcheck over the tests of `make check` and its negative control; testing evidence, not a safety verdict |

From CI run [38680243373](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38680243373) on `main` at `de27e6a`.
<!-- end status:checks -->

The full ACVP run of `test-acvp` uses the hash variant the runner's CPU selects:
`shani` and `avx2` on the x86-64 runner, `sha2` and `sha3` on both AArch64 runners.
`test-acvp-scalar` runs the same vectors on the scalar variant, forced for every
set: the variant the correctness proofs cover
([PROOFS](PROOFS.md#testing-the-specification-through-the-code)). `make check`
requires every other variant the host supports to produce the scalar variant's keys
and deterministic signatures byte for byte. [VALIDATION](VALIDATION.md) describes
each check and its controls.

## Proofs

<!-- begin status:proofs (rendered from docs/status.toml by ci/status.py; edit that file) -->
| Proof shard | Status | What a PASS covers |
| :-- | :-: | :-- |
| `proofs-sphincs` | PASS | the imported SPHINCS+ security proof, on this copy |
| `proofs-crypto-specs` | PASS | the imported FIPS 202 specification |
| `proofs-spec` | PASS | the FIPS 205 specification, its validation lemmas and its EUF-CMA theorems |
| `proofs-x86_64-portable` | NOT RUN | the set-independent correctness proofs on the x86-64 portable models |
| `proofs-aarch64-portable` | NOT RUN | the same on the AArch64 portable models |
| `proofs-aarch64-a64scalar` | NOT RUN | the same on the AArch64 scalar models |
| `proofs-inventory` | NOT RUN | the axiom inventories of the three models |
| `proofs-<pair>-<family>-<s|f>` (8 shards) | NOT RUN | the per-set proofs on the models of three parameter sets each, and their inventories |
| `proofs-extraction` | PASS | the committed models equal a fresh `jasmin2ec` extraction |

From CI run [38680243373](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38680243373) on `main` at `de27e6a`.
<!-- end status:proofs -->

All shards run on Linux x86-64, where the pinned SMT provers are available. What
the theorems state is in [PROOFS](PROOFS.md), and precisely in
[`proofs/README.md`](../proofs/README.md).

## Toolchain

<!-- begin status:toolchain (rendered from docs/status.toml by ci/status.py; edit that file) -->
| Check | Linux x86-64 | Linux AArch64 | macOS AArch64 |
| :-- | :-: | :-: | :-: |
| Rocq proofs of the compiler, extraction, assumption and admit checks, compiler tests | PASS | PASS | PASS |
| Jasmin EasyCrypt library and pinned provers | PASS | NOT APPLICABLE | PASS |

From CI run [38554446843](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38554446843) on `main` at `8646299`.
<!-- end status:toolchain -->

Linux AArch64 builds the compiler without EasyCrypt, because several pinned SMT
provers publish no binaries for it. CI timings are not performance results.

<!-- begin status:agree (rendered from docs/status.toml by ci/status.py; edit that file) -->
| Check | Status | What a PASS covers |
| :-- | :-: | :-- |
| `agree` | PASS | the three platforms used the same extracted compiler and assumptions, and wrote the same core transcripts |

From CI run [38680243373](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38680243373) on `main` at `de27e6a`.
<!-- end status:agree -->

## Not yet measured

No benchmark result is published. Performance against the baselines pinned under
`bench/` has not been measured on this revision.
