# Status

What has been validated, per interface, parameter set and architecture. A cell names its
result and the revision it was validated on; a dash means no result on `main` yet. The
summary per parameter set is in the [README](../README.md#status).

## External interfaces (FIPS 205, section 10)

| Interface | AArch64 Linux | AArch64 macOS | x86-64 Linux |
| :-------- | :-----------: | :-----------: | :----------: |
| `slh_keygen` | — | — | — |
| `slh_sign`, hedged | — | — | — |
| `slh_sign`, deterministic | — | — | — |
| `slh_verify` | — | — | — |
| `hash_slh_sign`, the 12 pre-hash functions | — | — | — |
| `hash_slh_verify`, the 12 pre-hash functions | — | — | — |

The pre-hash rows cover the twelve functions of `nirapod_slhdsa_prehash`, which are the ones NIST's
ACVP vectors test: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224,
SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256, each at every parameter set. FIPS 205
section 10.2 allows any approved hash function or XOF; choosing one strong enough for the
parameter set is the caller's, and the library does not check it.

## Internal functions (FIPS 205, section 9)

Exposed for testing and validation only, never to applications.

| Function | AArch64 Linux | AArch64 macOS | x86-64 Linux |
| :------- | :-----------: | :-----------: | :----------: |
| `slh_keygen_internal` | — | — | — |
| `slh_sign_internal` | — | — | — |
| `slh_verify_internal` | — | — | — |

## Analyses

| Analysis | AArch64 | x86-64 |
| :------- | :-----: | :----: |
| Constant time, every secret-dependent export | PASS, `ee70fee` | PASS, `ee70fee` |
| Speculative constant time, every secret-dependent export | PASS, `ee70fee` | PASS, `ee70fee` |
| Memory safety, every export | — | — |

The constant-time rows come from CI run
[38404907277](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38404907277):
`jasmin-ct` and `jasmin-ct --sct` on all 12 units for AArch64 Linux and macOS and all 24 units
for x86-64 Linux. They assume memory safety, which no tool has checked on these exports yet.
AArch64 now also builds an accelerated variant of each set (`sha2`, `sha3`), so it has 24 units;
those rows predate them and are refreshed from the first CI run on `main` that includes them.

## Toolchain

| Check | AArch64 | x86-64 |
| :---- | :-----: | :----: |
| Compiler proofs, extraction and tests, from scratch | PASS, `39acdf0` | PASS, `39acdf0` |
| Same compiler and build records on every platform | PASS, `39acdf0` | PASS, `39acdf0` |

AArch64 covers Linux and macOS; Linux AArch64 builds the compiler without EasyCrypt, so the
EasyCrypt library check of the first row ran on macOS for that column. Both rows come from CI run
[38333758447](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38333758447)
on hosted runners; CI timings are not performance results.
