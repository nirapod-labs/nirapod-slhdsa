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
| `hash_slh_sign`, every allowed pre-hash | — | — | — |
| `hash_slh_verify`, every allowed pre-hash | — | — | — |

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
| Constant time, every secret-dependent export | — | — |
| Speculative constant time, every secret-dependent export | — | — |
| Memory safety, every export | — | — |

## Toolchain

| Check | AArch64 | x86-64 |
| :---- | :-----: | :----: |
| Compiler proofs, extraction and tests, from scratch | PASS, `39acdf0` | PASS, `39acdf0` |
| Same compiler and build records on every platform | PASS, `39acdf0` | PASS, `39acdf0` |

AArch64 covers Linux and macOS; Linux AArch64 builds the compiler without EasyCrypt, so the
EasyCrypt library check of the first row ran on macOS for that column. Both rows come from CI run
[38333758447](https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/38333758447)
on hosted runners; CI timings are not performance results.
