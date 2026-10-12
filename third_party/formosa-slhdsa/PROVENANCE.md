<!--
SPDX-FileCopyrightText: nirapod-slhdsa contributors
SPDX-License-Identifier: Apache-2.0
-->

# formosa-slhdsa (imported): provenance

EasyCrypt proof of the EUF-CMA security of SPHINCS+ by Barbosa, Dupressoir,
Hülsing, Meijers and Strub, "A Tight Security Proof for SPHINCS+, Formally
Verified" (ePrint 2024/910). `proofs/security/` links the FIPS 205
specification to it.

| | |
|---|---|
| Upstream | https://github.com/formosa-crypto/formosa-slhdsa |
| Revision | `d2d4d032f4660525bc41e45e06f1aef44cd3a827` (2026-09-19) |
| Licence | MIT, see `LICENSE` (upstream's own file) |
| Local changes | none: every file below is byte-identical to upstream |

The import is the upstream tree without its CI configuration (`.github/`),
at the same relative paths. `README.md`, `easycrypt.project` and
`config/tests.config` are upstream's own.

| File | SHA-256 |
|---|---|
| `LICENSE` | `95a740f957b8b4b13f898b83023768265a3f8334a44450dc97aa4e7ed4f5361d` |
| `README.md` | `1e8491a2cc8629a300df6ca8507651c4d791ba94091ba9cc4ff359db8e642ec1` |
| `config/tests.config` | `0fe3a1e74307de652a8ffa378e05535ce87aeb844561d75d5ef6fca4a681caaf` |
| `easycrypt.project` | `496f13cb508b60d9a45894dbc8e11ae3720d515396cf619ea6f763f7076320cf` |
| `proofs/BinaryTrees.ec` | `84df7238002a0971e6bcd9375574977404493d751c082ac6a342f353a5f5f4ab` |
| `proofs/FL_SL_XMSS_MT_ES.ec` | `4554d850fc9c8892732a8560dba21cac4dbc8539148beb29996aa1e3ac9daebf` |
| `proofs/FORS_ES.ec` | `42169e8d6cc1826b55fc89aef6923509df60f67b1d3ffccbd090bd8d8482caaf` |
| `proofs/HashAddresses.eca` | `a843f686146208c55a8c4438096ac405a8fe67b70aee5d073f43f2d5a06ce35e` |
| `proofs/KeyedHashFunctions.eca` | `67b0031db0fbd8c335b8008fe3c00fb5bc109d4902591fabfdbaf99c60a130d1` |
| `proofs/MerkleTrees.ec` | `109d5261920540db6b5e96e26b890f2b942c0a619bcadb1c7f845c3402f92d4c` |
| `proofs/OpenPRE_From_TCR_DSPR_THF.eca` | `b7d317c07b3d99cfedf3d140cfd4f12b55d7753c999a87db84116b6fda7d0400` |
| `proofs/PRE_From_SPR_DSPR.ec` | `cff6afac8d0d543c3ec1d898a87f4170b0cac63699480f7e6c9fcd4fd8267e16` |
| `proofs/SPHINCS_PLUS.ec` | `3bb1ce65aec7af6ea91dc65be066ca2e7a1e7110e126acc02cd1886271372741` |
| `proofs/TweakableHashFunctions.eca` | `1e1f5c82fa6dcfd9a8b83004ea8df408fda8c7f87f03ae65d565dcd2ad904c92` |
| `proofs/WOTS_TW_ES.ec` | `d7f5e33f9408f9cd42bdc7c0026297d7e888bd4178b704a0d8f807d7ca4cbe7e` |

Upstream's proofs are re-checked on this copy by `make -C proofs
check-formosa`, with the provers its `easycrypt.project` names; their
correctness is claimed here only as far as that run establishes it.
