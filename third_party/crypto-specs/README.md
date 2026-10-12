<!--
SPDX-FileCopyrightText: nirapod-slhdsa contributors
SPDX-License-Identifier: Apache-2.0
-->

# crypto-specs (imported)

EasyCrypt specification of FIPS 202 (Keccak-p[1600], the sponge, SHA-3 and
SHAKE) from formosa-crypto, used by `proofs/spec/hash/FIPS202_Bytes.ec`.

| | |
|---|---|
| Upstream | https://github.com/formosa-crypto/crypto-specs |
| Revision | `fb050598ed356c5c6604d92a1e198b2dd4543777` (2026-02-23) |
| Licence | CC0-1.0, see `LICENSE` (upstream's own file) |
| Local changes | none: every file below is byte-identical to upstream |

The import is a subset of the upstream tree, at the same relative paths:
the FIPS 202 specification, its functional and byte-level restatements with
their equivalence proofs, and the library and array theories they require.

| File | SHA-256 |
|---|---|
| `LICENSE` | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` |
| `arrays/Array200.ec` | `948741d77744341b61727706ec4a45177c09370663185865568f52a6881b8728` |
| `arrays/Array24.ec` | `24ce8ef5c2008ca4464948f5614847a7ff768ae20ecf6855712a401c69537f2c` |
| `arrays/Array25.ec` | `93028dcc30026f11b72b8f5340ef07aaa8deed5b7c3c44bd327cb2178b283605` |
| `arrays/Array5.ec` | `f4d684618dc3ac6916fc46a8a4a18f250e40dad46a8bb5466e8fdd6471b5bfbb` |
| `arrays/WArray200.ec` | `b901dff595d622963256349350832dd61e27a25229ecc01ae250bc3569d8dcb4` |
| `common/EclibExtra.ec` | `580ce087e036f060ee1c481d1481985cf94de0cb0097f60e5465a96af568fa56` |
| `common/JWordList.ec` | `b9e6dea5a7b8c0bf853d9d31c9b7f04d13446e010a7625291f1ff1c4da525ed1` |
| `fips202/FIPS202_Keccakf1600.ec` | `40d7cc942211a2b77be13d38d8d80691b9bf5274c4e95ea2beda68e7a2333697` |
| `fips202/FIPS202_SHA3.ec` | `2d90f22e719140231fe9dd674a6e9c96859672c20c923e1a47b4b9e7e2a57921` |
| `fips202/Keccak1600_arrays.ec` | `951cf238f06c8f6432b12d85a4f1d9f87624fafbda32d95d0a8d4ba9d2d7b56a` |
| `fips202/properties/FIPS202_SHA3_Spec.ec` | `506e0926506124aa905d887fa5c5d0963f65c06e6767e9dbcbf9f26e6b129aac` |
| `fips202/properties/Keccak1600_Spec.ec` | `a092a1f89dedeff1eb5e3251a2f99316801aa92252ea4df8773ba316a0b5e273` |
| `fips202/properties/Keccakf1600_Spec.ec` | `e98796064db691bb7194b82a967dc884cb12ac9244026337eb2144d403cda4d5` |

Upstream's proofs are re-checked on this copy by `make -C proofs
check-imported`; their correctness is claimed here only as far as that run
establishes it. `Keccak1600_Spec.ec` contains two `admitted` proofs inside a
commented-out block (upstream lines 304 to 338); they are not part of the
checked theory, and the hole scan ignores comments.
