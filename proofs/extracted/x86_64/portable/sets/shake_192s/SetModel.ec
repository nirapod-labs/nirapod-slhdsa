(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * GENERATED FILE. DO NOT EDIT.
 *
 * Generator:
 *     tools/set_model.py, from src/slhdsa/params/shake_192s.jinc, src/slhdsa/constants.jinc,
 *     src/slhdsa/thash_shake.jinc and the array theories CoreExtracted.ec requires
 *
 * Model:
 *     x86_64/portable, kernels KeccakKernel=keccak KeccakKernelX=keccak Sha2Kernel=sha2 Sha2KernelX=sha2
 *
 * Regenerate:
 *     make -C proofs extract     (check: make -C proofs check-extraction)
 *
 * Entry src/slhdsa/sets/shake_192s.jinc
 * Sources under src/slhdsa (SHA-256, path):
 *     2582b4cc49d11c2f74494b660ed803f1f88549029bb7dd3285175c1b066d1e8d  ./address.jinc
 *     477aa0dfa2daf1e1479df5689a20167400b05f87b39d8777bd669a7122138aba  ./api.jinc
 *     d05ca920aabee0fbbeb0dc3ecafc1f4668fb57a9ac257135c45c013c97ab197b  ./constants.jinc
 *     280005a53c8a36e5f5aff67f3d3d505a1d49adc67332d7a57fe1a237d1276275  ./encoding.jinc
 *     2bc4ef3d1ff00b894fd7b26781c708c484d11e883263999807674a72a4f87765  ./external.jinc
 *     340d22ebd08b579bf0e306b4a49156e3c959650e350d264cc822e3cf8e53079a  ./fors.jinc
 *     2c34521eebc083a0fb3a093a9a4b621b8164b7f4e9e78101f1deab7dd9dac06c  ./hook/hook.jinc
 *     d7b18f9beaec87652738ce6ad7be5d65fa34185573010a1fabecc527a690408f  ./hypertree.jinc
 *     5094da980099f5b243f8fe72f15df762cde86291b06d81627b1de5e5a6776d25  ./internal.jinc
 *     cca7a74bdaaa992f6dbd7a4c440bd7d6243e58757895795f87ce5ad929705192  ./params/sha2_128f.jinc
 *     567a9e62d05da63e87dc0fe4560afca8540d82285c0fb639451cff04ba0fac27  ./params/sha2_128s.jinc
 *     48a177a2769b2b37b736a22d341d954c19bd4ea7f885119600fb1f9018a2fcf2  ./params/sha2_192f.jinc
 *     0343cc9cf62f6f64fef3ea398a48132bd039285ac3d0469d8cc40e894f7476df  ./params/sha2_192s.jinc
 *     a9b4f412aafa03cee0134786be1da60b059d0daa3a8980eb9636c823794302d2  ./params/sha2_256f.jinc
 *     cbf15b047c563a802208ba58605559d93806d1323c7e16911450b97dd28647b7  ./params/sha2_256s.jinc
 *     af8b3fad5c67626e1e4e2b0b681d9ee9a58085ad68901567fb0ba80229a3b04b  ./params/shake_128f.jinc
 *     0f358b05bc675289214da2cdaaac3c54e57e467144cea474696ed1c3814377e7  ./params/shake_128s.jinc
 *     2e7fbee72d7ec488a1a1c90336571be7b84b39e5ee77388891827e659a581e62  ./params/shake_192f.jinc
 *     7022d350e3946ccc421522e2eac86a1e9a3237091d4943e08ad31461f78a93e2  ./params/shake_192s.jinc
 *     c177395b0191d890c424e67bfe4278cfc47f0d42685037e1a2dedeac2aaa5d96  ./params/shake_256f.jinc
 *     81adc60eda574a1c990b5f5492dbf5d8cb08b68446fa485e46bfdbca6c486b00  ./params/shake_256s.jinc
 *     dcecd3ed230b7ff6ff6f946c7676ea2b6da3a692390e603dc60835c7750a1239  ./sets/sha2_128f.jinc
 *     f8a781a4007d829b845103967fd2aeac3e9c8f749b22f9676fb8b8050d09af9a  ./sets/sha2_128s.jinc
 *     51eaabc093ee34e2da60c5bc9d45bd5096cc0a60204d6111977a7c3efd50b60d  ./sets/sha2_192f.jinc
 *     6dbd18a6ced1527a27d12b330e5bc1805e27dd7dc68b4a24a58a90ce071d67c1  ./sets/sha2_192s.jinc
 *     cdd6204089fa08ef5a61741974e0a42a4078b444aeba4b79d49db11f52c933d7  ./sets/sha2_256f.jinc
 *     c155b3e2a116eb56b5b6c1885c7446db707605acffabf8ee80ae758da9c78c97  ./sets/sha2_256s.jinc
 *     d981f7bb15540689f4335c2f4d36e8fc34d4f6ff99984889e73f66018154ae06  ./sets/shake_128f.jinc
 *     0bef7dbb4e8f4db3c5aecfbc169e56fdfe15f7fe22ef8688aceb24be200f74c0  ./sets/shake_128s.jinc
 *     4ce65c3cd10d06776bc1d44d360d34d00c43bd9980f58a030ba860bcc06cb8a1  ./sets/shake_192f.jinc
 *     50ba3a1118c6a9ab860d6b93e2f5140d5d779f943177fcc56d8720ed57e78a85  ./sets/shake_192s.jinc
 *     8e47887cd0df893c455c1c55f618937d1c9ca4742c1e74299e60667fa439600f  ./sets/shake_256f.jinc
 *     648d27d2cc476ca9e0cb3721ecf0a9527407364ab51ee4d85c6c9e40e4820c11  ./sets/shake_256s.jinc
 *     5c0c391f5c6e991e82961975076a1744e547b4f158313ba156de58bbc5825a1a  ./thash_sha2.jinc
 *     28f33469c5abb2c3a846b3022cac13377b6059007666f5b2feed949a4f238a06  ./thash_sha2_t.jinc
 *     a9df893c857bf84ae64de22f43cc185e5fc68cf0fb3ef5c3e3e1411a38204827  ./thash_sha2_x4/multi/thash_sha2_x4.jinc
 *     b39dd95197fcddf2bfae5a75bb8a596c14b90c43d4dfcd662be166846f713d8a  ./thash_sha2_x4/single/thash_sha2_x4.jinc
 *     cb9f29a6f6330133c91ca8f7cc5fab2817eb365d87b3356b813d37718d17d226  ./thash_shake.jinc
 *     83e05c7b0b81e6e40d050325e79ec47d45e4d1afc0131837b772935725757f4f  ./thash_shake_t.jinc
 *     c07d85c226a2b1ed4666323733a31587771aa1172cfb53c1beecedf5c0dfea89  ./treehash.jinc
 *     fd07937ed7747e2f4334576e08c7e6bb174964e9fe26d5a30629e5bf41af0880  ./wots.jinc
 *     3c37445dd9ce2a76a90fb5371abdccfa62e800b657c041b9b4dc9a3682a33926  ./xmss.jinc
 * Sources under src/hash (SHA-256, path):
 *     3f9b879d57975656cbaa3d23520ba044fe9bbfa823a6640e0228eee023193392  ./aarch64/word.jinc
 *     5e10960ea822ac46820eacbfca5ee743235a6c0c8fbc48faeb21b046937f16b1  ./keccak/aarch64/scalar/keccakf1600.jinc
 *     22a1eef19fb0aec98084bf124b42da019e2117a648834bf0d1a00afa0eeb77a2  ./keccak/aarch64/sha3/keccak_round_x2.jinc
 *     ca50e936c4287c749b4160ec962c811156bed79c79b6f4c8d86a11be9c717beb  ./keccak/aarch64/sha3/keccakf1600.jinc
 *     1b8122d559769c2694f131a08d23bf1d96e4d0fc1d05fa5eaba7c7aa61f6e255  ./keccak/aarch64/sha3/keccakf1600_x4.jinc
 *     e08b6d810ab713cc8138f1c037780a80707a945ce6e3ff4854600c799a3c90fa  ./keccak/fips202.jinc
 *     4e61d1f0f7c98e07dcddaf09f9adaf0067373be370c599ac8666d5e2144dc46f  ./keccak/keccak_constants.jinc
 *     1e1b0ab610fa23c397d91d82d9b2c6a159d94d756a48be726a114eacabbcc7d1  ./keccak/keccakf1600.jinc
 *     720d2ed87aa816547feff0d63944d0385ee8b93387540c54324d28d2a65e4549  ./keccak/keccakf1600_x4.jinc
 *     e1e197db1f9068984e3b47ec996c72f37788cd77e538e5e4f3984f77fefcf07c  ./keccak/sponge.jinc
 *     9170acfa610c761afb06682b96dbf98c686313d114c8409af16be31f119d277b  ./keccak/sponge_array.jinc
 *     b48c65bcff9925e7842cfa8b430b1c14c0ad92f17aaf472ef4d3457ca9e6c9a7  ./keccak/sponge_x4.jinc
 *     0e9882b894c4069590749e796b5245a0631de2a70d5c0dda54a080bafb5c123d  ./keccak/sponge_x4_array.jinc
 *     1268ef0216a5e2a9c0f6c7bd58d70a817f9324243f89794864cf95dfb46f14fe  ./keccak/x86_64/avx2/keccakf1600_x4.jinc
 *     67f594060dea41e4ae0bafeba494c5072fad97c683ad291c5909d98a623d68e9  ./sha2/aarch64/scalar/sha256_compress.jinc
 *     819a4772ab06cb8d59e681cebff34a403f5cba6d41e5614b72d6b21e234baae6  ./sha2/aarch64/scalar/sha512_compress.jinc
 *     ab18ddca2d3b6c1cf69ae126fe7486c2e0c778c71b9b046c8b923edeb5447944  ./sha2/aarch64/sha2/sha256_compress.jinc
 *     1c1703a9a9fb0db2f2bbf1d9c098c8bd6b761567ab236c56dd2cc95281d8adcd  ./sha2/aarch64/sha2/sha512_compress.jinc
 *     ac08e58d565cadd6afe0df7943b811e155a74fdc1309f08d3dd8cda117d43de9  ./sha2/hmac.jinc
 *     60ac802ab9347651f0db7b04344fc6ed90b0afb2b2450fbd51bd9d5e44d545e1  ./sha2/mgf1.jinc
 *     e0a831db7da12266abfea713e32cd14c61630eef0b4cf0f72ab79430651c948a  ./sha2/sha256.jinc
 *     01653390a2f77047c8b8bbd695663f5c2b04b41df4dae8c05285b42ced346e1a  ./sha2/sha256_array.jinc
 *     2ef076349fa6419836c060a2bfe986952cfe80b4f8237a826c137c3d20b60b7f  ./sha2/sha256_compress.jinc
 *     fa9874158d69a3ea868a1c9eb101e336535a5dd26f07466c5d13e7f518faddd6  ./sha2/sha256_k.jinc
 *     8d434e2b7758cc64e9629c7de9dc1326ed328f4cde4bfa09eca5f09fed3701f6  ./sha2/sha256_x8.jinc
 *     fbbef2092ae1f8d791e72fe0b87a96679e70d2559949c4f43c0f8da3432ebd97  ./sha2/sha256_x8_array.jinc
 *     b8217856d4d0ea149f8f6647d56575412b638010be612ce0718aeb6c7523579d  ./sha2/sha256_x8_compress.jinc
 *     0ac501460769198eb1c78b1d3e3ec5183912f84dd319679529630c0a978710fc  ./sha2/sha512.jinc
 *     6190f1b947748d61cac0b134b38b8a2dd600bf6f47b3d457d9ad50b74ea697e6  ./sha2/sha512_array.jinc
 *     a1a07336c8455e3061f184abf313a48294d494e6e9f967810fc9237c324cbe30  ./sha2/sha512_compress.jinc
 *     5989b7c126302e22e9825fbf39b7120f487071ec0c25ff38352bf731b95416d7  ./sha2/sha512_k.jinc
 *     87347735dea610090c7d0283f3cb08896d0f3896464a500e0006bc3ae51e68f1  ./sha2/sha512_x4.jinc
 *     1db4579ecf71ce4970f9c32e03c606c0258eff2d5e72dce9238c5a3488b563d3  ./sha2/sha512_x4_array.jinc
 *     2788c54739fdb24576b668fee824850be0676ee2c77113737126a9fd942b855f  ./sha2/sha512_x4_compress.jinc
 *     2dae8e62486729e4d2dd1500e27e3f856673ab09d372fb27d1aea85edb4a2305  ./sha2/x86_64/avx2/sha256_x8_compress.jinc
 *     36ead19d7204328faae09389b59f4a2f33869eb2fabe160d8d0dfd1a603d0798  ./sha2/x86_64/avx2/sha512_x4_compress.jinc
 *     163442e375aae221fd61e067638d6ccc552acad567ae4ab1d5fd6d5c47f4e4df  ./sha2/x86_64/shani/sha256_compress.jinc
 *     54e51837c80a4400a91ab44302bd7193ecc335fb34fecf7e812b516429a004a8  ./sha2/x86_64/shani/sha512_compress.jinc
 *     bea946d51c2df65345c188cea2ae1769a2eea005299a60a2be1c6eab4e6e7115  ./x86_64/word.jinc
 *)

(* The names the per-set proofs use for SLH-DSA-SHAKE-192s. *)

require import AllCore.
require FIPS205_Params.
require BArray24 BArray39 BArray48 BArray51 BArray68 BArray72 BArray96 BArray332 BArray360 BArray408 BArray1224 BArray1440 BArray4896 BArray6120 BArray10080 BArray16224 SBArray48_24 SBArray96_24 SBArray96_48 SBArray360_24 SBArray408_24 SBArray1224_24 SBArray1440_24 SBArray1440_1224 SBArray6120_24 SBArray10080_1440 SBArray16224_24 SBArray16224_6120 SBArray16224_10080.

op P : FIPS205_Params.params = FIPS205_Params.slh_dsa_shake_192s.

lemma n_val : P.`n = 24 by rewrite /P.
lemma h_val : P.`h = 63 by rewrite /P.
lemma d_val : P.`d = 7 by rewrite /P.
lemma hp_val : P.`hp = 9 by rewrite /P.
lemma a_val : P.`a = 14 by rewrite /P.
lemma k_val : P.`k = 17 by rewrite /P.
lemma lgw_val : P.`lgw = 4 by rewrite /P.
lemma m_val : P.`m = 39 by rewrite /P.

(* an n-byte value (u8[n]) *)
theory Node = BArray24.
(* two n-byte values (u8[2n]) *)
theory Node2 = BArray48.
(* the message digest (u8[m]) *)
theory Digest = BArray39.
(* the k FORS indices (u32[k]) *)
theory ForsIdx = BArray68.
(* the len WOTS+ digits (u8[len]) *)
theory WotsDigits = BArray51.
(* the tweakable hash context (u64[THASH_CTX_WORDS]) *)
theory Ctx = BArray24.
(* len n-byte values, the input of T_len (u8[len n]) *)
theory TLenIn = BArray1224.
(* the n-byte slots of a TLenIn *)
theory TLenNode = SBArray1224_24.SBArray1224_24.
(* k n-byte values, the input of T_k (u8[k n]) *)
theory TKIn = BArray408.
(* four n-byte values, one per lane (u8[4n]) *)
theory Node4 = BArray96.
(* four TLenIn, one per lane (u8[4 len n]) *)
theory TLenIn4 = BArray4896.
(* the two n-byte halves of a Node2 *)
theory Node2Half = SBArray48_24.SBArray48_24.
(* the n-byte lanes of a Node4 *)
theory Node4Node = SBArray96_24.SBArray96_24.
(* the n-byte slots of a TKIn *)
theory TKNode = SBArray408_24.SBArray408_24.
(* the treehash fold stack: one node per height (u8[(a + 1) n]) *)
theory FoldBuf = BArray360.
(* the n-byte slots of a FoldBuf *)
theory FoldNode = SBArray360_24.SBArray360_24.
(* an XMSS signature: WOTS+ signature, then hp nodes (u8[(len + hp) n]) *)
theory XmssSig = BArray1440.
(* the n-byte slots of an XmssSig *)
theory XmssSigNode = SBArray1440_24.SBArray1440_24.
(* the WOTS+ signature slot of an XmssSig (u8[len n]) *)
theory XmssSigWots = SBArray1440_1224.SBArray1440_1224.
(* a FORS signature: k trees of a secret and a nodes (u8[k (a + 1) n]) *)
theory ForsSig = BArray6120.
(* the n-byte slots of a ForsSig *)
theory ForsSigNode = SBArray6120_24.SBArray6120_24.
(* an SLH-DSA signature: R, the FORS signature, then d XMSS signatures (u8[n + k (a + 1) n + d (len + hp) n]) *)
theory Sig = BArray16224.
(* a hypertree signature: d XMSS signatures (u8[d (len + hp) n]) *)
theory HtSig = BArray10080.
(* the XMSS signature slots of an HtSig *)
theory HtSigXmss = SBArray10080_1440.SBArray10080_1440.
(* the n-byte slots of a Sig, the first of which is R *)
theory SigR = SBArray16224_24.SBArray16224_24.
(* the FORS signature slot of a Sig *)
theory SigFors = SBArray16224_6120.SBArray16224_6120.
(* the hypertree signature slot of a Sig *)
theory SigHt = SBArray16224_10080.SBArray16224_10080.
(* a secret key: SK.seed, SK.prf, PK.seed, PK.root (u8[4n]) *)
theory SK = BArray96.
(* the n-byte fields of an SK *)
theory SkNode = SBArray96_24.SBArray96_24.
(* the 2n-byte halves of an SK, the second of which is the public key *)
theory SkPk = SBArray96_48.SBArray96_48.
(* a public key: PK.seed, PK.root (u8[2n]) *)
theory PK = BArray48.
(* the n-byte fields of a PK *)
theory PkNode = SBArray48_24.SBArray48_24.
(* the key generation seeds: SK.seed, SK.prf, PK.seed (u8[3n]) *)
theory Seeds = BArray72.
(* the buffer of the bytes that precede the message in M (u8[SLH_PREFIX_MAX]) *)
theory Prefix = BArray332.
