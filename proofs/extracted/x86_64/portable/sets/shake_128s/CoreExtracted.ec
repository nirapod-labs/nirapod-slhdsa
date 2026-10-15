(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * GENERATED FILE. DO NOT EDIT.
 *
 * Generator:
 *     jasmin2ec --arch=x86-64 (array model: the jasmin2ec default)
 *
 * Model:
 *     x86_64/portable, kernels KeccakKernel=keccak KeccakKernelX=keccak Sha2Kernel=sha2 Sha2KernelX=sha2
 *
 * Regenerate:
 *     make -C proofs extract     (check: make -C proofs check-extraction)
 *
 * Entry src/slhdsa/sets/shake_128s.jinc
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

require import AllCore IntDiv CoreMap List Distr.

from Jasmin require import JModel_x86.

import SLH64.

require import
BArray10 BArray16 BArray30 BArray32 BArray35 BArray40 BArray48 BArray56
BArray64 BArray128 BArray192 BArray200 BArray208 BArray224 BArray256
BArray257 BArray332 BArray560 BArray640 BArray704 BArray800 BArray2240
BArray2912 BArray4928 BArray7856 SBArray32_16 SBArray64_16 SBArray208_16
SBArray224_16 SBArray560_16 SBArray704_16 SBArray2912_16 SBArray7856_16
SBArray64_32 SBArray128_32 SBArray704_560 SBArray4928_704 SBArray7856_2912
SBArray7856_4928.

abbrev nIST_HASH_OID_PREFIX =
(BArray10.of_list8
[(W8.of_int 6); (W8.of_int 9); (W8.of_int 96); (W8.of_int (-122));
(W8.of_int 72); (W8.of_int 1); (W8.of_int 101); (W8.of_int 3); (W8.of_int 4);
(W8.of_int 2)]).

abbrev sHA512_256_IV =
(BArray64.of_list64
[(W64.of_int 2463787394917988140); (W64.of_int (-6965556091613846334));
(W64.of_int 2563595384472711505); (W64.of_int (-7622211418569250115));
(W64.of_int (-7626776825740460061)); (W64.of_int (-4729309413028513390));
(W64.of_int 3098927326965381290); (W64.of_int 1060366662362279074)]).

abbrev sHA512_224_IV =
(BArray64.of_list64
[(W64.of_int (-8341449602262348382)); (W64.of_int 8350123849800275158);
(W64.of_int 2160240930085379202); (W64.of_int 7466358040605728719);
(W64.of_int 1111592415079452072); (W64.of_int 8638871050018654530);
(W64.of_int 4583966954114332360); (W64.of_int 1230299281376055969)]).

abbrev sHA384_IV =
(BArray64.of_list64
[(W64.of_int (-3766243637369397544)); (W64.of_int 7105036623409894663);
(W64.of_int (-7973340178411365097)); (W64.of_int 1526699215303891257);
(W64.of_int 7436329637833083697); (W64.of_int (-8163818279084223215));
(W64.of_int (-2662702644619276377)); (W64.of_int 5167115440072839076)]).

abbrev sHA512_IV =
(BArray64.of_list64
[(W64.of_int 7640891576956012808); (W64.of_int (-4942790177534073029));
(W64.of_int 4354685564936845355); (W64.of_int (-6534734903238641935));
(W64.of_int 5840696475078001361); (W64.of_int (-7276294671716946913));
(W64.of_int 2270897969802886507); (W64.of_int 6620516959819538809)]).

abbrev sHA512_K =
(BArray640.of_list64
[(W64.of_int 4794697086780616226); (W64.of_int 8158064640168781261);
(W64.of_int (-5349999486874862801)); (W64.of_int (-1606136188198331460));
(W64.of_int 4131703408338449720); (W64.of_int 6480981068601479193);
(W64.of_int (-7908458776815382629)); (W64.of_int (-6116909921290321640));
(W64.of_int (-2880145864133508542)); (W64.of_int 1334009975649890238);
(W64.of_int 2608012711638119052); (W64.of_int 6128411473006802146);
(W64.of_int 8268148722764581231); (W64.of_int (-9160688886553864527));
(W64.of_int (-7215885187991268811)); (W64.of_int (-4495734319001033068));
(W64.of_int (-1973867731355612462)); (W64.of_int (-1171420211273849373));
(W64.of_int 1135362057144423861); (W64.of_int 2597628984639134821);
(W64.of_int 3308224258029322869); (W64.of_int 5365058923640841347);
(W64.of_int 6679025012923562964); (W64.of_int 8573033837759648693);
(W64.of_int (-7476448914759557205)); (W64.of_int (-6327057829258317296));
(W64.of_int (-5763719355590565569)); (W64.of_int (-4658551843659510044));
(W64.of_int (-4116276920077217854)); (W64.of_int (-3051310485924567259));
(W64.of_int 489312712824947311); (W64.of_int 1452737877330783856);
(W64.of_int 2861767655752347644); (W64.of_int 3322285676063803686);
(W64.of_int 5560940570517711597); (W64.of_int 5996557281743188959);
(W64.of_int 7280758554555802590); (W64.of_int 8532644243296465576);
(W64.of_int (-9096487096722542874)); (W64.of_int (-7894198246740708037));
(W64.of_int (-6719396339535248540)); (W64.of_int (-6333637450476146687));
(W64.of_int (-4446306890439682159)); (W64.of_int (-4076793802049405392));
(W64.of_int (-3345356375505022440)); (W64.of_int (-2983346525034927856));
(W64.of_int (-860691631967231958)); (W64.of_int 1182934255886127544);
(W64.of_int 1847814050463011016); (W64.of_int 2177327727835720531);
(W64.of_int 2830643537854262169); (W64.of_int 3796741975233480872);
(W64.of_int 4115178125766777443); (W64.of_int 5681478168544905931);
(W64.of_int 6601373596472566643); (W64.of_int 7507060721942968483);
(W64.of_int 8399075790359081724); (W64.of_int 8693463985226723168);
(W64.of_int (-8878714635349349518)); (W64.of_int (-8302665154208450068));
(W64.of_int (-8016688836872298968)); (W64.of_int (-6606660893046293015));
(W64.of_int (-4685533653050689259)); (W64.of_int (-4147400797238176981));
(W64.of_int (-3880063495543823972)); (W64.of_int (-3348786107499101689));
(W64.of_int (-1523767162380948706)); (W64.of_int (-757361751448694408));
(W64.of_int 500013540394364858); (W64.of_int 748580250866718886);
(W64.of_int 1242879168328830382); (W64.of_int 1977374033974150939);
(W64.of_int 2944078676154940804); (W64.of_int 3659926193048069267);
(W64.of_int 4368137639120453308); (W64.of_int 4836135668995329356);
(W64.of_int 5532061633213252278); (W64.of_int 6448918945643986474);
(W64.of_int 6902733635092675308); (W64.of_int 7801388544844847127)]).

abbrev sHA224_IV =
(BArray32.of_list32
[(W32.of_int (-1056596264)); (W32.of_int 914150663); (W32.of_int 812702999);
(W32.of_int (-150054599)); (W32.of_int (-4191439)); (W32.of_int 1750603025);
(W32.of_int 1694076839); (W32.of_int (-1090891868))]).

abbrev sHA256_IV =
(BArray32.of_list32
[(W32.of_int 1779033703); (W32.of_int (-1150833019));
(W32.of_int 1013904242); (W32.of_int (-1521486534)); (W32.of_int 1359893119);
(W32.of_int (-1694144372)); (W32.of_int 528734635); (W32.of_int 1541459225)]).

abbrev sHA256_K =
(BArray256.of_list32
[(W32.of_int 1116352408); (W32.of_int 1899447441);
(W32.of_int (-1245643825)); (W32.of_int (-373957723));
(W32.of_int 961987163); (W32.of_int 1508970993); (W32.of_int (-1841331548));
(W32.of_int (-1424204075)); (W32.of_int (-670586216));
(W32.of_int 310598401); (W32.of_int 607225278); (W32.of_int 1426881987);
(W32.of_int 1925078388); (W32.of_int (-2132889090));
(W32.of_int (-1680079193)); (W32.of_int (-1046744716));
(W32.of_int (-459576895)); (W32.of_int (-272742522)); (W32.of_int 264347078);
(W32.of_int 604807628); (W32.of_int 770255983); (W32.of_int 1249150122);
(W32.of_int 1555081692); (W32.of_int 1996064986); (W32.of_int (-1740746414));
(W32.of_int (-1473132947)); (W32.of_int (-1341970488));
(W32.of_int (-1084653625)); (W32.of_int (-958395405));
(W32.of_int (-710438585)); (W32.of_int 113926993); (W32.of_int 338241895);
(W32.of_int 666307205); (W32.of_int 773529912); (W32.of_int 1294757372);
(W32.of_int 1396182291); (W32.of_int 1695183700); (W32.of_int 1986661051);
(W32.of_int (-2117940946)); (W32.of_int (-1838011259));
(W32.of_int (-1564481375)); (W32.of_int (-1474664885));
(W32.of_int (-1035236496)); (W32.of_int (-949202525));
(W32.of_int (-778901479)); (W32.of_int (-694614492));
(W32.of_int (-200395387)); (W32.of_int 275423344); (W32.of_int 430227734);
(W32.of_int 506948616); (W32.of_int 659060556); (W32.of_int 883997877);
(W32.of_int 958139571); (W32.of_int 1322822218); (W32.of_int 1537002063);
(W32.of_int 1747873779); (W32.of_int 1955562222); (W32.of_int 2024104815);
(W32.of_int (-2067236844)); (W32.of_int (-1933114872));
(W32.of_int (-1866530822)); (W32.of_int (-1538233109));
(W32.of_int (-1090935817)); (W32.of_int (-965641998))]).

abbrev kECCAK_RC =
(BArray192.of_list64
[(W64.of_int 1); (W64.of_int 32898); (W64.of_int (-9223372036854742902));
(W64.of_int (-9223372034707259392)); (W64.of_int 32907);
(W64.of_int 2147483649); (W64.of_int (-9223372034707259263));
(W64.of_int (-9223372036854743031)); (W64.of_int 138); (W64.of_int 136);
(W64.of_int 2147516425); (W64.of_int 2147483658); (W64.of_int 2147516555);
(W64.of_int (-9223372036854775669)); (W64.of_int (-9223372036854742903));
(W64.of_int (-9223372036854743037)); (W64.of_int (-9223372036854743038));
(W64.of_int (-9223372036854775680)); (W64.of_int 32778);
(W64.of_int (-9223372034707292150)); (W64.of_int (-9223372034707259263));
(W64.of_int (-9223372036854742912)); (W64.of_int 2147483649);
(W64.of_int (-9223372034707259384))]).

module M = {
  proc __hook_fors_pk (pk:BArray16.t) : BArray16.t = {
    
    return pk;
  }
  proc __hook_ht_root (root:BArray16.t, layer:W32.t) : BArray16.t = {
    
    return root;
  }
  proc __store_be32 (adrs:BArray32.t, offset:int, v:W32.t) : BArray32.t = {
    var t:W32.t;
    t <- v;
    t <- (t `>>` (W8.of_int 24));
    adrs <- (BArray32.set8 adrs offset (truncateu8 t));
    t <- v;
    t <- (t `>>` (W8.of_int 16));
    adrs <- (BArray32.set8 adrs (offset + 1) (truncateu8 t));
    t <- v;
    t <- (t `>>` (W8.of_int 8));
    adrs <- (BArray32.set8 adrs (offset + 2) (truncateu8 t));
    adrs <- (BArray32.set8 adrs (offset + 3) (truncateu8 v));
    return adrs;
  }
  proc __adrs_zero (adrs:BArray32.t) : BArray32.t = {
    var z:W64.t;
    var i:int;
    z <- (W64.of_int 0);
    i <- 0;
    while ((i < 4)) {
      adrs <- (BArray32.set64 adrs i z);
      i <- (i + 1);
    }
    return adrs;
  }
  proc __adrs_set_layer (adrs:BArray32.t, layer:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 0, layer);
    return adrs;
  }
  proc __adrs_set_tree (adrs:BArray32.t, tree:W64.t) : BArray32.t = {
    var z:W32.t;
    var t:W64.t;
    var i:int;
    z <- (W32.of_int 0);
    adrs <- (BArray32.set32 adrs 1 z);
    i <- 0;
    while ((i < 8)) {
      t <- tree;
      t <- (t `>>` (W8.of_int (8 * (7 - i))));
      adrs <- (BArray32.set8 adrs (8 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return adrs;
  }
  proc __adrs_set_type_and_clear (adrs:BArray32.t, adrs_type:int) : BArray32.t = {
    var t:W64.t;
    t <- (W64.of_int (adrs_type `<<` 24));
    adrs <- (BArray32.set64 adrs 2 t);
    t <- (W64.of_int 0);
    adrs <- (BArray32.set64 adrs 3 t);
    return adrs;
  }
  proc __adrs_set_keypair (adrs:BArray32.t, keypair:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 20, keypair);
    return adrs;
  }
  proc __adrs_copy_keypair (dst:BArray32.t, src:BArray32.t) : BArray32.t = {
    var t:W32.t;
    t <- (BArray32.get32 src 5);
    dst <- (BArray32.set32 dst 5 t);
    return dst;
  }
  proc __adrs_set_chain (adrs:BArray32.t, chain:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 24, chain);
    return adrs;
  }
  proc __adrs_set_tree_height (adrs:BArray32.t, height:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 24, height);
    return adrs;
  }
  proc __adrs_set_hash (adrs:BArray32.t, hash:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 28, hash);
    return adrs;
  }
  proc __adrs_set_tree_index (adrs:BArray32.t, index:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 28, index);
    return adrs;
  }
  proc __adrs_copy (dst:BArray32.t, src:BArray32.t) : BArray32.t = {
    var i:int;
    var t:W64.t;
    i <- 0;
    while ((i < 4)) {
      t <- (BArray32.get64 src i);
      dst <- (BArray32.set64 dst i t);
      i <- (i + 1);
    }
    return dst;
  }
  proc __offset (i:W32.t, stride:int) : W64.t = {
    var off:W64.t;
    var c:W64.t;
    off <- (zeroextu64 i);
    c <- (W64.of_int stride);
    off <- (off * c);
    return off;
  }
  proc __offset64 (i:W64.t, stride:int) : W64.t = {
    var off:W64.t;
    var c:W64.t;
    off <- i;
    c <- (W64.of_int stride);
    off <- (off * c);
    return off;
  }
  proc __node_copy (dst:BArray16.t, src:BArray16.t) : BArray16.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 src i);
      dst <- (BArray16.set64 dst i t);
      i <- (i + 1);
    }
    return dst;
  }
  proc __node_concat (dst:BArray32.t, a:BArray16.t, b:BArray16.t) : BArray32.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 a i);
      dst <- (BArray32.set64 dst i t);
      i <- (i + 1);
    }
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 b i);
      dst <- (BArray32.set64 dst ((16 %/ 8) + i) t);
      i <- (i + 1);
    }
    return dst;
  }
  proc __fors_indices (idx:BArray56.t, digest:BArray30.t) : BArray56.t = {
    var i:int;
    var b0:int;
    var s:int;
    var v:W32.t;
    var t:W32.t;
    i <- 0;
    while ((i < 14)) {
      b0 <- ((i * 12) %/ 8);
      s <- ((i * 12) %% 8);
      v <- (zeroextu32 (BArray30.get8 digest b0));
      v <- (v `<<` (W8.of_int 16));
      t <- (zeroextu32 (BArray30.get8 digest (b0 + 1)));
      t <- (t `<<` (W8.of_int 8));
      v <- (v `|` t);
      t <- (zeroextu32 (BArray30.get8 digest (b0 + 2)));
      v <- (v `|` t);
      v <- (v `>>` (W8.of_int ((24 - s) - 12)));
      v <- (v `&` (W32.of_int ((1 `<<` 12) - 1)));
      idx <- (BArray56.set32 idx i v);
      i <- (i + 1);
    }
    return idx;
  }
  proc __digest_tree_leaf (digest:BArray30.t) : W64.t * W32.t = {
    var inc:int;
    var tree:W64.t;
    var leaf:W32.t;
    var j:int;
    var t:W64.t;
    var mask:W64.t;
    var u:W32.t;
    tree <- (W64.of_int 0);
    inc <- (((63 - 9) + 7) %/ 8);
    j <- 0;
    while ((j < inc)) {
      tree <- (tree `<<` (W8.of_int 8));
      t <- (zeroextu64 (BArray30.get8 digest ((((14 * 12) + 7) %/ 8) + j)));
      tree <- (tree `|` t);
      j <- (j + 1);
    }
    if (((63 - 9) < 64)) {
      mask <- (W64.of_int ((1 `<<` (63 - 9)) - 1));
      tree <- (tree `&` mask);
    } else {
      
    }
    leaf <- (W32.of_int 0);
    inc <- ((9 + 7) %/ 8);
    j <- 0;
    while ((j < inc)) {
      leaf <- (leaf `<<` (W8.of_int 8));
      u <-
      (zeroextu32
      (BArray30.get8 digest
      (((((14 * 12) + 7) %/ 8) + (((63 - 9) + 7) %/ 8)) + j)));
      leaf <- (leaf `|` u);
      j <- (j + 1);
    }
    leaf <- (leaf `&` (W32.of_int ((1 `<<` 9) - 1)));
    return (tree, leaf);
  }
  proc __keccak_rho (x:int, y:int) : int = {
    var r:int;
    var cx:int;
    var cy:int;
    var t:int;
    var nx:int;
    r <- 0;
    cx <- 1;
    cy <- 0;
    t <- 0;
    while ((t < 24)) {
      if (((cx = x) /\ (cy = y))) {
        r <- ((((t + 1) * (t + 2)) %/ 2) %% 64);
      } else {
        
      }
      nx <- cy;
      cy <- (((2 * cx) + (3 * cy)) %% 5);
      cx <- nx;
      t <- (t + 1);
    }
    return r;
  }
  proc __rotl64 (x:W64.t, r:int) : W64.t = {
    
    if ((r <> 0)) {
      x <- (x `|<<|` (W8.of_int r));
    } else {
      
    }
    return x;
  }
  proc __keccak_round (e:BArray200.t, a:BArray200.t) : BArray200.t = {
    var aux:W64.t;
    var x:int;
    var t:W64.t;
    var y:int;
    var u:W64.t;
    var c:BArray40.t;
    var d:BArray40.t;
    var xs:int;
    var b:BArray40.t;
    var r:int;
    b <- witness;
    c <- witness;
    d <- witness;
    x <- 0;
    while ((x < 5)) {
      t <- (BArray200.get64 a x);
      y <- 1;
      while ((y < 5)) {
        u <- (BArray200.get64 a (x + (5 * y)));
        t <- (t `^` u);
        y <- (y + 1);
      }
      c <- (BArray40.set64 c x t);
      x <- (x + 1);
    }
    x <- 0;
    while ((x < 5)) {
      t <- (BArray40.get64 c ((x + 1) %% 5));
      t <- (t `|<<|` (W8.of_int 1));
      u <- (BArray40.get64 c ((x + 4) %% 5));
      t <- (t `^` u);
      d <- (BArray40.set64 d x t);
      x <- (x + 1);
    }
    y <- 0;
    while ((y < 5)) {
      x <- 0;
      while ((x < 5)) {
        xs <- ((x + (3 * y)) %% 5);
        b <- (BArray40.set64 b x (BArray200.get64 a (xs + (5 * x))));
        t <- (BArray40.get64 d xs);
        b <- (BArray40.set64 b x ((BArray40.get64 b x) `^` t));
        r <@ __keccak_rho (xs, x);
        aux <@ __rotl64 ((BArray40.get64 b x), r);
        b <- (BArray40.set64 b x aux);
        x <- (x + 1);
      }
      x <- 0;
      while ((x < 5)) {
        t <- (BArray40.get64 b ((x + 1) %% 5));
        t <- (invw t);
        t <- (t `&` (BArray40.get64 b ((x + 2) %% 5)));
        t <- (t `^` (BArray40.get64 b x));
        e <- (BArray200.set64 e (x + (5 * y)) t);
        x <- (x + 1);
      }
      y <- (y + 1);
    }
    return e;
  }
  proc _keccakf1600 (st:BArray200.t, ms:W64.t) : BArray200.t * W64.t = {
    var round_buf:BArray200.t;
    var e:BArray200.t;
    var ir:W64.t;
    var more:bool;
    var rc_table:BArray192.t;
    var rc:W64.t;
    var t:W64.t;
    e <- witness;
    rc_table <- witness;
    round_buf <- witness;
    e <- round_buf;
    ir <- (W64.of_int 0);
    more <- (ir \ult (W64.of_int 24));
    while (more) {
      ms <- (update_msf more ms);
      e <@ __keccak_round (e, st);
      rc_table <- kECCAK_RC;
      rc <- (BArray192.get64 rc_table (W64.to_uint ir));
      ir <- (ir + (W64.of_int 1));
      t <- (BArray200.get64 e 0);
      t <- (t `^` rc);
      e <- (BArray200.set64 e 0 t);
      st <@ __keccak_round (st, e);
      rc_table <- kECCAK_RC;
      rc <- (BArray192.get64 rc_table (W64.to_uint ir));
      ir <- (ir + (W64.of_int 1));
      t <- (BArray200.get64 st 0);
      t <- (t `^` rc);
      st <- (BArray200.set64 st 0 t);
      more <- (ir \ult (W64.of_int 24));
    }
    ms <- (update_msf (! more) ms);
    return (st, ms);
  }
  proc __keccak_init (st:BArray200.t) : BArray200.t = {
    var z:W64.t;
    var i:int;
    z <- (W64.of_int 0);
    i <- 0;
    while ((i < 25)) {
      st <- (BArray200.set64 st i z);
      i <- (i + 1);
    }
    return st;
  }
  proc __keccak_xor_mem (st:BArray200.t, pos_:W64.t, in_0:W64.t, off_:W64.t,
                         n_:W64.t, ms:W64.t) : BArray200.t * W64.t = {
    var pos:W64.t;
    var off:W64.t;
    var n:W64.t;
    var head:W64.t;
    var end_0:W64.t;
    var more:bool;
    var t:W64.t;
    var v:W64.t;
    pos <- pos_;
    off <- off_;
    n <- n_;
    head <- pos;
    head <- (- head);
    head <- (head `&` (W64.of_int 7));
    head <- ((n \ult head) ? n : head);
    n <- (n - head);
    end_0 <- pos;
    end_0 <- (end_0 + head);
    more <- (pos \ult end_0);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (BArray200.get8 st (W64.to_uint pos)));
      v <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint (in_0 + off))));
      t <- (t `^` v);
      st <- (BArray200.set8 st (W64.to_uint pos) (truncateu8 t));
      pos <- (pos + (W64.of_int 1));
      off <- (off + (W64.of_int 1));
      more <- (pos \ult end_0);
    }
    ms <- (update_msf (! more) ms);
    more <- ((W64.of_int 8) \ule n);
    while (more) {
      ms <- (update_msf more ms);
      t <- (BArray200.get64d st (W64.to_uint pos));
      v <- (loadW64 Glob.mem (W64.to_uint (in_0 + off)));
      t <- (t `^` v);
      st <- (BArray200.set64d st (W64.to_uint pos) t);
      pos <- (pos + (W64.of_int 8));
      off <- (off + (W64.of_int 8));
      n <- (n - (W64.of_int 8));
      more <- ((W64.of_int 8) \ule n);
    }
    ms <- (update_msf (! more) ms);
    end_0 <- pos;
    end_0 <- (end_0 + n);
    more <- (pos \ult end_0);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (BArray200.get8 st (W64.to_uint pos)));
      v <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint (in_0 + off))));
      t <- (t `^` v);
      st <- (BArray200.set8 st (W64.to_uint pos) (truncateu8 t));
      pos <- (pos + (W64.of_int 1));
      off <- (off + (W64.of_int 1));
      more <- (pos \ult end_0);
    }
    ms <- (update_msf (! more) ms);
    return (st, ms);
  }
  proc __keccak_extract_mem (out:W64.t, off_:W64.t, st:BArray200.t,
                             pos_:W64.t, n_:W64.t, ms:W64.t) : W64.t = {
    var off:W64.t;
    var pos:W64.t;
    var n:W64.t;
    var head:W64.t;
    var end_0:W64.t;
    var more:bool;
    var t:W64.t;
    off <- off_;
    pos <- pos_;
    n <- n_;
    head <- pos;
    head <- (- head);
    head <- (head `&` (W64.of_int 7));
    head <- ((n \ult head) ? n : head);
    n <- (n - head);
    end_0 <- pos;
    end_0 <- (end_0 + head);
    more <- (pos \ult end_0);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (BArray200.get8 st (W64.to_uint pos)));
      Glob.mem <-
      (storeW8 Glob.mem (W64.to_uint (out + off)) (truncateu8 t));
      pos <- (pos + (W64.of_int 1));
      off <- (off + (W64.of_int 1));
      more <- (pos \ult end_0);
    }
    ms <- (update_msf (! more) ms);
    more <- ((W64.of_int 8) \ule n);
    while (more) {
      ms <- (update_msf more ms);
      t <- (BArray200.get64d st (W64.to_uint pos));
      Glob.mem <- (storeW64 Glob.mem (W64.to_uint (out + off)) t);
      pos <- (pos + (W64.of_int 8));
      off <- (off + (W64.of_int 8));
      n <- (n - (W64.of_int 8));
      more <- ((W64.of_int 8) \ule n);
    }
    ms <- (update_msf (! more) ms);
    end_0 <- pos;
    end_0 <- (end_0 + n);
    more <- (pos \ult end_0);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (BArray200.get8 st (W64.to_uint pos)));
      Glob.mem <-
      (storeW8 Glob.mem (W64.to_uint (out + off)) (truncateu8 t));
      pos <- (pos + (W64.of_int 1));
      off <- (off + (W64.of_int 1));
      more <- (pos \ult end_0);
    }
    ms <- (update_msf (! more) ms);
    return ms;
  }
  proc _keccak_absorb_mem (st:BArray200.t, pos:W64.t, rate:W64.t, in_0:W64.t,
                           inlen:W64.t, ms:W64.t) : BArray200.t * W64.t *
                                                    W64.t = {
    var off:W64.t;
    var more:bool;
    var n:W64.t;
    var full:bool;
    off <- (W64.of_int 0);
    more <- (inlen <> (W64.of_int 0));
    while (more) {
      ms <- (update_msf more ms);
      n <- rate;
      n <- (n - pos);
      n <- ((inlen \ult n) ? inlen : n);
      (st, ms) <@ __keccak_xor_mem (st, pos, in_0, off, n, ms);
      pos <- (pos + n);
      off <- (off + n);
      inlen <- (inlen - n);
      full <- (pos = rate);
      if (full) {
        ms <- (update_msf full ms);
        (* Erased call to spill *)
        (st, ms) <@ _keccakf1600 (st, ms);
        (* Erased call to unspill *)
        rate <- (protect_64 rate ms);
        in_0 <- (protect_64 in_0 ms);
        off <- (protect_64 off ms);
        inlen <- (protect_64 inlen ms);
        pos <- (W64.of_int 0);
      } else {
        ms <- (update_msf (! full) ms);
      }
      more <- (inlen <> (W64.of_int 0));
    }
    ms <- (update_msf (! more) ms);
    return (st, pos, ms);
  }
  proc _keccak_finalize (st:BArray200.t, pos:W64.t, rate:W64.t, ds:W64.t,
                         ms:W64.t) : BArray200.t * W64.t = {
    var t:W64.t;
    t <- (zeroextu64 (BArray200.get8 st (W64.to_uint pos)));
    t <- (t `^` ds);
    st <- (BArray200.set8 st (W64.to_uint pos) (truncateu8 t));
    rate <- (rate - (W64.of_int 1));
    t <- (zeroextu64 (BArray200.get8 st (W64.to_uint rate)));
    t <- (t `^` (W64.of_int 128));
    st <- (BArray200.set8 st (W64.to_uint rate) (truncateu8 t));
    (st, ms) <@ _keccakf1600 (st, ms);
    return (st, ms);
  }
  proc _keccak_squeeze_mem (st:BArray200.t, pos:W64.t, rate:W64.t, out:W64.t,
                            outlen:W64.t, ms:W64.t) : BArray200.t * W64.t *
                                                      W64.t = {
    var off:W64.t;
    var more:bool;
    var empty:bool;
    var n:W64.t;
    off <- (W64.of_int 0);
    more <- (outlen <> (W64.of_int 0));
    while (more) {
      ms <- (update_msf more ms);
      empty <- (pos = rate);
      if (empty) {
        ms <- (update_msf empty ms);
        (* Erased call to spill *)
        (st, ms) <@ _keccakf1600 (st, ms);
        (* Erased call to unspill *)
        rate <- (protect_64 rate ms);
        out <- (protect_64 out ms);
        off <- (protect_64 off ms);
        outlen <- (protect_64 outlen ms);
        pos <- (W64.of_int 0);
      } else {
        ms <- (update_msf (! empty) ms);
      }
      n <- rate;
      n <- (n - pos);
      n <- ((outlen \ult n) ? outlen : n);
      ms <@ __keccak_extract_mem (out, off, st, pos, n, ms);
      pos <- (pos + n);
      off <- (off + n);
      outlen <- (outlen - n);
      more <- (outlen <> (W64.of_int 0));
    }
    ms <- (update_msf (! more) ms);
    return (st, pos, ms);
  }
  proc _thash_ctx_init (ctx:BArray16.t, pk_seed:BArray16.t, ms:W64.t) : 
  BArray16.t * W64.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 pk_seed i);
      ctx <- (BArray16.set64 ctx i t);
      i <- (i + 1);
    }
    return (ctx, ms);
  }
  proc __shake_seeded_head (st:BArray200.t, ctx:BArray16.t, adrs:BArray32.t) : 
  BArray200.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    st <@ __keccak_init (st);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 ctx i);
      st <- (BArray200.set64 st i t);
      i <- (i + 1);
    }
    i <- 0;
    while ((i < 4)) {
      t <- (BArray32.get64 adrs i);
      st <- (BArray200.set64 st ((16 %/ 8) + i) t);
      i <- (i + 1);
    }
    return st;
  }
  proc __shake_pad_lanes (st:BArray200.t, lanes:int) : BArray200.t = {
    var t:W64.t;
    var u:W64.t;
    t <- (BArray200.get64 st lanes);
    t <- (t `^` (W64.of_int 31));
    st <- (BArray200.set64 st lanes t);
    t <- (BArray200.get64 st (17 - 1));
    u <- (W64.of_int 9223372036854775808);
    t <- (t `^` u);
    st <- (BArray200.set64 st (17 - 1) t);
    return st;
  }
  proc __shake_extract_n (out:BArray16.t, st:BArray200.t) : BArray16.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray200.get64 st i);
      out <- (BArray16.set64 out i t);
      i <- (i + 1);
    }
    return out;
  }
  proc _thash_prf (out:BArray16.t, sk_seed:BArray16.t, ctx:BArray16.t,
                   adrs:BArray32.t, ms:W64.t) : BArray16.t * W64.t = {
    var inc:int;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    st <@ __shake_seeded_head (st, ctx, adrs);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 sk_seed i);
      st <- (BArray200.set64 st (((16 %/ 8) + 4) + i) t);
      i <- (i + 1);
    }
    st <@ __shake_pad_lanes (st, ((2 * (16 %/ 8)) + 4));
    (* Erased call to spill *)
    (st, ms) <@ _keccakf1600 (st, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    out <@ __shake_extract_n (out, st);
    return (out, ms);
  }
  proc _thash_f (x:BArray16.t, ctx:BArray16.t, adrs:BArray32.t, ms:W64.t) : 
  BArray16.t * W64.t = {
    var inc:int;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    st <@ __shake_seeded_head (st, ctx, adrs);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 x i);
      st <- (BArray200.set64 st (((16 %/ 8) + 4) + i) t);
      i <- (i + 1);
    }
    st <@ __shake_pad_lanes (st, ((2 * (16 %/ 8)) + 4));
    (* Erased call to spill *)
    (st, ms) <@ _keccakf1600 (st, ms);
    (* Erased call to unspill *)
    x <- (protect_ptr x ms);
    x <@ __shake_extract_n (x, st);
    return (x, ms);
  }
  proc _thash_h (out:BArray16.t, in_0:BArray32.t, ctx:BArray16.t,
                 adrs:BArray32.t, ms:W64.t) : BArray16.t * W64.t = {
    var inc:int;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    st <@ __shake_seeded_head (st, ctx, adrs);
    inc <- (2 * (16 %/ 8));
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 in_0 i);
      st <- (BArray200.set64 st (((16 %/ 8) + 4) + i) t);
      i <- (i + 1);
    }
    st <@ __shake_pad_lanes (st, ((3 * (16 %/ 8)) + 4));
    (* Erased call to spill *)
    (st, ms) <@ _keccakf1600 (st, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    out <@ __shake_extract_n (out, st);
    return (out, ms);
  }
  proc tLen___thash_t (out:BArray16.t, in_0:BArray560.t, ctx:BArray16.t,
                       adrs:BArray32.t, ms:W64.t) : BArray16.t * W64.t = {
    var st_s:BArray200.t;
    var st:BArray200.t;
    var pos:W64.t;
    var i:W64.t;
    var more:bool;
    var cap:W64.t;
    var v:W64.t;
    var t:W64.t;
    var full:bool;
    st <- witness;
    st_s <- witness;
    st <- st_s;
    st <@ __shake_seeded_head (st, ctx, adrs);
    pos <- (W64.of_int ((16 %/ 8) + 4));
    (* Erased call to spill *)
    i <- (W64.of_int 0);
    more <- (i \ult (W64.of_int ((((2 * 16) + 3) * 16) %/ 8)));
    while (more) {
      ms <- (update_msf more ms);
      cap <- (W64.of_int (17 - 1));
      pos <- (((W64.of_int 17) \ule pos) ? cap : pos);
      v <- (BArray560.get64 in_0 (W64.to_uint i));
      t <- (BArray200.get64 st (W64.to_uint pos));
      t <- (t `^` v);
      st <- (BArray200.set64 st (W64.to_uint pos) t);
      pos <- (pos + (W64.of_int 1));
      full <- (pos = (W64.of_int 17));
      if (full) {
        ms <- (update_msf full ms);
        (* Erased call to spill *)
        (st, ms) <@ _keccakf1600 (st, ms);
        (* Erased call to unspill *)
        in_0 <- (protect_ptr in_0 ms);
        i <- (protect_64 i ms);
        pos <- (W64.of_int 0);
      } else {
        ms <- (update_msf (! full) ms);
      }
      i <- (i + (W64.of_int 1));
      more <- (i \ult (W64.of_int ((((2 * 16) + 3) * 16) %/ 8)));
    }
    ms <- (update_msf (! more) ms);
    t <- (BArray200.get64 st (W64.to_uint pos));
    t <- (t `^` (W64.of_int 31));
    st <- (BArray200.set64 st (W64.to_uint pos) t);
    t <- (BArray200.get64 st (17 - 1));
    v <- (W64.of_int 9223372036854775808);
    t <- (t `^` v);
    st <- (BArray200.set64 st (17 - 1) t);
    (st, ms) <@ _keccakf1600 (st, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    out <@ __shake_extract_n (out, st);
    return (out, ms);
  }
  proc tK___thash_t (out:BArray16.t, in_0:BArray224.t, ctx:BArray16.t,
                     adrs:BArray32.t, ms:W64.t) : BArray16.t * W64.t = {
    var st_s:BArray200.t;
    var st:BArray200.t;
    var pos:W64.t;
    var i:W64.t;
    var more:bool;
    var cap:W64.t;
    var v:W64.t;
    var t:W64.t;
    var full:bool;
    st <- witness;
    st_s <- witness;
    st <- st_s;
    st <@ __shake_seeded_head (st, ctx, adrs);
    pos <- (W64.of_int ((16 %/ 8) + 4));
    (* Erased call to spill *)
    i <- (W64.of_int 0);
    more <- (i \ult (W64.of_int ((14 * 16) %/ 8)));
    while (more) {
      ms <- (update_msf more ms);
      cap <- (W64.of_int (17 - 1));
      pos <- (((W64.of_int 17) \ule pos) ? cap : pos);
      v <- (BArray224.get64 in_0 (W64.to_uint i));
      t <- (BArray200.get64 st (W64.to_uint pos));
      t <- (t `^` v);
      st <- (BArray200.set64 st (W64.to_uint pos) t);
      pos <- (pos + (W64.of_int 1));
      full <- (pos = (W64.of_int 17));
      if (full) {
        ms <- (update_msf full ms);
        (* Erased call to spill *)
        (st, ms) <@ _keccakf1600 (st, ms);
        (* Erased call to unspill *)
        in_0 <- (protect_ptr in_0 ms);
        i <- (protect_64 i ms);
        pos <- (W64.of_int 0);
      } else {
        ms <- (update_msf (! full) ms);
      }
      i <- (i + (W64.of_int 1));
      more <- (i \ult (W64.of_int ((14 * 16) %/ 8)));
    }
    ms <- (update_msf (! more) ms);
    t <- (BArray200.get64 st (W64.to_uint pos));
    t <- (t `^` (W64.of_int 31));
    st <- (BArray200.set64 st (W64.to_uint pos) t);
    t <- (BArray200.get64 st (17 - 1));
    v <- (W64.of_int 9223372036854775808);
    t <- (t `^` v);
    st <- (BArray200.set64 st (17 - 1) t);
    (st, ms) <@ _keccakf1600 (st, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    out <@ __shake_extract_n (out, st);
    return (out, ms);
  }
  proc _thash_t_len (out:BArray16.t, in_0:BArray560.t, ctx:BArray16.t,
                     adrs:BArray32.t, ms:W64.t) : BArray16.t * W64.t = {
    
    (out, ms) <@ tLen___thash_t (out, in_0, ctx, adrs, ms);
    return (out, ms);
  }
  proc _thash_t_k (out:BArray16.t, in_0:BArray224.t, ctx:BArray16.t,
                   adrs:BArray32.t, ms:W64.t) : BArray16.t * W64.t = {
    
    (out, ms) <@ tK___thash_t (out, in_0, ctx, adrs, ms);
    return (out, ms);
  }
  proc _shake_absorb_prefix (st:BArray200.t, pos:W64.t, prefix:BArray332.t,
                             len:W64.t, ms:W64.t) : BArray200.t * W64.t *
                                                    W64.t = {
    var i:W64.t;
    var more:bool;
    var cap:W64.t;
    var t:W64.t;
    var b:W64.t;
    var full:bool;
    i <- (W64.of_int 0);
    more <- (i \ult len);
    while (more) {
      ms <- (update_msf more ms);
      cap <- (W64.of_int (136 - 1));
      pos <- (((W64.of_int 136) \ule pos) ? cap : pos);
      t <- (zeroextu64 (BArray200.get8 st (W64.to_uint pos)));
      b <- (zeroextu64 (BArray332.get8 prefix (W64.to_uint i)));
      t <- (t `^` b);
      st <- (BArray200.set8 st (W64.to_uint pos) (truncateu8 t));
      pos <- (pos + (W64.of_int 1));
      full <- (pos = (W64.of_int 136));
      if (full) {
        ms <- (update_msf full ms);
        (* Erased call to spill *)
        (st, ms) <@ _keccakf1600 (st, ms);
        (* Erased call to unspill *)
        prefix <- (protect_ptr prefix ms);
        len <- (protect_64 len ms);
        i <- (protect_64 i ms);
        pos <- (W64.of_int 0);
      } else {
        ms <- (update_msf (! full) ms);
      }
      i <- (i + (W64.of_int 1));
      more <- (i \ult len);
    }
    ms <- (update_msf (! more) ms);
    cap <- (W64.of_int (136 - 1));
    pos <- (((W64.of_int 136) \ule pos) ? cap : pos);
    return (st, pos, ms);
  }
  proc __shake_absorb_message (st:BArray200.t, head:int, prefix:BArray332.t,
                               prefix_len:W64.t, msg:W64.t, msg_len:W64.t,
                               ms:W64.t) : BArray200.t * W64.t = {
    var pos:W64.t;
    var rate:W64.t;
    var ds:W64.t;
    pos <- (W64.of_int head);
    prefix_len <- (protect_64 prefix_len ms);
    (* Erased call to spill *)
    (st, pos, ms) <@ _shake_absorb_prefix (st, pos, prefix, prefix_len, ms);
    (* Erased call to unspill *)
    msg <- (protect_64 msg ms);
    msg_len <- (protect_64 msg_len ms);
    rate <- (W64.of_int 136);
    (st, pos, ms) <@ _keccak_absorb_mem (st, pos, rate, msg, msg_len, ms);
    rate <- (W64.of_int 136);
    ds <- (W64.of_int 31);
    (st, ms) <@ _keccak_finalize (st, pos, rate, ds, ms);
    return (st, ms);
  }
  proc _prf_msg (r:BArray16.t, sk_prf:BArray16.t, opt_rand:BArray16.t,
                 prefix:BArray332.t, prefix_len:W64.t, msg:W64.t,
                 msg_len:W64.t, ms:W64.t) : BArray16.t * W64.t = {
    var inc:int;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    st <@ __keccak_init (st);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 sk_prf i);
      st <- (BArray200.set64 st i t);
      t <- (BArray16.get64 opt_rand i);
      st <- (BArray200.set64 st ((16 %/ 8) + i) t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    (st, ms) <@ __shake_absorb_message (st, (2 * 16), prefix, prefix_len,
    msg, msg_len, ms);
    (* Erased call to unspill *)
    r <- (protect_ptr r ms);
    r <@ __shake_extract_n (r, st);
    return (r, ms);
  }
  proc _h_msg (digest:BArray30.t, r:BArray16.t, pk:BArray32.t,
               prefix:BArray332.t, prefix_len:W64.t, msg:W64.t,
               msg_len:W64.t, ms:W64.t) : BArray30.t * W64.t = {
    var inc:int;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    st <@ __keccak_init (st);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 r i);
      st <- (BArray200.set64 st i t);
      i <- (i + 1);
    }
    inc <- (2 * (16 %/ 8));
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 pk i);
      st <- (BArray200.set64 st ((16 %/ 8) + i) t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    (st, ms) <@ __shake_absorb_message (st, (3 * 16), prefix, prefix_len,
    msg, msg_len, ms);
    (* Erased call to unspill *)
    digest <- (protect_ptr digest ms);
    i <- 0;
    while ((i < 30)) {
      t <- (zeroextu64 (BArray200.get8 st i));
      digest <- (BArray30.set8 digest i (truncateu8 t));
      i <- (i + 1);
    }
    return (digest, ms);
  }
  proc _keccakf1600_x4 (st:BArray800.t, ms:W64.t) : BArray800.t * W64.t = {
    var k:int;
    var j:int;
    var t:W64.t;
    var one:BArray200.t;
    one <- witness;
    k <- 0;
    while ((k < 4)) {
      j <- 0;
      while ((j < 25)) {
        t <- (BArray800.get64 st ((4 * j) + k));
        one <- (BArray200.set64 one j t);
        j <- (j + 1);
      }
      (* Erased call to spill *)
      (one, ms) <@ _keccakf1600 (one, ms);
      (* Erased call to unspill *)
      st <- (protect_ptr st ms);
      j <- 0;
      while ((j < 25)) {
        t <- (BArray200.get64 one j);
        st <- (BArray800.set64 st ((4 * j) + k) t);
        j <- (j + 1);
      }
      k <- (k + 1);
    }
    return (st, ms);
  }
  proc __keccak_x4_init (st:BArray800.t) : BArray800.t = {
    var z:W64.t;
    var i:int;
    z <- (W64.of_int 0);
    i <- 0;
    while ((i < 100)) {
      st <- (BArray800.set64 st i z);
      i <- (i + 1);
    }
    return st;
  }
  proc _keccak_x4_finalize (st:BArray800.t, pos:W64.t, rate:W64.t, ds:W64.t,
                            ms:W64.t) : BArray800.t * W64.t = {
    var lane:W64.t;
    var last_0:W64.t;
    var t:W64.t;
    var k:int;
    lane <- pos;
    lane <- (lane `>>` (W8.of_int 3));
    lane <- (lane `<<` (W8.of_int 5));
    pos <- (pos `&` (W64.of_int 7));
    lane <- (lane + pos);
    rate <- (rate - (W64.of_int 1));
    last_0 <- rate;
    last_0 <- (last_0 `>>` (W8.of_int 3));
    last_0 <- (last_0 `<<` (W8.of_int 5));
    rate <- (rate `&` (W64.of_int 7));
    last_0 <- (last_0 + rate);
    k <- 0;
    while ((k < 4)) {
      t <- (zeroextu64 (BArray800.get8 st (W64.to_uint lane)));
      t <- (t `^` ds);
      st <- (BArray800.set8 st (W64.to_uint lane) (truncateu8 t));
      t <- (zeroextu64 (BArray800.get8 st (W64.to_uint last_0)));
      t <- (t `^` (W64.of_int 128));
      st <- (BArray800.set8 st (W64.to_uint last_0) (truncateu8 t));
      lane <- (lane + (W64.of_int 8));
      last_0 <- (last_0 + (W64.of_int 8));
      k <- (k + 1);
    }
    (st, ms) <@ _keccakf1600_x4 (st, ms);
    return (st, ms);
  }
  proc __shake_x4_seeded_head (st:BArray800.t, ctx:BArray16.t,
                               adrs:BArray128.t) : BArray800.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    var k:int;
    st <@ __keccak_x4_init (st);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 ctx i);
      k <- 0;
      while ((k < 4)) {
        st <- (BArray800.set64 st ((4 * i) + k) t);
        k <- (k + 1);
      }
      i <- (i + 1);
    }
    k <- 0;
    while ((k < 4)) {
      i <- 0;
      while ((i < 4)) {
        t <- (BArray128.get64 adrs ((4 * k) + i));
        st <- (BArray800.set64 st ((4 * ((16 %/ 8) + i)) + k) t);
        i <- (i + 1);
      }
      k <- (k + 1);
    }
    return st;
  }
  proc __shake_x4_pad_lanes (st:BArray800.t, lanes:int) : BArray800.t = {
    var u:W64.t;
    var k:int;
    var t:W64.t;
    u <- (W64.of_int 9223372036854775808);
    k <- 0;
    while ((k < 4)) {
      t <- (BArray800.get64 st ((4 * lanes) + k));
      t <- (t `^` (W64.of_int 31));
      st <- (BArray800.set64 st ((4 * lanes) + k) t);
      t <- (BArray800.get64 st ((4 * (17 - 1)) + k));
      t <- (t `^` u);
      st <- (BArray800.set64 st ((4 * (17 - 1)) + k) t);
      k <- (k + 1);
    }
    return st;
  }
  proc __shake_x4_extract_n (out:BArray64.t, st:BArray800.t) : BArray64.t = {
    var inc:int;
    var k:int;
    var i:int;
    var t:W64.t;
    k <- 0;
    while ((k < 4)) {
      inc <- (16 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray800.get64 st ((4 * i) + k));
        out <- (BArray64.set64 out (((16 %/ 8) * k) + i) t);
        i <- (i + 1);
      }
      k <- (k + 1);
    }
    return out;
  }
  proc _thash_prf_x4 (out:BArray64.t, sk_seed:BArray16.t, ctx:BArray16.t,
                      adrs:BArray128.t, ms:W64.t) : BArray64.t * W64.t = {
    var inc:int;
    var st:BArray800.t;
    var i:int;
    var t:W64.t;
    var k:int;
    st <- witness;
    st <@ __shake_x4_seeded_head (st, ctx, adrs);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 sk_seed i);
      k <- 0;
      while ((k < 4)) {
        st <- (BArray800.set64 st ((4 * (((16 %/ 8) + 4) + i)) + k) t);
        k <- (k + 1);
      }
      i <- (i + 1);
    }
    st <@ __shake_x4_pad_lanes (st, ((2 * (16 %/ 8)) + 4));
    (* Erased call to spill *)
    (st, ms) <@ _keccakf1600_x4 (st, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    out <@ __shake_x4_extract_n (out, st);
    return (out, ms);
  }
  proc _thash_f_x4 (x:BArray64.t, ctx:BArray16.t, adrs:BArray128.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var inc:int;
    var st:BArray800.t;
    var i:int;
    var k:int;
    var t:W64.t;
    st <- witness;
    st <@ __shake_x4_seeded_head (st, ctx, adrs);
    k <- 0;
    while ((k < 4)) {
      inc <- (16 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray64.get64 x (((16 %/ 8) * k) + i));
        st <- (BArray800.set64 st ((4 * (((16 %/ 8) + 4) + i)) + k) t);
        i <- (i + 1);
      }
      k <- (k + 1);
    }
    st <@ __shake_x4_pad_lanes (st, ((2 * (16 %/ 8)) + 4));
    (* Erased call to spill *)
    (st, ms) <@ _keccakf1600_x4 (st, ms);
    (* Erased call to unspill *)
    x <- (protect_ptr x ms);
    x <@ __shake_x4_extract_n (x, st);
    return (x, ms);
  }
  proc _thash_t_len_x4 (out:BArray64.t, in_0:BArray2240.t, ctx:BArray16.t,
                        adrs:BArray128.t, ms:W64.t) : BArray64.t * W64.t = {
    var st_s:BArray800.t;
    var st:BArray800.t;
    var pos:W64.t;
    var i:W64.t;
    var more:bool;
    var cap:W64.t;
    var lane:W64.t;
    var o:W64.t;
    var v:W64.t;
    var t:W64.t;
    var k:int;
    var full:bool;
    st <- witness;
    st_s <- witness;
    st <- st_s;
    st <@ __shake_x4_seeded_head (st, ctx, adrs);
    pos <- (W64.of_int ((16 %/ 8) + 4));
    (* Erased call to spill *)
    i <- (W64.of_int 0);
    more <- (i \ult (W64.of_int (((2 * 16) + 3) * (16 %/ 8))));
    while (more) {
      ms <- (update_msf more ms);
      cap <- (W64.of_int (17 - 1));
      pos <- (((W64.of_int 17) \ule pos) ? cap : pos);
      lane <- pos;
      lane <- (lane `<<` (W8.of_int 2));
      o <- i;
      k <- 0;
      while ((k < 4)) {
        v <- (BArray2240.get64 in_0 (W64.to_uint o));
        t <- (BArray800.get64 st (W64.to_uint lane));
        t <- (t `^` v);
        st <- (BArray800.set64 st (W64.to_uint lane) t);
        o <- (o + (W64.of_int (((2 * 16) + 3) * (16 %/ 8))));
        lane <- (lane + (W64.of_int 1));
        k <- (k + 1);
      }
      pos <- (pos + (W64.of_int 1));
      full <- (pos = (W64.of_int 17));
      if (full) {
        ms <- (update_msf full ms);
        (* Erased call to spill *)
        (st, ms) <@ _keccakf1600_x4 (st, ms);
        (* Erased call to unspill *)
        in_0 <- (protect_ptr in_0 ms);
        i <- (protect_64 i ms);
        pos <- (W64.of_int 0);
      } else {
        ms <- (update_msf (! full) ms);
      }
      i <- (i + (W64.of_int 1));
      more <- (i \ult (W64.of_int (((2 * 16) + 3) * (16 %/ 8))));
    }
    ms <- (update_msf (! more) ms);
    lane <- pos;
    lane <- (lane `<<` (W8.of_int 2));
    v <- (W64.of_int 9223372036854775808);
    k <- 0;
    while ((k < 4)) {
      t <- (BArray800.get64 st (W64.to_uint lane));
      t <- (t `^` (W64.of_int 31));
      st <- (BArray800.set64 st (W64.to_uint lane) t);
      lane <- (lane + (W64.of_int 1));
      t <- (BArray800.get64 st ((4 * (17 - 1)) + k));
      t <- (t `^` v);
      st <- (BArray800.set64 st ((4 * (17 - 1)) + k) t);
      k <- (k + 1);
    }
    (st, ms) <@ _keccakf1600_x4 (st, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    out <@ __shake_x4_extract_n (out, st);
    return (out, ms);
  }
  proc __wots_digits (d:BArray35.t, msg:BArray16.t) : BArray35.t = {
    var csum:W32.t;
    var i:int;
    var b:W32.t;
    var hi:W32.t;
    var lo:W32.t;
    var t:W32.t;
    csum <- (W32.of_int 0);
    i <- 0;
    while ((i < 16)) {
      b <- (zeroextu32 (BArray16.get8 msg i));
      hi <- b;
      hi <- (hi `>>` (W8.of_int 4));
      lo <- b;
      lo <- (lo `&` (W32.of_int 15));
      d <- (BArray35.set8 d (2 * i) (truncateu8 hi));
      d <- (BArray35.set8 d ((2 * i) + 1) (truncateu8 lo));
      csum <- (csum + (W32.of_int 30));
      csum <- (csum - hi);
      csum <- (csum - lo);
      i <- (i + 1);
    }
    t <- csum;
    t <- (t `>>` (W8.of_int 8));
    d <- (BArray35.set8 d (2 * 16) (truncateu8 t));
    t <- csum;
    t <- (t `>>` (W8.of_int 4));
    t <- (t `&` (W32.of_int 15));
    d <- (BArray35.set8 d ((2 * 16) + 1) (truncateu8 t));
    t <- csum;
    t <- (t `&` (W32.of_int 15));
    d <- (BArray35.set8 d ((2 * 16) + 2) (truncateu8 t));
    return d;
  }
  proc _wots_chain (x:BArray16.t, start:W32.t, steps:W32.t, ctx:BArray16.t,
                    adrs:BArray32.t, ms:W64.t) : BArray16.t * BArray32.t *
                                                 W64.t = {
    var j:W32.t;
    var end_0:W32.t;
    var more:bool;
    j <- start;
    end_0 <- start;
    end_0 <- (end_0 + steps);
    more <- (j \ult end_0);
    while (more) {
      ms <- (update_msf more ms);
      adrs <@ __adrs_set_hash (adrs, j);
      (* Erased call to spill *)
      (x, ms) <@ _thash_f (x, ctx, adrs, ms);
      (* Erased call to unspill *)
      ctx <- (protect_ptr ctx ms);
      adrs <- (protect_ptr adrs ms);
      j <- (protect_32 j ms);
      end_0 <- (protect_32 end_0 ms);
      j <- (j + (W32.of_int 1));
      more <- (j \ult end_0);
    }
    ms <- (update_msf (! more) ms);
    return (x, adrs, ms);
  }
  proc _wots_leaf_x4 (leaves:BArray64.t, sig:BArray560.t, sk_seed:BArray16.t,
                      ctx:BArray16.t, adrs:BArray32.t, kp0:W32.t,
                      steps:BArray35.t, lane:W64.t, ms:W64.t) : BArray64.t *
                                                                BArray560.t *
                                                                W64.t = {
    var aux:BArray32.t;
    var inc:int;
    var kp:W32.t;
    var k:int;
    var sk_adrs:BArray128.t;
    var chain_adrs:BArray128.t;
    var pk_adrs:BArray128.t;
    var fill:W64.t;
    var pk:BArray2240.t;
    var i:W32.t;
    var more:bool;
    var cur:BArray64.t;
    var split_0:W32.t;
    var take:bool;
    var off:W64.t;
    var j:W32.t;
    var step:bool;
    var hit:bool;
    var src:W64.t;
    var cp:BArray64.t;
    var t:W64.t;
    var w:int;
    var fwd:bool;
    var dst:BArray2240.t;
    chain_adrs <- witness;
    cp <- witness;
    cur <- witness;
    dst <- witness;
    pk <- witness;
    pk_adrs <- witness;
    sk_adrs <- witness;
    k <- 0;
    while ((k < 4)) {
      kp <- kp0;
      kp <- (kp + (W32.of_int k));
      aux <@ __adrs_copy ((SBArray128_32.get_sub64 sk_adrs (4 * k)), adrs);
      sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
      aux <@ __adrs_set_type_and_clear ((SBArray128_32.get_sub64 sk_adrs
                                        (4 * k)),
      5);
      sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
      aux <@ __adrs_set_keypair ((SBArray128_32.get_sub64 sk_adrs (4 * k)),
      kp);
      sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
      aux <@ __adrs_copy ((SBArray128_32.get_sub64 chain_adrs (4 * k)),
      adrs);
      chain_adrs <- (SBArray128_32.set_sub64 chain_adrs (4 * k) aux);
      aux <@ __adrs_set_type_and_clear ((SBArray128_32.get_sub64 chain_adrs
                                        (4 * k)),
      0);
      chain_adrs <- (SBArray128_32.set_sub64 chain_adrs (4 * k) aux);
      aux <@ __adrs_set_keypair ((SBArray128_32.get_sub64 chain_adrs (4 * k)),
      kp);
      chain_adrs <- (SBArray128_32.set_sub64 chain_adrs (4 * k) aux);
      aux <@ __adrs_copy ((SBArray128_32.get_sub64 pk_adrs (4 * k)), adrs);
      pk_adrs <- (SBArray128_32.set_sub64 pk_adrs (4 * k) aux);
      aux <@ __adrs_set_type_and_clear ((SBArray128_32.get_sub64 pk_adrs
                                        (4 * k)),
      1);
      pk_adrs <- (SBArray128_32.set_sub64 pk_adrs (4 * k) aux);
      aux <@ __adrs_set_keypair ((SBArray128_32.get_sub64 pk_adrs (4 * k)),
      kp);
      pk_adrs <- (SBArray128_32.set_sub64 pk_adrs (4 * k) aux);
      k <- (k + 1);
    }
    (* Erased call to spill *)
    fill <- (W64.of_int 0);
    inc <- (((4 * ((2 * 16) + 3)) * 16) %/ 8);
    k <- 0;
    while ((k < inc)) {
      pk <- (BArray2240.set64 pk k fill);
      k <- (k + 1);
    }
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int ((2 * 16) + 3)));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to spill *)
      k <- 0;
      while ((k < 4)) {
        aux <@ __adrs_set_chain ((SBArray128_32.get_sub64 sk_adrs (4 * k)),
        i);
        sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
        aux <@ __adrs_set_chain ((SBArray128_32.get_sub64 chain_adrs (4 * k)),
        i);
        chain_adrs <- (SBArray128_32.set_sub64 chain_adrs (4 * k) aux);
        k <- (k + 1);
      }
      (* Erased call to unspill *)
      sk_seed <- (protect_ptr sk_seed ms);
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      (cur, ms) <@ _thash_prf_x4 (cur, sk_seed, ctx, sk_adrs, ms);
      (* Erased call to unspill *)
      i <- (protect_32 i ms);
      steps <- (protect_ptr steps ms);
      lane <- (protect_64 lane ms);
      (* Erased call to spill *)
      split_0 <- (W32.of_int 16);
      take <- (lane \ult (W64.of_int 4));
      if (take) {
        ms <- (update_msf take ms);
        off <- (zeroextu64 i);
        split_0 <- (zeroextu32 (BArray35.get8 steps (W64.to_uint off)));
        split_0 <- (protect_32 split_0 ms);
      } else {
        ms <- (update_msf (! take) ms);
      }
      (* Erased call to spill *)
      j <- (W32.of_int 0);
      step <- (j \ult (W32.of_int 16));
      while (step) {
        ms <- (update_msf step ms);
        (* Erased call to unspill *)
        split_0 <- (protect_32 split_0 ms);
        (* Erased call to spill *)
        hit <- (j = split_0);
        if (hit) {
          ms <- (update_msf hit ms);
          (* Erased call to unspill *)
          i <- (protect_32 i ms);
          lane <- (protect_64 lane ms);
          sig <- (protect_ptr sig ms);
          off <@ __offset (i, 16);
          src <@ __offset64 (lane, 16);
          cp <- cur;
          inc <- (16 %/ 8);
          w <- 0;
          while ((w < inc)) {
            t <- (BArray64.get64d cp (W64.to_uint src));
            sig <- (BArray560.set64d sig (W64.to_uint off) t);
            src <- (src + (W64.of_int 8));
            off <- (off + (W64.of_int 8));
            w <- (w + 1);
          }
          cur <- cp;
          (* Erased call to spill *)
        } else {
          ms <- (update_msf (! hit) ms);
        }
        fwd <- (j \ult (W32.of_int (16 - 1)));
        if (fwd) {
          ms <- (update_msf fwd ms);
          k <- 0;
          while ((k < 4)) {
            aux <@ __adrs_set_hash ((SBArray128_32.get_sub64 chain_adrs
                                    (4 * k)),
            j);
            chain_adrs <- (SBArray128_32.set_sub64 chain_adrs (4 * k) aux);
            k <- (k + 1);
          }
          (* Erased call to spill *)
          (* Erased call to unspill *)
          ctx <- (protect_ptr ctx ms);
          (* Erased call to spill *)
          (cur, ms) <@ _thash_f_x4 (cur, ctx, chain_adrs, ms);
          (* Erased call to unspill *)
          j <- (protect_32 j ms);
        } else {
          ms <- (update_msf (! fwd) ms);
        }
        j <- (j + (W32.of_int 1));
        step <- (j \ult (W32.of_int 16));
      }
      ms <- (update_msf (! step) ms);
      (* Erased call to unspill *)
      i <- (protect_32 i ms);
      (* Erased call to spill *)
      off <@ __offset (i, 16);
      dst <- pk;
      k <- 0;
      while ((k < 4)) {
        inc <- (16 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray64.get64 cur (((16 %/ 8) * k) + w));
          dst <- (BArray2240.set64d dst (W64.to_uint off) t);
          off <- (off + (W64.of_int 8));
          w <- (w + 1);
        }
        off <- (off + (W64.of_int ((((2 * 16) + 3) - 1) * 16)));
        k <- (k + 1);
      }
      pk <- dst;
      i <- (i + (W32.of_int 1));
      more <- (i \ult (W32.of_int ((2 * 16) + 3)));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    leaves <- (protect_ptr leaves ms);
    ctx <- (protect_ptr ctx ms);
    (leaves, ms) <@ _thash_t_len_x4 (leaves, pk, ctx, pk_adrs, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    return (leaves, sig, ms);
  }
  proc _wots_pk_from_sig (pk:BArray16.t, sig:BArray560.t, msg:BArray16.t,
                          ctx:BArray16.t, adrs:BArray32.t, keypair:W32.t,
                          ms:W64.t) : BArray16.t * W64.t = {
    var aux:BArray16.t;
    var inc:int;
    var digits:BArray35.t;
    var chain_adrs:BArray32.t;
    var pk_adrs:BArray32.t;
    var fill:W64.t;
    var k:int;
    var tmp:BArray560.t;
    var i:W32.t;
    var more:bool;
    var dp:BArray35.t;
    var off:W64.t;
    var start:W32.t;
    var steps:W32.t;
    var cur:BArray16.t;
    var dst:BArray560.t;
    chain_adrs <- witness;
    cur <- witness;
    digits <- witness;
    dp <- witness;
    dst <- witness;
    pk_adrs <- witness;
    tmp <- witness;
    digits <@ __wots_digits (digits, msg);
    (* Erased call to declassify *)
    chain_adrs <@ __adrs_copy (chain_adrs, adrs);
    chain_adrs <@ __adrs_set_type_and_clear (chain_adrs, 0);
    chain_adrs <@ __adrs_set_keypair (chain_adrs, keypair);
    pk_adrs <@ __adrs_copy (pk_adrs, adrs);
    pk_adrs <@ __adrs_set_type_and_clear (pk_adrs, 1);
    pk_adrs <@ __adrs_set_keypair (pk_adrs, keypair);
    (* Erased call to spill *)
    fill <- (W64.of_int 0);
    inc <- ((((2 * 16) + 3) * 16) %/ 8);
    k <- 0;
    while ((k < inc)) {
      tmp <- (BArray560.set64 tmp k fill);
      k <- (k + 1);
    }
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int ((2 * 16) + 3)));
    while (more) {
      ms <- (update_msf more ms);
      chain_adrs <@ __adrs_set_chain (chain_adrs, i);
      dp <- digits;
      off <- (zeroextu64 i);
      start <- (zeroextu32 (BArray35.get8 dp (W64.to_uint off)));
      start <- (protect_32 start ms);
      steps <- (W32.of_int (16 - 1));
      steps <- (steps - start);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      (* Erased call to spill *)
      off <@ __offset (i, 16);
      cur <@ __node_copy (cur,
      (SBArray560_16.get_sub8 sig (W64.to_uint off)));
      (* Erased call to spill *)
      (* Erased call to unspill *)
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      (cur, chain_adrs, ms) <@ _wots_chain (cur, start, steps, ctx,
      chain_adrs, ms);
      (* Erased call to unspill *)
      i <- (protect_32 i ms);
      (* Erased call to spill *)
      off <@ __offset (i, 16);
      dst <- tmp;
      aux <@ __node_copy ((SBArray560_16.get_sub8 dst (W64.to_uint off)),
      cur);
      dst <- (SBArray560_16.set_sub8 dst (W64.to_uint off) aux);
      tmp <- dst;
      i <- (i + (W32.of_int 1));
      more <- (i \ult (W32.of_int ((2 * 16) + 3)));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    pk <- (protect_ptr pk ms);
    ctx <- (protect_ptr ctx ms);
    (pk, ms) <@ _thash_t_len (pk, tmp, ctx, pk_adrs, ms);
    return (pk, ms);
  }
  proc __fold_slot (z:W32.t) : W64.t = {
    var off:W64.t;
    var cap:W32.t;
    cap <- (W32.of_int 12);
    z <- ((z \ult (W32.of_int 12)) ? z : cap);
    off <@ __offset (z, 16);
    return off;
  }
  proc _treehash_fold (nodes:BArray208.t, auth:BArray208.t, node:BArray16.t,
                       idx:W32.t, adrs_idx:W32.t, target:W32.t,
                       ctx:BArray16.t, node_adrs:BArray32.t, ms:W64.t) : 
  BArray208.t * BArray208.t * BArray16.t * BArray32.t * W64.t = {
    var aux:BArray16.t;
    var z:W32.t;
    var sib:W32.t;
    var odd:bool;
    var off:W64.t;
    var pair:BArray32.t;
    var found:bool;
    var bit:W32.t;
    pair <- witness;
    z <- (W32.of_int 0);
    sib <- target;
    sib <- (sib `^` (W32.of_int 1));
    found <- (idx = sib);
    if (found) {
      ms <- (update_msf found ms);
      off <@ __fold_slot (z);
      aux <@ __node_copy ((SBArray208_16.get_sub8 auth (W64.to_uint off)),
      node);
      auth <- (SBArray208_16.set_sub8 auth (W64.to_uint off) aux);
    } else {
      ms <- (update_msf (! found) ms);
    }
    bit <- idx;
    bit <- (bit `&` (W32.of_int 1));
    odd <- (bit = (W32.of_int 1));
    while (odd) {
      ms <- (update_msf odd ms);
      off <@ __fold_slot (z);
      aux <@ __node_copy ((SBArray32_16.get_sub8 pair 0),
      (SBArray208_16.get_sub8 nodes (W64.to_uint off)));
      pair <- (SBArray32_16.set_sub8 pair 0 aux);
      aux <@ __node_copy ((SBArray32_16.get_sub8 pair 16), node);
      pair <- (SBArray32_16.set_sub8 pair 16 aux);
      z <- (z + (W32.of_int 1));
      idx <- (idx `>>` (W8.of_int 1));
      adrs_idx <- (adrs_idx `>>` (W8.of_int 1));
      sib <- (sib `>>` (W8.of_int 1));
      sib <- (sib `^` (W32.of_int 1));
      node_adrs <@ __adrs_set_tree_height (node_adrs, z);
      node_adrs <@ __adrs_set_tree_index (node_adrs, adrs_idx);
      (* Erased call to spill *)
      (node, ms) <@ _thash_h (node, pair, ctx, node_adrs, ms);
      (* Erased call to unspill *)
      nodes <- (protect_ptr nodes ms);
      auth <- (protect_ptr auth ms);
      ctx <- (protect_ptr ctx ms);
      node_adrs <- (protect_ptr node_adrs ms);
      idx <- (protect_32 idx ms);
      adrs_idx <- (protect_32 adrs_idx ms);
      z <- (protect_32 z ms);
      sib <- (protect_32 sib ms);
      found <- (idx = sib);
      if (found) {
        ms <- (update_msf found ms);
        off <@ __fold_slot (z);
        aux <@ __node_copy ((SBArray208_16.get_sub8 auth (W64.to_uint off)),
        node);
        auth <- (SBArray208_16.set_sub8 auth (W64.to_uint off) aux);
      } else {
        ms <- (update_msf (! found) ms);
      }
      bit <- idx;
      bit <- (bit `&` (W32.of_int 1));
      odd <- (bit = (W32.of_int 1));
    }
    ms <- (update_msf (! odd) ms);
    off <@ __fold_slot (z);
    aux <@ __node_copy ((SBArray208_16.get_sub8 nodes (W64.to_uint off)),
    node);
    nodes <- (SBArray208_16.set_sub8 nodes (W64.to_uint off) aux);
    return (nodes, auth, node, node_adrs, ms);
  }
  proc _xmss_treehash (root:BArray16.t, sig:BArray704.t, sk_seed:BArray16.t,
                       ctx:BArray16.t, adrs:BArray32.t, target:W32.t,
                       steps:BArray35.t, ms:W64.t) : BArray16.t *
                                                     BArray704.t * W64.t = {
    var inc:int;
    var tree_adrs:BArray32.t;
    var fill:W64.t;
    var k:int;
    var nodes:BArray208.t;
    var auth:BArray208.t;
    var wsig:BArray560.t;
    var i:W32.t;
    var more:bool;
    var d:W32.t;
    var lane:W64.t;
    var four:W64.t;
    var kp:W32.t;
    var leaves:BArray64.t;
    var w:int;
    var t:W64.t;
    var node:BArray16.t;
    var li:W32.t;
    var ai:W32.t;
    var tg:W32.t;
    var found:bool;
    auth <- witness;
    leaves <- witness;
    node <- witness;
    nodes <- witness;
    tree_adrs <- witness;
    wsig <- witness;
    tree_adrs <@ __adrs_copy (tree_adrs, adrs);
    tree_adrs <@ __adrs_set_type_and_clear (tree_adrs, 2);
    fill <- (W64.of_int 0);
    inc <- (((12 + 1) * 16) %/ 8);
    k <- 0;
    while ((k < inc)) {
      nodes <- (BArray208.set64 nodes k fill);
      auth <- (BArray208.set64 auth k fill);
      k <- (k + 1);
    }
    inc <- ((((2 * 16) + 3) * 16) %/ 8);
    k <- 0;
    while ((k < inc)) {
      wsig <- (BArray560.set64 wsig k fill);
      k <- (k + 1);
    }
    (* Erased call to spill *)
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int (1 `<<` 9)));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to spill *)
      (* Erased call to unspill *)
      sk_seed <- (protect_ptr sk_seed ms);
      ctx <- (protect_ptr ctx ms);
      adrs <- (protect_ptr adrs ms);
      target <- (protect_32 target ms);
      steps <- (protect_ptr steps ms);
      (* Erased call to spill *)
      d <- target;
      d <- (d - i);
      lane <- (zeroextu64 d);
      four <- (W64.of_int 4);
      lane <- ((d \ult (W32.of_int 4)) ? lane : four);
      kp <- i;
      (leaves, wsig, ms) <@ _wots_leaf_x4 (leaves, wsig, sk_seed, ctx, 
      adrs, kp, steps, lane, ms);
      k <- 0;
      while ((k < 4)) {
        inc <- (16 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray64.get64 leaves (((16 %/ 8) * k) + w));
          node <- (BArray16.set64 node w t);
          w <- (w + 1);
        }
        (* Erased call to unspill *)
        i <- (protect_32 i ms);
        target <- (protect_32 target ms);
        ctx <- (protect_ptr ctx ms);
        (* Erased call to spill *)
        li <- i;
        li <- (li + (W32.of_int k));
        ai <- li;
        tg <- target;
        (nodes, auth, node, tree_adrs, ms) <@ _treehash_fold (nodes, 
        auth, node, li, ai, tg, ctx, tree_adrs, ms);
        k <- (k + 1);
      }
      (* Erased call to unspill *)
      i <- (protect_32 i ms);
      (* Erased call to spill *)
      i <- (i + (W32.of_int 4));
      more <- (i \ult (W32.of_int (1 `<<` 9)));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    root <- (protect_ptr root ms);
    sig <- (protect_ptr sig ms);
    target <- (protect_32 target ms);
    root <@ __node_copy (root, (SBArray208_16.get_sub8 nodes (9 * 16)));
    found <- (target \ult (W32.of_int (1 `<<` 9)));
    if (found) {
      ms <- (update_msf found ms);
      inc <- ((((2 * 16) + 3) * 16) %/ 8);
      k <- 0;
      while ((k < inc)) {
        t <- (BArray560.get64 wsig k);
        sig <- (BArray704.set64 sig k t);
        k <- (k + 1);
      }
      inc <- ((9 * 16) %/ 8);
      k <- 0;
      while ((k < inc)) {
        t <- (BArray208.get64 auth k);
        sig <- (BArray704.set64 sig (((((2 * 16) + 3) * 16) %/ 8) + k) t);
        k <- (k + 1);
      }
    } else {
      ms <- (update_msf (! found) ms);
    }
    return (root, sig, ms);
  }
  proc _xmss_pk_from_sig (root:BArray16.t, sig:BArray704.t, msg:BArray16.t,
                          ctx:BArray16.t, adrs:BArray32.t, idx:W32.t,
                          ms:W64.t) : BArray16.t * W64.t = {
    var aux:BArray16.t;
    var tree_adrs:BArray32.t;
    var kp:W32.t;
    var node:BArray16.t;
    var k:W32.t;
    var more:bool;
    var off:W64.t;
    var bit:W32.t;
    var odd:bool;
    var pair:BArray32.t;
    node <- witness;
    pair <- witness;
    tree_adrs <- witness;
    tree_adrs <@ __adrs_copy (tree_adrs, adrs);
    tree_adrs <@ __adrs_set_type_and_clear (tree_adrs, 2);
    (* Erased call to spill *)
    kp <- idx;
    (node, ms) <@ _wots_pk_from_sig (node, (SBArray704_560.get_sub8 sig 0),
    msg, ctx, adrs, kp, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    idx <- (protect_32 idx ms);
    (* Erased call to spill *)
    k <- (W32.of_int 0);
    more <- (k \ult (W32.of_int 9));
    while (more) {
      ms <- (update_msf more ms);
      off <@ __offset (k, 16);
      off <- (off + (W64.of_int (((2 * 16) + 3) * 16)));
      bit <- idx;
      bit <- (bit `&` (W32.of_int 1));
      odd <- (bit = (W32.of_int 1));
      if (odd) {
        ms <- (update_msf odd ms);
        aux <@ __node_copy ((SBArray32_16.get_sub8 pair 0),
        (SBArray704_16.get_sub8 sig (W64.to_uint off)));
        pair <- (SBArray32_16.set_sub8 pair 0 aux);
        aux <@ __node_copy ((SBArray32_16.get_sub8 pair 16), node);
        pair <- (SBArray32_16.set_sub8 pair 16 aux);
      } else {
        ms <- (update_msf (! odd) ms);
        aux <@ __node_copy ((SBArray32_16.get_sub8 pair 0), node);
        pair <- (SBArray32_16.set_sub8 pair 0 aux);
        aux <@ __node_copy ((SBArray32_16.get_sub8 pair 16),
        (SBArray704_16.get_sub8 sig (W64.to_uint off)));
        pair <- (SBArray32_16.set_sub8 pair 16 aux);
      }
      k <- (k + (W32.of_int 1));
      idx <- (idx `>>` (W8.of_int 1));
      tree_adrs <@ __adrs_set_tree_height (tree_adrs, k);
      tree_adrs <@ __adrs_set_tree_index (tree_adrs, idx);
      (* Erased call to spill *)
      (* Erased call to unspill *)
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      (node, ms) <@ _thash_h (node, pair, ctx, tree_adrs, ms);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      idx <- (protect_32 idx ms);
      k <- (protect_32 k ms);
      (* Erased call to spill *)
      more <- (k \ult (W32.of_int 9));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    root <- (protect_ptr root ms);
    root <@ __node_copy (root, node);
    return (root, ms);
  }
  proc _ht_sign (sig:BArray7856.t, msg:BArray16.t, sk_seed:BArray16.t,
                 ctx:BArray16.t, idx_tree:W64.t, idx_leaf:W32.t, ms:W64.t) : 
  BArray7856.t * BArray16.t * W64.t = {
    var adrs:BArray32.t;
    var j:W32.t;
    var more:bool;
    var digits:BArray35.t;
    var leaf:W32.t;
    var layer:BArray704.t;
    var off:W64.t;
    var src:BArray704.t;
    var k:W64.t;
    var copy:bool;
    var t:W64.t;
    var o:W64.t;
    adrs <- witness;
    digits <- witness;
    layer <- witness;
    src <- witness;
    adrs <@ __adrs_zero (adrs);
    (* Erased call to spill *)
    j <- (W32.of_int 0);
    more <- (j \ult (W32.of_int 7));
    while (more) {
      ms <- (update_msf more ms);
      adrs <@ __adrs_set_layer (adrs, j);
      adrs <@ __adrs_set_tree (adrs, idx_tree);
      digits <@ __wots_digits (digits, msg);
      (* Erased call to declassify *)
      leaf <- idx_leaf;
      (* Erased call to spill *)
      (* Erased call to unspill *)
      sk_seed <- (protect_ptr sk_seed ms);
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      (msg, layer, ms) <@ _xmss_treehash (msg, layer, sk_seed, ctx, adrs,
      leaf, digits, ms);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      idx_tree <- (protect_64 idx_tree ms);
      j <- (protect_32 j ms);
      msg <@ __hook_ht_root (msg, j);
      off <@ __offset (j, ((((2 * 16) + 3) + 9) * 16));
      off <- (off + (W64.of_int (16 + ((14 * (12 + 1)) * 16))));
      src <- layer;
      k <- (W64.of_int 0);
      copy <- (k \ult (W64.of_int ((((2 * 16) + 3) + 9) * 16)));
      while (copy) {
        ms <- (update_msf copy ms);
        t <- (BArray704.get64d src (W64.to_uint k));
        o <- off;
        o <- (o + k);
        sig <- (BArray7856.set64d sig (W64.to_uint o) t);
        k <- (k + (W64.of_int 8));
        copy <- (k \ult (W64.of_int ((((2 * 16) + 3) + 9) * 16)));
      }
      ms <- (update_msf (! copy) ms);
      layer <- src;
      (* Erased call to spill *)
      idx_leaf <- (truncateu32 idx_tree);
      idx_leaf <- (idx_leaf `&` (W32.of_int ((1 `<<` 9) - 1)));
      idx_tree <- (idx_tree `>>` (W8.of_int 9));
      j <- (j + (W32.of_int 1));
      more <- (j \ult (W32.of_int 7));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    return (sig, msg, ms);
  }
  proc _ht_verify (sig:BArray4928.t, msg:BArray16.t, pk_root:BArray16.t,
                   ctx:BArray16.t, idx_tree:W64.t, idx_leaf:W32.t, ms:W64.t) : 
  W64.t * W64.t = {
    var inc:int;
    var result:W64.t;
    var node:BArray16.t;
    var adrs:BArray32.t;
    var j:W32.t;
    var more:bool;
    var off:W64.t;
    var leaf:W32.t;
    var next:BArray16.t;
    var diff:W64.t;
    var k:int;
    var t:W64.t;
    var u:W64.t;
    adrs <- witness;
    next <- witness;
    node <- witness;
    node <@ __node_copy (node, msg);
    adrs <@ __adrs_zero (adrs);
    (* Erased call to spill *)
    j <- (W32.of_int 0);
    more <- (j \ult (W32.of_int 7));
    while (more) {
      ms <- (update_msf more ms);
      adrs <@ __adrs_set_layer (adrs, j);
      adrs <@ __adrs_set_tree (adrs, idx_tree);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      off <@ __offset (j, ((((2 * 16) + 3) + 9) * 16));
      leaf <- idx_leaf;
      (* Erased call to spill *)
      (next, ms) <@ _xmss_pk_from_sig (next,
      (SBArray4928_704.get_sub8 sig (W64.to_uint off)), node, ctx, adrs,
      leaf, ms);
      (* Erased call to unspill *)
      j <- (protect_32 j ms);
      idx_tree <- (protect_64 idx_tree ms);
      idx_leaf <- (protect_32 idx_leaf ms);
      (* Erased call to spill *)
      node <@ __node_copy (node, next);
      idx_leaf <- (truncateu32 idx_tree);
      idx_leaf <- (idx_leaf `&` (W32.of_int ((1 `<<` 9) - 1)));
      idx_tree <- (idx_tree `>>` (W8.of_int 9));
      j <- (j + (W32.of_int 1));
      more <- (j \ult (W32.of_int 7));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    pk_root <- (protect_ptr pk_root ms);
    diff <- (W64.of_int 0);
    inc <- (16 %/ 8);
    k <- 0;
    while ((k < inc)) {
      t <- (BArray16.get64 node k);
      u <- (BArray16.get64 pk_root k);
      t <- (t `^` u);
      diff <- (diff `|` t);
      k <- (k + 1);
    }
    result <- (W64.of_int 0);
    t <- (W64.of_int (- 1));
    result <- ((diff <> (W64.of_int 0)) ? t : result);
    (* Erased call to declassify *)
    result <- (protect_64 result ms);
    return (result, ms);
  }
  proc _fors_tree (sig:BArray208.t, root:BArray16.t, sk_seed:BArray16.t,
                   ctx:BArray16.t, adrs:BArray32.t, tree:W32.t, target:W32.t,
                   ms:W64.t) : BArray208.t * BArray16.t * W64.t = {
    var aux_0:BArray16.t;
    var aux:BArray32.t;
    var inc:int;
    var k:int;
    var sk_adrs:BArray128.t;
    var leaf_adrs:BArray128.t;
    var node_adrs:BArray32.t;
    var fill:W64.t;
    var nodes:BArray208.t;
    var auth:BArray208.t;
    var selected:BArray16.t;
    var base:W32.t;
    var i:W32.t;
    var more:bool;
    var g:W32.t;
    var z:W32.t;
    var gk:W32.t;
    var leaves:BArray64.t;
    var d:W32.t;
    var found:bool;
    var src:W64.t;
    var lp:BArray64.t;
    var t:W64.t;
    var w:int;
    var node:BArray16.t;
    var li:W32.t;
    var gi:W32.t;
    var tg:W32.t;
    auth <- witness;
    leaf_adrs <- witness;
    leaves <- witness;
    lp <- witness;
    node <- witness;
    node_adrs <- witness;
    nodes <- witness;
    selected <- witness;
    sk_adrs <- witness;
    k <- 0;
    while ((k < 4)) {
      aux <@ __adrs_copy ((SBArray128_32.get_sub64 sk_adrs (4 * k)), adrs);
      sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
      aux <@ __adrs_set_type_and_clear ((SBArray128_32.get_sub64 sk_adrs
                                        (4 * k)),
      6);
      sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
      aux <@ __adrs_copy_keypair ((SBArray128_32.get_sub64 sk_adrs (4 * k)),
      adrs);
      sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
      aux <@ __adrs_copy ((SBArray128_32.get_sub64 leaf_adrs (4 * k)), adrs);
      leaf_adrs <- (SBArray128_32.set_sub64 leaf_adrs (4 * k) aux);
      k <- (k + 1);
    }
    node_adrs <@ __adrs_copy (node_adrs, adrs);
    fill <- (W64.of_int 0);
    inc <- (((12 + 1) * 16) %/ 8);
    k <- 0;
    while ((k < inc)) {
      nodes <- (BArray208.set64 nodes k fill);
      auth <- (BArray208.set64 auth k fill);
      k <- (k + 1);
    }
    inc <- (16 %/ 8);
    k <- 0;
    while ((k < inc)) {
      selected <- (BArray16.set64 selected k fill);
      k <- (k + 1);
    }
    base <- tree;
    base <- (base `<<` (W8.of_int 12));
    (* Erased call to spill *)
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int (1 `<<` 12)));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to unspill *)
      base <- (protect_32 base ms);
      (* Erased call to spill *)
      g <- base;
      g <- (g + i);
      (* Erased call to spill *)
      z <- (W32.of_int 0);
      k <- 0;
      while ((k < 4)) {
        gk <- g;
        gk <- (gk + (W32.of_int k));
        aux <@ __adrs_set_tree_index ((SBArray128_32.get_sub64 sk_adrs
                                      (4 * k)),
        gk);
        sk_adrs <- (SBArray128_32.set_sub64 sk_adrs (4 * k) aux);
        aux <@ __adrs_set_tree_height ((SBArray128_32.get_sub64 leaf_adrs
                                       (4 * k)),
        z);
        leaf_adrs <- (SBArray128_32.set_sub64 leaf_adrs (4 * k) aux);
        aux <@ __adrs_set_tree_index ((SBArray128_32.get_sub64 leaf_adrs
                                      (4 * k)),
        gk);
        leaf_adrs <- (SBArray128_32.set_sub64 leaf_adrs (4 * k) aux);
        k <- (k + 1);
      }
      (* Erased call to unspill *)
      sk_seed <- (protect_ptr sk_seed ms);
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      (leaves, ms) <@ _thash_prf_x4 (leaves, sk_seed, ctx, sk_adrs, ms);
      (* Erased call to unspill *)
      i <- (protect_32 i ms);
      target <- (protect_32 target ms);
      (* Erased call to spill *)
      d <- target;
      d <- (d - i);
      found <- (d \ult (W32.of_int 4));
      if (found) {
        ms <- (update_msf found ms);
        src <- (zeroextu64 d);
        src <@ __offset64 (src, 16);
        lp <- leaves;
        inc <- (16 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray64.get64d lp (W64.to_uint src));
          selected <- (BArray16.set64 selected w t);
          src <- (src + (W64.of_int 8));
          w <- (w + 1);
        }
        leaves <- lp;
      } else {
        ms <- (update_msf (! found) ms);
      }
      (* Erased call to unspill *)
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      (leaves, ms) <@ _thash_f_x4 (leaves, ctx, leaf_adrs, ms);
      k <- 0;
      while ((k < 4)) {
        inc <- (16 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray64.get64 leaves (((16 %/ 8) * k) + w));
          node <- (BArray16.set64 node w t);
          w <- (w + 1);
        }
        (* Erased call to unspill *)
        i <- (protect_32 i ms);
        g <- (protect_32 g ms);
        target <- (protect_32 target ms);
        ctx <- (protect_ptr ctx ms);
        (* Erased call to spill *)
        li <- i;
        li <- (li + (W32.of_int k));
        gi <- g;
        gi <- (gi + (W32.of_int k));
        tg <- target;
        (nodes, auth, node, node_adrs, ms) <@ _treehash_fold (nodes, 
        auth, node, li, gi, tg, ctx, node_adrs, ms);
        k <- (k + 1);
      }
      (* Erased call to unspill *)
      i <- (protect_32 i ms);
      (* Erased call to spill *)
      i <- (i + (W32.of_int 4));
      more <- (i \ult (W32.of_int (1 `<<` 12)));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    root <- (protect_ptr root ms);
    root <@ __node_copy (root, (SBArray208_16.get_sub8 nodes (12 * 16)));
    aux_0 <@ __node_copy ((SBArray208_16.get_sub8 sig 0), selected);
    sig <- (SBArray208_16.set_sub8 sig 0 aux_0);
    inc <- ((12 * 16) %/ 8);
    k <- 0;
    while ((k < inc)) {
      t <- (BArray208.get64 auth k);
      sig <- (BArray208.set64 sig ((16 %/ 8) + k) t);
      k <- (k + 1);
    }
    return (sig, root, ms);
  }
  proc _fors_sign (sig:BArray7856.t, pk_fors:BArray16.t, indices:BArray56.t,
                   sk_seed:BArray16.t, ctx:BArray16.t, adrs:BArray32.t,
                   ms:W64.t) : BArray7856.t * BArray16.t * W64.t = {
    var aux:BArray16.t;
    var inc:int;
    var fill:W64.t;
    var j:int;
    var roots:BArray224.t;
    var t:W32.t;
    var more:bool;
    var ti:W64.t;
    var target:W32.t;
    var tree:W32.t;
    var tree_sig:BArray208.t;
    var root:BArray16.t;
    var off:W64.t;
    var src:BArray208.t;
    var k:W64.t;
    var copy:bool;
    var w:W64.t;
    var o:W64.t;
    var root_off:W64.t;
    var dst:BArray224.t;
    var roots_adrs:BArray32.t;
    dst <- witness;
    root <- witness;
    roots <- witness;
    roots_adrs <- witness;
    src <- witness;
    tree_sig <- witness;
    (* Erased call to spill *)
    fill <- (W64.of_int 0);
    inc <- ((14 * 16) %/ 8);
    j <- 0;
    while ((j < inc)) {
      roots <- (BArray224.set64 roots j fill);
      j <- (j + 1);
    }
    t <- (W32.of_int 0);
    more <- (t \ult (W32.of_int 14));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to unspill *)
      indices <- (protect_ptr indices ms);
      (* Erased call to spill *)
      ti <- (zeroextu64 t);
      target <- (BArray56.get32 indices (W64.to_uint ti));
      target <- (protect_32 target ms);
      tree <- t;
      (* Erased call to spill *)
      (* Erased call to unspill *)
      sk_seed <- (protect_ptr sk_seed ms);
      ctx <- (protect_ptr ctx ms);
      adrs <- (protect_ptr adrs ms);
      (* Erased call to spill *)
      (tree_sig, root, ms) <@ _fors_tree (tree_sig, root, sk_seed, ctx, 
      adrs, tree, target, ms);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      t <- (protect_32 t ms);
      off <@ __offset (t, ((12 + 1) * 16));
      off <- (off + (W64.of_int 16));
      src <- tree_sig;
      k <- (W64.of_int 0);
      copy <- (k \ult (W64.of_int ((12 + 1) * 16)));
      while (copy) {
        ms <- (update_msf copy ms);
        w <- (BArray208.get64d src (W64.to_uint k));
        o <- off;
        o <- (o + k);
        sig <- (BArray7856.set64d sig (W64.to_uint o) w);
        k <- (k + (W64.of_int 8));
        copy <- (k \ult (W64.of_int ((12 + 1) * 16)));
      }
      ms <- (update_msf (! copy) ms);
      tree_sig <- src;
      (* Erased call to spill *)
      root_off <@ __offset (t, 16);
      dst <- roots;
      aux <@ __node_copy ((SBArray224_16.get_sub8 dst (W64.to_uint root_off)),
      root);
      dst <- (SBArray224_16.set_sub8 dst (W64.to_uint root_off) aux);
      roots <- dst;
      t <- (t + (W32.of_int 1));
      more <- (t \ult (W32.of_int 14));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    adrs <- (protect_ptr adrs ms);
    ctx <- (protect_ptr ctx ms);
    pk_fors <- (protect_ptr pk_fors ms);
    roots_adrs <@ __adrs_copy (roots_adrs, adrs);
    roots_adrs <@ __adrs_set_type_and_clear (roots_adrs, 4);
    roots_adrs <@ __adrs_copy_keypair (roots_adrs, adrs);
    (pk_fors, ms) <@ _thash_t_k (pk_fors, roots, ctx, roots_adrs, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    return (sig, pk_fors, ms);
  }
  proc _fors_pk_from_sig (pk_fors:BArray16.t, sig:BArray2912.t,
                          indices:BArray56.t, ctx:BArray16.t,
                          adrs:BArray32.t, ms:W64.t) : BArray16.t * W64.t = {
    var aux:BArray16.t;
    var inc:int;
    var node_adrs:BArray32.t;
    var fill:W64.t;
    var k:int;
    var roots:BArray224.t;
    var t:W32.t;
    var more:bool;
    var ti:W64.t;
    var idx:W32.t;
    var g:W32.t;
    var sig_off:W64.t;
    var node:BArray16.t;
    var z:W32.t;
    var climb:bool;
    var auth_off:W64.t;
    var bit:W32.t;
    var odd:bool;
    var pair:BArray32.t;
    var root_off:W64.t;
    var dst:BArray224.t;
    var roots_adrs:BArray32.t;
    dst <- witness;
    node <- witness;
    node_adrs <- witness;
    pair <- witness;
    roots <- witness;
    roots_adrs <- witness;
    node_adrs <@ __adrs_copy (node_adrs, adrs);
    (* Erased call to spill *)
    fill <- (W64.of_int 0);
    inc <- ((14 * 16) %/ 8);
    k <- 0;
    while ((k < inc)) {
      roots <- (BArray224.set64 roots k fill);
      k <- (k + 1);
    }
    t <- (W32.of_int 0);
    more <- (t \ult (W32.of_int 14));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to unspill *)
      indices <- (protect_ptr indices ms);
      (* Erased call to spill *)
      ti <- (zeroextu64 t);
      idx <- (BArray56.get32 indices (W64.to_uint ti));
      idx <- (protect_32 idx ms);
      g <- t;
      g <- (g `<<` (W8.of_int 12));
      g <- (g + idx);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      sig_off <@ __offset (t, ((12 + 1) * 16));
      node <@ __node_copy (node,
      (SBArray2912_16.get_sub8 sig (W64.to_uint sig_off)));
      z <- (W32.of_int 0);
      node_adrs <@ __adrs_set_tree_height (node_adrs, z);
      node_adrs <@ __adrs_set_tree_index (node_adrs, g);
      (* Erased call to spill *)
      (node, ms) <@ _thash_f (node, ctx, node_adrs, ms);
      (* Erased call to unspill *)
      t <- (protect_32 t ms);
      idx <- (protect_32 idx ms);
      g <- (protect_32 g ms);
      sig_off <- (protect_64 sig_off ms);
      (* Erased call to spill *)
      z <- (W32.of_int 0);
      climb <- (z \ult (W32.of_int 12));
      while (climb) {
        ms <- (update_msf climb ms);
        (* Erased call to unspill *)
        sig <- (protect_ptr sig ms);
        (* Erased call to spill *)
        auth_off <@ __offset (z, 16);
        auth_off <- (auth_off + sig_off);
        auth_off <- (auth_off + (W64.of_int 16));
        bit <- idx;
        bit <- (bit `&` (W32.of_int 1));
        odd <- (bit = (W32.of_int 1));
        if (odd) {
          ms <- (update_msf odd ms);
          aux <@ __node_copy ((SBArray32_16.get_sub8 pair 0),
          (SBArray2912_16.get_sub8 sig (W64.to_uint auth_off)));
          pair <- (SBArray32_16.set_sub8 pair 0 aux);
          aux <@ __node_copy ((SBArray32_16.get_sub8 pair 16), node);
          pair <- (SBArray32_16.set_sub8 pair 16 aux);
        } else {
          ms <- (update_msf (! odd) ms);
          aux <@ __node_copy ((SBArray32_16.get_sub8 pair 0), node);
          pair <- (SBArray32_16.set_sub8 pair 0 aux);
          aux <@ __node_copy ((SBArray32_16.get_sub8 pair 16),
          (SBArray2912_16.get_sub8 sig (W64.to_uint auth_off)));
          pair <- (SBArray32_16.set_sub8 pair 16 aux);
        }
        z <- (z + (W32.of_int 1));
        idx <- (idx `>>` (W8.of_int 1));
        g <- (g `>>` (W8.of_int 1));
        node_adrs <@ __adrs_set_tree_height (node_adrs, z);
        node_adrs <@ __adrs_set_tree_index (node_adrs, g);
        (* Erased call to spill *)
        (* Erased call to unspill *)
        ctx <- (protect_ptr ctx ms);
        (* Erased call to spill *)
        (node, ms) <@ _thash_h (node, pair, ctx, node_adrs, ms);
        (* Erased call to unspill *)
        t <- (protect_32 t ms);
        idx <- (protect_32 idx ms);
        g <- (protect_32 g ms);
        z <- (protect_32 z ms);
        sig_off <- (protect_64 sig_off ms);
        (* Erased call to spill *)
        climb <- (z \ult (W32.of_int 12));
      }
      ms <- (update_msf (! climb) ms);
      root_off <@ __offset (t, 16);
      dst <- roots;
      aux <@ __node_copy ((SBArray224_16.get_sub8 dst (W64.to_uint root_off)),
      node);
      dst <- (SBArray224_16.set_sub8 dst (W64.to_uint root_off) aux);
      roots <- dst;
      t <- (t + (W32.of_int 1));
      more <- (t \ult (W32.of_int 14));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    pk_fors <- (protect_ptr pk_fors ms);
    ctx <- (protect_ptr ctx ms);
    adrs <- (protect_ptr adrs ms);
    roots_adrs <@ __adrs_copy (roots_adrs, adrs);
    roots_adrs <@ __adrs_set_type_and_clear (roots_adrs, 4);
    roots_adrs <@ __adrs_copy_keypair (roots_adrs, adrs);
    (pk_fors, ms) <@ _thash_t_k (pk_fors, roots, ctx, roots_adrs, ms);
    return (pk_fors, ms);
  }
  proc _slh_keygen (pk:BArray32.t, sk:BArray64.t, seeds:BArray48.t, ms:W64.t) : 
  BArray32.t * BArray64.t * W64.t = {
    var aux:BArray16.t;
    var inc:int;
    var i:int;
    var t:W64.t;
    var no_steps:BArray35.t;
    var ctx:BArray16.t;
    var adrs:BArray32.t;
    var layer:W32.t;
    var target:W32.t;
    var root:BArray16.t;
    var no_sig:BArray704.t;
    adrs <- witness;
    ctx <- witness;
    no_sig <- witness;
    no_steps <- witness;
    root <- witness;
    inc <- ((3 * 16) %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray48.get64 seeds i);
      sk <- (BArray64.set64 sk i t);
      i <- (i + 1);
    }
    t <- (W64.of_int 0);
    inc <- ((2 * 16) + 3);
    i <- 0;
    while ((i < inc)) {
      no_steps <- (BArray35.set8 no_steps i (truncateu8 t));
      i <- (i + 1);
    }
    (* Erased call to declassify *)
    (* Erased call to spill *)
    (ctx, ms) <@ _thash_ctx_init (ctx, (SBArray64_16.get_sub8 sk (2 * 16)),
    ms);
    (* Erased call to unspill *)
    sk <- (protect_ptr sk ms);
    adrs <@ __adrs_zero (adrs);
    layer <- (W32.of_int (7 - 1));
    adrs <@ __adrs_set_layer (adrs, layer);
    target <- (W32.of_int (- 1));
    (* Erased call to spill *)
    (root, no_sig, ms) <@ _xmss_treehash (root, no_sig,
    (SBArray64_16.get_sub8 sk 0), ctx, adrs, target, no_steps, ms);
    (* Erased call to unspill *)
    pk <- (protect_ptr pk ms);
    sk <- (protect_ptr sk ms);
    aux <@ __node_copy ((SBArray64_16.get_sub8 sk (3 * 16)), root);
    sk <- (SBArray64_16.set_sub8 sk (3 * 16) aux);
    aux <@ __node_copy ((SBArray32_16.get_sub8 pk 0),
    (SBArray64_16.get_sub8 sk (2 * 16)));
    pk <- (SBArray32_16.set_sub8 pk 0 aux);
    aux <@ __node_copy ((SBArray32_16.get_sub8 pk 16), root);
    pk <- (SBArray32_16.set_sub8 pk 16 aux);
    return (pk, sk, ms);
  }
  proc _slh_sign (sig:BArray7856.t, prefix:BArray332.t, prefix_len:W64.t,
                  msg:W64.t, msg_len:W64.t, sk:BArray64.t,
                  opt_rand:BArray16.t, ms:W64.t) : BArray7856.t * W64.t = {
    var inc:int;
    var ctx:BArray16.t;
    var r:BArray16.t;
    var i:int;
    var t:W64.t;
    var digest:BArray30.t;
    var indices:BArray56.t;
    var idx_tree:W64.t;
    var idx_leaf:W32.t;
    var adrs:BArray32.t;
    var pk_fors:BArray16.t;
    adrs <- witness;
    ctx <- witness;
    digest <- witness;
    indices <- witness;
    pk_fors <- witness;
    r <- witness;
    (* Erased call to spill *)
    (ctx, ms) <@ _thash_ctx_init (ctx, (SBArray64_16.get_sub8 sk (2 * 16)),
    ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    prefix <- (protect_ptr prefix ms);
    sk <- (protect_ptr sk ms);
    opt_rand <- (protect_ptr opt_rand ms);
    (* Erased call to spill *)
    (r, ms) <@ _prf_msg (r, (SBArray64_16.get_sub8 sk 16), opt_rand, 
    prefix, prefix_len, msg, msg_len, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    prefix <- (protect_ptr prefix ms);
    sk <- (protect_ptr sk ms);
    inc <- (16 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray16.get64 r i);
      sig <- (BArray7856.set64 sig i t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    (digest, ms) <@ _h_msg (digest, r, (SBArray64_32.get_sub8 sk (2 * 16)),
    prefix, prefix_len, msg, msg_len, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    sk <- (protect_ptr sk ms);
    indices <@ __fors_indices (indices, digest);
    (idx_tree, idx_leaf) <@ __digest_tree_leaf (digest);
    (* Erased call to declassify *)
    (* Erased call to declassify *)
    (* Erased call to declassify *)
    idx_tree <- (protect_64 idx_tree ms);
    idx_leaf <- (protect_32 idx_leaf ms);
    adrs <@ __adrs_zero (adrs);
    adrs <@ __adrs_set_tree (adrs, idx_tree);
    adrs <@ __adrs_set_type_and_clear (adrs, 3);
    adrs <@ __adrs_set_keypair (adrs, idx_leaf);
    (* Erased call to spill *)
    (sig, pk_fors, ms) <@ _fors_sign (sig, pk_fors, indices,
    (SBArray64_16.get_sub8 sk 0), ctx, adrs, ms);
    pk_fors <@ __hook_fors_pk (pk_fors);
    (* Erased call to unspill *)
    sk <- (protect_ptr sk ms);
    idx_tree <- (protect_64 idx_tree ms);
    idx_leaf <- (protect_32 idx_leaf ms);
    (sig, pk_fors, ms) <@ _ht_sign (sig, pk_fors,
    (SBArray64_16.get_sub8 sk 0), ctx, idx_tree, idx_leaf, ms);
    return (sig, ms);
  }
  proc _slh_verify (sig:BArray7856.t, prefix:BArray332.t, prefix_len:W64.t,
                    msg:W64.t, msg_len:W64.t, pk:BArray32.t, ms:W64.t) : 
  W64.t * W64.t = {
    var result:W64.t;
    var ctx:BArray16.t;
    var digest:BArray30.t;
    var indices:BArray56.t;
    var idx_tree:W64.t;
    var idx_leaf:W32.t;
    var adrs:BArray32.t;
    var pk_fors:BArray16.t;
    adrs <- witness;
    ctx <- witness;
    digest <- witness;
    indices <- witness;
    pk_fors <- witness;
    (* Erased call to spill *)
    (ctx, ms) <@ _thash_ctx_init (ctx, (SBArray32_16.get_sub8 pk 0), ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    prefix <- (protect_ptr prefix ms);
    pk <- (protect_ptr pk ms);
    (* Erased call to spill *)
    (digest, ms) <@ _h_msg (digest, (SBArray7856_16.get_sub8 sig 0), 
    pk, prefix, prefix_len, msg, msg_len, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    pk <- (protect_ptr pk ms);
    (* Erased call to spill *)
    indices <@ __fors_indices (indices, digest);
    (idx_tree, idx_leaf) <@ __digest_tree_leaf (digest);
    (* Erased call to declassify *)
    (* Erased call to declassify *)
    (* Erased call to declassify *)
    idx_tree <- (protect_64 idx_tree ms);
    idx_leaf <- (protect_32 idx_leaf ms);
    adrs <@ __adrs_zero (adrs);
    adrs <@ __adrs_set_tree (adrs, idx_tree);
    adrs <@ __adrs_set_type_and_clear (adrs, 3);
    adrs <@ __adrs_set_keypair (adrs, idx_leaf);
    (* Erased call to spill *)
    (pk_fors, ms) <@ _fors_pk_from_sig (pk_fors,
    (SBArray7856_2912.get_sub8 sig 16), indices, ctx, adrs, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    pk <- (protect_ptr pk ms);
    idx_tree <- (protect_64 idx_tree ms);
    idx_leaf <- (protect_32 idx_leaf ms);
    (result, ms) <@ _ht_verify ((SBArray7856_4928.get_sub8 sig
                                (16 + ((14 * (12 + 1)) * 16))),
    pk_fors, (SBArray32_16.get_sub8 pk 16), ctx, idx_tree, idx_leaf, 
    ms);
    return (result, ms);
  }
  proc __bswap32 (x:W32.t) : W32.t = {
    
    x <- (BSWAP_32 x);
    return x;
  }
  proc __bswap64 (x:W64.t) : W64.t = {
    
    x <- (BSWAP_64 x);
    return x;
  }
  proc __Sigma0_256 (x:W32.t) : W32.t = {
    var r:W32.t;
    var t:W32.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 2));
    t <- x;
    t <- (t `|>>|` (W8.of_int 13));
    r <- (r `^` t);
    t <- x;
    t <- (t `|>>|` (W8.of_int 22));
    r <- (r `^` t);
    return r;
  }
  proc __Sigma1_256 (x:W32.t) : W32.t = {
    var r:W32.t;
    var t:W32.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 6));
    t <- x;
    t <- (t `|>>|` (W8.of_int 11));
    r <- (r `^` t);
    t <- x;
    t <- (t `|>>|` (W8.of_int 25));
    r <- (r `^` t);
    return r;
  }
  proc __sigma0_256 (x:W32.t) : W32.t = {
    var r:W32.t;
    var t:W32.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 7));
    t <- x;
    t <- (t `|>>|` (W8.of_int 18));
    r <- (r `^` t);
    t <- x;
    t <- (t `>>` (W8.of_int 3));
    r <- (r `^` t);
    return r;
  }
  proc __sigma1_256 (x:W32.t) : W32.t = {
    var r:W32.t;
    var t:W32.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 17));
    t <- x;
    t <- (t `|>>|` (W8.of_int 19));
    r <- (r `^` t);
    t <- x;
    t <- (t `>>` (W8.of_int 10));
    r <- (r `^` t);
    return r;
  }
  proc __sha256_rounds (h:BArray32.t, w:BArray64.t) : BArray32.t = {
    var i:int;
    var v:BArray32.t;
    var t:int;
    var t1:W32.t;
    var x:W32.t;
    var k:BArray256.t;
    var y:W32.t;
    k <- witness;
    v <- witness;
    i <- 0;
    while ((i < 8)) {
      v <- (BArray32.set32 v i (BArray32.get32 h i));
      i <- (i + 1);
    }
    t <- 0;
    while ((t < 64)) {
      if ((16 <= t)) {
        x <- (BArray64.get32 w ((t - 2) %% 16));
        t1 <@ __sigma1_256 (x);
        x <- (BArray64.get32 w ((t - 15) %% 16));
        x <@ __sigma0_256 (x);
        t1 <- (t1 + x);
        x <- (BArray64.get32 w ((t - 7) %% 16));
        t1 <- (t1 + x);
        x <- (BArray64.get32 w (t %% 16));
        t1 <- (t1 + x);
        w <- (BArray64.set32 w (t %% 16) t1);
      } else {
        t1 <- (BArray64.get32 w t);
      }
      t1 <- (t1 + (BArray32.get32 v (((7 + 64) - t) %% 8)));
      x <@ __Sigma1_256 ((BArray32.get32 v (((4 + 64) - t) %% 8)));
      t1 <- (t1 + x);
      x <- (BArray32.get32 v (((5 + 64) - t) %% 8));
      x <- (x `^` (BArray32.get32 v (((6 + 64) - t) %% 8)));
      x <- (x `&` (BArray32.get32 v (((4 + 64) - t) %% 8)));
      x <- (x `^` (BArray32.get32 v (((6 + 64) - t) %% 8)));
      t1 <- (t1 + x);
      k <- sHA256_K;
      x <- (BArray256.get32 k t);
      t1 <- (t1 + x);
      v <-
      (BArray32.set32 v (((3 + 64) - t) %% 8)
      ((BArray32.get32 v (((3 + 64) - t) %% 8)) + t1));
      x <@ __Sigma0_256 ((BArray32.get32 v (((0 + 64) - t) %% 8)));
      t1 <- (t1 + x);
      x <- (BArray32.get32 v (((0 + 64) - t) %% 8));
      x <- (x `^` (BArray32.get32 v (((1 + 64) - t) %% 8)));
      x <- (x `&` (BArray32.get32 v (((2 + 64) - t) %% 8)));
      y <- (BArray32.get32 v (((0 + 64) - t) %% 8));
      y <- (y `&` (BArray32.get32 v (((1 + 64) - t) %% 8)));
      x <- (x `^` y);
      t1 <- (t1 + x);
      v <- (BArray32.set32 v (((7 + 64) - t) %% 8) t1);
      t <- (t + 1);
    }
    i <- 0;
    while ((i < 8)) {
      x <- (BArray32.get32 h i);
      x <- (x + (BArray32.get32 v i));
      h <- (BArray32.set32 h i x);
      i <- (i + 1);
    }
    return h;
  }
  proc _sha256_compress (h:BArray32.t, block:BArray64.t, ms:W64.t) : 
  BArray32.t * W64.t = {
    var i:int;
    var x:W32.t;
    var w:BArray64.t;
    w <- witness;
    i <- 0;
    while ((i < 16)) {
      x <- (BArray64.get32 block i);
      x <@ __bswap32 (x);
      w <- (BArray64.set32 w i x);
      i <- (i + 1);
    }
    h <@ __sha256_rounds (h, w);
    return (h, ms);
  }
  proc _sha256_compress_one (h:BArray32.t, p:W64.t, ms:W64.t) : BArray32.t *
                                                                W64.t = {
    var i:int;
    var x:W32.t;
    var w:BArray64.t;
    w <- witness;
    i <- 0;
    while ((i < 16)) {
      x <- (loadW32 Glob.mem (W64.to_uint (p + (W64.of_int (4 * i)))));
      x <@ __bswap32 (x);
      w <- (BArray64.set32 w i x);
      i <- (i + 1);
    }
    h <@ __sha256_rounds (h, w);
    return (h, ms);
  }
  proc _sha256_compress_blocks (h:BArray32.t, p:W64.t, n:W64.t, ms:W64.t) : 
  BArray32.t * W64.t = {
    var more:bool;
    more <- (n <> (W64.of_int 0));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha256_compress_one (h, p, ms);
      (* Erased call to unspill *)
      p <- (protect_64 p ms);
      n <- (protect_64 n ms);
      p <- (p + (W64.of_int 64));
      n <- (n - (W64.of_int 1));
      more <- (n <> (W64.of_int 0));
    }
    ms <- (update_msf (! more) ms);
    return (h, ms);
  }
  proc __sha256_init (h:BArray32.t) : BArray32.t = {
    var iv:BArray32.t;
    var i:int;
    var t:W32.t;
    iv <- witness;
    iv <- sHA256_IV;
    i <- 0;
    while ((i < 8)) {
      t <- (BArray32.get32 iv i);
      h <- (BArray32.set32 h i t);
      i <- (i + 1);
    }
    return h;
  }
  proc __sha224_init (h:BArray32.t) : BArray32.t = {
    var iv:BArray32.t;
    var i:int;
    var t:W32.t;
    iv <- witness;
    iv <- sHA224_IV;
    i <- 0;
    while ((i < 8)) {
      t <- (BArray32.get32 iv i);
      h <- (BArray32.set32 h i t);
      i <- (i + 1);
    }
    return h;
  }
  proc _sha256_absorb_mem (h:BArray32.t, buf:BArray64.t, total:W64.t,
                           in_0:W64.t, inlen:W64.t, ms:W64.t) : BArray32.t *
                                                                BArray64.t *
                                                                W64.t * W64.t = {
    var fill:W64.t;
    var n:W64.t;
    var end_0:W64.t;
    var more:bool;
    var t:W64.t;
    var full:bool;
    var off:W64.t;
    fill <- total;
    fill <- (fill `&` (W64.of_int 63));
    total <- (total + inlen);
    n <- (W64.of_int 64);
    n <- (n - fill);
    n <- ((inlen \ult n) ? inlen : n);
    n <- ((fill = (W64.of_int 0)) ? fill : n);
    inlen <- (inlen - n);
    end_0 <- fill;
    end_0 <- (end_0 + n);
    more <- (fill \ult end_0);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint in_0)));
      buf <- (BArray64.set8 buf (W64.to_uint fill) (truncateu8 t));
      fill <- (fill + (W64.of_int 1));
      in_0 <- (in_0 + (W64.of_int 1));
      more <- (fill \ult end_0);
    }
    ms <- (update_msf (! more) ms);
    full <- (fill = (W64.of_int 64));
    if (full) {
      ms <- (update_msf full ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha256_compress (h, buf, ms);
      (* Erased call to unspill *)
      total <- (protect_64 total ms);
      in_0 <- (protect_64 in_0 ms);
      inlen <- (protect_64 inlen ms);
      buf <- (protect_ptr buf ms);
    } else {
      ms <- (update_msf (! full) ms);
    }
    off <- (W64.of_int 0);
    n <- inlen;
    n <- (n `>>` (W8.of_int 6));
    more <- (n <> (W64.of_int 0));
    if (more) {
      ms <- (update_msf more ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha256_compress_blocks (h, in_0, n, ms);
      (* Erased call to unspill *)
      total <- (protect_64 total ms);
      in_0 <- (protect_64 in_0 ms);
      inlen <- (protect_64 inlen ms);
      buf <- (protect_ptr buf ms);
      off <- inlen;
      off <- (off `>>` (W8.of_int 6));
      off <- (off `<<` (W8.of_int 6));
      inlen <- (inlen `&` (W64.of_int 63));
    } else {
      ms <- (update_msf (! more) ms);
    }
    fill <- (W64.of_int 0);
    more <- (fill \ult inlen);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint (in_0 + off))));
      buf <- (BArray64.set8 buf (W64.to_uint fill) (truncateu8 t));
      fill <- (fill + (W64.of_int 1));
      off <- (off + (W64.of_int 1));
      more <- (fill \ult inlen);
    }
    ms <- (update_msf (! more) ms);
    return (h, buf, total, ms);
  }
  proc _sha256_finalize (out:BArray32.t, h:BArray32.t, buf:BArray64.t,
                         total:W64.t, ms:W64.t) : BArray32.t * BArray32.t *
                                                  BArray64.t * W64.t = {
    var fill:W64.t;
    var z:W64.t;
    var t:W64.t;
    var two_blocks:bool;
    var more:bool;
    var i:int;
    var x:W32.t;
    fill <- total;
    fill <- (fill `&` (W64.of_int 63));
    z <- (W64.of_int 0);
    t <- (W64.of_int 128);
    buf <- (BArray64.set8 buf (W64.to_uint fill) (truncateu8 t));
    fill <- (fill + (W64.of_int 1));
    two_blocks <- ((W64.of_int 56) \ult fill);
    if (two_blocks) {
      ms <- (update_msf two_blocks ms);
      more <- (fill \ult (W64.of_int 64));
      while (more) {
        ms <- (update_msf more ms);
        buf <- (BArray64.set8 buf (W64.to_uint fill) (truncateu8 z));
        fill <- (fill + (W64.of_int 1));
        more <- (fill \ult (W64.of_int 64));
      }
      ms <- (update_msf (! more) ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha256_compress (h, buf, ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      buf <- (protect_ptr buf ms);
      total <- (protect_64 total ms);
      fill <- (W64.of_int 0);
      z <- (W64.of_int 0);
    } else {
      ms <- (update_msf (! two_blocks) ms);
    }
    more <- (fill \ult (W64.of_int 56));
    while (more) {
      ms <- (update_msf more ms);
      buf <- (BArray64.set8 buf (W64.to_uint fill) (truncateu8 z));
      fill <- (fill + (W64.of_int 1));
      more <- (fill \ult (W64.of_int 56));
    }
    ms <- (update_msf (! more) ms);
    t <- total;
    t <- (t `<<` (W8.of_int 3));
    t <@ __bswap64 (t);
    buf <- (BArray64.set64d buf 56 t);
    (* Erased call to spill *)
    (h, ms) <@ _sha256_compress (h, buf, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    buf <- (protect_ptr buf ms);
    i <- 0;
    while ((i < 8)) {
      x <- (BArray32.get32 h i);
      x <@ __bswap32 (x);
      out <- (BArray32.set32 out i x);
      i <- (i + 1);
    }
    return (out, h, buf, ms);
  }
  proc __sha256_mem_from (out:BArray32.t, h:BArray32.t, in_0:W64.t,
                          inlen:W64.t, ms:W64.t) : BArray32.t * W64.t = {
    var i:int;
    var buf_s:BArray64.t;
    var buf:BArray64.t;
    var total:W64.t;
    buf <- witness;
    buf_s <- witness;
    i <- 0;
    while ((i < 8)) {
      buf_s <- (BArray64.set64 buf_s i (W64.of_int 0));
      i <- (i + 1);
    }
    buf <- buf_s;
    total <- (W64.of_int 0);
    (* Erased call to spill *)
    (h, buf, total, ms) <@ _sha256_absorb_mem (h, buf, total, in_0, inlen,
    ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    (out, h, buf, ms) <@ _sha256_finalize (out, h, buf, total, ms);
    return (out, ms);
  }
  proc _sha256_mem (out:BArray32.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray32.t * W64.t = {
    var h:BArray32.t;
    h <- witness;
    h <@ __sha256_init (h);
    (out, ms) <@ __sha256_mem_from (out, h, in_0, inlen, ms);
    return (out, ms);
  }
  proc _sha224_mem (out:BArray32.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray32.t * W64.t = {
    var h:BArray32.t;
    h <- witness;
    h <@ __sha224_init (h);
    (out, ms) <@ __sha256_mem_from (out, h, in_0, inlen, ms);
    return (out, ms);
  }
  proc __Sigma0_512 (x:W64.t) : W64.t = {
    var r:W64.t;
    var t:W64.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 28));
    t <- x;
    t <- (t `|>>|` (W8.of_int 34));
    r <- (r `^` t);
    t <- x;
    t <- (t `|>>|` (W8.of_int 39));
    r <- (r `^` t);
    return r;
  }
  proc __Sigma1_512 (x:W64.t) : W64.t = {
    var r:W64.t;
    var t:W64.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 14));
    t <- x;
    t <- (t `|>>|` (W8.of_int 18));
    r <- (r `^` t);
    t <- x;
    t <- (t `|>>|` (W8.of_int 41));
    r <- (r `^` t);
    return r;
  }
  proc __sigma0_512 (x:W64.t) : W64.t = {
    var r:W64.t;
    var t:W64.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 1));
    t <- x;
    t <- (t `|>>|` (W8.of_int 8));
    r <- (r `^` t);
    t <- x;
    t <- (t `>>` (W8.of_int 7));
    r <- (r `^` t);
    return r;
  }
  proc __sigma1_512 (x:W64.t) : W64.t = {
    var r:W64.t;
    var t:W64.t;
    r <- x;
    r <- (r `|>>|` (W8.of_int 19));
    t <- x;
    t <- (t `|>>|` (W8.of_int 61));
    r <- (r `^` t);
    t <- x;
    t <- (t `>>` (W8.of_int 6));
    r <- (r `^` t);
    return r;
  }
  proc __sha512_rounds (h:BArray64.t, w:BArray128.t) : BArray64.t = {
    var i:int;
    var v:BArray64.t;
    var t:int;
    var t1:W64.t;
    var x:W64.t;
    var k:BArray640.t;
    var y:W64.t;
    k <- witness;
    v <- witness;
    i <- 0;
    while ((i < 8)) {
      v <- (BArray64.set64 v i (BArray64.get64 h i));
      i <- (i + 1);
    }
    t <- 0;
    while ((t < 80)) {
      if ((16 <= t)) {
        x <- (BArray128.get64 w ((t - 2) %% 16));
        t1 <@ __sigma1_512 (x);
        x <- (BArray128.get64 w ((t - 15) %% 16));
        x <@ __sigma0_512 (x);
        t1 <- (t1 + x);
        x <- (BArray128.get64 w ((t - 7) %% 16));
        t1 <- (t1 + x);
        x <- (BArray128.get64 w (t %% 16));
        t1 <- (t1 + x);
        w <- (BArray128.set64 w (t %% 16) t1);
      } else {
        t1 <- (BArray128.get64 w t);
      }
      t1 <- (t1 + (BArray64.get64 v (((7 + 80) - t) %% 8)));
      x <@ __Sigma1_512 ((BArray64.get64 v (((4 + 80) - t) %% 8)));
      t1 <- (t1 + x);
      x <- (BArray64.get64 v (((5 + 80) - t) %% 8));
      x <- (x `^` (BArray64.get64 v (((6 + 80) - t) %% 8)));
      x <- (x `&` (BArray64.get64 v (((4 + 80) - t) %% 8)));
      x <- (x `^` (BArray64.get64 v (((6 + 80) - t) %% 8)));
      t1 <- (t1 + x);
      k <- sHA512_K;
      x <- (BArray640.get64 k t);
      t1 <- (t1 + x);
      v <-
      (BArray64.set64 v (((3 + 80) - t) %% 8)
      ((BArray64.get64 v (((3 + 80) - t) %% 8)) + t1));
      x <@ __Sigma0_512 ((BArray64.get64 v (((0 + 80) - t) %% 8)));
      t1 <- (t1 + x);
      x <- (BArray64.get64 v (((0 + 80) - t) %% 8));
      x <- (x `^` (BArray64.get64 v (((1 + 80) - t) %% 8)));
      x <- (x `&` (BArray64.get64 v (((2 + 80) - t) %% 8)));
      y <- (BArray64.get64 v (((0 + 80) - t) %% 8));
      y <- (y `&` (BArray64.get64 v (((1 + 80) - t) %% 8)));
      x <- (x `^` y);
      t1 <- (t1 + x);
      v <- (BArray64.set64 v (((7 + 80) - t) %% 8) t1);
      t <- (t + 1);
    }
    i <- 0;
    while ((i < 8)) {
      x <- (BArray64.get64 h i);
      x <- (x + (BArray64.get64 v i));
      h <- (BArray64.set64 h i x);
      i <- (i + 1);
    }
    return h;
  }
  proc _sha512_compress (h:BArray64.t, block:BArray128.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var i:int;
    var x:W64.t;
    var w:BArray128.t;
    w <- witness;
    i <- 0;
    while ((i < 16)) {
      x <- (BArray128.get64 block i);
      x <@ __bswap64 (x);
      w <- (BArray128.set64 w i x);
      i <- (i + 1);
    }
    h <@ __sha512_rounds (h, w);
    return (h, ms);
  }
  proc _sha512_compress_one (h:BArray64.t, p:W64.t, ms:W64.t) : BArray64.t *
                                                                W64.t = {
    var i:int;
    var x:W64.t;
    var w:BArray128.t;
    w <- witness;
    i <- 0;
    while ((i < 16)) {
      x <- (loadW64 Glob.mem (W64.to_uint (p + (W64.of_int (8 * i)))));
      x <@ __bswap64 (x);
      w <- (BArray128.set64 w i x);
      i <- (i + 1);
    }
    h <@ __sha512_rounds (h, w);
    return (h, ms);
  }
  proc _sha512_compress_blocks (h:BArray64.t, p:W64.t, n:W64.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var more:bool;
    more <- (n <> (W64.of_int 0));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha512_compress_one (h, p, ms);
      (* Erased call to unspill *)
      p <- (protect_64 p ms);
      n <- (protect_64 n ms);
      p <- (p + (W64.of_int 128));
      n <- (n - (W64.of_int 1));
      more <- (n <> (W64.of_int 0));
    }
    ms <- (update_msf (! more) ms);
    return (h, ms);
  }
  proc __sha512_load_iv (h:BArray64.t, iv:BArray64.t) : BArray64.t = {
    var i:int;
    var t:W64.t;
    i <- 0;
    while ((i < 8)) {
      t <- (BArray64.get64 iv i);
      h <- (BArray64.set64 h i t);
      i <- (i + 1);
    }
    return h;
  }
  proc __sha512_init (h:BArray64.t) : BArray64.t = {
    
    h <@ __sha512_load_iv (h, sHA512_IV);
    return h;
  }
  proc __sha384_init (h:BArray64.t) : BArray64.t = {
    
    h <@ __sha512_load_iv (h, sHA384_IV);
    return h;
  }
  proc __sha512_224_init (h:BArray64.t) : BArray64.t = {
    
    h <@ __sha512_load_iv (h, sHA512_224_IV);
    return h;
  }
  proc __sha512_256_init (h:BArray64.t) : BArray64.t = {
    
    h <@ __sha512_load_iv (h, sHA512_256_IV);
    return h;
  }
  proc _sha512_absorb_mem (h:BArray64.t, buf:BArray128.t, total:W64.t,
                           in_0:W64.t, inlen:W64.t, ms:W64.t) : BArray64.t *
                                                                BArray128.t *
                                                                W64.t * W64.t = {
    var fill:W64.t;
    var n:W64.t;
    var end_0:W64.t;
    var more:bool;
    var t:W64.t;
    var full:bool;
    var off:W64.t;
    fill <- total;
    fill <- (fill `&` (W64.of_int 127));
    total <- (total + inlen);
    n <- (W64.of_int 128);
    n <- (n - fill);
    n <- ((inlen \ult n) ? inlen : n);
    n <- ((fill = (W64.of_int 0)) ? fill : n);
    inlen <- (inlen - n);
    end_0 <- fill;
    end_0 <- (end_0 + n);
    more <- (fill \ult end_0);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint in_0)));
      buf <- (BArray128.set8 buf (W64.to_uint fill) (truncateu8 t));
      fill <- (fill + (W64.of_int 1));
      in_0 <- (in_0 + (W64.of_int 1));
      more <- (fill \ult end_0);
    }
    ms <- (update_msf (! more) ms);
    full <- (fill = (W64.of_int 128));
    if (full) {
      ms <- (update_msf full ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha512_compress (h, buf, ms);
      (* Erased call to unspill *)
      total <- (protect_64 total ms);
      in_0 <- (protect_64 in_0 ms);
      inlen <- (protect_64 inlen ms);
      buf <- (protect_ptr buf ms);
    } else {
      ms <- (update_msf (! full) ms);
    }
    off <- (W64.of_int 0);
    n <- inlen;
    n <- (n `>>` (W8.of_int 7));
    more <- (n <> (W64.of_int 0));
    if (more) {
      ms <- (update_msf more ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha512_compress_blocks (h, in_0, n, ms);
      (* Erased call to unspill *)
      total <- (protect_64 total ms);
      in_0 <- (protect_64 in_0 ms);
      inlen <- (protect_64 inlen ms);
      buf <- (protect_ptr buf ms);
      off <- inlen;
      off <- (off `>>` (W8.of_int 7));
      off <- (off `<<` (W8.of_int 7));
      inlen <- (inlen `&` (W64.of_int 127));
    } else {
      ms <- (update_msf (! more) ms);
    }
    fill <- (W64.of_int 0);
    more <- (fill \ult inlen);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint (in_0 + off))));
      buf <- (BArray128.set8 buf (W64.to_uint fill) (truncateu8 t));
      fill <- (fill + (W64.of_int 1));
      off <- (off + (W64.of_int 1));
      more <- (fill \ult inlen);
    }
    ms <- (update_msf (! more) ms);
    return (h, buf, total, ms);
  }
  proc _sha512_finalize (out:BArray64.t, h:BArray64.t, buf:BArray128.t,
                         total:W64.t, ms:W64.t) : BArray64.t * BArray64.t *
                                                  BArray128.t * W64.t = {
    var fill:W64.t;
    var z:W64.t;
    var t:W64.t;
    var two_blocks:bool;
    var more:bool;
    var i:int;
    var x:W64.t;
    fill <- total;
    fill <- (fill `&` (W64.of_int 127));
    z <- (W64.of_int 0);
    t <- (W64.of_int 128);
    buf <- (BArray128.set8 buf (W64.to_uint fill) (truncateu8 t));
    fill <- (fill + (W64.of_int 1));
    two_blocks <- ((W64.of_int 112) \ult fill);
    if (two_blocks) {
      ms <- (update_msf two_blocks ms);
      more <- (fill \ult (W64.of_int 128));
      while (more) {
        ms <- (update_msf more ms);
        buf <- (BArray128.set8 buf (W64.to_uint fill) (truncateu8 z));
        fill <- (fill + (W64.of_int 1));
        more <- (fill \ult (W64.of_int 128));
      }
      ms <- (update_msf (! more) ms);
      (* Erased call to spill *)
      (h, ms) <@ _sha512_compress (h, buf, ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      buf <- (protect_ptr buf ms);
      total <- (protect_64 total ms);
      fill <- (W64.of_int 0);
      z <- (W64.of_int 0);
    } else {
      ms <- (update_msf (! two_blocks) ms);
    }
    more <- (fill \ult (W64.of_int 112));
    while (more) {
      ms <- (update_msf more ms);
      buf <- (BArray128.set8 buf (W64.to_uint fill) (truncateu8 z));
      fill <- (fill + (W64.of_int 1));
      more <- (fill \ult (W64.of_int 112));
    }
    ms <- (update_msf (! more) ms);
    t <- total;
    t <- (t `>>` (W8.of_int 61));
    t <@ __bswap64 (t);
    buf <- (BArray128.set64d buf 112 t);
    t <- total;
    t <- (t `<<` (W8.of_int 3));
    t <@ __bswap64 (t);
    buf <- (BArray128.set64d buf 120 t);
    (* Erased call to spill *)
    (h, ms) <@ _sha512_compress (h, buf, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    buf <- (protect_ptr buf ms);
    i <- 0;
    while ((i < 8)) {
      x <- (BArray64.get64 h i);
      x <@ __bswap64 (x);
      out <- (BArray64.set64 out i x);
      i <- (i + 1);
    }
    return (out, h, buf, ms);
  }
  proc __sha512_mem_from (out:BArray64.t, h:BArray64.t, in_0:W64.t,
                          inlen:W64.t, ms:W64.t) : BArray64.t * W64.t = {
    var i:int;
    var buf_s:BArray128.t;
    var buf:BArray128.t;
    var total:W64.t;
    buf <- witness;
    buf_s <- witness;
    i <- 0;
    while ((i < 16)) {
      buf_s <- (BArray128.set64 buf_s i (W64.of_int 0));
      i <- (i + 1);
    }
    buf <- buf_s;
    total <- (W64.of_int 0);
    (* Erased call to spill *)
    (h, buf, total, ms) <@ _sha512_absorb_mem (h, buf, total, in_0, inlen,
    ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    (out, h, buf, ms) <@ _sha512_finalize (out, h, buf, total, ms);
    return (out, ms);
  }
  proc _sha512_mem (out:BArray64.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var h:BArray64.t;
    h <- witness;
    h <@ __sha512_init (h);
    (out, ms) <@ __sha512_mem_from (out, h, in_0, inlen, ms);
    return (out, ms);
  }
  proc _sha384_mem (out:BArray64.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var h:BArray64.t;
    h <- witness;
    h <@ __sha384_init (h);
    (out, ms) <@ __sha512_mem_from (out, h, in_0, inlen, ms);
    return (out, ms);
  }
  proc _sha512_224_mem (out:BArray64.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var h:BArray64.t;
    h <- witness;
    h <@ __sha512_224_init (h);
    (out, ms) <@ __sha512_mem_from (out, h, in_0, inlen, ms);
    return (out, ms);
  }
  proc _sha512_256_mem (out:BArray64.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var h:BArray64.t;
    h <- witness;
    h <@ __sha512_256_init (h);
    (out, ms) <@ __sha512_mem_from (out, h, in_0, inlen, ms);
    return (out, ms);
  }
  proc _ph_keccak (out:BArray64.t, rate:W64.t, ds_byte:W64.t, msg:W64.t,
                   msg_len:W64.t, outlen:W64.t, ms:W64.t) : BArray64.t *
                                                            W64.t = {
    var st_s:BArray200.t;
    var st:BArray200.t;
    var pos:W64.t;
    var r:W64.t;
    var m:W64.t;
    var l:W64.t;
    var ds:W64.t;
    var i:W64.t;
    var more:bool;
    var t:W64.t;
    st <- witness;
    st_s <- witness;
    st <- st_s;
    st <@ __keccak_init (st);
    pos <- (W64.of_int 0);
    r <- rate;
    m <- msg;
    l <- msg_len;
    (* Erased call to spill *)
    (st, pos, ms) <@ _keccak_absorb_mem (st, pos, r, m, l, ms);
    (* Erased call to unspill *)
    rate <- (protect_64 rate ms);
    ds_byte <- (protect_64 ds_byte ms);
    ds <- ds_byte;
    r <- rate;
    (st, ms) <@ _keccak_finalize (st, pos, r, ds, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    outlen <- (protect_64 outlen ms);
    i <- (W64.of_int 0);
    more <- (i \ult outlen);
    while (more) {
      ms <- (update_msf more ms);
      t <- (zeroextu64 (BArray200.get8 st (W64.to_uint i)));
      out <- (BArray64.set8 out (W64.to_uint i) (truncateu8 t));
      i <- (i + (W64.of_int 1));
      more <- (i \ult outlen);
    }
    ms <- (update_msf (! more) ms);
    return (out, ms);
  }
  proc _prehash (ph:BArray64.t, sel:W64.t, msg:W64.t, msg_len:W64.t, ms:W64.t) : 
  BArray64.t * W64.t * W64.t = {
    var aux:BArray32.t;
    var aux_0:W64.t;
    var inc:int;
    var len:W64.t;
    var b:bool;
    var rate:W64.t;
    var o:W64.t;
    var m:W64.t;
    var l:W64.t;
    var ds:W64.t;
    var d:BArray64.t;
    var i:int;
    var t:W64.t;
    d <- witness;
    (* Erased call to spill *)
    b <- (sel = (W64.of_int 1));
    if (b) {
      ms <- (update_msf b ms);
      m <- msg;
      l <- msg_len;
      (aux, aux_0) <@ _sha256_mem ((SBArray64_32.get_sub8 d 0), m, l, ms);
      d <- (SBArray64_32.set_sub8 d 0 aux);
      ms <- aux_0;
      len <- (W64.of_int 32);
    } else {
      ms <- (update_msf (! b) ms);
      b <- (sel = (W64.of_int 2));
      if (b) {
        ms <- (update_msf b ms);
        m <- msg;
        l <- msg_len;
        (d, ms) <@ _sha384_mem (d, m, l, ms);
        len <- (W64.of_int 48);
      } else {
        ms <- (update_msf (! b) ms);
        b <- (sel = (W64.of_int 3));
        if (b) {
          ms <- (update_msf b ms);
          m <- msg;
          l <- msg_len;
          (d, ms) <@ _sha512_mem (d, m, l, ms);
          len <- (W64.of_int 64);
        } else {
          ms <- (update_msf (! b) ms);
          b <- (sel = (W64.of_int 4));
          if (b) {
            ms <- (update_msf b ms);
            m <- msg;
            l <- msg_len;
            (aux, aux_0) <@ _sha224_mem ((SBArray64_32.get_sub8 d 0), 
            m, l, ms);
            d <- (SBArray64_32.set_sub8 d 0 aux);
            ms <- aux_0;
            len <- (W64.of_int 28);
          } else {
            ms <- (update_msf (! b) ms);
            b <- (sel = (W64.of_int 5));
            if (b) {
              ms <- (update_msf b ms);
              m <- msg;
              l <- msg_len;
              (d, ms) <@ _sha512_224_mem (d, m, l, ms);
              len <- (W64.of_int 28);
            } else {
              ms <- (update_msf (! b) ms);
              b <- (sel = (W64.of_int 6));
              if (b) {
                ms <- (update_msf b ms);
                m <- msg;
                l <- msg_len;
                (d, ms) <@ _sha512_256_mem (d, m, l, ms);
                len <- (W64.of_int 32);
              } else {
                ms <- (update_msf (! b) ms);
                b <- (sel = (W64.of_int 7));
                if (b) {
                  ms <- (update_msf b ms);
                  m <- msg;
                  l <- msg_len;
                  rate <- (W64.of_int 144);
                  ds <- (W64.of_int 6);
                  o <- (W64.of_int 28);
                  (d, ms) <@ _ph_keccak (d, rate, ds, m, l, o, ms);
                  len <- (W64.of_int 28);
                } else {
                  ms <- (update_msf (! b) ms);
                  b <- (sel = (W64.of_int 8));
                  if (b) {
                    ms <- (update_msf b ms);
                    m <- msg;
                    l <- msg_len;
                    rate <- (W64.of_int 136);
                    ds <- (W64.of_int 6);
                    o <- (W64.of_int 32);
                    (d, ms) <@ _ph_keccak (d, rate, ds, m, l, o, ms);
                    len <- (W64.of_int 32);
                  } else {
                    ms <- (update_msf (! b) ms);
                    b <- (sel = (W64.of_int 9));
                    if (b) {
                      ms <- (update_msf b ms);
                      m <- msg;
                      l <- msg_len;
                      rate <- (W64.of_int 104);
                      ds <- (W64.of_int 6);
                      o <- (W64.of_int 48);
                      (d, ms) <@ _ph_keccak (d, rate, ds, m, l, o, ms);
                      len <- (W64.of_int 48);
                    } else {
                      ms <- (update_msf (! b) ms);
                      b <- (sel = (W64.of_int 10));
                      if (b) {
                        ms <- (update_msf b ms);
                        m <- msg;
                        l <- msg_len;
                        rate <- (W64.of_int 72);
                        ds <- (W64.of_int 6);
                        o <- (W64.of_int 64);
                        (d, ms) <@ _ph_keccak (d, rate, ds, m, l, o, ms);
                        len <- (W64.of_int 64);
                      } else {
                        ms <- (update_msf (! b) ms);
                        b <- (sel = (W64.of_int 11));
                        if (b) {
                          ms <- (update_msf b ms);
                          rate <- (W64.of_int 168);
                          o <- (W64.of_int 32);
                          m <- msg;
                          l <- msg_len;
                          ds <- (W64.of_int 31);
                          (d, ms) <@ _ph_keccak (d, rate, ds, m, l, o, ms);
                          len <- (W64.of_int 32);
                        } else {
                          ms <- (update_msf (! b) ms);
                          rate <- (W64.of_int 136);
                          o <- (W64.of_int 64);
                          m <- msg;
                          l <- msg_len;
                          ds <- (W64.of_int 31);
                          (d, ms) <@ _ph_keccak (d, rate, ds, m, l, o, ms);
                          len <- (W64.of_int 64);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    (* Erased call to unspill *)
    ph <- (protect_ptr ph ms);
    inc <- (64 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray64.get64 d i);
      ph <- (BArray64.set64 ph i t);
      i <- (i + 1);
    }
    return (ph, len, ms);
  }
  proc _slh_frame (prefix:BArray332.t, domain:BArray257.t, msg:W64.t,
                   msg_len:W64.t, ms:W64.t) : BArray332.t * W64.t * W64.t *
                                              W64.t * W64.t = {
    var inc:int;
    var prefix_len:W64.t;
    var status:W64.t;
    var fill:W64.t;
    var k:int;
    var sel:W64.t;
    var ctx_len:W64.t;
    var valid:bool;
    var t:W64.t;
    var i:W64.t;
    var end_0:W64.t;
    var more:bool;
    var pos:W64.t;
    var pure:bool;
    var oid:BArray10.t;
    var ph:BArray64.t;
    var len:W64.t;
    var cap:W64.t;
    var php:BArray64.t;
    var o:W64.t;
    oid <- witness;
    ph <- witness;
    php <- witness;
    fill <- (W64.of_int 0);
    inc <- ((((2 + 255) + 11) + 64) %/ 8);
    k <- 0;
    while ((k < inc)) {
      prefix <- (BArray332.set64 prefix k fill);
      k <- (k + 1);
    }
    prefix <-
    (BArray332.set32 prefix (((((2 + 255) + 11) + 64) %/ 4) - 1)
    (truncateu32 fill));
    sel <- (zeroextu64 (BArray257.get8 domain 0));
    sel <- (protect_64 sel ms);
    ctx_len <- (zeroextu64 (BArray257.get8 domain 1));
    ctx_len <- (protect_64 ctx_len ms);
    valid <- (sel \ule (W64.of_int 12));
    if (valid) {
      ms <- (update_msf valid ms);
      t <- (W64.of_int 1);
      t <- ((sel = (W64.of_int 0)) ? sel : t);
      prefix <- (BArray332.set8 prefix 0 (truncateu8 t));
      prefix <- (BArray332.set8 prefix 1 (truncateu8 ctx_len));
      i <- (W64.of_int 2);
      end_0 <- ctx_len;
      end_0 <- (end_0 + (W64.of_int 2));
      more <- (i \ult end_0);
      while (more) {
        ms <- (update_msf more ms);
        t <- (zeroextu64 (BArray257.get8 domain (W64.to_uint i)));
        prefix <- (BArray332.set8 prefix (W64.to_uint i) (truncateu8 t));
        i <- (i + (W64.of_int 1));
        more <- (i \ult end_0);
      }
      ms <- (update_msf (! more) ms);
      pos <- end_0;
      pure <- (sel = (W64.of_int 0));
      if (pure) {
        ms <- (update_msf pure ms);
        prefix_len <- pos;
      } else {
        ms <- (update_msf (! pure) ms);
        oid <- nIST_HASH_OID_PREFIX;
        k <- 0;
        while ((k < 10)) {
          t <- (zeroextu64 (BArray10.get8 oid k));
          prefix <- (BArray332.set8 prefix (W64.to_uint pos) (truncateu8 t));
          pos <- (pos + (W64.of_int 1));
          k <- (k + 1);
        }
        prefix <- (BArray332.set8 prefix (W64.to_uint pos) (truncateu8 sel));
        pos <- (pos + (W64.of_int 1));
        (* Erased call to spill *)
        (ph, len, ms) <@ _prehash (ph, sel, msg, msg_len, ms);
        (* Erased call to unspill *)
        prefix <- (protect_ptr prefix ms);
        pos <- (protect_64 pos ms);
        cap <- (W64.of_int 64);
        len <- ((cap \ule len) ? cap : len);
        php <- ph;
        i <- (W64.of_int 0);
        more <- (i \ult len);
        while (more) {
          ms <- (update_msf more ms);
          t <- (zeroextu64 (BArray64.get8 php (W64.to_uint i)));
          o <- pos;
          o <- (o + i);
          prefix <- (BArray332.set8 prefix (W64.to_uint o) (truncateu8 t));
          i <- (i + (W64.of_int 1));
          more <- (i \ult len);
        }
        ms <- (update_msf (! more) ms);
        prefix_len <- pos;
        prefix_len <- (prefix_len + len);
        msg_len <- (W64.of_int 0);
      }
      status <- (W64.of_int 0);
    } else {
      ms <- (update_msf (! valid) ms);
      status <- (W64.of_int (- 1));
      prefix_len <- (W64.of_int 0);
      msg_len <- (W64.of_int 0);
    }
    cap <- (W64.of_int (((2 + 255) + 11) + 64));
    prefix_len <- ((cap \ule prefix_len) ? cap : prefix_len);
    return (prefix, prefix_len, msg_len, status, ms);
  }
  proc keygen (pk:BArray32.t, sk:BArray64.t, seeds:BArray48.t) : BArray32.t *
                                                                 BArray64.t = {
    var ms:W64.t;
    ms <- (init_msf);
    pk <- (protect_ptr pk ms);
    sk <- (protect_ptr sk ms);
    seeds <- (protect_ptr seeds ms);
    (pk, sk, ms) <@ _slh_keygen (pk, sk, seeds, ms);
    return (pk, sk);
  }
  proc sign (sig:BArray7856.t, msg:W64.t, msg_len:W64.t, domain:BArray257.t,
             sk:BArray64.t, opt_rand:BArray16.t) : BArray7856.t * W64.t = {
    var status:W64.t;
    var ms:W64.t;
    var prefix:BArray332.t;
    var prefix_len:W64.t;
    var ok:bool;
    prefix <- witness;
    ms <- (init_msf);
    sig <- (protect_ptr sig ms);
    msg <- (protect_64 msg ms);
    msg_len <- (protect_64 msg_len ms);
    domain <- (protect_ptr domain ms);
    sk <- (protect_ptr sk ms);
    opt_rand <- (protect_ptr opt_rand ms);
    (* Erased call to spill *)
    (prefix, prefix_len, msg_len, status, ms) <@ _slh_frame (prefix, 
    domain, msg, msg_len, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    msg <- (protect_64 msg ms);
    sk <- (protect_ptr sk ms);
    opt_rand <- (protect_ptr opt_rand ms);
    ok <- (status = (W64.of_int 0));
    if (ok) {
      ms <- (update_msf ok ms);
      (* Erased call to spill *)
      (sig, ms) <@ _slh_sign (sig, prefix, prefix_len, msg, msg_len, 
      sk, opt_rand, ms);
      (* Erased call to unspill *)
      status <- (protect_64 status ms);
      (* Erased call to spill *)
    } else {
      ms <- (update_msf (! ok) ms);
    }
    return (sig, status);
  }
  proc verify (sig:BArray7856.t, msg:W64.t, msg_len:W64.t,
               domain:BArray257.t, pk:BArray32.t) : W64.t = {
    var result:W64.t;
    var ms:W64.t;
    var prefix:BArray332.t;
    var prefix_len:W64.t;
    var status:W64.t;
    var ok:bool;
    prefix <- witness;
    ms <- (init_msf);
    sig <- (protect_ptr sig ms);
    msg <- (protect_64 msg ms);
    msg_len <- (protect_64 msg_len ms);
    domain <- (protect_ptr domain ms);
    pk <- (protect_ptr pk ms);
    (* Erased call to spill *)
    (prefix, prefix_len, msg_len, status, ms) <@ _slh_frame (prefix, 
    domain, msg, msg_len, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    msg <- (protect_64 msg ms);
    pk <- (protect_ptr pk ms);
    result <- status;
    ok <- (status = (W64.of_int 0));
    if (ok) {
      ms <- (update_msf ok ms);
      (result, ms) <@ _slh_verify (sig, prefix, prefix_len, msg, msg_len, 
      pk, ms);
    } else {
      ms <- (update_msf (! ok) ms);
    }
    return result;
  }
  proc sign_internal (sig:BArray7856.t, msg:W64.t, msg_len:W64.t,
                      sk:BArray64.t, opt_rand:BArray16.t) : BArray7856.t = {
    var ms:W64.t;
    var prefix_len:W64.t;
    var prefix:BArray332.t;
    prefix <- witness;
    ms <- (init_msf);
    sig <- (protect_ptr sig ms);
    msg <- (protect_64 msg ms);
    msg_len <- (protect_64 msg_len ms);
    sk <- (protect_ptr sk ms);
    opt_rand <- (protect_ptr opt_rand ms);
    prefix_len <- (W64.of_int 0);
    (sig, ms) <@ _slh_sign (sig, prefix, prefix_len, msg, msg_len, sk,
    opt_rand, ms);
    return sig;
  }
  proc verify_internal (sig:BArray7856.t, msg:W64.t, msg_len:W64.t,
                        pk:BArray32.t) : W64.t = {
    var result:W64.t;
    var ms:W64.t;
    var prefix_len:W64.t;
    var prefix:BArray332.t;
    prefix <- witness;
    ms <- (init_msf);
    sig <- (protect_ptr sig ms);
    msg <- (protect_64 msg ms);
    msg_len <- (protect_64 msg_len ms);
    pk <- (protect_ptr pk ms);
    prefix_len <- (W64.of_int 0);
    (result, ms) <@ _slh_verify (sig, prefix, prefix_len, msg, msg_len, 
    pk, ms);
    return result;
  }
}.
