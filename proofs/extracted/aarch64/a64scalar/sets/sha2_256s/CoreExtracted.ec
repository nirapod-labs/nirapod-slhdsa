(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * GENERATED FILE. DO NOT EDIT.
 *
 * Generator:
 *     jasmin2ec --arch=armv8a (array model: the jasmin2ec default)
 *
 * Model:
 *     aarch64/a64scalar, kernels KeccakKernel=keccak/aarch64/scalar KeccakKernelX=keccak Sha2Kernel=sha2 Sha2KernelX=sha2
 *
 * Regenerate:
 *     make -C proofs extract     (check: make -C proofs check-extraction)
 *
 * Entry src/slhdsa/sets/sha2_256s.jinc
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
 *     063788335e2c760895b7b408107ed40db1ee8df0ffe686bab2985595462cba32  ./sha2/sha256.jinc
 *     01653390a2f77047c8b8bbd695663f5c2b04b41df4dae8c05285b42ced346e1a  ./sha2/sha256_array.jinc
 *     2ef076349fa6419836c060a2bfe986952cfe80b4f8237a826c137c3d20b60b7f  ./sha2/sha256_compress.jinc
 *     fa9874158d69a3ea868a1c9eb101e336535a5dd26f07466c5d13e7f518faddd6  ./sha2/sha256_k.jinc
 *     8d434e2b7758cc64e9629c7de9dc1326ed328f4cde4bfa09eca5f09fed3701f6  ./sha2/sha256_x8.jinc
 *     fbbef2092ae1f8d791e72fe0b87a96679e70d2559949c4f43c0f8da3432ebd97  ./sha2/sha256_x8_array.jinc
 *     b8217856d4d0ea149f8f6647d56575412b638010be612ce0718aeb6c7523579d  ./sha2/sha256_x8_compress.jinc
 *     21fc6c1de6f58d4440bc7292f323fe9ac383c0937b5a685ee092b10d41822db2  ./sha2/sha512.jinc
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

from Jasmin require import JModel_armv8a.

import SLH64.

require import
BArray10 BArray32 BArray47 BArray64 BArray67 BArray88 BArray96 BArray128
BArray192 BArray200 BArray256 BArray257 BArray320 BArray332 BArray480
BArray640 BArray704 BArray768 BArray2144 BArray2304 BArray2400 BArray8576
BArray10560 BArray19200 BArray29792 SBArray64_32 SBArray128_32 SBArray480_32
SBArray704_32 SBArray2144_32 SBArray2400_32 SBArray10560_32 SBArray29792_32
SBArray128_64 SBArray320_64 SBArray768_64 SBArray2304_64 SBArray320_128
SBArray768_128 SBArray2304_128 SBArray2400_2144 SBArray8576_2144
SBArray19200_2400 SBArray29792_10560 SBArray29792_19200.

abbrev nIST_HASH_OID_PREFIX =
(BArray10.of_list8
[(W8.of_int 6); (W8.of_int 9); (W8.of_int 96); (W8.of_int (-122));
(W8.of_int 72); (W8.of_int 1); (W8.of_int 101); (W8.of_int 3); (W8.of_int 4);
(W8.of_int 2)]).

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

module M = {
  proc __hook_fors_pk (pk:BArray32.t) : BArray32.t = {
    
    return pk;
  }
  proc __hook_ht_root (root:BArray32.t, layer:W32.t) : BArray32.t = {
    
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
  proc __node_copy (dst:BArray32.t, src:BArray32.t) : BArray32.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 src i);
      dst <- (BArray32.set64 dst i t);
      i <- (i + 1);
    }
    return dst;
  }
  proc __node_concat (dst:BArray64.t, a:BArray32.t, b:BArray32.t) : BArray64.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 a i);
      dst <- (BArray64.set64 dst i t);
      i <- (i + 1);
    }
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 b i);
      dst <- (BArray64.set64 dst ((32 %/ 8) + i) t);
      i <- (i + 1);
    }
    return dst;
  }
  proc __fors_indices (idx:BArray88.t, digest:BArray47.t) : BArray88.t = {
    var i:int;
    var b0:int;
    var s:int;
    var v:W32.t;
    var t:W32.t;
    i <- 0;
    while ((i < 22)) {
      b0 <- ((i * 14) %/ 8);
      s <- ((i * 14) %% 8);
      v <- (zeroextu32 (BArray47.get8 digest b0));
      v <- (v `<<` (W8.of_int 16));
      t <- (zeroextu32 (BArray47.get8 digest (b0 + 1)));
      t <- (t `<<` (W8.of_int 8));
      v <- (v `|` t);
      t <- (zeroextu32 (BArray47.get8 digest (b0 + 2)));
      v <- (v `|` t);
      v <- (v `>>` (W8.of_int ((24 - s) - 14)));
      v <- (v `&` (W32.of_int ((1 `<<` 14) - 1)));
      idx <- (BArray88.set32 idx i v);
      i <- (i + 1);
    }
    return idx;
  }
  proc __digest_tree_leaf (digest:BArray47.t) : W64.t * W32.t = {
    var inc:int;
    var tree:W64.t;
    var leaf:W32.t;
    var j:int;
    var t:W64.t;
    var mask:W64.t;
    var u:W32.t;
    tree <- (W64.of_int 0);
    inc <- (((64 - 8) + 7) %/ 8);
    j <- 0;
    while ((j < inc)) {
      tree <- (tree `<<` (W8.of_int 8));
      t <- (zeroextu64 (BArray47.get8 digest ((((22 * 14) + 7) %/ 8) + j)));
      tree <- (tree `|` t);
      j <- (j + 1);
    }
    if (((64 - 8) < 64)) {
      mask <- (W64.of_int ((1 `<<` (64 - 8)) - 1));
      tree <- (tree `&` mask);
    } else {
      
    }
    leaf <- (W32.of_int 0);
    inc <- ((8 + 7) %/ 8);
    j <- 0;
    while ((j < inc)) {
      leaf <- (leaf `<<` (W8.of_int 8));
      u <-
      (zeroextu32
      (BArray47.get8 digest
      (((((22 * 14) + 7) %/ 8) + (((64 - 8) + 7) %/ 8)) + j)));
      leaf <- (leaf `|` u);
      j <- (j + 1);
    }
    leaf <- (leaf `&` (W32.of_int ((1 `<<` 8) - 1)));
    return (tree, leaf);
  }
  proc __bswap32 (x:W32.t) : W32.t = {
    
    x <- (REV_32 x);
    return x;
  }
  proc __bswap64 (x:W64.t) : W64.t = {
    
    x <- (REV_64 x);
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
    } else {
      ms <- (update_msf (! more) ms);
    }
    inlen <- (inlen `&` (W64.of_int 63));
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
    } else {
      ms <- (update_msf (! more) ms);
    }
    inlen <- (inlen `&` (W64.of_int 127));
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
  proc _hmac_sha256_keyblock_mem (k0:BArray64.t, key:W64.t, keylen:W64.t,
                                  ms:W64.t) : BArray64.t * W64.t = {
    var j:int;
    var long:bool;
    var i:W64.t;
    var more:bool;
    var t:W64.t;
    var digest:BArray32.t;
    var z:W64.t;
    digest <- witness;
    j <- 0;
    while ((j < 8)) {
      k0 <- (BArray64.set64 k0 j (W64.of_int 0));
      j <- (j + 1);
    }
    long <- ((W64.of_int 64) \ult keylen);
    if (long) {
      ms <- (update_msf long ms);
      (* Erased call to spill *)
      (digest, ms) <@ _sha256_mem (digest, key, keylen, ms);
      (* Erased call to unspill *)
      k0 <- (protect_ptr k0 ms);
      j <- 0;
      while ((j < 4)) {
        t <- (BArray32.get64 digest j);
        k0 <- (BArray64.set64 k0 j t);
        j <- (j + 1);
      }
      i <- (W64.of_int 32);
    } else {
      ms <- (update_msf (! long) ms);
      i <- (W64.of_int 0);
      more <- (i \ult keylen);
      while (more) {
        ms <- (update_msf more ms);
        t <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint (key + i))));
        k0 <- (BArray64.set8 k0 (W64.to_uint i) (truncateu8 t));
        i <- (i + (W64.of_int 1));
        more <- (i \ult keylen);
      }
      ms <- (update_msf (! more) ms);
    }
    z <- (W64.of_int 0);
    more <- (i \ult (W64.of_int 64));
    while (more) {
      ms <- (update_msf more ms);
      k0 <- (BArray64.set8 k0 (W64.to_uint i) (truncateu8 z));
      i <- (i + (W64.of_int 1));
      more <- (i \ult (W64.of_int 64));
    }
    ms <- (update_msf (! more) ms);
    return (k0, ms);
  }
  proc _hmac_sha512_keyblock_mem (k0:BArray128.t, key:W64.t, keylen:W64.t,
                                  ms:W64.t) : BArray128.t * W64.t = {
    var j:int;
    var long:bool;
    var i:W64.t;
    var more:bool;
    var t:W64.t;
    var digest:BArray64.t;
    var z:W64.t;
    digest <- witness;
    j <- 0;
    while ((j < 16)) {
      k0 <- (BArray128.set64 k0 j (W64.of_int 0));
      j <- (j + 1);
    }
    long <- ((W64.of_int 128) \ult keylen);
    if (long) {
      ms <- (update_msf long ms);
      (* Erased call to spill *)
      (digest, ms) <@ _sha512_mem (digest, key, keylen, ms);
      (* Erased call to unspill *)
      k0 <- (protect_ptr k0 ms);
      j <- 0;
      while ((j < 8)) {
        t <- (BArray64.get64 digest j);
        k0 <- (BArray128.set64 k0 j t);
        j <- (j + 1);
      }
      i <- (W64.of_int 64);
    } else {
      ms <- (update_msf (! long) ms);
      i <- (W64.of_int 0);
      more <- (i \ult keylen);
      while (more) {
        ms <- (update_msf more ms);
        t <- (zeroextu64 (loadW8 Glob.mem (W64.to_uint (key + i))));
        k0 <- (BArray128.set8 k0 (W64.to_uint i) (truncateu8 t));
        i <- (i + (W64.of_int 1));
        more <- (i \ult keylen);
      }
      ms <- (update_msf (! more) ms);
    }
    z <- (W64.of_int 0);
    more <- (i \ult (W64.of_int 128));
    while (more) {
      ms <- (update_msf more ms);
      k0 <- (BArray128.set8 k0 (W64.to_uint i) (truncateu8 z));
      i <- (i + (W64.of_int 1));
      more <- (i \ult (W64.of_int 128));
    }
    ms <- (update_msf (! more) ms);
    return (k0, ms);
  }
  proc __hmac_sha256_init (inner:BArray32.t, outer:BArray32.t, k0:BArray64.t,
                           ms:W64.t) : BArray32.t * BArray32.t * W64.t = {
    var mi:W64.t;
    var mo:W64.t;
    var i:int;
    var t:W64.t;
    var u:W64.t;
    var ipad:BArray64.t;
    var opad:BArray64.t;
    ipad <- witness;
    opad <- witness;
    mi <- (W64.of_int 3906369333256140342);
    mo <- (W64.of_int 6655295901103053916);
    i <- 0;
    while ((i < 8)) {
      t <- (BArray64.get64 k0 i);
      u <- t;
      t <- (t `^` mi);
      u <- (u `^` mo);
      ipad <- (BArray64.set64 ipad i t);
      opad <- (BArray64.set64 opad i u);
      i <- (i + 1);
    }
    inner <@ __sha256_init (inner);
    (inner, ms) <@ _sha256_compress (inner, ipad, ms);
    outer <@ __sha256_init (outer);
    (outer, ms) <@ _sha256_compress (outer, opad, ms);
    return (inner, outer, ms);
  }
  proc __hmac_sha512_init (inner:BArray64.t, outer:BArray64.t,
                           k0:BArray128.t, ms:W64.t) : BArray64.t *
                                                       BArray64.t * W64.t = {
    var mi:W64.t;
    var mo:W64.t;
    var i:int;
    var t:W64.t;
    var u:W64.t;
    var ipad:BArray128.t;
    var opad:BArray128.t;
    ipad <- witness;
    opad <- witness;
    mi <- (W64.of_int 3906369333256140342);
    mo <- (W64.of_int 6655295901103053916);
    i <- 0;
    while ((i < 16)) {
      t <- (BArray128.get64 k0 i);
      u <- t;
      t <- (t `^` mi);
      u <- (u `^` mo);
      ipad <- (BArray128.set64 ipad i t);
      opad <- (BArray128.set64 opad i u);
      i <- (i + 1);
    }
    inner <@ __sha512_init (inner);
    (inner, ms) <@ _sha512_compress (inner, ipad, ms);
    outer <@ __sha512_init (outer);
    (outer, ms) <@ _sha512_compress (outer, opad, ms);
    return (inner, outer, ms);
  }
  proc __hmac_sha256_finalize (out:BArray32.t, inner:BArray32.t,
                               buf:BArray64.t, total:W64.t, outer:BArray32.t,
                               ms:W64.t) : BArray32.t * BArray32.t *
                                           BArray64.t * W64.t = {
    var digest:BArray32.t;
    var i:int;
    var x:W32.t;
    var t:W64.t;
    digest <- witness;
    (digest, inner, buf, ms) <@ _sha256_finalize (digest, inner, buf, 
    total, ms);
    i <- 0;
    while ((i < 8)) {
      x <- (BArray32.get32 outer i);
      inner <- (BArray32.set32 inner i x);
      i <- (i + 1);
    }
    i <- 0;
    while ((i < 4)) {
      t <- (BArray32.get64 digest i);
      buf <- (BArray64.set64 buf i t);
      i <- (i + 1);
    }
    total <- (W64.of_int (64 + 32));
    (out, inner, buf, ms) <@ _sha256_finalize (out, inner, buf, total, ms);
    return (out, inner, buf, ms);
  }
  proc __hmac_sha512_finalize (out:BArray64.t, inner:BArray64.t,
                               buf:BArray128.t, total:W64.t,
                               outer:BArray64.t, ms:W64.t) : BArray64.t *
                                                             BArray64.t *
                                                             BArray128.t *
                                                             W64.t = {
    var digest:BArray64.t;
    var i:int;
    var t:W64.t;
    digest <- witness;
    (digest, inner, buf, ms) <@ _sha512_finalize (digest, inner, buf, 
    total, ms);
    i <- 0;
    while ((i < 8)) {
      t <- (BArray64.get64 outer i);
      inner <- (BArray64.set64 inner i t);
      i <- (i + 1);
    }
    i <- 0;
    while ((i < 8)) {
      t <- (BArray64.get64 digest i);
      buf <- (BArray128.set64 buf i t);
      i <- (i + 1);
    }
    total <- (W64.of_int (128 + 64));
    (out, inner, buf, ms) <@ _sha512_finalize (out, inner, buf, total, ms);
    return (out, inner, buf, ms);
  }
  proc mgf____mgf1_layout (m:BArray320.t, seed:BArray128.t, padded:int) : 
  BArray320.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var t:W64.t;
    z <- (W64.of_int 0);
    inc <- padded;
    i <- 0;
    while ((i < inc)) {
      m <- (BArray320.set8 m i (truncateu8 z));
      i <- (i + 1);
    }
    inc <- ((2 * 32) + (32 * (1 + ((5 + 1) %/ 4))));
    i <- 0;
    while ((i < inc)) {
      t <- (zeroextu64 (BArray128.get8 seed i));
      m <- (BArray320.set8 m i (truncateu8 t));
      i <- (i + 1);
    }
    t <- (W64.of_int 128);
    m <-
    (BArray320.set8 m (((2 * 32) + (32 * (1 + ((5 + 1) %/ 4)))) + 4)
    (truncateu8 t));
    t <- (W64.of_int ((((2 * 32) + (32 * (1 + ((5 + 1) %/ 4)))) + 4) * 8));
    i <- 0;
    while ((i < 8)) {
      m <- (BArray320.set8 m ((padded - 1) - i) (truncateu8 t));
      t <- (t `>>` (W8.of_int 8));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf____mgf1_set_counter (m:BArray320.t, c:int) : BArray320.t = {
    var t:W64.t;
    var i:int;
    i <- 0;
    while ((i < 4)) {
      t <- (W64.of_int c);
      t <- (t `>>` (W8.of_int (8 * (3 - i))));
      m <-
      (BArray320.set8 m (((2 * 32) + (32 * (1 + ((5 + 1) %/ 4)))) + i)
      (truncateu8 t));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf___mgf1_sha256 (out:BArray47.t, seed:BArray128.t, ms:W64.t) : 
  BArray47.t * W64.t = {
    var inc:int;
    var inc_0:int;
    var m:BArray320.t;
    var c:int;
    var h:BArray32.t;
    var b:int;
    var n:int;
    var i:int;
    var x:W32.t;
    var t:W64.t;
    h <- witness;
    m <- witness;
    m <@ mgf____mgf1_layout (m, seed,
    (64 *
    (((((((2 * 32) + (32 * (1 + ((5 + 1) %/ 4)))) + 4) + 1) + 8) + 63) %/ 64)));
    inc <- ((47 + 31) %/ 32);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf____mgf1_set_counter (m, c);
      h <@ __sha256_init (h);
      inc_0 <-
      (((((((2 * 32) + (32 * (1 + ((5 + 1) %/ 4)))) + 4) + 1) + 8) + 63) %/
      64);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h, (SBArray320_64.get_sub8 m (64 * b)),
        ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((47 - (32 * c)) < 32) ? (47 - (32 * c)) : 32);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        x <- (BArray32.get32 h (i %/ 4));
        x <- (x `>>` (W8.of_int (8 * (3 - (i %% 4)))));
        t <- (zeroextu64 x);
        out <- (BArray47.set8 out ((32 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf___mgf1_sha512 (out:BArray47.t, seed:BArray128.t, ms:W64.t) : 
  BArray47.t * W64.t = {
    var inc:int;
    var inc_0:int;
    var m:BArray320.t;
    var c:int;
    var h:BArray64.t;
    var b:int;
    var n:int;
    var i:int;
    var t:W64.t;
    h <- witness;
    m <- witness;
    m <@ mgf____mgf1_layout (m, seed,
    (128 *
    (((((((2 * 32) + (32 * (1 + ((5 + 1) %/ 4)))) + 4) + 1) + 16) + 127) %/
    128)));
    inc <- ((47 + 63) %/ 64);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf____mgf1_set_counter (m, c);
      h <@ __sha512_init (h);
      inc_0 <-
      (((((((2 * 32) + (32 * (1 + ((5 + 1) %/ 4)))) + 4) + 1) + 16) + 127) %/
      128);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha512_compress (h,
        (SBArray320_128.get_sub8 m (128 * b)), ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((47 - (64 * c)) < 64) ? (47 - (64 * c)) : 64);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        t <- (BArray64.get64 h (i %/ 8));
        t <- (t `>>` (W8.of_int (8 * (7 - (i %% 8)))));
        out <- (BArray47.set8 out ((64 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc __adrs_compress_into64 (dst:BArray64.t, adrs:BArray32.t) : BArray64.t = {
    var t:W64.t;
    var i:int;
    t <- (zeroextu64 (BArray32.get8 adrs 3));
    dst <- (BArray64.set8 dst 0 (truncateu8 t));
    i <- 0;
    while ((i < 8)) {
      t <- (zeroextu64 (BArray32.get8 adrs (8 + i)));
      dst <- (BArray64.set8 dst (1 + i) (truncateu8 t));
      i <- (i + 1);
    }
    t <- (zeroextu64 (BArray32.get8 adrs 19));
    dst <- (BArray64.set8 dst 9 (truncateu8 t));
    i <- 0;
    while ((i < 12)) {
      t <- (zeroextu64 (BArray32.get8 adrs (20 + i)));
      dst <- (BArray64.set8 dst (10 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return dst;
  }
  proc __adrs_compress_into128 (dst:BArray128.t, adrs:BArray32.t) : BArray128.t = {
    var t:W64.t;
    var i:int;
    t <- (zeroextu64 (BArray32.get8 adrs 3));
    dst <- (BArray128.set8 dst 0 (truncateu8 t));
    i <- 0;
    while ((i < 8)) {
      t <- (zeroextu64 (BArray32.get8 adrs (8 + i)));
      dst <- (BArray128.set8 dst (1 + i) (truncateu8 t));
      i <- (i + 1);
    }
    t <- (zeroextu64 (BArray32.get8 adrs 19));
    dst <- (BArray128.set8 dst 9 (truncateu8 t));
    i <- 0;
    while ((i < 12)) {
      t <- (zeroextu64 (BArray32.get8 adrs (20 + i)));
      dst <- (BArray128.set8 dst (10 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return dst;
  }
  proc __sha256_trunc_n (out:BArray32.t, h:BArray32.t) : BArray32.t = {
    var inc:int;
    var i:int;
    var w:W32.t;
    inc <- (32 %/ 4);
    i <- 0;
    while ((i < inc)) {
      w <- (BArray32.get32 h i);
      w <@ __bswap32 (w);
      out <- (BArray32.set32 out i w);
      i <- (i + 1);
    }
    return out;
  }
  proc __sha512_trunc_n (out:BArray32.t, h:BArray64.t) : BArray32.t = {
    var inc:int;
    var i:int;
    var w:W64.t;
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      w <- (BArray64.get64 h i);
      w <@ __bswap64 (w);
      out <- (BArray32.set64 out i w);
      i <- (i + 1);
    }
    return out;
  }
  proc _thash_ctx_init (ctx:BArray96.t, pk_seed:BArray32.t, ms:W64.t) : 
  BArray96.t * W64.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var block:BArray128.t;
    var t:W64.t;
    var h256:BArray32.t;
    var h512:BArray64.t;
    block <- witness;
    h256 <- witness;
    h512 <- witness;
    z <- (W64.of_int 0);
    i <- 0;
    while ((i < 16)) {
      block <- (BArray128.set64 block i z);
      i <- (i + 1);
    }
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 pk_seed i);
      block <- (BArray128.set64 block i t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    h256 <@ __sha256_init (h256);
    (h256, ms) <@ _sha256_compress (h256, (SBArray128_64.get_sub8 block 0),
    ms);
    (* Erased call to unspill *)
    ctx <- (protect_ptr ctx ms);
    (* Erased call to spill *)
    i <- 0;
    while ((i < 4)) {
      t <- (BArray32.get64 h256 i);
      ctx <- (BArray96.set64 ctx i t);
      i <- (i + 1);
    }
    if ((((5 + 1) %/ 4) = 1)) {
      (* Erased call to spill *)
      h512 <@ __sha512_init (h512);
      (h512, ms) <@ _sha512_compress (h512, block, ms);
      (* Erased call to unspill *)
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      i <- 0;
      while ((i < 8)) {
        t <- (BArray64.get64 h512 i);
        ctx <- (BArray96.set64 ctx (4 + i) t);
        i <- (i + 1);
      }
    } else {
      z <- (W64.of_int 0);
      i <- 0;
      while ((i < 8)) {
        ctx <- (BArray96.set64 ctx (4 + i) z);
        i <- (i + 1);
      }
    }
    return (ctx, ms);
  }
  proc __sha256_seeded_block (block:BArray64.t, adrs:BArray32.t, x_len:int,
                              bits:int) : BArray64.t = {
    var z:W64.t;
    var i:int;
    var t:W64.t;
    z <- (W64.of_int 0);
    i <- 0;
    while ((i < 8)) {
      block <- (BArray64.set64 block i z);
      i <- (i + 1);
    }
    block <@ __adrs_compress_into64 (block, adrs);
    t <- (W64.of_int 128);
    block <- (BArray64.set8 block (22 + x_len) (truncateu8 t));
    t <- (W64.of_int (bits `|>>` 8));
    block <- (BArray64.set8 block 62 (truncateu8 t));
    t <- (truncateu64 ((W256.of_int bits) `&` (W256.of_int 255)));
    block <- (BArray64.set8 block 63 (truncateu8 t));
    return block;
  }
  proc _thash_prf (out:BArray32.t, sk_seed:BArray32.t, ctx:BArray96.t,
                   adrs:BArray32.t, ms:W64.t) : BArray32.t * W64.t = {
    var inc:int;
    var block:BArray64.t;
    var i:int;
    var t:W64.t;
    var h:BArray32.t;
    block <- witness;
    h <- witness;
    block <@ __sha256_seeded_block (block, adrs, 32, (8 * ((64 + 22) + 32)));
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 sk_seed i);
      block <- (BArray64.set64d block (22 + (8 * i)) t);
      i <- (i + 1);
    }
    i <- 0;
    while ((i < 4)) {
      t <- (BArray96.get64 ctx i);
      h <- (BArray32.set64 h i t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    (h, ms) <@ _sha256_compress (h, block, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    out <@ __sha256_trunc_n (out, h);
    return (out, ms);
  }
  proc _thash_f (x:BArray32.t, ctx:BArray96.t, adrs:BArray32.t, ms:W64.t) : 
  BArray32.t * W64.t = {
    var inc:int;
    var block:BArray64.t;
    var i:int;
    var t:W64.t;
    var h:BArray32.t;
    block <- witness;
    h <- witness;
    block <@ __sha256_seeded_block (block, adrs, 32, (8 * ((64 + 22) + 32)));
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 x i);
      block <- (BArray64.set64d block (22 + (8 * i)) t);
      i <- (i + 1);
    }
    i <- 0;
    while ((i < 4)) {
      t <- (BArray96.get64 ctx i);
      h <- (BArray32.set64 h i t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    (h, ms) <@ _sha256_compress (h, block, ms);
    (* Erased call to unspill *)
    x <- (protect_ptr x ms);
    x <@ __sha256_trunc_n (x, h);
    return (x, ms);
  }
  proc _thash_h (out:BArray32.t, in_0:BArray64.t, ctx:BArray96.t,
                 adrs:BArray32.t, ms:W64.t) : BArray32.t * W64.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var wide:BArray128.t;
    var t:W64.t;
    var h512:BArray64.t;
    var block:BArray64.t;
    var h:BArray32.t;
    block <- witness;
    h <- witness;
    h512 <- witness;
    wide <- witness;
    if ((((5 + 1) %/ 4) = 0)) {
      block <@ __sha256_seeded_block (block, adrs, (2 * 32),
      (8 * ((64 + 22) + (2 * 32))));
      inc <- (32 %/ 4);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray64.get64 in_0 i);
        block <- (BArray64.set64d block (22 + (8 * i)) t);
        i <- (i + 1);
      }
      i <- 0;
      while ((i < 4)) {
        t <- (BArray96.get64 ctx i);
        h <- (BArray32.set64 h i t);
        i <- (i + 1);
      }
      (* Erased call to spill *)
      (h, ms) <@ _sha256_compress (h, block, ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      out <@ __sha256_trunc_n (out, h);
    } else {
      z <- (W64.of_int 0);
      i <- 0;
      while ((i < 16)) {
        wide <- (BArray128.set64 wide i z);
        i <- (i + 1);
      }
      wide <@ __adrs_compress_into128 (wide, adrs);
      inc <- (32 %/ 4);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray64.get64 in_0 i);
        wide <- (BArray128.set64d wide (22 + (8 * i)) t);
        i <- (i + 1);
      }
      t <- (W64.of_int 128);
      wide <- (BArray128.set8 wide (22 + (2 * 32)) (truncateu8 t));
      t <- (W64.of_int ((8 * ((128 + 22) + (2 * 32))) `|>>` 8));
      wide <- (BArray128.set8 wide 126 (truncateu8 t));
      t <-
      (truncateu64
      ((W256.of_int (8 * ((128 + 22) + (2 * 32)))) `&` (W256.of_int 255)));
      wide <- (BArray128.set8 wide 127 (truncateu8 t));
      i <- 0;
      while ((i < 8)) {
        t <- (BArray96.get64 ctx (4 + i));
        h512 <- (BArray64.set64 h512 i t);
        i <- (i + 1);
      }
      (* Erased call to spill *)
      (h512, ms) <@ _sha512_compress (h512, wide, ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      out <@ __sha512_trunc_n (out, h512);
    }
    return (out, ms);
  }
  proc tLen____t_layout (buf:BArray2304.t, in_0:BArray2144.t,
                         adrs:BArray32.t, padded:int, bits:int, ms:W64.t) : 
  BArray2304.t * W64.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var t:W64.t;
    var k:W64.t;
    var more:bool;
    var o:W64.t;
    z <- (W64.of_int 0);
    inc <- (((((22 + (((2 * 32) + 3) * 32)) + 17) + 127) %/ 128) * 16);
    i <- 0;
    while ((i < inc)) {
      buf <- (BArray2304.set64 buf i z);
      i <- (i + 1);
    }
    t <- (zeroextu64 (BArray32.get8 adrs 3));
    buf <- (BArray2304.set8 buf 0 (truncateu8 t));
    i <- 0;
    while ((i < 8)) {
      t <- (zeroextu64 (BArray32.get8 adrs (8 + i)));
      buf <- (BArray2304.set8 buf (1 + i) (truncateu8 t));
      i <- (i + 1);
    }
    t <- (zeroextu64 (BArray32.get8 adrs 19));
    buf <- (BArray2304.set8 buf 9 (truncateu8 t));
    i <- 0;
    while ((i < 12)) {
      t <- (zeroextu64 (BArray32.get8 adrs (20 + i)));
      buf <- (BArray2304.set8 buf (10 + i) (truncateu8 t));
      i <- (i + 1);
    }
    k <- (W64.of_int 0);
    more <- (k \ult (W64.of_int ((((2 * 32) + 3) * 32) %/ 8)));
    while (more) {
      ms <- (update_msf more ms);
      t <- (BArray2144.get64 in_0 (W64.to_uint k));
      o <- k;
      o <- (o `<<` (W8.of_int 3));
      o <- (o + (W64.of_int 22));
      buf <- (BArray2304.set64d buf (W64.to_uint o) t);
      k <- (k + (W64.of_int 1));
      more <- (k \ult (W64.of_int ((((2 * 32) + 3) * 32) %/ 8)));
    }
    ms <- (update_msf (! more) ms);
    t <- (W64.of_int 128);
    buf <- (BArray2304.set8 buf (22 + (((2 * 32) + 3) * 32)) (truncateu8 t));
    t <- (W64.of_int (bits `|>>` 8));
    buf <- (BArray2304.set8 buf (padded - 2) (truncateu8 t));
    t <- (truncateu64 ((W256.of_int bits) `&` (W256.of_int 255)));
    buf <- (BArray2304.set8 buf (padded - 1) (truncateu8 t));
    return (buf, ms);
  }
  proc tLen___thash_t (out:BArray32.t, in_0:BArray2144.t, ctx:BArray96.t,
                       adrs:BArray32.t, ms:W64.t) : BArray32.t * W64.t = {
    var buf:BArray2304.t;
    var p:BArray2304.t;
    var i:int;
    var t:W64.t;
    var h512:BArray64.t;
    var h:BArray32.t;
    var off:W64.t;
    var more:bool;
    buf <- witness;
    h <- witness;
    h512 <- witness;
    p <- witness;
    p <- buf;
    if ((((5 + 1) %/ 4) = 0)) {
      (p, ms) <@ tLen____t_layout (p, in_0, adrs,
      (64 * ((((22 + (((2 * 32) + 3) * 32)) + 9) + 63) %/ 64)),
      (8 * (64 + (22 + (((2 * 32) + 3) * 32)))), ms);
      i <- 0;
      while ((i < 4)) {
        t <- (BArray96.get64 ctx i);
        h <- (BArray32.set64 h i t);
        i <- (i + 1);
      }
    } else {
      (p, ms) <@ tLen____t_layout (p, in_0, adrs,
      (128 * ((((22 + (((2 * 32) + 3) * 32)) + 17) + 127) %/ 128)),
      (8 * (128 + (22 + (((2 * 32) + 3) * 32)))), ms);
      i <- 0;
      while ((i < 8)) {
        t <- (BArray96.get64 ctx (4 + i));
        h512 <- (BArray64.set64 h512 i t);
        i <- (i + 1);
      }
    }
    buf <- p;
    (* Erased call to spill *)
    off <- (W64.of_int 0);
    if ((((5 + 1) %/ 4) = 0)) {
      more <-
      (off \ult
      (W64.of_int (64 * ((((22 + (((2 * 32) + 3) * 32)) + 9) + 63) %/ 64))));
      while (more) {
        ms <- (update_msf more ms);
        p <- buf;
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h,
        (SBArray2304_64.get_sub8 p (W64.to_uint off)), ms);
        (* Erased call to unspill *)
        off <- (protect_64 off ms);
        off <- (off + (W64.of_int 64));
        more <-
        (off \ult
        (W64.of_int (64 * ((((22 + (((2 * 32) + 3) * 32)) + 9) + 63) %/ 64))));
      }
      ms <- (update_msf (! more) ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      out <@ __sha256_trunc_n (out, h);
    } else {
      more <-
      (off \ult
      (W64.of_int
      (128 * ((((22 + (((2 * 32) + 3) * 32)) + 17) + 127) %/ 128))));
      while (more) {
        ms <- (update_msf more ms);
        p <- buf;
        (* Erased call to spill *)
        (h512, ms) <@ _sha512_compress (h512,
        (SBArray2304_128.get_sub8 p (W64.to_uint off)), ms);
        (* Erased call to unspill *)
        off <- (protect_64 off ms);
        off <- (off + (W64.of_int 128));
        more <-
        (off \ult
        (W64.of_int
        (128 * ((((22 + (((2 * 32) + 3) * 32)) + 17) + 127) %/ 128))));
      }
      ms <- (update_msf (! more) ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      out <@ __sha512_trunc_n (out, h512);
    }
    return (out, ms);
  }
  proc tK____t_layout (buf:BArray768.t, in_0:BArray704.t, adrs:BArray32.t,
                       padded:int, bits:int, ms:W64.t) : BArray768.t * W64.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var t:W64.t;
    var k:W64.t;
    var more:bool;
    var o:W64.t;
    z <- (W64.of_int 0);
    inc <- (((((22 + (22 * 32)) + 17) + 127) %/ 128) * 16);
    i <- 0;
    while ((i < inc)) {
      buf <- (BArray768.set64 buf i z);
      i <- (i + 1);
    }
    t <- (zeroextu64 (BArray32.get8 adrs 3));
    buf <- (BArray768.set8 buf 0 (truncateu8 t));
    i <- 0;
    while ((i < 8)) {
      t <- (zeroextu64 (BArray32.get8 adrs (8 + i)));
      buf <- (BArray768.set8 buf (1 + i) (truncateu8 t));
      i <- (i + 1);
    }
    t <- (zeroextu64 (BArray32.get8 adrs 19));
    buf <- (BArray768.set8 buf 9 (truncateu8 t));
    i <- 0;
    while ((i < 12)) {
      t <- (zeroextu64 (BArray32.get8 adrs (20 + i)));
      buf <- (BArray768.set8 buf (10 + i) (truncateu8 t));
      i <- (i + 1);
    }
    k <- (W64.of_int 0);
    more <- (k \ult (W64.of_int ((22 * 32) %/ 8)));
    while (more) {
      ms <- (update_msf more ms);
      t <- (BArray704.get64 in_0 (W64.to_uint k));
      o <- k;
      o <- (o `<<` (W8.of_int 3));
      o <- (o + (W64.of_int 22));
      buf <- (BArray768.set64d buf (W64.to_uint o) t);
      k <- (k + (W64.of_int 1));
      more <- (k \ult (W64.of_int ((22 * 32) %/ 8)));
    }
    ms <- (update_msf (! more) ms);
    t <- (W64.of_int 128);
    buf <- (BArray768.set8 buf (22 + (22 * 32)) (truncateu8 t));
    t <- (W64.of_int (bits `|>>` 8));
    buf <- (BArray768.set8 buf (padded - 2) (truncateu8 t));
    t <- (truncateu64 ((W256.of_int bits) `&` (W256.of_int 255)));
    buf <- (BArray768.set8 buf (padded - 1) (truncateu8 t));
    return (buf, ms);
  }
  proc tK___thash_t (out:BArray32.t, in_0:BArray704.t, ctx:BArray96.t,
                     adrs:BArray32.t, ms:W64.t) : BArray32.t * W64.t = {
    var buf:BArray768.t;
    var p:BArray768.t;
    var i:int;
    var t:W64.t;
    var h512:BArray64.t;
    var h:BArray32.t;
    var off:W64.t;
    var more:bool;
    buf <- witness;
    h <- witness;
    h512 <- witness;
    p <- witness;
    p <- buf;
    if ((((5 + 1) %/ 4) = 0)) {
      (p, ms) <@ tK____t_layout (p, in_0, adrs,
      (64 * ((((22 + (22 * 32)) + 9) + 63) %/ 64)),
      (8 * (64 + (22 + (22 * 32)))), ms);
      i <- 0;
      while ((i < 4)) {
        t <- (BArray96.get64 ctx i);
        h <- (BArray32.set64 h i t);
        i <- (i + 1);
      }
    } else {
      (p, ms) <@ tK____t_layout (p, in_0, adrs,
      (128 * ((((22 + (22 * 32)) + 17) + 127) %/ 128)),
      (8 * (128 + (22 + (22 * 32)))), ms);
      i <- 0;
      while ((i < 8)) {
        t <- (BArray96.get64 ctx (4 + i));
        h512 <- (BArray64.set64 h512 i t);
        i <- (i + 1);
      }
    }
    buf <- p;
    (* Erased call to spill *)
    off <- (W64.of_int 0);
    if ((((5 + 1) %/ 4) = 0)) {
      more <-
      (off \ult (W64.of_int (64 * ((((22 + (22 * 32)) + 9) + 63) %/ 64))));
      while (more) {
        ms <- (update_msf more ms);
        p <- buf;
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h,
        (SBArray768_64.get_sub8 p (W64.to_uint off)), ms);
        (* Erased call to unspill *)
        off <- (protect_64 off ms);
        off <- (off + (W64.of_int 64));
        more <-
        (off \ult (W64.of_int (64 * ((((22 + (22 * 32)) + 9) + 63) %/ 64))));
      }
      ms <- (update_msf (! more) ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      out <@ __sha256_trunc_n (out, h);
    } else {
      more <-
      (off \ult
      (W64.of_int (128 * ((((22 + (22 * 32)) + 17) + 127) %/ 128))));
      while (more) {
        ms <- (update_msf more ms);
        p <- buf;
        (* Erased call to spill *)
        (h512, ms) <@ _sha512_compress (h512,
        (SBArray768_128.get_sub8 p (W64.to_uint off)), ms);
        (* Erased call to unspill *)
        off <- (protect_64 off ms);
        off <- (off + (W64.of_int 128));
        more <-
        (off \ult
        (W64.of_int (128 * ((((22 + (22 * 32)) + 17) + 127) %/ 128))));
      }
      ms <- (update_msf (! more) ms);
      (* Erased call to unspill *)
      out <- (protect_ptr out ms);
      out <@ __sha512_trunc_n (out, h512);
    }
    return (out, ms);
  }
  proc _thash_t_len (out:BArray32.t, in_0:BArray2144.t, ctx:BArray96.t,
                     adrs:BArray32.t, ms:W64.t) : BArray32.t * W64.t = {
    
    (out, ms) <@ tLen___thash_t (out, in_0, ctx, adrs, ms);
    return (out, ms);
  }
  proc _thash_t_k (out:BArray32.t, in_0:BArray704.t, ctx:BArray96.t,
                   adrs:BArray32.t, ms:W64.t) : BArray32.t * W64.t = {
    
    (out, ms) <@ tK___thash_t (out, in_0, ctx, adrs, ms);
    return (out, ms);
  }
  proc __sha256_absorb_prefix (h:BArray32.t, buf:BArray64.t, total:W64.t,
                               prefix:BArray332.t, len:W64.t, ms:W64.t) : 
  BArray32.t * BArray64.t * W64.t * W64.t = {
    var i:W64.t;
    var more:bool;
    var fill:W64.t;
    var t:W64.t;
    var full:bool;
    i <- (W64.of_int 0);
    more <- (i \ult len);
    while (more) {
      ms <- (update_msf more ms);
      fill <- total;
      fill <- (fill `&` (W64.of_int 63));
      t <- (zeroextu64 (BArray332.get8 prefix (W64.to_uint i)));
      buf <- (BArray64.set8 buf (W64.to_uint fill) (truncateu8 t));
      total <- (total + (W64.of_int 1));
      i <- (i + (W64.of_int 1));
      full <- (fill = (W64.of_int 63));
      if (full) {
        ms <- (update_msf full ms);
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h, buf, ms);
        (* Erased call to unspill *)
        buf <- (protect_ptr buf ms);
        total <- (protect_64 total ms);
        prefix <- (protect_ptr prefix ms);
        len <- (protect_64 len ms);
        i <- (protect_64 i ms);
        (* Erased call to spill *)
      } else {
        ms <- (update_msf (! full) ms);
      }
      more <- (i \ult len);
    }
    ms <- (update_msf (! more) ms);
    return (h, buf, total, ms);
  }
  proc __sha512_absorb_prefix (h:BArray64.t, buf:BArray128.t, total:W64.t,
                               prefix:BArray332.t, len:W64.t, ms:W64.t) : 
  BArray64.t * BArray128.t * W64.t * W64.t = {
    var i:W64.t;
    var more:bool;
    var fill:W64.t;
    var t:W64.t;
    var full:bool;
    i <- (W64.of_int 0);
    more <- (i \ult len);
    while (more) {
      ms <- (update_msf more ms);
      fill <- total;
      fill <- (fill `&` (W64.of_int 127));
      t <- (zeroextu64 (BArray332.get8 prefix (W64.to_uint i)));
      buf <- (BArray128.set8 buf (W64.to_uint fill) (truncateu8 t));
      total <- (total + (W64.of_int 1));
      i <- (i + (W64.of_int 1));
      full <- (fill = (W64.of_int 127));
      if (full) {
        ms <- (update_msf full ms);
        (* Erased call to spill *)
        (h, ms) <@ _sha512_compress (h, buf, ms);
        (* Erased call to unspill *)
        buf <- (protect_ptr buf ms);
        total <- (protect_64 total ms);
        prefix <- (protect_ptr prefix ms);
        len <- (protect_64 len ms);
        i <- (protect_64 i ms);
        (* Erased call to spill *)
      } else {
        ms <- (update_msf (! full) ms);
      }
      more <- (i \ult len);
    }
    ms <- (update_msf (! more) ms);
    return (h, buf, total, ms);
  }
  proc __sha256_absorb_message (h:BArray32.t, buf:BArray64.t, total:W64.t,
                                prefix:BArray332.t, prefix_len:W64.t,
                                msg:W64.t, msg_len:W64.t, ms:W64.t) : 
  BArray32.t * BArray64.t * W64.t * W64.t = {
    
    prefix_len <- (protect_64 prefix_len ms);
    (* Erased call to spill *)
    (h, buf, total, ms) <@ __sha256_absorb_prefix (h, buf, total, prefix,
    prefix_len, ms);
    (* Erased call to unspill *)
    msg <- (protect_64 msg ms);
    msg_len <- (protect_64 msg_len ms);
    (h, buf, total, ms) <@ _sha256_absorb_mem (h, buf, total, msg, msg_len,
    ms);
    return (h, buf, total, ms);
  }
  proc __sha512_absorb_message (h:BArray64.t, buf:BArray128.t, total:W64.t,
                                prefix:BArray332.t, prefix_len:W64.t,
                                msg:W64.t, msg_len:W64.t, ms:W64.t) : 
  BArray64.t * BArray128.t * W64.t * W64.t = {
    
    prefix_len <- (protect_64 prefix_len ms);
    (* Erased call to spill *)
    (h, buf, total, ms) <@ __sha512_absorb_prefix (h, buf, total, prefix,
    prefix_len, ms);
    (* Erased call to unspill *)
    msg <- (protect_64 msg ms);
    msg_len <- (protect_64 msg_len ms);
    (h, buf, total, ms) <@ _sha512_absorb_mem (h, buf, total, msg, msg_len,
    ms);
    return (h, buf, total, ms);
  }
  proc _prf_msg (r:BArray32.t, sk_prf:BArray32.t, opt_rand:BArray32.t,
                 prefix:BArray332.t, prefix_len:W64.t, msg:W64.t,
                 msg_len:W64.t, ms:W64.t) : BArray32.t * W64.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var k0:BArray128.t;
    var t:W64.t;
    var inner512:BArray64.t;
    var outer512:BArray64.t;
    var fill:W64.t;
    var buf512:BArray128.t;
    var total:W64.t;
    var tag512:BArray64.t;
    var inner:BArray32.t;
    var outer:BArray32.t;
    var buf:BArray64.t;
    var tag:BArray32.t;
    buf <- witness;
    buf512 <- witness;
    inner <- witness;
    inner512 <- witness;
    k0 <- witness;
    outer <- witness;
    outer512 <- witness;
    tag <- witness;
    tag512 <- witness;
    z <- (W64.of_int 0);
    i <- 0;
    while ((i < 16)) {
      k0 <- (BArray128.set64 k0 i z);
      i <- (i + 1);
    }
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 sk_prf i);
      k0 <- (BArray128.set64 k0 i t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    if ((((5 + 1) %/ 4) = 0)) {
      (inner, outer, ms) <@ __hmac_sha256_init (inner, outer,
      (SBArray128_64.get_sub8 k0 0), ms);
      fill <- (W64.of_int 0);
      i <- 0;
      while ((i < 8)) {
        buf <- (BArray64.set64 buf i fill);
        i <- (i + 1);
      }
      (* Erased call to unspill *)
      opt_rand <- (protect_ptr opt_rand ms);
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray32.get64 opt_rand i);
        buf <- (BArray64.set64 buf i t);
        i <- (i + 1);
      }
      total <- (W64.of_int (64 + 32));
      (* Erased call to unspill *)
      prefix <- (protect_ptr prefix ms);
      (inner, buf, total, ms) <@ __sha256_absorb_message (inner, buf, 
      total, prefix, prefix_len, msg, msg_len, ms);
      (tag, inner, buf, ms) <@ __hmac_sha256_finalize (tag, inner, buf,
      total, outer, ms);
      (* Erased call to unspill *)
      r <- (protect_ptr r ms);
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray32.get64 tag i);
        r <- (BArray32.set64 r i t);
        i <- (i + 1);
      }
    } else {
      (inner512, outer512, ms) <@ __hmac_sha512_init (inner512, outer512, 
      k0, ms);
      fill <- (W64.of_int 0);
      i <- 0;
      while ((i < 16)) {
        buf512 <- (BArray128.set64 buf512 i fill);
        i <- (i + 1);
      }
      (* Erased call to unspill *)
      opt_rand <- (protect_ptr opt_rand ms);
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray32.get64 opt_rand i);
        buf512 <- (BArray128.set64 buf512 i t);
        i <- (i + 1);
      }
      total <- (W64.of_int (128 + 32));
      (* Erased call to unspill *)
      prefix <- (protect_ptr prefix ms);
      (inner512, buf512, total, ms) <@ __sha512_absorb_message (inner512,
      buf512, total, prefix, prefix_len, msg, msg_len, ms);
      (tag512, inner512, buf512, ms) <@ __hmac_sha512_finalize (tag512,
      inner512, buf512, total, outer512, ms);
      (* Erased call to unspill *)
      r <- (protect_ptr r ms);
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray64.get64 tag512 i);
        r <- (BArray32.set64 r i t);
        i <- (i + 1);
      }
    }
    return (r, ms);
  }
  proc _h_msg (digest:BArray47.t, r:BArray32.t, pk:BArray64.t,
               prefix:BArray332.t, prefix_len:W64.t, msg:W64.t,
               msg_len:W64.t, ms:W64.t) : BArray47.t * W64.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    var head:BArray96.t;
    var seed:BArray128.t;
    var h512:BArray64.t;
    var fill:W64.t;
    var buf512:BArray128.t;
    var total:W64.t;
    var d512:BArray64.t;
    var h:BArray32.t;
    var buf:BArray64.t;
    var d256:BArray32.t;
    buf <- witness;
    buf512 <- witness;
    d256 <- witness;
    d512 <- witness;
    h <- witness;
    h512 <- witness;
    head <- witness;
    seed <- witness;
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 r i);
      head <- (BArray96.set64 head i t);
      seed <- (BArray128.set64 seed i t);
      i <- (i + 1);
    }
    inc <- ((2 * 32) %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray64.get64 pk i);
      head <- (BArray96.set64 head ((32 %/ 8) + i) t);
      i <- (i + 1);
    }
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray64.get64 pk i);
      seed <- (BArray128.set64 seed ((32 %/ 8) + i) t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    if ((((5 + 1) %/ 4) = 0)) {
      h <@ __sha256_init (h);
      fill <- (W64.of_int 0);
      i <- 0;
      while ((i < 8)) {
        buf <- (BArray64.set64 buf i fill);
        i <- (i + 1);
      }
      inc <- ((3 * 32) %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray96.get64 head i);
        buf <- (BArray64.set64 buf i t);
        i <- (i + 1);
      }
      total <- (W64.of_int (3 * 32));
      (* Erased call to unspill *)
      prefix <- (protect_ptr prefix ms);
      (h, buf, total, ms) <@ __sha256_absorb_message (h, buf, total, 
      prefix, prefix_len, msg, msg_len, ms);
      (d256, h, buf, ms) <@ _sha256_finalize (d256, h, buf, total, ms);
      i <- 0;
      while ((i < 4)) {
        t <- (BArray32.get64 d256 i);
        seed <- (BArray128.set64 seed (((2 * 32) %/ 8) + i) t);
        i <- (i + 1);
      }
    } else {
      h512 <@ __sha512_init (h512);
      fill <- (W64.of_int 0);
      i <- 0;
      while ((i < 16)) {
        buf512 <- (BArray128.set64 buf512 i fill);
        i <- (i + 1);
      }
      inc <- ((3 * 32) %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray96.get64 head i);
        buf512 <- (BArray128.set64 buf512 i t);
        i <- (i + 1);
      }
      total <- (W64.of_int (3 * 32));
      (* Erased call to unspill *)
      prefix <- (protect_ptr prefix ms);
      (h512, buf512, total, ms) <@ __sha512_absorb_message (h512, buf512,
      total, prefix, prefix_len, msg, msg_len, ms);
      (d512, h512, buf512, ms) <@ _sha512_finalize (d512, h512, buf512,
      total, ms);
      i <- 0;
      while ((i < 8)) {
        t <- (BArray64.get64 d512 i);
        seed <- (BArray128.set64 seed (((2 * 32) %/ 8) + i) t);
        i <- (i + 1);
      }
    }
    (* Erased call to unspill *)
    digest <- (protect_ptr digest ms);
    if ((((5 + 1) %/ 4) = 0)) {
      (digest, ms) <@ mgf___mgf1_sha256 (digest, seed, ms);
    } else {
      (digest, ms) <@ mgf___mgf1_sha512 (digest, seed, ms);
    }
    return (digest, ms);
  }
  proc _thash_prf_x4 (out:BArray128.t, sk_seed:BArray32.t, ctx:BArray96.t,
                      adrs:BArray128.t, ms:W64.t) : BArray128.t * W64.t = {
    var inc:int;
    var i:int;
    var k:int;
    var t:W64.t;
    var a:BArray32.t;
    var one:BArray32.t;
    var res_0:BArray128.t;
    a <- witness;
    one <- witness;
    res_0 <- witness;
    (* Erased call to spill *)
    k <- 0;
    while ((k < 4)) {
      (* Erased call to unspill *)
      sk_seed <- (protect_ptr sk_seed ms);
      ctx <- (protect_ptr ctx ms);
      adrs <- (protect_ptr adrs ms);
      (* Erased call to spill *)
      i <- 0;
      while ((i < 4)) {
        t <- (BArray128.get64 adrs ((4 * k) + i));
        a <- (BArray32.set64 a i t);
        i <- (i + 1);
      }
      (one, ms) <@ _thash_prf (one, sk_seed, ctx, a, ms);
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray32.get64 one i);
        res_0 <- (BArray128.set64 res_0 (((32 %/ 8) * k) + i) t);
        i <- (i + 1);
      }
      k <- (k + 1);
    }
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    inc <- (32 %/ 2);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray128.get64 res_0 i);
      out <- (BArray128.set64 out i t);
      i <- (i + 1);
    }
    return (out, ms);
  }
  proc _thash_f_x4 (x:BArray128.t, ctx:BArray96.t, adrs:BArray128.t, ms:W64.t) : 
  BArray128.t * W64.t = {
    var inc:int;
    var i:int;
    var t:W64.t;
    var res_0:BArray128.t;
    var k:int;
    var a:BArray32.t;
    var one:BArray32.t;
    a <- witness;
    one <- witness;
    res_0 <- witness;
    inc <- (32 %/ 2);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray128.get64 x i);
      res_0 <- (BArray128.set64 res_0 i t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    k <- 0;
    while ((k < 4)) {
      (* Erased call to unspill *)
      ctx <- (protect_ptr ctx ms);
      adrs <- (protect_ptr adrs ms);
      (* Erased call to spill *)
      i <- 0;
      while ((i < 4)) {
        t <- (BArray128.get64 adrs ((4 * k) + i));
        a <- (BArray32.set64 a i t);
        i <- (i + 1);
      }
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray128.get64 res_0 (((32 %/ 8) * k) + i));
        one <- (BArray32.set64 one i t);
        i <- (i + 1);
      }
      (one, ms) <@ _thash_f (one, ctx, a, ms);
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray32.get64 one i);
        res_0 <- (BArray128.set64 res_0 (((32 %/ 8) * k) + i) t);
        i <- (i + 1);
      }
      k <- (k + 1);
    }
    (* Erased call to unspill *)
    x <- (protect_ptr x ms);
    inc <- (32 %/ 2);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray128.get64 res_0 i);
      x <- (BArray128.set64 x i t);
      i <- (i + 1);
    }
    return (x, ms);
  }
  proc _thash_t_len_x4 (out:BArray128.t, in_0:BArray8576.t, ctx:BArray96.t,
                        adrs:BArray128.t, ms:W64.t) : BArray128.t * W64.t = {
    var inc:int;
    var i:int;
    var k:int;
    var t:W64.t;
    var a:BArray32.t;
    var one:BArray32.t;
    var res_0:BArray128.t;
    a <- witness;
    one <- witness;
    res_0 <- witness;
    (* Erased call to spill *)
    k <- 0;
    while ((k < 4)) {
      (* Erased call to unspill *)
      in_0 <- (protect_ptr in_0 ms);
      ctx <- (protect_ptr ctx ms);
      adrs <- (protect_ptr adrs ms);
      (* Erased call to spill *)
      i <- 0;
      while ((i < 4)) {
        t <- (BArray128.get64 adrs ((4 * k) + i));
        a <- (BArray32.set64 a i t);
        i <- (i + 1);
      }
      (one, ms) <@ tLen___thash_t (one,
      (SBArray8576_2144.get_sub8 in_0 ((((2 * 32) + 3) * 32) * k)), ctx, 
      a, ms);
      inc <- (32 %/ 8);
      i <- 0;
      while ((i < inc)) {
        t <- (BArray32.get64 one i);
        res_0 <- (BArray128.set64 res_0 (((32 %/ 8) * k) + i) t);
        i <- (i + 1);
      }
      k <- (k + 1);
    }
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    inc <- (32 %/ 2);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray128.get64 res_0 i);
      out <- (BArray128.set64 out i t);
      i <- (i + 1);
    }
    return (out, ms);
  }
  proc __wots_digits (d:BArray67.t, msg:BArray32.t) : BArray67.t = {
    var csum:W32.t;
    var i:int;
    var b:W32.t;
    var hi:W32.t;
    var lo:W32.t;
    var t:W32.t;
    csum <- (W32.of_int 0);
    i <- 0;
    while ((i < 32)) {
      b <- (zeroextu32 (BArray32.get8 msg i));
      hi <- b;
      hi <- (hi `>>` (W8.of_int 4));
      lo <- b;
      lo <- (lo `&` (W32.of_int 15));
      d <- (BArray67.set8 d (2 * i) (truncateu8 hi));
      d <- (BArray67.set8 d ((2 * i) + 1) (truncateu8 lo));
      csum <- (csum + (W32.of_int 30));
      csum <- (csum - hi);
      csum <- (csum - lo);
      i <- (i + 1);
    }
    t <- csum;
    t <- (t `>>` (W8.of_int 8));
    d <- (BArray67.set8 d (2 * 32) (truncateu8 t));
    t <- csum;
    t <- (t `>>` (W8.of_int 4));
    t <- (t `&` (W32.of_int 15));
    d <- (BArray67.set8 d ((2 * 32) + 1) (truncateu8 t));
    t <- csum;
    t <- (t `&` (W32.of_int 15));
    d <- (BArray67.set8 d ((2 * 32) + 2) (truncateu8 t));
    return d;
  }
  proc _wots_chain (x:BArray32.t, start:W32.t, steps:W32.t, ctx:BArray96.t,
                    adrs:BArray32.t, ms:W64.t) : BArray32.t * BArray32.t *
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
  proc _wots_leaf_x4 (leaves:BArray128.t, sig:BArray2144.t,
                      sk_seed:BArray32.t, ctx:BArray96.t, adrs:BArray32.t,
                      kp0:W32.t, steps:BArray67.t, lane:W64.t, ms:W64.t) : 
  BArray128.t * BArray2144.t * W64.t = {
    var aux:BArray32.t;
    var inc:int;
    var kp:W32.t;
    var k:int;
    var sk_adrs:BArray128.t;
    var chain_adrs:BArray128.t;
    var pk_adrs:BArray128.t;
    var fill:W64.t;
    var pk:BArray8576.t;
    var i:W32.t;
    var more:bool;
    var cur:BArray128.t;
    var split_0:W32.t;
    var take:bool;
    var off:W64.t;
    var j:W32.t;
    var step:bool;
    var hit:bool;
    var src:W64.t;
    var cp:BArray128.t;
    var t:W64.t;
    var w:int;
    var fwd:bool;
    var dst:BArray8576.t;
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
    inc <- (((4 * ((2 * 32) + 3)) * 32) %/ 8);
    k <- 0;
    while ((k < inc)) {
      pk <- (BArray8576.set64 pk k fill);
      k <- (k + 1);
    }
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int ((2 * 32) + 3)));
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
        split_0 <- (zeroextu32 (BArray67.get8 steps (W64.to_uint off)));
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
          off <@ __offset (i, 32);
          src <@ __offset64 (lane, 32);
          cp <- cur;
          inc <- (32 %/ 8);
          w <- 0;
          while ((w < inc)) {
            t <- (BArray128.get64d cp (W64.to_uint src));
            sig <- (BArray2144.set64d sig (W64.to_uint off) t);
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
      off <@ __offset (i, 32);
      dst <- pk;
      k <- 0;
      while ((k < 4)) {
        inc <- (32 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray128.get64 cur (((32 %/ 8) * k) + w));
          dst <- (BArray8576.set64d dst (W64.to_uint off) t);
          off <- (off + (W64.of_int 8));
          w <- (w + 1);
        }
        off <- (off + (W64.of_int ((((2 * 32) + 3) - 1) * 32)));
        k <- (k + 1);
      }
      pk <- dst;
      i <- (i + (W32.of_int 1));
      more <- (i \ult (W32.of_int ((2 * 32) + 3)));
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
  proc _wots_pk_from_sig (pk:BArray32.t, sig:BArray2144.t, msg:BArray32.t,
                          ctx:BArray96.t, adrs:BArray32.t, keypair:W32.t,
                          ms:W64.t) : BArray32.t * W64.t = {
    var aux:BArray32.t;
    var inc:int;
    var digits:BArray67.t;
    var chain_adrs:BArray32.t;
    var pk_adrs:BArray32.t;
    var fill:W64.t;
    var k:int;
    var tmp:BArray2144.t;
    var i:W32.t;
    var more:bool;
    var dp:BArray67.t;
    var off:W64.t;
    var start:W32.t;
    var steps:W32.t;
    var cur:BArray32.t;
    var dst:BArray2144.t;
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
    inc <- ((((2 * 32) + 3) * 32) %/ 8);
    k <- 0;
    while ((k < inc)) {
      tmp <- (BArray2144.set64 tmp k fill);
      k <- (k + 1);
    }
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int ((2 * 32) + 3)));
    while (more) {
      ms <- (update_msf more ms);
      chain_adrs <@ __adrs_set_chain (chain_adrs, i);
      dp <- digits;
      off <- (zeroextu64 i);
      start <- (zeroextu32 (BArray67.get8 dp (W64.to_uint off)));
      start <- (protect_32 start ms);
      steps <- (W32.of_int (16 - 1));
      steps <- (steps - start);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      (* Erased call to spill *)
      off <@ __offset (i, 32);
      cur <@ __node_copy (cur,
      (SBArray2144_32.get_sub8 sig (W64.to_uint off)));
      (* Erased call to spill *)
      (* Erased call to unspill *)
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      (cur, chain_adrs, ms) <@ _wots_chain (cur, start, steps, ctx,
      chain_adrs, ms);
      (* Erased call to unspill *)
      i <- (protect_32 i ms);
      (* Erased call to spill *)
      off <@ __offset (i, 32);
      dst <- tmp;
      aux <@ __node_copy ((SBArray2144_32.get_sub8 dst (W64.to_uint off)),
      cur);
      dst <- (SBArray2144_32.set_sub8 dst (W64.to_uint off) aux);
      tmp <- dst;
      i <- (i + (W32.of_int 1));
      more <- (i \ult (W32.of_int ((2 * 32) + 3)));
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
    cap <- (W32.of_int 14);
    z <- ((z \ult (W32.of_int 14)) ? z : cap);
    off <@ __offset (z, 32);
    return off;
  }
  proc _treehash_fold (nodes:BArray480.t, auth:BArray480.t, node:BArray32.t,
                       idx:W32.t, adrs_idx:W32.t, target:W32.t,
                       ctx:BArray96.t, node_adrs:BArray32.t, ms:W64.t) : 
  BArray480.t * BArray480.t * BArray32.t * BArray32.t * W64.t = {
    var aux:BArray32.t;
    var z:W32.t;
    var sib:W32.t;
    var odd:bool;
    var off:W64.t;
    var pair:BArray64.t;
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
      aux <@ __node_copy ((SBArray480_32.get_sub8 auth (W64.to_uint off)),
      node);
      auth <- (SBArray480_32.set_sub8 auth (W64.to_uint off) aux);
    } else {
      ms <- (update_msf (! found) ms);
    }
    bit <- idx;
    bit <- (bit `&` (W32.of_int 1));
    odd <- (bit = (W32.of_int 1));
    while (odd) {
      ms <- (update_msf odd ms);
      off <@ __fold_slot (z);
      aux <@ __node_copy ((SBArray64_32.get_sub8 pair 0),
      (SBArray480_32.get_sub8 nodes (W64.to_uint off)));
      pair <- (SBArray64_32.set_sub8 pair 0 aux);
      aux <@ __node_copy ((SBArray64_32.get_sub8 pair 32), node);
      pair <- (SBArray64_32.set_sub8 pair 32 aux);
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
        aux <@ __node_copy ((SBArray480_32.get_sub8 auth (W64.to_uint off)),
        node);
        auth <- (SBArray480_32.set_sub8 auth (W64.to_uint off) aux);
      } else {
        ms <- (update_msf (! found) ms);
      }
      bit <- idx;
      bit <- (bit `&` (W32.of_int 1));
      odd <- (bit = (W32.of_int 1));
    }
    ms <- (update_msf (! odd) ms);
    off <@ __fold_slot (z);
    aux <@ __node_copy ((SBArray480_32.get_sub8 nodes (W64.to_uint off)),
    node);
    nodes <- (SBArray480_32.set_sub8 nodes (W64.to_uint off) aux);
    return (nodes, auth, node, node_adrs, ms);
  }
  proc _xmss_treehash (root:BArray32.t, sig:BArray2400.t, sk_seed:BArray32.t,
                       ctx:BArray96.t, adrs:BArray32.t, target:W32.t,
                       steps:BArray67.t, ms:W64.t) : BArray32.t *
                                                     BArray2400.t * W64.t = {
    var inc:int;
    var tree_adrs:BArray32.t;
    var fill:W64.t;
    var k:int;
    var nodes:BArray480.t;
    var auth:BArray480.t;
    var wsig:BArray2144.t;
    var i:W32.t;
    var more:bool;
    var d:W32.t;
    var lane:W64.t;
    var four:W64.t;
    var kp:W32.t;
    var leaves:BArray128.t;
    var w:int;
    var t:W64.t;
    var node:BArray32.t;
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
    inc <- (((14 + 1) * 32) %/ 8);
    k <- 0;
    while ((k < inc)) {
      nodes <- (BArray480.set64 nodes k fill);
      auth <- (BArray480.set64 auth k fill);
      k <- (k + 1);
    }
    inc <- ((((2 * 32) + 3) * 32) %/ 8);
    k <- 0;
    while ((k < inc)) {
      wsig <- (BArray2144.set64 wsig k fill);
      k <- (k + 1);
    }
    (* Erased call to spill *)
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int (1 `<<` 8)));
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
        inc <- (32 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray128.get64 leaves (((32 %/ 8) * k) + w));
          node <- (BArray32.set64 node w t);
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
      more <- (i \ult (W32.of_int (1 `<<` 8)));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    root <- (protect_ptr root ms);
    sig <- (protect_ptr sig ms);
    target <- (protect_32 target ms);
    root <@ __node_copy (root, (SBArray480_32.get_sub8 nodes (8 * 32)));
    found <- (target \ult (W32.of_int (1 `<<` 8)));
    if (found) {
      ms <- (update_msf found ms);
      inc <- ((((2 * 32) + 3) * 32) %/ 8);
      k <- 0;
      while ((k < inc)) {
        t <- (BArray2144.get64 wsig k);
        sig <- (BArray2400.set64 sig k t);
        k <- (k + 1);
      }
      inc <- ((8 * 32) %/ 8);
      k <- 0;
      while ((k < inc)) {
        t <- (BArray480.get64 auth k);
        sig <- (BArray2400.set64 sig (((((2 * 32) + 3) * 32) %/ 8) + k) t);
        k <- (k + 1);
      }
    } else {
      ms <- (update_msf (! found) ms);
    }
    return (root, sig, ms);
  }
  proc _xmss_pk_from_sig (root:BArray32.t, sig:BArray2400.t, msg:BArray32.t,
                          ctx:BArray96.t, adrs:BArray32.t, idx:W32.t,
                          ms:W64.t) : BArray32.t * W64.t = {
    var aux:BArray32.t;
    var tree_adrs:BArray32.t;
    var kp:W32.t;
    var node:BArray32.t;
    var k:W32.t;
    var more:bool;
    var off:W64.t;
    var bit:W32.t;
    var odd:bool;
    var pair:BArray64.t;
    node <- witness;
    pair <- witness;
    tree_adrs <- witness;
    tree_adrs <@ __adrs_copy (tree_adrs, adrs);
    tree_adrs <@ __adrs_set_type_and_clear (tree_adrs, 2);
    (* Erased call to spill *)
    kp <- idx;
    (node, ms) <@ _wots_pk_from_sig (node, (SBArray2400_2144.get_sub8 sig 0),
    msg, ctx, adrs, kp, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    idx <- (protect_32 idx ms);
    (* Erased call to spill *)
    k <- (W32.of_int 0);
    more <- (k \ult (W32.of_int 8));
    while (more) {
      ms <- (update_msf more ms);
      off <@ __offset (k, 32);
      off <- (off + (W64.of_int (((2 * 32) + 3) * 32)));
      bit <- idx;
      bit <- (bit `&` (W32.of_int 1));
      odd <- (bit = (W32.of_int 1));
      if (odd) {
        ms <- (update_msf odd ms);
        aux <@ __node_copy ((SBArray64_32.get_sub8 pair 0),
        (SBArray2400_32.get_sub8 sig (W64.to_uint off)));
        pair <- (SBArray64_32.set_sub8 pair 0 aux);
        aux <@ __node_copy ((SBArray64_32.get_sub8 pair 32), node);
        pair <- (SBArray64_32.set_sub8 pair 32 aux);
      } else {
        ms <- (update_msf (! odd) ms);
        aux <@ __node_copy ((SBArray64_32.get_sub8 pair 0), node);
        pair <- (SBArray64_32.set_sub8 pair 0 aux);
        aux <@ __node_copy ((SBArray64_32.get_sub8 pair 32),
        (SBArray2400_32.get_sub8 sig (W64.to_uint off)));
        pair <- (SBArray64_32.set_sub8 pair 32 aux);
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
      more <- (k \ult (W32.of_int 8));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    root <- (protect_ptr root ms);
    root <@ __node_copy (root, node);
    return (root, ms);
  }
  proc _ht_sign (sig:BArray29792.t, msg:BArray32.t, sk_seed:BArray32.t,
                 ctx:BArray96.t, idx_tree:W64.t, idx_leaf:W32.t, ms:W64.t) : 
  BArray29792.t * BArray32.t * W64.t = {
    var adrs:BArray32.t;
    var j:W32.t;
    var more:bool;
    var digits:BArray67.t;
    var leaf:W32.t;
    var layer:BArray2400.t;
    var off:W64.t;
    var src:BArray2400.t;
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
    more <- (j \ult (W32.of_int 8));
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
      off <@ __offset (j, ((((2 * 32) + 3) + 8) * 32));
      off <- (off + (W64.of_int (32 + ((22 * (14 + 1)) * 32))));
      src <- layer;
      k <- (W64.of_int 0);
      copy <- (k \ult (W64.of_int ((((2 * 32) + 3) + 8) * 32)));
      while (copy) {
        ms <- (update_msf copy ms);
        t <- (BArray2400.get64d src (W64.to_uint k));
        o <- off;
        o <- (o + k);
        sig <- (BArray29792.set64d sig (W64.to_uint o) t);
        k <- (k + (W64.of_int 8));
        copy <- (k \ult (W64.of_int ((((2 * 32) + 3) + 8) * 32)));
      }
      ms <- (update_msf (! copy) ms);
      layer <- src;
      (* Erased call to spill *)
      idx_leaf <- (truncateu32 idx_tree);
      idx_leaf <- (idx_leaf `&` (W32.of_int ((1 `<<` 8) - 1)));
      idx_tree <- (idx_tree `>>` (W8.of_int 8));
      j <- (j + (W32.of_int 1));
      more <- (j \ult (W32.of_int 8));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    return (sig, msg, ms);
  }
  proc _ht_verify (sig:BArray19200.t, msg:BArray32.t, pk_root:BArray32.t,
                   ctx:BArray96.t, idx_tree:W64.t, idx_leaf:W32.t, ms:W64.t) : 
  W64.t * W64.t = {
    var inc:int;
    var result:W64.t;
    var node:BArray32.t;
    var adrs:BArray32.t;
    var j:W32.t;
    var more:bool;
    var off:W64.t;
    var leaf:W32.t;
    var next:BArray32.t;
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
    more <- (j \ult (W32.of_int 8));
    while (more) {
      ms <- (update_msf more ms);
      adrs <@ __adrs_set_layer (adrs, j);
      adrs <@ __adrs_set_tree (adrs, idx_tree);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      off <@ __offset (j, ((((2 * 32) + 3) + 8) * 32));
      leaf <- idx_leaf;
      (* Erased call to spill *)
      (next, ms) <@ _xmss_pk_from_sig (next,
      (SBArray19200_2400.get_sub8 sig (W64.to_uint off)), node, ctx, 
      adrs, leaf, ms);
      (* Erased call to unspill *)
      j <- (protect_32 j ms);
      idx_tree <- (protect_64 idx_tree ms);
      idx_leaf <- (protect_32 idx_leaf ms);
      (* Erased call to spill *)
      node <@ __node_copy (node, next);
      idx_leaf <- (truncateu32 idx_tree);
      idx_leaf <- (idx_leaf `&` (W32.of_int ((1 `<<` 8) - 1)));
      idx_tree <- (idx_tree `>>` (W8.of_int 8));
      j <- (j + (W32.of_int 1));
      more <- (j \ult (W32.of_int 8));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    pk_root <- (protect_ptr pk_root ms);
    diff <- (W64.of_int 0);
    inc <- (32 %/ 8);
    k <- 0;
    while ((k < inc)) {
      t <- (BArray32.get64 node k);
      u <- (BArray32.get64 pk_root k);
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
  proc _fors_tree (sig:BArray480.t, root:BArray32.t, sk_seed:BArray32.t,
                   ctx:BArray96.t, adrs:BArray32.t, tree:W32.t, target:W32.t,
                   ms:W64.t) : BArray480.t * BArray32.t * W64.t = {
    var aux:BArray32.t;
    var inc:int;
    var k:int;
    var sk_adrs:BArray128.t;
    var leaf_adrs:BArray128.t;
    var node_adrs:BArray32.t;
    var fill:W64.t;
    var nodes:BArray480.t;
    var auth:BArray480.t;
    var selected:BArray32.t;
    var base:W32.t;
    var i:W32.t;
    var more:bool;
    var g:W32.t;
    var z:W32.t;
    var gk:W32.t;
    var leaves:BArray128.t;
    var d:W32.t;
    var found:bool;
    var src:W64.t;
    var lp:BArray128.t;
    var t:W64.t;
    var w:int;
    var node:BArray32.t;
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
    inc <- (((14 + 1) * 32) %/ 8);
    k <- 0;
    while ((k < inc)) {
      nodes <- (BArray480.set64 nodes k fill);
      auth <- (BArray480.set64 auth k fill);
      k <- (k + 1);
    }
    inc <- (32 %/ 8);
    k <- 0;
    while ((k < inc)) {
      selected <- (BArray32.set64 selected k fill);
      k <- (k + 1);
    }
    base <- tree;
    base <- (base `<<` (W8.of_int 14));
    (* Erased call to spill *)
    i <- (W32.of_int 0);
    more <- (i \ult (W32.of_int (1 `<<` 14)));
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
        src <@ __offset64 (src, 32);
        lp <- leaves;
        inc <- (32 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray128.get64d lp (W64.to_uint src));
          selected <- (BArray32.set64 selected w t);
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
        inc <- (32 %/ 8);
        w <- 0;
        while ((w < inc)) {
          t <- (BArray128.get64 leaves (((32 %/ 8) * k) + w));
          node <- (BArray32.set64 node w t);
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
      more <- (i \ult (W32.of_int (1 `<<` 14)));
    }
    ms <- (update_msf (! more) ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    root <- (protect_ptr root ms);
    root <@ __node_copy (root, (SBArray480_32.get_sub8 nodes (14 * 32)));
    aux <@ __node_copy ((SBArray480_32.get_sub8 sig 0), selected);
    sig <- (SBArray480_32.set_sub8 sig 0 aux);
    inc <- ((14 * 32) %/ 8);
    k <- 0;
    while ((k < inc)) {
      t <- (BArray480.get64 auth k);
      sig <- (BArray480.set64 sig ((32 %/ 8) + k) t);
      k <- (k + 1);
    }
    return (sig, root, ms);
  }
  proc _fors_sign (sig:BArray29792.t, pk_fors:BArray32.t, indices:BArray88.t,
                   sk_seed:BArray32.t, ctx:BArray96.t, adrs:BArray32.t,
                   ms:W64.t) : BArray29792.t * BArray32.t * W64.t = {
    var aux:BArray32.t;
    var inc:int;
    var fill:W64.t;
    var j:int;
    var roots:BArray704.t;
    var t:W32.t;
    var more:bool;
    var ti:W64.t;
    var target:W32.t;
    var tree:W32.t;
    var tree_sig:BArray480.t;
    var root:BArray32.t;
    var off:W64.t;
    var src:BArray480.t;
    var k:W64.t;
    var copy:bool;
    var w:W64.t;
    var o:W64.t;
    var root_off:W64.t;
    var dst:BArray704.t;
    var roots_adrs:BArray32.t;
    dst <- witness;
    root <- witness;
    roots <- witness;
    roots_adrs <- witness;
    src <- witness;
    tree_sig <- witness;
    (* Erased call to spill *)
    fill <- (W64.of_int 0);
    inc <- ((22 * 32) %/ 8);
    j <- 0;
    while ((j < inc)) {
      roots <- (BArray704.set64 roots j fill);
      j <- (j + 1);
    }
    t <- (W32.of_int 0);
    more <- (t \ult (W32.of_int 22));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to unspill *)
      indices <- (protect_ptr indices ms);
      (* Erased call to spill *)
      ti <- (zeroextu64 t);
      target <- (BArray88.get32 indices (W64.to_uint ti));
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
      off <@ __offset (t, ((14 + 1) * 32));
      off <- (off + (W64.of_int 32));
      src <- tree_sig;
      k <- (W64.of_int 0);
      copy <- (k \ult (W64.of_int ((14 + 1) * 32)));
      while (copy) {
        ms <- (update_msf copy ms);
        w <- (BArray480.get64d src (W64.to_uint k));
        o <- off;
        o <- (o + k);
        sig <- (BArray29792.set64d sig (W64.to_uint o) w);
        k <- (k + (W64.of_int 8));
        copy <- (k \ult (W64.of_int ((14 + 1) * 32)));
      }
      ms <- (update_msf (! copy) ms);
      tree_sig <- src;
      (* Erased call to spill *)
      root_off <@ __offset (t, 32);
      dst <- roots;
      aux <@ __node_copy ((SBArray704_32.get_sub8 dst (W64.to_uint root_off)),
      root);
      dst <- (SBArray704_32.set_sub8 dst (W64.to_uint root_off) aux);
      roots <- dst;
      t <- (t + (W32.of_int 1));
      more <- (t \ult (W32.of_int 22));
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
  proc _fors_pk_from_sig (pk_fors:BArray32.t, sig:BArray10560.t,
                          indices:BArray88.t, ctx:BArray96.t,
                          adrs:BArray32.t, ms:W64.t) : BArray32.t * W64.t = {
    var aux:BArray32.t;
    var inc:int;
    var node_adrs:BArray32.t;
    var fill:W64.t;
    var k:int;
    var roots:BArray704.t;
    var t:W32.t;
    var more:bool;
    var ti:W64.t;
    var idx:W32.t;
    var g:W32.t;
    var sig_off:W64.t;
    var node:BArray32.t;
    var z:W32.t;
    var climb:bool;
    var auth_off:W64.t;
    var bit:W32.t;
    var odd:bool;
    var pair:BArray64.t;
    var root_off:W64.t;
    var dst:BArray704.t;
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
    inc <- ((22 * 32) %/ 8);
    k <- 0;
    while ((k < inc)) {
      roots <- (BArray704.set64 roots k fill);
      k <- (k + 1);
    }
    t <- (W32.of_int 0);
    more <- (t \ult (W32.of_int 22));
    while (more) {
      ms <- (update_msf more ms);
      (* Erased call to unspill *)
      indices <- (protect_ptr indices ms);
      (* Erased call to spill *)
      ti <- (zeroextu64 t);
      idx <- (BArray88.get32 indices (W64.to_uint ti));
      idx <- (protect_32 idx ms);
      g <- t;
      g <- (g `<<` (W8.of_int 14));
      g <- (g + idx);
      (* Erased call to unspill *)
      sig <- (protect_ptr sig ms);
      ctx <- (protect_ptr ctx ms);
      (* Erased call to spill *)
      sig_off <@ __offset (t, ((14 + 1) * 32));
      node <@ __node_copy (node,
      (SBArray10560_32.get_sub8 sig (W64.to_uint sig_off)));
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
      climb <- (z \ult (W32.of_int 14));
      while (climb) {
        ms <- (update_msf climb ms);
        (* Erased call to unspill *)
        sig <- (protect_ptr sig ms);
        (* Erased call to spill *)
        auth_off <@ __offset (z, 32);
        auth_off <- (auth_off + sig_off);
        auth_off <- (auth_off + (W64.of_int 32));
        bit <- idx;
        bit <- (bit `&` (W32.of_int 1));
        odd <- (bit = (W32.of_int 1));
        if (odd) {
          ms <- (update_msf odd ms);
          aux <@ __node_copy ((SBArray64_32.get_sub8 pair 0),
          (SBArray10560_32.get_sub8 sig (W64.to_uint auth_off)));
          pair <- (SBArray64_32.set_sub8 pair 0 aux);
          aux <@ __node_copy ((SBArray64_32.get_sub8 pair 32), node);
          pair <- (SBArray64_32.set_sub8 pair 32 aux);
        } else {
          ms <- (update_msf (! odd) ms);
          aux <@ __node_copy ((SBArray64_32.get_sub8 pair 0), node);
          pair <- (SBArray64_32.set_sub8 pair 0 aux);
          aux <@ __node_copy ((SBArray64_32.get_sub8 pair 32),
          (SBArray10560_32.get_sub8 sig (W64.to_uint auth_off)));
          pair <- (SBArray64_32.set_sub8 pair 32 aux);
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
        climb <- (z \ult (W32.of_int 14));
      }
      ms <- (update_msf (! climb) ms);
      root_off <@ __offset (t, 32);
      dst <- roots;
      aux <@ __node_copy ((SBArray704_32.get_sub8 dst (W64.to_uint root_off)),
      node);
      dst <- (SBArray704_32.set_sub8 dst (W64.to_uint root_off) aux);
      roots <- dst;
      t <- (t + (W32.of_int 1));
      more <- (t \ult (W32.of_int 22));
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
  proc _slh_keygen (pk:BArray64.t, sk:BArray128.t, seeds:BArray96.t, ms:W64.t) : 
  BArray64.t * BArray128.t * W64.t = {
    var aux:BArray32.t;
    var inc:int;
    var i:int;
    var t:W64.t;
    var no_steps:BArray67.t;
    var ctx:BArray96.t;
    var adrs:BArray32.t;
    var layer:W32.t;
    var target:W32.t;
    var root:BArray32.t;
    var no_sig:BArray2400.t;
    adrs <- witness;
    ctx <- witness;
    no_sig <- witness;
    no_steps <- witness;
    root <- witness;
    inc <- ((3 * 32) %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray96.get64 seeds i);
      sk <- (BArray128.set64 sk i t);
      i <- (i + 1);
    }
    t <- (W64.of_int 0);
    inc <- ((2 * 32) + 3);
    i <- 0;
    while ((i < inc)) {
      no_steps <- (BArray67.set8 no_steps i (truncateu8 t));
      i <- (i + 1);
    }
    (* Erased call to declassify *)
    (* Erased call to spill *)
    (ctx, ms) <@ _thash_ctx_init (ctx, (SBArray128_32.get_sub8 sk (2 * 32)),
    ms);
    (* Erased call to unspill *)
    sk <- (protect_ptr sk ms);
    adrs <@ __adrs_zero (adrs);
    layer <- (W32.of_int (8 - 1));
    adrs <@ __adrs_set_layer (adrs, layer);
    target <- (W32.of_int (- 1));
    (* Erased call to spill *)
    (root, no_sig, ms) <@ _xmss_treehash (root, no_sig,
    (SBArray128_32.get_sub8 sk 0), ctx, adrs, target, no_steps, ms);
    (* Erased call to unspill *)
    pk <- (protect_ptr pk ms);
    sk <- (protect_ptr sk ms);
    aux <@ __node_copy ((SBArray128_32.get_sub8 sk (3 * 32)), root);
    sk <- (SBArray128_32.set_sub8 sk (3 * 32) aux);
    aux <@ __node_copy ((SBArray64_32.get_sub8 pk 0),
    (SBArray128_32.get_sub8 sk (2 * 32)));
    pk <- (SBArray64_32.set_sub8 pk 0 aux);
    aux <@ __node_copy ((SBArray64_32.get_sub8 pk 32), root);
    pk <- (SBArray64_32.set_sub8 pk 32 aux);
    return (pk, sk, ms);
  }
  proc _slh_sign (sig:BArray29792.t, prefix:BArray332.t, prefix_len:W64.t,
                  msg:W64.t, msg_len:W64.t, sk:BArray128.t,
                  opt_rand:BArray32.t, ms:W64.t) : BArray29792.t * W64.t = {
    var inc:int;
    var ctx:BArray96.t;
    var r:BArray32.t;
    var i:int;
    var t:W64.t;
    var digest:BArray47.t;
    var indices:BArray88.t;
    var idx_tree:W64.t;
    var idx_leaf:W32.t;
    var adrs:BArray32.t;
    var pk_fors:BArray32.t;
    adrs <- witness;
    ctx <- witness;
    digest <- witness;
    indices <- witness;
    pk_fors <- witness;
    r <- witness;
    (* Erased call to spill *)
    (ctx, ms) <@ _thash_ctx_init (ctx, (SBArray128_32.get_sub8 sk (2 * 32)),
    ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    prefix <- (protect_ptr prefix ms);
    sk <- (protect_ptr sk ms);
    opt_rand <- (protect_ptr opt_rand ms);
    (* Erased call to spill *)
    (r, ms) <@ _prf_msg (r, (SBArray128_32.get_sub8 sk 32), opt_rand, 
    prefix, prefix_len, msg, msg_len, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    prefix <- (protect_ptr prefix ms);
    sk <- (protect_ptr sk ms);
    inc <- (32 %/ 8);
    i <- 0;
    while ((i < inc)) {
      t <- (BArray32.get64 r i);
      sig <- (BArray29792.set64 sig i t);
      i <- (i + 1);
    }
    (* Erased call to spill *)
    (digest, ms) <@ _h_msg (digest, r, (SBArray128_64.get_sub8 sk (2 * 32)),
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
    (SBArray128_32.get_sub8 sk 0), ctx, adrs, ms);
    pk_fors <@ __hook_fors_pk (pk_fors);
    (* Erased call to unspill *)
    sk <- (protect_ptr sk ms);
    idx_tree <- (protect_64 idx_tree ms);
    idx_leaf <- (protect_32 idx_leaf ms);
    (sig, pk_fors, ms) <@ _ht_sign (sig, pk_fors,
    (SBArray128_32.get_sub8 sk 0), ctx, idx_tree, idx_leaf, ms);
    return (sig, ms);
  }
  proc _slh_verify (sig:BArray29792.t, prefix:BArray332.t, prefix_len:W64.t,
                    msg:W64.t, msg_len:W64.t, pk:BArray64.t, ms:W64.t) : 
  W64.t * W64.t = {
    var result:W64.t;
    var ctx:BArray96.t;
    var digest:BArray47.t;
    var indices:BArray88.t;
    var idx_tree:W64.t;
    var idx_leaf:W32.t;
    var adrs:BArray32.t;
    var pk_fors:BArray32.t;
    adrs <- witness;
    ctx <- witness;
    digest <- witness;
    indices <- witness;
    pk_fors <- witness;
    (* Erased call to spill *)
    (ctx, ms) <@ _thash_ctx_init (ctx, (SBArray64_32.get_sub8 pk 0), ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    prefix <- (protect_ptr prefix ms);
    pk <- (protect_ptr pk ms);
    (* Erased call to spill *)
    (digest, ms) <@ _h_msg (digest, (SBArray29792_32.get_sub8 sig 0), 
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
    (SBArray29792_10560.get_sub8 sig 32), indices, ctx, adrs, ms);
    (* Erased call to unspill *)
    sig <- (protect_ptr sig ms);
    pk <- (protect_ptr pk ms);
    idx_tree <- (protect_64 idx_tree ms);
    idx_leaf <- (protect_32 idx_leaf ms);
    (result, ms) <@ _ht_verify ((SBArray29792_19200.get_sub8 sig
                                (32 + ((22 * (14 + 1)) * 32))),
    pk_fors, (SBArray64_32.get_sub8 pk 32), ctx, idx_tree, idx_leaf, 
    ms);
    return (result, ms);
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
  proc __parity (a:BArray200.t, x:int) : W64.t = {
    var c:W64.t;
    c <- ((BArray200.get64 a x) `^` (BArray200.get64 a (x + 5)));
    c <- (c `^` (BArray200.get64 a (x + 10)));
    c <- (c `^` (BArray200.get64 a (x + 15)));
    c <- (c `^` (BArray200.get64 a (x + 20)));
    return c;
  }
  proc __keccak_round_regs (a:BArray200.t, ir:int) : BArray200.t = {
    var c0:W64.t;
    var c1:W64.t;
    var s21:W64.t;
    var c2:W64.t;
    var s22:W64.t;
    var c3:W64.t;
    var s23:W64.t;
    var c4:W64.t;
    var s24:W64.t;
    var d:W64.t;
    var y:int;
    var t0:W64.t;
    var cur:int;
    var x:int;
    var s:int;
    var r:int;
    var k:int;
    var s0:W64.t;
    var t1:W64.t;
    var i:int;
    var t2:W64.t;
    var rc:BArray192.t;
    rc <- witness;
    c0 <@ __parity (a, 0);
    c1 <@ __parity (a, 1);
    s21 <- (BArray200.get64 a 21);
    c2 <@ __parity (a, 2);
    s22 <- (BArray200.get64 a 22);
    c3 <@ __parity (a, 3);
    s23 <- (BArray200.get64 a 23);
    c4 <@ __parity (a, 4);
    s24 <- (BArray200.get64 a 24);
    d <- (c4 `^` (c1 `|>>|` (W8.of_int 63)));
    y <- 0;
    while ((y < 5)) {
      a <- (BArray200.set64 a (5 * y) ((BArray200.get64 a (5 * y)) `^` d));
      y <- (y + 1);
    }
    d <- (c1 `^` (c3 `|>>|` (W8.of_int 63)));
    a <- (BArray200.set64 a 22 s22);
    y <- 0;
    while ((y < 5)) {
      a <-
      (BArray200.set64 a (2 + (5 * y))
      ((BArray200.get64 a (2 + (5 * y))) `^` d));
      y <- (y + 1);
    }
    d <- (c2 `^` (c4 `|>>|` (W8.of_int 63)));
    a <- (BArray200.set64 a 23 s23);
    y <- 0;
    while ((y < 5)) {
      a <-
      (BArray200.set64 a (3 + (5 * y))
      ((BArray200.get64 a (3 + (5 * y))) `^` d));
      y <- (y + 1);
    }
    d <- (c0 `^` (c2 `|>>|` (W8.of_int 63)));
    a <- (BArray200.set64 a 21 s21);
    y <- 0;
    while ((y < 5)) {
      a <-
      (BArray200.set64 a (1 + (5 * y))
      ((BArray200.get64 a (1 + (5 * y))) `^` d));
      y <- (y + 1);
    }
    d <- (c3 `^` (c0 `|>>|` (W8.of_int 63)));
    a <- (BArray200.set64 a 24 s24);
    y <- 0;
    while ((y < 5)) {
      a <-
      (BArray200.set64 a (4 + (5 * y))
      ((BArray200.get64 a (4 + (5 * y))) `^` d));
      y <- (y + 1);
    }
    t0 <- (BArray200.get64 a 1);
    cur <- 1;
    k <- 0;
    while ((k < 24)) {
      x <- (cur %% 5);
      y <- (cur %/ 5);
      s <- (((x + (3 * y)) %% 5) + (5 * x));
      r <@ __keccak_rho (((x + (3 * y)) %% 5), x);
      if ((s = 1)) {
        a <- (BArray200.set64 a cur (t0 `|<<|` (W8.of_int r)));
      } else {
        a <-
        (BArray200.set64 a cur ((BArray200.get64 a s) `|<<|` (W8.of_int r)));
      }
      cur <- s;
      k <- (k + 1);
    }
    t0 <- (BIC_64 (BArray200.get64 a 2) (BArray200.get64 a 1));
    t0 <- (t0 `^` (BArray200.get64 a 0));
    s0 <- t0;
    t1 <- (BIC_64 (BArray200.get64 a 3) (BArray200.get64 a 2));
    t1 <- (t1 `^` (BArray200.get64 a 1));
    t0 <- (BIC_64 (BArray200.get64 a 4) (BArray200.get64 a 3));
    a <- (BArray200.set64 a 2 ((BArray200.get64 a 2) `^` t0));
    t0 <- (BIC_64 (BArray200.get64 a 0) (BArray200.get64 a 4));
    a <- (BArray200.set64 a 3 ((BArray200.get64 a 3) `^` t0));
    t0 <- (BIC_64 (BArray200.get64 a 1) (BArray200.get64 a 0));
    a <- (BArray200.set64 a 4 ((BArray200.get64 a 4) `^` t0));
    a <- (BArray200.set64 a 1 t1);
    y <- 1;
    while ((y < 5)) {
      i <- (5 * y);
      t0 <- (BIC_64 (BArray200.get64 a (i + 2)) (BArray200.get64 a (i + 1)));
      t1 <- (BIC_64 (BArray200.get64 a (i + 3)) (BArray200.get64 a (i + 2)));
      t2 <- (BIC_64 (BArray200.get64 a (i + 4)) (BArray200.get64 a (i + 3)));
      a <- (BArray200.set64 a (i + 2) ((BArray200.get64 a (i + 2)) `^` t2));
      t2 <- (BIC_64 (BArray200.get64 a i) (BArray200.get64 a (i + 4)));
      a <- (BArray200.set64 a (i + 3) ((BArray200.get64 a (i + 3)) `^` t2));
      t2 <- (BIC_64 (BArray200.get64 a (i + 1)) (BArray200.get64 a i));
      a <- (BArray200.set64 a (i + 4) ((BArray200.get64 a (i + 4)) `^` t2));
      a <- (BArray200.set64 a i ((BArray200.get64 a i) `^` t0));
      a <- (BArray200.set64 a (i + 1) ((BArray200.get64 a (i + 1)) `^` t1));
      y <- (y + 1);
    }
    rc <- kECCAK_RC;
    t0 <- (BArray192.get64 rc ir);
    a <- (BArray200.set64 a 0 s0);
    a <- (BArray200.set64 a 0 ((BArray200.get64 a 0) `^` t0));
    return a;
  }
  proc _keccakf1600 (st:BArray200.t, ms:W64.t) : BArray200.t * W64.t = {
    var i:int;
    var a:BArray200.t;
    var ir:int;
    a <- witness;
    i <- 0;
    while ((i < 25)) {
      a <- (BArray200.set64 a i (BArray200.get64 st i));
      i <- (i + 1);
    }
    (* Erased call to spill *)
    ir <- 0;
    while ((ir < 24)) {
      a <@ __keccak_round_regs (a, ir);
      ir <- (ir + 1);
    }
    (* Erased call to unspill *)
    st <- (protect_ptr st ms);
    i <- 0;
    while ((i < 25)) {
      st <- (BArray200.set64 st i (BArray200.get64 a i));
      i <- (i + 1);
    }
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
  proc keygen (pk:BArray64.t, sk:BArray128.t, seeds:BArray96.t) : BArray64.t *
                                                                  BArray128.t = {
    var ms:W64.t;
    ms <- (init_msf);
    pk <- (protect_ptr pk ms);
    sk <- (protect_ptr sk ms);
    seeds <- (protect_ptr seeds ms);
    (pk, sk, ms) <@ _slh_keygen (pk, sk, seeds, ms);
    return (pk, sk);
  }
  proc sign (sig:BArray29792.t, msg:W64.t, msg_len:W64.t, domain:BArray257.t,
             sk:BArray128.t, opt_rand:BArray32.t) : BArray29792.t * W64.t = {
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
  proc verify (sig:BArray29792.t, msg:W64.t, msg_len:W64.t,
               domain:BArray257.t, pk:BArray64.t) : W64.t = {
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
  proc sign_internal (sig:BArray29792.t, msg:W64.t, msg_len:W64.t,
                      sk:BArray128.t, opt_rand:BArray32.t) : BArray29792.t = {
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
  proc verify_internal (sig:BArray29792.t, msg:W64.t, msg_len:W64.t,
                        pk:BArray64.t) : W64.t = {
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
