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
 * Entry proofs/extracted/hash.jazz SHA-256 d5e906772951bcc9172f384dab5acb1047af58af445e422ce3d32728c8e99d8f
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

from Jasmin require import JModel_armv8a.

import SLH64.

require import
BArray28 BArray30 BArray32 BArray34 BArray39 BArray42 BArray47 BArray48
BArray49 BArray64 BArray112 BArray128 BArray192 BArray200 BArray256 BArray320
BArray640 SBArray192_64 SBArray320_64 SBArray192_128 SBArray320_128.

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
  proc __sha3_absorb_all (st:BArray200.t, rate:W64.t, ds:W64.t, in_0:W64.t,
                          inlen:W64.t, ms:W64.t) : BArray200.t * W64.t = {
    var pos:W64.t;
    st <@ __keccak_init (st);
    pos <- (W64.of_int 0);
    (* Erased call to spill *)
    (st, pos, ms) <@ _keccak_absorb_mem (st, pos, rate, in_0, inlen, ms);
    (* Erased call to unspill *)
    rate <- (protect_64 rate ms);
    ds <- (protect_64 ds ms);
    (st, ms) <@ _keccak_finalize (st, pos, rate, ds, ms);
    return (st, ms);
  }
  proc _sha3_224_mem (out:BArray28.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray28.t * W64.t = {
    var rate:W64.t;
    var ds:W64.t;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    var w:W32.t;
    st <- witness;
    rate <- (W64.of_int 144);
    ds <- (W64.of_int 6);
    (* Erased call to spill *)
    (st, ms) <@ __sha3_absorb_all (st, rate, ds, in_0, inlen, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    i <- 0;
    while ((i < 3)) {
      t <- (BArray200.get64 st i);
      out <- (BArray28.set64 out i t);
      i <- (i + 1);
    }
    w <- (BArray200.get32 st 6);
    out <- (BArray28.set32 out 6 w);
    return (out, ms);
  }
  proc _sha3_256_mem (out:BArray32.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray32.t * W64.t = {
    var rate:W64.t;
    var ds:W64.t;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    rate <- (W64.of_int 136);
    ds <- (W64.of_int 6);
    (* Erased call to spill *)
    (st, ms) <@ __sha3_absorb_all (st, rate, ds, in_0, inlen, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    i <- 0;
    while ((i < 4)) {
      t <- (BArray200.get64 st i);
      out <- (BArray32.set64 out i t);
      i <- (i + 1);
    }
    return (out, ms);
  }
  proc _sha3_384_mem (out:BArray48.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray48.t * W64.t = {
    var rate:W64.t;
    var ds:W64.t;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    rate <- (W64.of_int 104);
    ds <- (W64.of_int 6);
    (* Erased call to spill *)
    (st, ms) <@ __sha3_absorb_all (st, rate, ds, in_0, inlen, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    i <- 0;
    while ((i < 6)) {
      t <- (BArray200.get64 st i);
      out <- (BArray48.set64 out i t);
      i <- (i + 1);
    }
    return (out, ms);
  }
  proc _sha3_512_mem (out:BArray64.t, in_0:W64.t, inlen:W64.t, ms:W64.t) : 
  BArray64.t * W64.t = {
    var rate:W64.t;
    var ds:W64.t;
    var st:BArray200.t;
    var i:int;
    var t:W64.t;
    st <- witness;
    rate <- (W64.of_int 72);
    ds <- (W64.of_int 6);
    (* Erased call to spill *)
    (st, ms) <@ __sha3_absorb_all (st, rate, ds, in_0, inlen, ms);
    (* Erased call to unspill *)
    out <- (protect_ptr out ms);
    i <- 0;
    while ((i < 8)) {
      t <- (BArray200.get64 st i);
      out <- (BArray64.set64 out i t);
      i <- (i + 1);
    }
    return (out, ms);
  }
  proc __shake_mem (rate:W64.t, out:W64.t, outlen:W64.t, in_0:W64.t,
                    inlen:W64.t, ms:W64.t) : W64.t = {
    var ds:W64.t;
    var st:BArray200.t;
    var pos:W64.t;
    st <- witness;
    ds <- (W64.of_int 31);
    (* Erased call to spill *)
    (st, ms) <@ __sha3_absorb_all (st, rate, ds, in_0, inlen, ms);
    (* Erased call to unspill *)
    out <- (protect_64 out ms);
    outlen <- (protect_64 outlen ms);
    rate <- (protect_64 rate ms);
    pos <- (W64.of_int 0);
    (st, pos, ms) <@ _keccak_squeeze_mem (st, pos, rate, out, outlen, ms);
    return ms;
  }
  proc _shake128_mem (out:W64.t, outlen:W64.t, in_0:W64.t, inlen:W64.t,
                      ms:W64.t) : W64.t = {
    var rate:W64.t;
    rate <- (W64.of_int 168);
    ms <@ __shake_mem (rate, out, outlen, in_0, inlen, ms);
    return ms;
  }
  proc _shake256_mem (out:W64.t, outlen:W64.t, in_0:W64.t, inlen:W64.t,
                      ms:W64.t) : W64.t = {
    var rate:W64.t;
    rate <- (W64.of_int 136);
    ms <@ __shake_mem (rate, out, outlen, in_0, inlen, ms);
    return ms;
  }
  proc mgf64_30____mgf1_layout (m:BArray192.t, seed:BArray64.t, padded:int) : 
  BArray192.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var t:W64.t;
    z <- (W64.of_int 0);
    inc <- padded;
    i <- 0;
    while ((i < inc)) {
      m <- (BArray192.set8 m i (truncateu8 z));
      i <- (i + 1);
    }
    i <- 0;
    while ((i < 64)) {
      t <- (zeroextu64 (BArray64.get8 seed i));
      m <- (BArray192.set8 m i (truncateu8 t));
      i <- (i + 1);
    }
    t <- (W64.of_int 128);
    m <- (BArray192.set8 m (64 + 4) (truncateu8 t));
    t <- (W64.of_int ((64 + 4) * 8));
    i <- 0;
    while ((i < 8)) {
      m <- (BArray192.set8 m ((padded - 1) - i) (truncateu8 t));
      t <- (t `>>` (W8.of_int 8));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf64_30____mgf1_set_counter (m:BArray192.t, c:int) : BArray192.t = {
    var t:W64.t;
    var i:int;
    i <- 0;
    while ((i < 4)) {
      t <- (W64.of_int c);
      t <- (t `>>` (W8.of_int (8 * (3 - i))));
      m <- (BArray192.set8 m (64 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf64_30___mgf1_sha256 (out:BArray30.t, seed:BArray64.t, ms:W64.t) : 
  BArray30.t * W64.t = {
    var inc:int;
    var inc_0:int;
    var m:BArray192.t;
    var c:int;
    var h:BArray32.t;
    var b:int;
    var n:int;
    var i:int;
    var x:W32.t;
    var t:W64.t;
    h <- witness;
    m <- witness;
    m <@ mgf64_30____mgf1_layout (m, seed,
    (64 * (((((64 + 4) + 1) + 8) + 63) %/ 64)));
    inc <- ((30 + 31) %/ 32);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf64_30____mgf1_set_counter (m, c);
      h <@ __sha256_init (h);
      inc_0 <- (((((64 + 4) + 1) + 8) + 63) %/ 64);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h, (SBArray192_64.get_sub8 m (64 * b)),
        ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((30 - (32 * c)) < 32) ? (30 - (32 * c)) : 32);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        x <- (BArray32.get32 h (i %/ 4));
        x <- (x `>>` (W8.of_int (8 * (3 - (i %% 4)))));
        t <- (zeroextu64 x);
        out <- (BArray30.set8 out ((32 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf64_30___mgf1_sha512 (out:BArray30.t, seed:BArray64.t, ms:W64.t) : 
  BArray30.t * W64.t = {
    var inc:int;
    var inc_0:int;
    var m:BArray192.t;
    var c:int;
    var h:BArray64.t;
    var b:int;
    var n:int;
    var i:int;
    var t:W64.t;
    h <- witness;
    m <- witness;
    m <@ mgf64_30____mgf1_layout (m, seed,
    (128 * (((((64 + 4) + 1) + 16) + 127) %/ 128)));
    inc <- ((30 + 63) %/ 64);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf64_30____mgf1_set_counter (m, c);
      h <@ __sha512_init (h);
      inc_0 <- (((((64 + 4) + 1) + 16) + 127) %/ 128);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha512_compress (h,
        (SBArray192_128.get_sub8 m (128 * b)), ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((30 - (64 * c)) < 64) ? (30 - (64 * c)) : 64);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        t <- (BArray64.get64 h (i %/ 8));
        t <- (t `>>` (W8.of_int (8 * (7 - (i %% 8)))));
        out <- (BArray30.set8 out ((64 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf64_34____mgf1_layout (m:BArray192.t, seed:BArray64.t, padded:int) : 
  BArray192.t = {
    var inc:int;
    var z:W64.t;
    var i:int;
    var t:W64.t;
    z <- (W64.of_int 0);
    inc <- padded;
    i <- 0;
    while ((i < inc)) {
      m <- (BArray192.set8 m i (truncateu8 z));
      i <- (i + 1);
    }
    i <- 0;
    while ((i < 64)) {
      t <- (zeroextu64 (BArray64.get8 seed i));
      m <- (BArray192.set8 m i (truncateu8 t));
      i <- (i + 1);
    }
    t <- (W64.of_int 128);
    m <- (BArray192.set8 m (64 + 4) (truncateu8 t));
    t <- (W64.of_int ((64 + 4) * 8));
    i <- 0;
    while ((i < 8)) {
      m <- (BArray192.set8 m ((padded - 1) - i) (truncateu8 t));
      t <- (t `>>` (W8.of_int 8));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf64_34____mgf1_set_counter (m:BArray192.t, c:int) : BArray192.t = {
    var t:W64.t;
    var i:int;
    i <- 0;
    while ((i < 4)) {
      t <- (W64.of_int c);
      t <- (t `>>` (W8.of_int (8 * (3 - i))));
      m <- (BArray192.set8 m (64 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf64_34___mgf1_sha256 (out:BArray34.t, seed:BArray64.t, ms:W64.t) : 
  BArray34.t * W64.t = {
    var inc:int;
    var inc_0:int;
    var m:BArray192.t;
    var c:int;
    var h:BArray32.t;
    var b:int;
    var n:int;
    var i:int;
    var x:W32.t;
    var t:W64.t;
    h <- witness;
    m <- witness;
    m <@ mgf64_34____mgf1_layout (m, seed,
    (64 * (((((64 + 4) + 1) + 8) + 63) %/ 64)));
    inc <- ((34 + 31) %/ 32);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf64_34____mgf1_set_counter (m, c);
      h <@ __sha256_init (h);
      inc_0 <- (((((64 + 4) + 1) + 8) + 63) %/ 64);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h, (SBArray192_64.get_sub8 m (64 * b)),
        ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((34 - (32 * c)) < 32) ? (34 - (32 * c)) : 32);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        x <- (BArray32.get32 h (i %/ 4));
        x <- (x `>>` (W8.of_int (8 * (3 - (i %% 4)))));
        t <- (zeroextu64 x);
        out <- (BArray34.set8 out ((32 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf64_34___mgf1_sha512 (out:BArray34.t, seed:BArray64.t, ms:W64.t) : 
  BArray34.t * W64.t = {
    var inc:int;
    var inc_0:int;
    var m:BArray192.t;
    var c:int;
    var h:BArray64.t;
    var b:int;
    var n:int;
    var i:int;
    var t:W64.t;
    h <- witness;
    m <- witness;
    m <@ mgf64_34____mgf1_layout (m, seed,
    (128 * (((((64 + 4) + 1) + 16) + 127) %/ 128)));
    inc <- ((34 + 63) %/ 64);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf64_34____mgf1_set_counter (m, c);
      h <@ __sha512_init (h);
      inc_0 <- (((((64 + 4) + 1) + 16) + 127) %/ 128);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha512_compress (h,
        (SBArray192_128.get_sub8 m (128 * b)), ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((34 - (64 * c)) < 64) ? (34 - (64 * c)) : 64);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        t <- (BArray64.get64 h (i %/ 8));
        t <- (t `>>` (W8.of_int (8 * (7 - (i %% 8)))));
        out <- (BArray34.set8 out ((64 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf112_39____mgf1_layout (m:BArray320.t, seed:BArray112.t, padded:int) : 
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
    i <- 0;
    while ((i < 112)) {
      t <- (zeroextu64 (BArray112.get8 seed i));
      m <- (BArray320.set8 m i (truncateu8 t));
      i <- (i + 1);
    }
    t <- (W64.of_int 128);
    m <- (BArray320.set8 m (112 + 4) (truncateu8 t));
    t <- (W64.of_int ((112 + 4) * 8));
    i <- 0;
    while ((i < 8)) {
      m <- (BArray320.set8 m ((padded - 1) - i) (truncateu8 t));
      t <- (t `>>` (W8.of_int 8));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf112_39____mgf1_set_counter (m:BArray320.t, c:int) : BArray320.t = {
    var t:W64.t;
    var i:int;
    i <- 0;
    while ((i < 4)) {
      t <- (W64.of_int c);
      t <- (t `>>` (W8.of_int (8 * (3 - i))));
      m <- (BArray320.set8 m (112 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf112_39___mgf1_sha256 (out:BArray39.t, seed:BArray112.t, ms:W64.t) : 
  BArray39.t * W64.t = {
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
    m <@ mgf112_39____mgf1_layout (m, seed,
    (64 * (((((112 + 4) + 1) + 8) + 63) %/ 64)));
    inc <- ((39 + 31) %/ 32);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf112_39____mgf1_set_counter (m, c);
      h <@ __sha256_init (h);
      inc_0 <- (((((112 + 4) + 1) + 8) + 63) %/ 64);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h, (SBArray320_64.get_sub8 m (64 * b)),
        ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((39 - (32 * c)) < 32) ? (39 - (32 * c)) : 32);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        x <- (BArray32.get32 h (i %/ 4));
        x <- (x `>>` (W8.of_int (8 * (3 - (i %% 4)))));
        t <- (zeroextu64 x);
        out <- (BArray39.set8 out ((32 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf112_39___mgf1_sha512 (out:BArray39.t, seed:BArray112.t, ms:W64.t) : 
  BArray39.t * W64.t = {
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
    m <@ mgf112_39____mgf1_layout (m, seed,
    (128 * (((((112 + 4) + 1) + 16) + 127) %/ 128)));
    inc <- ((39 + 63) %/ 64);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf112_39____mgf1_set_counter (m, c);
      h <@ __sha512_init (h);
      inc_0 <- (((((112 + 4) + 1) + 16) + 127) %/ 128);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha512_compress (h,
        (SBArray320_128.get_sub8 m (128 * b)), ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((39 - (64 * c)) < 64) ? (39 - (64 * c)) : 64);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        t <- (BArray64.get64 h (i %/ 8));
        t <- (t `>>` (W8.of_int (8 * (7 - (i %% 8)))));
        out <- (BArray39.set8 out ((64 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf112_42____mgf1_layout (m:BArray320.t, seed:BArray112.t, padded:int) : 
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
    i <- 0;
    while ((i < 112)) {
      t <- (zeroextu64 (BArray112.get8 seed i));
      m <- (BArray320.set8 m i (truncateu8 t));
      i <- (i + 1);
    }
    t <- (W64.of_int 128);
    m <- (BArray320.set8 m (112 + 4) (truncateu8 t));
    t <- (W64.of_int ((112 + 4) * 8));
    i <- 0;
    while ((i < 8)) {
      m <- (BArray320.set8 m ((padded - 1) - i) (truncateu8 t));
      t <- (t `>>` (W8.of_int 8));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf112_42____mgf1_set_counter (m:BArray320.t, c:int) : BArray320.t = {
    var t:W64.t;
    var i:int;
    i <- 0;
    while ((i < 4)) {
      t <- (W64.of_int c);
      t <- (t `>>` (W8.of_int (8 * (3 - i))));
      m <- (BArray320.set8 m (112 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf112_42___mgf1_sha256 (out:BArray42.t, seed:BArray112.t, ms:W64.t) : 
  BArray42.t * W64.t = {
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
    m <@ mgf112_42____mgf1_layout (m, seed,
    (64 * (((((112 + 4) + 1) + 8) + 63) %/ 64)));
    inc <- ((42 + 31) %/ 32);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf112_42____mgf1_set_counter (m, c);
      h <@ __sha256_init (h);
      inc_0 <- (((((112 + 4) + 1) + 8) + 63) %/ 64);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h, (SBArray320_64.get_sub8 m (64 * b)),
        ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((42 - (32 * c)) < 32) ? (42 - (32 * c)) : 32);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        x <- (BArray32.get32 h (i %/ 4));
        x <- (x `>>` (W8.of_int (8 * (3 - (i %% 4)))));
        t <- (zeroextu64 x);
        out <- (BArray42.set8 out ((32 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf112_42___mgf1_sha512 (out:BArray42.t, seed:BArray112.t, ms:W64.t) : 
  BArray42.t * W64.t = {
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
    m <@ mgf112_42____mgf1_layout (m, seed,
    (128 * (((((112 + 4) + 1) + 16) + 127) %/ 128)));
    inc <- ((42 + 63) %/ 64);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf112_42____mgf1_set_counter (m, c);
      h <@ __sha512_init (h);
      inc_0 <- (((((112 + 4) + 1) + 16) + 127) %/ 128);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha512_compress (h,
        (SBArray320_128.get_sub8 m (128 * b)), ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((42 - (64 * c)) < 64) ? (42 - (64 * c)) : 64);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        t <- (BArray64.get64 h (i %/ 8));
        t <- (t `>>` (W8.of_int (8 * (7 - (i %% 8)))));
        out <- (BArray42.set8 out ((64 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf128_47____mgf1_layout (m:BArray320.t, seed:BArray128.t, padded:int) : 
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
    i <- 0;
    while ((i < 128)) {
      t <- (zeroextu64 (BArray128.get8 seed i));
      m <- (BArray320.set8 m i (truncateu8 t));
      i <- (i + 1);
    }
    t <- (W64.of_int 128);
    m <- (BArray320.set8 m (128 + 4) (truncateu8 t));
    t <- (W64.of_int ((128 + 4) * 8));
    i <- 0;
    while ((i < 8)) {
      m <- (BArray320.set8 m ((padded - 1) - i) (truncateu8 t));
      t <- (t `>>` (W8.of_int 8));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf128_47____mgf1_set_counter (m:BArray320.t, c:int) : BArray320.t = {
    var t:W64.t;
    var i:int;
    i <- 0;
    while ((i < 4)) {
      t <- (W64.of_int c);
      t <- (t `>>` (W8.of_int (8 * (3 - i))));
      m <- (BArray320.set8 m (128 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf128_47___mgf1_sha256 (out:BArray47.t, seed:BArray128.t, ms:W64.t) : 
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
    m <@ mgf128_47____mgf1_layout (m, seed,
    (64 * (((((128 + 4) + 1) + 8) + 63) %/ 64)));
    inc <- ((47 + 31) %/ 32);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf128_47____mgf1_set_counter (m, c);
      h <@ __sha256_init (h);
      inc_0 <- (((((128 + 4) + 1) + 8) + 63) %/ 64);
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
  proc mgf128_47___mgf1_sha512 (out:BArray47.t, seed:BArray128.t, ms:W64.t) : 
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
    m <@ mgf128_47____mgf1_layout (m, seed,
    (128 * (((((128 + 4) + 1) + 16) + 127) %/ 128)));
    inc <- ((47 + 63) %/ 64);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf128_47____mgf1_set_counter (m, c);
      h <@ __sha512_init (h);
      inc_0 <- (((((128 + 4) + 1) + 16) + 127) %/ 128);
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
  proc mgf128_49____mgf1_layout (m:BArray320.t, seed:BArray128.t, padded:int) : 
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
    i <- 0;
    while ((i < 128)) {
      t <- (zeroextu64 (BArray128.get8 seed i));
      m <- (BArray320.set8 m i (truncateu8 t));
      i <- (i + 1);
    }
    t <- (W64.of_int 128);
    m <- (BArray320.set8 m (128 + 4) (truncateu8 t));
    t <- (W64.of_int ((128 + 4) * 8));
    i <- 0;
    while ((i < 8)) {
      m <- (BArray320.set8 m ((padded - 1) - i) (truncateu8 t));
      t <- (t `>>` (W8.of_int 8));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf128_49____mgf1_set_counter (m:BArray320.t, c:int) : BArray320.t = {
    var t:W64.t;
    var i:int;
    i <- 0;
    while ((i < 4)) {
      t <- (W64.of_int c);
      t <- (t `>>` (W8.of_int (8 * (3 - i))));
      m <- (BArray320.set8 m (128 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return m;
  }
  proc mgf128_49___mgf1_sha256 (out:BArray49.t, seed:BArray128.t, ms:W64.t) : 
  BArray49.t * W64.t = {
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
    m <@ mgf128_49____mgf1_layout (m, seed,
    (64 * (((((128 + 4) + 1) + 8) + 63) %/ 64)));
    inc <- ((49 + 31) %/ 32);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf128_49____mgf1_set_counter (m, c);
      h <@ __sha256_init (h);
      inc_0 <- (((((128 + 4) + 1) + 8) + 63) %/ 64);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha256_compress (h, (SBArray320_64.get_sub8 m (64 * b)),
        ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((49 - (32 * c)) < 32) ? (49 - (32 * c)) : 32);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        x <- (BArray32.get32 h (i %/ 4));
        x <- (x `>>` (W8.of_int (8 * (3 - (i %% 4)))));
        t <- (zeroextu64 x);
        out <- (BArray49.set8 out ((32 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
  proc mgf128_49___mgf1_sha512 (out:BArray49.t, seed:BArray128.t, ms:W64.t) : 
  BArray49.t * W64.t = {
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
    m <@ mgf128_49____mgf1_layout (m, seed,
    (128 * (((((128 + 4) + 1) + 16) + 127) %/ 128)));
    inc <- ((49 + 63) %/ 64);
    c <- 0;
    while ((c < inc)) {
      m <@ mgf128_49____mgf1_set_counter (m, c);
      h <@ __sha512_init (h);
      inc_0 <- (((((128 + 4) + 1) + 16) + 127) %/ 128);
      b <- 0;
      while ((b < inc_0)) {
        (* Erased call to spill *)
        (h, ms) <@ _sha512_compress (h,
        (SBArray320_128.get_sub8 m (128 * b)), ms);
        (* Erased call to unspill *)
        out <- (protect_ptr out ms);
        b <- (b + 1);
      }
      n <- (((49 - (64 * c)) < 64) ? (49 - (64 * c)) : 64);
      inc_0 <- n;
      i <- 0;
      while ((i < inc_0)) {
        t <- (BArray64.get64 h (i %/ 8));
        t <- (t `>>` (W8.of_int (8 * (7 - (i %% 8)))));
        out <- (BArray49.set8 out ((64 * c) + i) (truncateu8 t));
        i <- (i + 1);
      }
      c <- (c + 1);
    }
    return (out, ms);
  }
}.
