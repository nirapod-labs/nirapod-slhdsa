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
 * Entry proofs/extracted/hash.jazz SHA-256 ee2d389dc1c565eeadf2a7218164eacfc55f45165823d299fa6e9defaadbb0fd
 * Sources under src/hash (SHA-256, path):
 *     3f9b879d57975656cbaa3d23520ba044fe9bbfa823a6640e0228eee023193392  ./aarch64/word.jinc
 *     5e10960ea822ac46820eacbfca5ee743235a6c0c8fbc48faeb21b046937f16b1  ./keccak/aarch64/scalar/keccakf1600.jinc
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
BArray32 BArray40 BArray64 BArray128 BArray192 BArray200 BArray256 BArray640.

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
}.
