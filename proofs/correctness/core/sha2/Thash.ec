(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thash.ec
 * ========
 *
 * The SHA2 tweakable hash functions of FIPS 205 section 11.2 against the
 * model of one SHA2 parameter set.
 *
 * Every SHA2 input starts with PK.seed padded by zeros to one compression
 * block, so the implementation compresses that block once
 * (_thash_ctx_init) and keeps the chaining value in ctx:
 *
 *     ctx bytes  0 .. 31   SHA-256 chaining value after the seed block
 *     ctx bytes 32 .. 95   SHA-512 chaining value after the seed block
 *                          (sets with n = 24 or 32; zero otherwise)
 *
 * For F, PRF and the narrow H the rest of the input fits the last block,
 * so the hash is two compressions (FIPS180_SHA2_Blocks): the seed block,
 * whose result is ctx, and the tail block ADRS^c || M || padding that
 * the procedure builds. ctx_ok states the ctx layout; the theorems take
 * it as a precondition and thash_ctx_init_correct establishes it.
 *
 * The compression functions enter as section premises (sha256_compress_h,
 * sha512_compress_h), with the statements of the hash kernel proofs on
 * this unit's own copy of the kernels.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils.
require import Bytes FIPS180_SHA2 FIPS180_SHA2_Blocks.
require import FIPS205_Params FIPS205_Encoding FIPS205_Address FIPS205_Address_Props FIPS205_Hash.
require import BArray32 BArray64 BArray96 BArray128 SetModel CoreExtracted ADRSc WordSpec.
require ArchWord.

lemma family_sha2 : P.`family = SHA2 by rewrite /P.

(* ------------------------------------------------------------------ *)
(* Views                                                              *)

(* Chaining values as word lists, the view of the kernel proofs. *)
op hw256 (h : BArray32.t) : W32.t list = map (BArray32.get32 h) (iota_ 0 8).
op hw512 (h : BArray64.t) : W64.t list = map (BArray64.get64 h) (iota_ 0 8).

(* The two chaining values held in ctx. *)
op cv256 (c : BArray96.t) : W32.t list = map (BArray96.get32 c) (iota_ 0 8).
op cv512 (c : BArray96.t) : W64.t list = map (fun i => BArray96.get64 c (4 + i)) (iota_ 0 8).

(* PK.seed padded to one block, as in every SHA2 function of section 11.2. *)
op seed_block (b : int) (pk : bytes) : bytes = pk ++ toByte 0 (b - P.`n).

(* ctx holds the chaining values after the seed block. *)
op ctx_ok (pk : bytes) (c : BArray96.t) =
     cv256 c = SHA256.compress SHA256.H0_256 (words256 (seed_block 64 pk))
  /\ (P.`n <> 16 =>
      cv512 c = SHA512.compress SHA512.H0_512 (words512 (seed_block 128 pk))).

(* ------------------------------------------------------------------ *)
(* Bytes and words                                                    *)

lemma hw256_bytes (h : BArray32.t) (c : BArray96.t) :
  (forall j, 0 <= j < 32 => h.[j] = c.[j]) => hw256 h = cv256 c.
proof.
move=> hj; apply eq_in_map => k /mem_iota hk /=.
by apply W4u8.wordP => i hi; rewrite BArray32.get32d_byte // BArray96.get32d_byte // hj /#.
qed.

lemma hw512_bytes (h : BArray64.t) (c : BArray96.t) :
  (forall j, 0 <= j < 64 => h.[j] = c.[32 + j]) => hw512 h = cv512 c.
proof.
move=> hj; apply eq_in_map => k /mem_iota hk /=.
apply W8u8.wordP => i hi; rewrite BArray64.get64d_byte // BArray96.get64d_byte //.
by rewrite hj 1:/#; congr; ring.
qed.

lemma size_w32_be (w : W32.t) : size (w32_be w) = 4.
proof. by rewrite /w32_be size_rev W4u8.size_to_list. qed.

lemma size_w64_be (w : W64.t) : size (w64_be w) = 8.
proof. by rewrite /w64_be size_rev W8u8.size_to_list. qed.

lemma nth_w32_be (w : W32.t) (k : int) : 0 <= k < 4 =>
  nth W8.zero (w32_be w) k = w \bits8 (3 - k).
proof.
move=> hk; rewrite /w32_be nth_rev W4u8.size_to_list // (nth_map 0) ?iotaredE ?size_iota 1:/#.
by rewrite nth_iota /#.
qed.

lemma nth_w64_be (w : W64.t) (k : int) : 0 <= k < 8 =>
  nth W8.zero (w64_be w) k = w \bits8 (7 - k).
proof.
move=> hk; rewrite /w64_be nth_rev W8u8.size_to_list // (nth_map 0) ?iotaredE ?size_iota 1:/#.
by rewrite nth_iota /#.
qed.

lemma size_hw256 (h : BArray32.t) : size (hw256 h) = 8 by rewrite /hw256 size_map size_iota.
lemma size_hw512 (h : BArray64.t) : size (hw512 h) = 8 by rewrite /hw512 size_map size_iota.

lemma size_flat32 (ws : W32.t list) : size (flatten (map w32_be ws)) = 4 * size ws.
proof. by elim: ws => [|w ws ih] //=; rewrite flatten_cons size_cat size_w32_be ih /#. qed.

lemma size_flat64 (ws : W64.t list) : size (flatten (map w64_be ws)) = 8 * size ws.
proof. by elim: ws => [|w ws ih] //=; rewrite flatten_cons size_cat size_w64_be ih /#. qed.

lemma nth_flat32 (ws : W32.t list) (j : int) : 0 <= j < 4 * size ws =>
  nth W8.zero (flatten (map w32_be ws)) j = nth W32.zero ws (j %/ 4) \bits8 (3 - j %% 4).
proof.
elim: ws j => [|w ws ih] j hj /=; first smt().
rewrite flatten_cons nth_cat size_w32_be.
case: (j < 4) => hj4; first by rewrite nth_w32_be 1:/# divz_small 1:/# modz_small /#.
rewrite ih 1:/# (_ : j %/ 4 = (j - 4) %/ 4 + 1) 1:/# ifF 1:/# /=.
by rewrite (_ : j %% 4 = (j - 4) %% 4) 1:/#.
qed.

lemma nth_flat64 (ws : W64.t list) (j : int) : 0 <= j < 8 * size ws =>
  nth W8.zero (flatten (map w64_be ws)) j = nth W64.zero ws (j %/ 8) \bits8 (7 - j %% 8).
proof.
elim: ws j => [|w ws ih] j hj /=; first smt().
rewrite flatten_cons nth_cat size_w64_be.
case: (j < 8) => hj8; first by rewrite nth_w64_be 1:/# divz_small 1:/# modz_small /#.
rewrite ih 1:/# (_ : j %/ 8 = (j - 8) %/ 8 + 1) 1:/# ifF 1:/# /=.
by rewrite (_ : j %% 8 = (j - 8) %% 8) 1:/#.
qed.

lemma bswap32_bits (w : W32.t) (k : int) : 0 <= k < 4 => bswap32 w \bits8 k = w \bits8 (3 - k).
proof.
move=> hk; rewrite /bswap32 W4u8.pack4bE // W4u8.Pack.get_of_list 1:/# nth_rev ?W4u8.size_to_list //.
by rewrite (nth_map 0) ?iotaredE ?size_iota 1:/# nth_iota /#.
qed.

lemma bswap64_bits (w : W64.t) (k : int) : 0 <= k < 8 => bswap64 w \bits8 k = w \bits8 (7 - k).
proof.
move=> hk; rewrite /bswap64 W8u8.pack8bE // W8u8.Pack.get_of_list 1:/# nth_rev ?W8u8.size_to_list //.
by rewrite (nth_map 0) ?iotaredE ?size_iota 1:/# nth_iota /#.
qed.

(* The length field bytes the procedures store as literals. *)
lemma len_hi (b : int) : 0 <= b => truncateu8 (W64.of_int (b `|>>` 8)) = W8.of_int (b %/ 256).
proof.
move=> hb; rewrite /(`|>>`) /(`<<`) /= /truncateu8 W64.of_uintK.
by rewrite -W8.of_int_mod -(W8.of_int_mod (b %/ 256)); congr; smt(modz_dvd).
qed.

lemma len_lo (b : int) : 0 <= b =>
  truncateu8 (truncateu64 (W256.of_int b `&` W256.of_int 255)) = W8.of_int b.
proof.
move=> hb; rewrite (_ : 255 = 2 ^ 8 - 1) // W256.and_mod // /truncateu64 /truncateu8.
rewrite !W256.of_uintK W64.of_uintK -W8.of_int_mod -(W8.of_int_mod b); congr.
smt(modz_dvd).
qed.

(* ------------------------------------------------------------------ *)
(* The tail block                                                     *)

(* Byte j of the last SHA-256 block after one 64-byte block, |r| <= 55. *)
lemma nth_tail256 (r : bytes) (j : int) : size r <= 55 => 0 <= j < 64 =>
  nth W8.zero (tail_block256 64 r) j =
    if j < size r then nth W8.zero r j
    else if j = size r then W8.of_int 128
    else if j < 62 then W8.zero
    else if j = 62 then W8.of_int (8 * (64 + size r) %/ 256)
    else W8.of_int (8 * (64 + size r)).
proof.
move=> hr hj; rewrite /tail_block256.
have hs : size (r ++ [W8.of_int 128] ++ zeros (55 - size r)) = 56.
+ by rewrite !size_cat size_zeros /#.
rewrite nth_cat hs; case: (j < 56) => h3.
+ rewrite nth_cat size_cat /=; case: (j < size r + 1) => h2.
  + rewrite nth_cat; case: (j < size r) => // h1.
    have -> : j - size r = 0 by smt().
    by rewrite /= ifT 1:/#.
  by rewrite /zeros nth_nseq 1:/# ifF 1:/# ifF 1:/# ifT 1:/#.
rewrite ifF 1:/# ifF 1:/# /be_bytes nth_mkseq 1:/# /=.
have hb : 0 <= 8 * (64 + size r) < 65536 by smt(size_ge0).
have -> : 8 - 1 - (j - 56) = 63 - j by ring.
case: (j < 62) => h4.
+ have hk : 1 <= 256 ^ (61 - j) by smt(expr_gt0).
  rewrite (_ : 63 - j = 2 + (61 - j)) 1:/# exprD_nneg 1,2:/# expr2 /= divz_small //.
  by rewrite ger0_norm; smt().
case: (j = 62) => [-> /= | h5]; first by rewrite ?expr1.
by rewrite (_ : 63 - j = 0) 1:/# ?expr0 ?divz1.
qed.

(* ------------------------------------------------------------------ *)
(* __sha256_seeded_block and __sha256_trunc_n                         *)

(* The block before the payload: ADRS^c, 0x80 after x_len payload bytes,
   the low 16 bits of the bit length in bytes 62 and 63, zeros elsewhere. *)
op seeded (a : BArray32.t) (xl bits j : int) : W8.t =
  if j < 22 then nth W8.zero (compress (BArray32.to_list a)) j
  else if j = 22 + xl then W8.of_int 128
  else if j = 62 then W8.of_int (bits %/ 256)
  else if j = 63 then W8.of_int bits
  else W8.zero.

lemma seeded_block_h (a0 : BArray32.t) (xl b0 : int) :
  0 <= xl => 22 + xl < 62 => 0 <= b0 =>
  hoare [M.__sha256_seeded_block : adrs = a0 /\ x_len = xl /\ bits = b0 ==>
    forall j, 0 <= j < 64 => res.[j] = seeded a0 xl b0 j].
proof.
move=> h0 h1 h2; proc.
wp; ecall (adrs_compress_into64_h block a0).
while (0 <= i <= 8 /\ adrs = a0 /\ x_len = xl /\ bits = b0 /\ z = W64.zero /\
       forall j, 0 <= j < 8 * i => block.[j] = W8.zero).
+ wp; skip => &m [#] g0 g1 ga gx gb gz hj hlt; do !(split; first smt()); move=> j hj'.
  rewrite BArray64.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
  + by rewrite ifT 1:/# gz W8u8.get_zero.
  by rewrite hj 1:/#.
wp; skip => /> &m; split; first smt().
move=> b1 i1 g0 g1 g2 g4 b2 ht hdr j hj0 hj1.
have hi1 : i1 = 8 by smt().
rewrite !BArray64.get_setE 1..3:/# /seeded.
case: (j = 63) => h63 /=; first by rewrite ifF 1:/# ifF 1:/# ifF 1:/# len_lo.
case: (j = 62) => h62 /=; first by rewrite ifF 1:/# ifF 1:/# len_hi.
case: (j = 22 + xl) => hx /=; first by rewrite ifF 1:/# /truncateu8 W64.of_uintK.
case: (j < 22) => h22 /=.
+ by rewrite -ht nth_take // BArray64.get_to_list.
have := congr1 (fun l => nth W8.zero l (j - 22)) _ _ hdr => /=.
by rewrite !nth_drop 1..4:/# !BArray64.get_to_list /= => ->; rewrite g4 /#.
qed.

lemma seeded_block_ll : islossless M.__sha256_seeded_block.
proof. by proc; wp; call adrs_compress_into64_ll; wp; while true (8 - i); auto => /#. qed.

lemma trunc256_h (h0 : BArray32.t) :
  hoare [M.__sha256_trunc_n : h = h0 ==>
    Node.to_list res = take P.`n (flatten (map w32_be (hw256 h0)))].
proof.
proc; have hn := n_val.
while (0 <= i <= inc /\ inc = P.`n %/ 4 /\ h = h0 /\
       forall j, 0 <= j < 4 * i => Node.get8 out j = nth W8.zero (flatten (map w32_be (hw256 h0))) j).
+ inline M.__bswap32; wp; skip => &m [#] g0 g1 gi gh hj hlt; do !(split; first smt()); move=> j hj'.
  rewrite Node.get8_set32dE; case: (4 * i{m} <= j < 4 * i{m} + 4) => h /=.
  + rewrite ifT 1:/# ArchWord.bswap32E bswap32_bits 1:/# nth_flat32 /hw256 ?size_map ?size_iota 1:/#.
    by rewrite (nth_map 0) ?size_iota 1:/# nth_iota 1:/# gh; congr; smt().
  by rewrite hj 1:/#.
wp; skip => /> &m; split; first smt().
move=> i o h1 h2 h3 h4 h5; apply (eq_from_nth W8.zero).
+ by rewrite Node.size_to_list size_take 1:/# size_flat32 size_hw256 /#.
move=> j; rewrite Node.size_to_list => hj.
by rewrite Node.get_to_list nth_take 1,2:/# h5 /#.
qed.

lemma seeded_block_p (a0 : BArray32.t) (xl b0 : int) :
  phoare [M.__sha256_seeded_block :
    adrs = a0 /\ x_len = xl /\ bits = b0 /\ 0 <= xl /\ 22 + xl < 62 /\ 0 <= b0 ==>
    forall j, 0 <= j < 64 => res.[j] = seeded a0 xl b0 j] = 1%r.
proof.
case: (0 <= xl /\ 22 + xl < 62 /\ 0 <= b0) => [[h0 [h1 h2]] | hn].
+ by conseq seeded_block_ll (seeded_block_h a0 xl b0 h0 h1 h2).
by exfalso; smt().
qed.

lemma trunc256_ll : islossless M.__sha256_trunc_n.
proof. by proc; inline *; wp; while true (inc - i); auto => /#. qed.

lemma trunc256_p (h0 : BArray32.t) :
  phoare [M.__sha256_trunc_n : h = h0 ==>
    Node.to_list res = take P.`n (flatten (map w32_be (hw256 h0)))] = 1%r.
proof. by conseq trunc256_ll (trunc256_h h0). qed.

(* The block _thash_f, _thash_prf and the narrow _thash_h compress last. *)
lemma tail_bytes (a : BArray32.t) (x : bytes) (blk : BArray64.t) :
  22 + size x <= 55 =>
  (forall j, 0 <= j < 64 => blk.[j] =
     if 22 <= j < 22 + size x then nth W8.zero x (j - 22)
     else seeded a (size x) (8 * (64 + (22 + size x))) j) =>
  BArray64.to_list blk = tail_block256 64 (compress (BArray32.to_list a) ++ x).
proof.
move=> hx hb; have hr : size (compress (BArray32.to_list a) ++ x) = 22 + size x.
+ by rewrite size_cat size_compress.
apply (eq_from_nth W8.zero).
+ by rewrite BArray64.size_to_list size_tail_block256 // hr.
move=> j; rewrite BArray64.size_to_list => hj.
have {hj} hj : 0 <= j < 64 by smt().
rewrite BArray64.get_to_list hb // nth_tail256 1,2:/# hr nth_cat size_compress /seeded.
move: (nth W8.zero x (j - 22)) (nth W8.zero (compress (BArray32.to_list a)) j) (W8.of_int 128).
move: (W8.of_int (8 * (64 + (22 + size x)) %/ 256)) (W8.of_int (8 * (64 + (22 + size x)))).
by move=> q4 q3 q0 q1 q2; smt(size_ge0).
qed.

(* Two compressions from ctx: the SHA-256 functions of section 11.2. *)
lemma two_blocks256 (pk x : bytes) (c : BArray96.t) (h : BArray32.t) (blk : BArray64.t)
                    (a : BArray32.t) :
  size pk = P.`n => 22 + size x <= 55 => ctx_ok pk c => hw256 h = cv256 c =>
  BArray64.to_list blk = tail_block256 64 (compress (BArray32.to_list a) ++ x) =>
  take P.`n (flatten (map w32_be (SHA256.compress (hw256 h) (map be32 (chunk 4 (BArray64.to_list blk))))))
  = trunc P.`n (SHA256.sha256 (pk ++ toByte 0 (64 - P.`n) ++ compress (BArray32.to_list a) ++ x)).
proof.
move=> hpk hx [hc _] hh hb.
rewrite hh hc hb /trunc -(catA (pk ++ toByte 0 (64 - P.`n)) (compress (BArray32.to_list a)) x).
rewrite sha256_two_blocks.
+ by rewrite size_cat hpk toByte0 1:/# size_nseq /#.
+ by rewrite size_cat size_compress /#.
by rewrite /seed_block.
qed.

(* ------------------------------------------------------------------ *)
(* The SHA-512 tail block of the wide H                               *)

(* Byte j of the last SHA-512 block after one 128-byte block, |r| <= 111. *)
lemma nth_tail512 (r : bytes) (j : int) : size r <= 111 => 0 <= j < 128 =>
  nth W8.zero (tail_block512 128 r) j =
    if j < size r then nth W8.zero r j
    else if j = size r then W8.of_int 128
    else if j < 126 then W8.zero
    else if j = 126 then W8.of_int (8 * (128 + size r) %/ 256)
    else W8.of_int (8 * (128 + size r)).
proof.
move=> hr hj; rewrite /tail_block512.
have hs : size (r ++ [W8.of_int 128] ++ zeros (111 - size r)) = 112.
+ by rewrite !size_cat size_zeros /#.
rewrite nth_cat hs; case: (j < 112) => h3.
+ rewrite nth_cat size_cat /=; case: (j < size r + 1) => h2.
  + rewrite nth_cat; case: (j < size r) => // h1.
    have -> : j - size r = 0 by smt().
    by rewrite /= ifT 1:/#.
  by rewrite /zeros nth_nseq 1:/# ifF 1:/# ifF 1:/# ifT 1:/#.
rewrite ifF 1:/# ifF 1:/# /be_bytes nth_mkseq 1:/# /=.
have hb : 0 <= 8 * (128 + size r) < 65536 by smt(size_ge0).
have -> : 16 - 1 - (j - 112) = 127 - j by ring.
case: (j < 126) => h4.
+ have hk : 1 <= 256 ^ (125 - j) by smt(expr_gt0).
  rewrite (_ : 127 - j = 2 + (125 - j)) 1:/# exprD_nneg 1,2:/# expr2 /= divz_small //.
  by rewrite ger0_norm; smt().
case: (j = 126) => [-> /= | h5]; first by rewrite ?expr1.
by rewrite (_ : 127 - j = 0) 1:/# ?expr0 ?divz1.
qed.

(* __adrs_compress_into128 leaves ADRS^c in bytes 0 .. 21, d0 above. *)
lemma into128_bytes (a : BArray32.t) (w0 w : BArray128.t) (j : int) :
  take 22 (BArray128.to_list w) = compress (BArray32.to_list a) =>
  drop 22 (BArray128.to_list w) = drop 22 (BArray128.to_list w0) =>
  0 <= j < 128 =>
  w.[j] = if j < 22 then nth W8.zero (compress (BArray32.to_list a)) j else w0.[j].
proof.
move=> ht hd hj; case: (j < 22) => h22 /=.
+ by rewrite -ht nth_take // BArray128.get_to_list.
have := congr1 (fun l => nth W8.zero l (j - 22)) _ _ hd => /=.
by rewrite !nth_drop 1..4:/# !BArray128.get_to_list /=; smt().
qed.

(* The wide block: ADRS^c || M2 then 0x80 and the 16-bit length the
   procedure stores in bytes 126 and 127. *)
lemma wide_tail (a : BArray32.t) (x : bytes) (w : BArray128.t) (p b q : int) :
  22 + size x <= 111 => p = 22 + size x => b = 8 * (128 + p) =>
  truncateu8 (W64.of_int q) = W8.of_int (b %/ 256) =>
  (forall j, 0 <= j < 128 => w.[j] =
     if j < 22 then nth W8.zero (compress (BArray32.to_list a)) j
     else if j < 22 + size x then nth W8.zero x (j - 22) else W8.zero) =>
  BArray128.to_list
    (BArray128.set8 (BArray128.set8 (BArray128.set8 w p (truncateu8 (W64.of_int 128)))
       126 (truncateu8 (W64.of_int q)))
       127 (truncateu8 (truncateu64 (W256.of_int b `&` W256.of_int 255))))
  = tail_block512 128 (compress (BArray32.to_list a) ++ x).
proof.
move=> hx -> -> hq hw; have hr : size (compress (BArray32.to_list a) ++ x) = 22 + size x.
+ by rewrite size_cat size_compress.
apply (eq_from_nth W8.zero).
+ by rewrite BArray128.size_to_list size_tail_block512 // hr.
move=> j; rewrite BArray128.size_to_list => hj.
have {hj} hj : 0 <= j < 128 by smt().
have hx0 := size_ge0 x; rewrite BArray128.get_to_list !BArray128.get_setE 1..3:/# nth_tail512 1,2:/# hr nth_cat size_compress.
rewrite len_lo 1:/# hq (_ : truncateu8 (W64.of_int 128) = W8.of_int 128).
+ by rewrite /truncateu8 W64.of_uintK.
rewrite hw 1:/#.
move: (nth W8.zero x (j - 22)) (nth W8.zero (compress (BArray32.to_list a)) j) (W8.of_int 128).
move: (W8.of_int (8 * (128 + (22 + size x)) %/ 256)) (W8.of_int (8 * (128 + (22 + size x)))).
by move=> q4 q3 q0 q1 q2; smt(size_ge0).
qed.

(* Two compressions from ctx: the SHA-512 functions of section 11.2. *)
lemma two_blocks512 (pk x : bytes) (c : BArray96.t) (h : BArray64.t) (a : BArray32.t) :
  size pk = P.`n => 22 + size x <= 111 => P.`n <> 16 => ctx_ok pk c => hw512 h = cv512 c =>
  take P.`n (flatten (map w64_be (SHA512.compress (hw512 h)
    (map be64 (chunk 8 (tail_block512 128 (compress (BArray32.to_list a) ++ x)))))))
  = trunc P.`n (SHA512.sha512 (pk ++ toByte 0 (128 - P.`n) ++ compress (BArray32.to_list a) ++ x)).
proof.
move=> hpk hx h16 [_ hc] hh.
rewrite hh (hc h16) /trunc -(catA (pk ++ toByte 0 (128 - P.`n)) (compress (BArray32.to_list a)) x).
rewrite sha512_two_blocks.
+ by rewrite size_cat hpk toByte0 1:/# size_nseq /#.
+ by rewrite size_cat size_compress /#.
by rewrite /seed_block.
qed.

lemma trunc512_h (h0 : BArray64.t) :
  hoare [M.__sha512_trunc_n : h = h0 ==>
    Node.to_list res = take P.`n (flatten (map w64_be (hw512 h0)))].
proof.
proc; have hn := n_val.
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ h = h0 /\
       forall j, 0 <= j < 8 * i => Node.get8 out j = nth W8.zero (flatten (map w64_be (hw512 h0))) j).
+ inline M.__bswap64; wp; skip => &m [#] g0 g1 gi gh hj hlt; do !(split; first smt()); move=> j hj'.
  rewrite Node.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
  + rewrite ifT 1:/# ArchWord.bswap64E bswap64_bits 1:/# nth_flat64 /hw512 ?size_map ?size_iota 1:/#.
    by rewrite (nth_map 0) ?size_iota 1:/# nth_iota 1:/# gh; congr; smt().
  by rewrite hj 1:/#.
wp; skip => /> &m; split; first smt().
move=> i o h1 h2 h3 h4 h5; apply (eq_from_nth W8.zero).
+ by rewrite Node.size_to_list size_take 1:/# size_flat64 size_hw512 /#.
move=> j; rewrite Node.size_to_list => hj.
by rewrite Node.get_to_list nth_take 1,2:/# h5 /#.
qed.

lemma trunc512_ll : islossless M.__sha512_trunc_n.
proof. by proc; inline *; wp; while true (inc - i); auto => /#. qed.

lemma trunc512_p (h0 : BArray64.t) :
  phoare [M.__sha512_trunc_n : h = h0 ==>
    Node.to_list res = take P.`n (flatten (map w64_be (hw512 h0)))] = 1%r.
proof. by conseq trunc512_ll (trunc512_h h0). qed.

(* ------------------------------------------------------------------ *)
(* The functions                                                      *)

section Thash.

declare axiom sha256_compress_h (h0 : W32.t list) (blk : BArray64.t) :
  phoare [M._sha256_compress : hw256 h = h0 /\ block = blk ==>
          hw256 res.`1 = SHA256.compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))] = 1%r.

lemma compress256_ll : islossless M._sha256_compress.
proof. by proc*; ecall (sha256_compress_h (hw256 h) block); auto. qed.

declare axiom sha512_compress_h (h0 : W64.t list) (blk : BArray128.t) :
  phoare [M._sha512_compress : hw512 h = h0 /\ block = blk ==>
          hw512 res.`1 = SHA512.compress h0 (map be64 (chunk 8 (BArray128.to_list blk)))] = 1%r.

lemma compress512_ll : islossless M._sha512_compress.
proof. by proc*; ecall (sha512_compress_h (hw512 h) block); auto. qed.

(* F(PK.seed, ADRS, M1): the tail block is ADRS^c || M1 || padding. *)
lemma thash_f_correct (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : Node.t) :
  phoare [M._thash_f :
    x = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = F P pk (BArray32.to_list a0) (Node.to_list x0)] = 1%r.
proof.
proc; have hn := n_val.
ecall (trunc256_p h).
wp; ecall (sha256_compress_h (hw256 h) block).
while (0 <= i <= 4 /\ ctx = c0 /\ forall j, 0 <= j < 8 * i => h.[j] = c0.[j]) (4 - i).
+ move=> z; wp; skip => &m [#] g0 g1 gc hj hlt hz; split; last by smt().
  do !(split; first smt()); move=> j hj'.
  rewrite BArray32.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
  + by rewrite ifT 1:/# gc BArray96.get64d_byte /#.
  by rewrite hj 1:/#.
wp.
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ x = x0 /\ ctx = c0 /\
       forall j, 0 <= j < 64 => block.[j] =
         if 22 <= j < 22 + 8 * i then Node.get8 x0 (j - 22)
         else seeded a0 P.`n (8 * (64 + (22 + P.`n))) j) (inc - i).
+ move=> z; wp; skip => &m [#] g0 g1 gi gx gc hj hlt hz; split; last by smt().
  do !(split; first smt()); move=> j hj'.
  rewrite BArray64.get8_set64dE; case: (22 + 8 * i{m} <= j < 22 + 8 * i{m} + 8) => h /=.
  + by rewrite ifT 1:/# ifT 1:/# gx Node.get64d_byte 1:/#; congr; ring.
  by rewrite hj //; smt().
wp; ecall (seeded_block_p a0 P.`n (8 * (64 + (22 + P.`n)))).
wp; skip => &m [#] hx hc ha hpk hok /=.
split; first smt().
move=> _ blk hblk; split.
+ do !(split; first smt()).
  by move=> j hj; rewrite hblk // ifF 1:/#.
move=> blk1 i1; split; first smt().
move=> hi1 [#] g0 g1 g2 g3 g4 hb1; split.
+ by split; [smt() | move=> j /#].
move=> h1 i2; split; first smt().
move=> hi2 [#] f0 f1 f2 hh r0 hr0 r1 hr1.
rewrite hr1 hr0 /F family_sha2 /=.
have hsx : size (Node.to_list x0) = P.`n by rewrite Node.size_to_list; smt().
have hbl : BArray64.to_list blk1 =
           tail_block256 64 (compress (BArray32.to_list a0) ++ Node.to_list x0).
+ apply tail_bytes; first smt().
  move=> j hj; rewrite hb1 // hsx Node.get_to_list.
  by rewrite (_ : 8 * i1 = P.`n) 1:/# (_ : 8 * (86 + P.`n) = 8 * (64 + (22 + P.`n))) 1:/#.
apply (two_blocks256 pk (Node.to_list x0) c0 h1 blk1 a0 hpk _ hok _ hbl); first smt().
by apply hw256_bytes => j hj; rewrite hh 1:/#.
+ wp; while true (4 - i); first by auto => /#.
  wp; while true (inc - i); first by auto => /#.
  by wp; call seeded_block_ll; auto => /#.
wp; call compress256_ll.
wp; while true (4 - i); first by auto => /#.
wp; while true (inc - i); first by auto => /#.
by wp; call seeded_block_ll; auto => /#.
qed.

(* PRF(PK.seed, SK.seed, ADRS): F with SK.seed as the payload. *)
lemma thash_prf_correct (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : Node.t) :
  phoare [M._thash_prf :
    sk_seed = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = PRF P pk (Node.to_list x0) (BArray32.to_list a0)] = 1%r.
proof.
proc; have hn := n_val.
ecall (trunc256_p h).
wp; ecall (sha256_compress_h (hw256 h) block).
while (0 <= i <= 4 /\ ctx = c0 /\ forall j, 0 <= j < 8 * i => h.[j] = c0.[j]) (4 - i).
+ move=> z; wp; skip => &m [#] g0 g1 gc hj hlt hz; split; last by smt().
  do !(split; first smt()); move=> j hj'.
  rewrite BArray32.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
  + by rewrite ifT 1:/# gc BArray96.get64d_byte /#.
  by rewrite hj 1:/#.
wp.
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ sk_seed = x0 /\ ctx = c0 /\
       forall j, 0 <= j < 64 => block.[j] =
         if 22 <= j < 22 + 8 * i then Node.get8 x0 (j - 22)
         else seeded a0 P.`n (8 * (64 + (22 + P.`n))) j) (inc - i).
+ move=> z; wp; skip => &m [#] g0 g1 gi gx gc hj hlt hz; split; last by smt().
  do !(split; first smt()); move=> j hj'.
  rewrite BArray64.get8_set64dE; case: (22 + 8 * i{m} <= j < 22 + 8 * i{m} + 8) => h /=.
  + by rewrite ifT 1:/# ifT 1:/# gx Node.get64d_byte 1:/#; congr; ring.
  by rewrite hj //; smt().
wp; ecall (seeded_block_p a0 P.`n (8 * (64 + (22 + P.`n)))).
wp; skip => &m [#] hx hc ha hpk hok /=.
split; first smt().
move=> _ blk hblk; split.
+ do !(split; first smt()).
  by move=> j hj; rewrite hblk // ifF 1:/#.
move=> blk1 i1; split; first smt().
move=> hi1 [#] g0 g1 g2 g3 g4 hb1; split.
+ by split; [smt() | move=> j /#].
move=> h1 i2; split; first smt().
move=> hi2 [#] f0 f1 f2 hh r0 hr0 r1 hr1.
rewrite hr1 hr0 /PRF family_sha2 /=.
have hsx : size (Node.to_list x0) = P.`n by rewrite Node.size_to_list; smt().
have hbl : BArray64.to_list blk1 =
           tail_block256 64 (compress (BArray32.to_list a0) ++ Node.to_list x0).
+ apply tail_bytes; first smt().
  move=> j hj; rewrite hb1 // hsx Node.get_to_list.
  by rewrite (_ : 8 * i1 = P.`n) 1:/# (_ : 8 * (86 + P.`n) = 8 * (64 + (22 + P.`n))) 1:/#.
apply (two_blocks256 pk (Node.to_list x0) c0 h1 blk1 a0 hpk _ hok _ hbl); first smt().
by apply hw256_bytes => j hj; rewrite hh 1:/#.
+ wp; while true (4 - i); first by auto => /#.
  wp; while true (inc - i); first by auto => /#.
  by wp; call seeded_block_ll; auto => /#.
wp; call compress256_ll.
wp; while true (4 - i); first by auto => /#.
wp; while true (inc - i); first by auto => /#.
by wp; call seeded_block_ll; auto => /#.
qed.

end section Thash.
