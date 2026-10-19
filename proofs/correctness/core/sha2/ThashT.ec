(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ThashT.ec (SHA2 sets)
 * =====================
 *
 * T_len and T_k of the SHA2 parameter sets (FIPS 205 section 11.2):
 * thash_sha2_t.jinc lays ADRS^c || M_l and the SHA-2 padding of the
 * whole input PK.seed || zeros || ADRS^c || M_l out in a work buffer,
 * then compresses the buffer block by block from the chaining value
 * after the seed block, which ctx holds (Thash.ctx_ok). SHA-256 for
 * n = 16, SHA-512 otherwise.
 *
 * __t_layout (both instances) leaves, below the padded length l of the
 * call, the bytes tlay: ADRS^c, the l n-byte inputs, 0x80, zeros, and
 * the two low bytes of the bit length (every T_l input of FIPS 205 is
 * shorter than 2^16 bits, so the six higher bytes of the length field
 * are zero). With l and the bit length of the call these are the bytes
 * of ThashBlocks.pad_tail256 64 (pad_tail512 128) of ADRS^c || M_l
 * (tlay_pad256, tlay_pad512). The compression loop extends the fold of
 * ThashBlocks.sha256_hash_seeded (sha512_hash_seeded) one block at a
 * time (step256, step512).
 *
 * Model. The branches on SHA2_WIDE are literals in each model; the
 * narrow (n = 16) and wide (n = 24, 32) theorems hold on every set, the
 * dead one from the contradiction between its condition on n and n_val.
 *
 * Theorems (total correctness, ctx_ok for PK.seed):
 *     thash_t_len_total   _thash_t_len returns T_l(PK.seed, ADRS, M) on
 *                         the len n-byte values M
 *     thash_t_k_total     _thash_t_k, the same on the k FORS roots
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS180_SHA2 FIPS180_SHA2_Blocks.
require import FIPS205_Params FIPS205_Encoding FIPS205_Address FIPS205_Address_Props FIPS205_Hash.
require import BArray32 BArray64 BArray96 BArray128 SetModel CoreExtracted ADRSc.
require import Thash ThashBlocks HashKernels MsgHash Mgf1.

(* ------------------------------------------------------------------ *)
(* The laid-out input                                                 *)

op tin (a : BArray32.t) (x : bytes) : bytes = compress (BArray32.to_list a) ++ x.

lemma size_tin (a : BArray32.t) (x : bytes) : size (tin a x) = 22 + size x.
proof. by rewrite /tin size_cat size_compress. qed.

(* The first l bytes of the work buffer after __t_layout, b the bit length. *)
op tlay (a : BArray32.t) (x : bytes) (l b j : int) : W8.t =
  if j < 22 then nth W8.zero (compress (BArray32.to_list a)) j
  else if j < 22 + size x then nth W8.zero x (j - 22)
  else if j = 22 + size x then W8.of_int 128
  else if j < l - 2 then W8.zero
  else if j = l - 2 then W8.of_int (b %/ 256)
  else W8.of_int b.

lemma tlay_pad256 (a : BArray32.t) (x : bytes) (j : int) :
  8 * (64 + (22 + size x)) < 65536 => 0 <= j < size (pad_tail256 64 (tin a x)) =>
  tlay a x (size (pad_tail256 64 (tin a x))) (8 * (64 + (22 + size x))) j
  = nth W8.zero (pad_tail256 64 (tin a x)) j.
proof.
move=> hb hj; have hs := size_tin a x.
have ht : forall k, nth W8.zero (tin a x) k =
  if k < 22 then nth W8.zero (compress (BArray32.to_list a)) k else nth W8.zero x (k - 22).
+ by move=> k; rewrite /tin nth_cat size_compress.
rewrite nth_pad_tail256 1,2:/# hs ht /tlay.
by smt(size_ge0).
qed.

lemma tlay_pad512 (a : BArray32.t) (x : bytes) (j : int) :
  8 * (128 + (22 + size x)) < 65536 => 0 <= j < size (pad_tail512 128 (tin a x)) =>
  tlay a x (size (pad_tail512 128 (tin a x))) (8 * (128 + (22 + size x))) j
  = nth W8.zero (pad_tail512 128 (tin a x)) j.
proof.
move=> hb hj; have hs := size_tin a x.
have ht : forall k, nth W8.zero (tin a x) k =
  if k < 22 then nth W8.zero (compress (BArray32.to_list a)) k else nth W8.zero x (k - 22).
+ by move=> k; rewrite /tin nth_cat size_compress.
rewrite nth_pad_tail512 1,2:/# hs ht /tlay.
by smt(size_ge0).
qed.

(* The byte offset of input word k in the work buffer. *)
lemma off_word (k : W64.t) : to_uint k < 65536 =>
  to_uint ((k `<<` W8.of_int 3) + W64.of_int 22) = 8 * to_uint k + 22.
proof.
move=> hk; have [h0 _] := W64.to_uint_cmp k.
have hM : 524288 < W64.modulus by trivial.
have hs : to_uint (k `<<` W8.of_int 3) = 8 * to_uint k.
+ rewrite W64.shl_shlw // W64.to_uint_shl // (_ : 2 ^ 3 = 8) 1:// pmod_small; smt().
by rewrite W64.to_uintD_small hs W64.of_uintK /=; smt().
qed.

lemma inc_off (o : W64.t) (c : int) : 0 <= c < 65536 => to_uint o < 65536 =>
  to_uint (o + W64.of_int c) = to_uint o + c.
proof.
move=> hc ho; have hM : 131072 < W64.modulus by trivial.
by rewrite W64.to_uintD_small W64.of_uintK pmod_small; smt(W64.to_uint_cmp).
qed.

lemma inc_one (x : W64.t) : to_uint x < 65536 => to_uint (x + W64.one) = to_uint x + 1.
proof.
move=> h; have hM : 131072 < W64.modulus by trivial.
by rewrite W64.to_uintD_small W64.to_uint1; smt(W64.to_uint_cmp).
qed.

lemma step_le (d o p : int) : 0 < d => o %% d = 0 => p %% d = 0 => o < p => o + d <= p.
proof.
move=> hd ho hp hlt.
have eo := divz_eq o d; have ep := divz_eq p d; rewrite ho /= in eo; rewrite hp /= in ep.
have : o %/ d < p %/ d by smt(ltr_pmul2r).
by smt().
qed.

lemma src_mid (i : int) : 0 <= i < 8 => adrsc_src (1 + i) = 8 + i.
proof. by rewrite /adrsc_src; smt(). qed.

lemma src_hi (i : int) : 0 <= i < 12 => adrsc_src (10 + i) = 20 + i.
proof. by rewrite /adrsc_src; smt(). qed.

(* ------------------------------------------------------------------ *)
(* Closing: the fold from ctx is T_l                                  *)

lemma close256 (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x : bytes) (hv : W32.t list) :
  P.`n = 16 => size pk = P.`n => ctx_ok pk c0 =>
  hv = foldl SHA256.compress (cv256 c0) (SHA256.parse (pad_tail256 64 (tin a0 x))) =>
  take P.`n (flatten (map w32_be hv)) = T_l P pk (BArray32.to_list a0) x.
proof.
move=> h16 hpk [hc _] ->.
have hsb : size (seed_block 64 pk) = 64.
+ by rewrite /seed_block size_cat hpk toByte0 1:/# size_nseq; smt(n_val).
rewrite /T_l family_sha2 /= ifT 1:/# /trunc hc /tin.
rewrite -(catA (pk ++ toByte 0 (64 - P.`n))) (_ : pk ++ toByte 0 (64 - P.`n) = seed_block 64 pk) 1://.
by rewrite (sha256_seeded _ _ hsb).
qed.

lemma close512 (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x : bytes) (hv : W64.t list) :
  P.`n <> 16 => size pk = P.`n => ctx_ok pk c0 =>
  hv = foldl SHA512.compress (cv512 c0) (SHA512.parse (pad_tail512 128 (tin a0 x))) =>
  take P.`n (flatten (map w64_be hv)) = T_l P pk (BArray32.to_list a0) x.
proof.
move=> h16 hpk [_ hc] ->.
have hsb : size (seed_block 128 pk) = 128.
+ by rewrite /seed_block size_cat hpk toByte0 1:/# size_nseq; smt(n_val).
rewrite /T_l family_sha2 /= ifF 1:/# /trunc (hc h16) /tin.
rewrite -(catA (pk ++ toByte 0 (128 - P.`n))) (_ : pk ++ toByte 0 (128 - P.`n) = seed_block 128 pk) 1://.
by rewrite (sha512_seeded _ _ hsb).
qed.

(* ------------------------------------------------------------------ *)
(* T_len                                                              *)

op tlen_pl256 : int = 64 * ((22 + TLenIn.size + 72) %/ 64).
op tlen_pl512 : int = 128 * ((22 + TLenIn.size + 144) %/ 128).

lemma size_tlen (x : TLenIn.t) : size (TLenIn.to_list x) = TLenIn.size.
proof. by rewrite TLenIn.size_to_list; smt(). qed.

lemma tlen_dims :
  0 < TLenIn.size /\ TLenIn.size %% 8 = 0 /\ 8 * (128 + (22 + TLenIn.size)) < 65536 /\
  tlen_pl512 = TLenBuf.size /\ 22 + TLenIn.size + 3 <= tlen_pl256 <= TLenBuf.size /\
  tlen_pl256 %% 64 = 0 /\ tlen_pl512 %% 128 = 0 /\ 22 + TLenIn.size + 3 <= tlen_pl512.
proof. by rewrite /tlen_pl256 /tlen_pl512; smt(). qed.

lemma tlen_size256 (a : BArray32.t) (x : TLenIn.t) :
  size (pad_tail256 64 (tin a (TLenIn.to_list x))) = tlen_pl256.
proof. by rewrite size_pad_tail256 size_tin size_tlen /tlen_pl256; smt(). qed.

lemma tlen_size512 (a : BArray32.t) (x : TLenIn.t) :
  size (pad_tail512 128 (tin a (TLenIn.to_list x))) = tlen_pl512.
proof. by rewrite size_pad_tail512 size_tin size_tlen /tlen_pl512; smt(). qed.

lemma tlen_lay256 (a : BArray32.t) (x : TLenIn.t) (j : int) : 0 <= j < tlen_pl256 =>
  tlay a (TLenIn.to_list x) tlen_pl256 (8 * (64 + (22 + TLenIn.size))) j
  = nth W8.zero (pad_tail256 64 (tin a (TLenIn.to_list x))) j.
proof.
move=> hj; have hs := size_tlen x; have hp := tlen_size256 a x; have hd := tlen_dims.
have := tlay_pad256 a (TLenIn.to_list x) j _ _; 1,2: smt().
by rewrite hp hs.
qed.

lemma tlen_lay512 (a : BArray32.t) (x : TLenIn.t) (j : int) : 0 <= j < tlen_pl512 =>
  tlay a (TLenIn.to_list x) tlen_pl512 (8 * (128 + (22 + TLenIn.size))) j
  = nth W8.zero (pad_tail512 128 (tin a (TLenIn.to_list x))) j.
proof.
move=> hj; have hs := size_tlen x; have hp := tlen_size512 a x; have hd := tlen_dims.
have := tlay_pad512 a (TLenIn.to_list x) j _ _; 1,2: smt().
by rewrite hp hs.
qed.

(* One compression of the loop: block o / 64 of the padded string p. *)
lemma tlen_step256 (m : TLenBuf.t) (p : bytes) (h0 : W32.t list) (o : int) :
  0 <= o => o %% 64 = 0 => o + 64 <= size p => size p <= TLenBuf.size => size p %% 64 = 0 =>
  (forall k, 0 <= k < size p => TLenBuf.get8 m k = nth W8.zero p k) =>
  SHA256.compress (foldl SHA256.compress h0 (take (o %/ 64) (SHA256.parse p)))
    (map be32 (chunk 4 (BArray64.to_list (TLenBlk256.get_sub m o))))
  = foldl SHA256.compress h0 (take ((o + 64) %/ 64) (SHA256.parse p)).
proof.
move=> h0o hd hp hpb hpd hm.
have hsb : BArray64.to_list (TLenBlk256.get_sub m o) = take 64 (drop o p).
+ apply (eq_from_nth W8.zero).
  + by rewrite BArray64.size_to_list size_take // size_drop 1:/#; smt().
  move=> j; rewrite BArray64.size_to_list => hj.
  rewrite BArray64.get_to_list TLenBlk256.get8_get_sub hj /= hm 1:/#.
  by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
have ho : o = 64 * (o %/ 64) by smt().
have hq := size_parse256 p (size p %/ 64) _ _; 1,2: smt().
have hn := nth_parse256 p (o %/ 64) _ _; 1,2: smt().
by rewrite (_ : (o + 64) %/ 64 = o %/ 64 + 1) 1:/# (take_nth []) 1:/# foldl_rcons hn -ho hsb.
qed.

lemma tlen_step512 (m : TLenBuf.t) (p : bytes) (h0 : W64.t list) (o : int) :
  0 <= o => o %% 128 = 0 => o + 128 <= size p => size p <= TLenBuf.size => size p %% 128 = 0 =>
  (forall k, 0 <= k < size p => TLenBuf.get8 m k = nth W8.zero p k) =>
  SHA512.compress (foldl SHA512.compress h0 (take (o %/ 128) (SHA512.parse p)))
    (map be64 (chunk 8 (BArray128.to_list (TLenBlk512.get_sub m o))))
  = foldl SHA512.compress h0 (take ((o + 128) %/ 128) (SHA512.parse p)).
proof.
move=> h0o hd hp hpb hpd hm.
have hsb : BArray128.to_list (TLenBlk512.get_sub m o) = take 128 (drop o p).
+ apply (eq_from_nth W8.zero).
  + by rewrite BArray128.size_to_list size_take // size_drop 1:/#; smt().
  move=> j; rewrite BArray128.size_to_list => hj.
  rewrite BArray128.get_to_list TLenBlk512.get8_get_sub hj /= hm 1:/#.
  by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
have ho : o = 128 * (o %/ 128) by smt().
have hq := size_parse512 p (size p %/ 128) _ _; 1,2: smt().
have hn := nth_parse512 p (o %/ 128) _ _; 1,2: smt().
by rewrite (_ : (o + 128) %/ 128 = o %/ 128 + 1) 1:/# (take_nth []) 1:/# foldl_rcons hn -ho hsb.
qed.

lemma tlen_all256 (a : BArray32.t) (x : TLenIn.t) :
  take (tlen_pl256 %/ 64) (SHA256.parse (pad_tail256 64 (tin a (TLenIn.to_list x))))
  = SHA256.parse (pad_tail256 64 (tin a (TLenIn.to_list x))).
proof.
have hp := tlen_size256 a x; have hd := tlen_dims.
rewrite take_oversize // (size_parse256 _ (tlen_pl256 %/ 64)); smt().
qed.

lemma tlen_all512 (a : BArray32.t) (x : TLenIn.t) :
  take (tlen_pl512 %/ 128) (SHA512.parse (pad_tail512 128 (tin a (TLenIn.to_list x))))
  = SHA512.parse (pad_tail512 128 (tin a (TLenIn.to_list x))).
proof.
have hp := tlen_size512 a x; have hd := tlen_dims.
rewrite take_oversize // (size_parse512 _ (tlen_pl512 %/ 128)); smt().
qed.

lemma tlen_layout_h (a0 : BArray32.t) (x0 : TLenIn.t) (l b : int) :
  22 + TLenIn.size + 3 <= l <= TLenBuf.size => 0 <= b =>
  hoare [M.tLen____t_layout : in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b ==>
    forall j, 0 <= j < l => TLenBuf.get8 res.`1 j = tlay a0 (TLenIn.to_list x0) l b j].
proof.
move=> hl hb; have hd := tlen_dims; proc.
seq 4 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TLenBuf.size => TLenBuf.get8 buf j = W8.zero).
+ while (0 <= i <= inc /\ 8 * inc = TLenBuf.size /\ z = W64.zero /\ in_0 = x0 /\ adrs = a0 /\
         padded = l /\ bits = b /\ forall j, 0 <= j < 8 * i => TLenBuf.get8 buf j = W8.zero).
  + wp; skip => &m [#] h0 h1 hinc hz hx ha hp hbb hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite TLenBuf.get8_set64dE hz; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
    + by rewrite ifT 1:/# W8u8.get_zero.
    by rewrite hj 1:/#.
  by auto => /> &m; smt().
seq 4 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TLenBuf.size => TLenBuf.get8 buf j =
           if j < 9 then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
+ while (0 <= i <= 8 /\ in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TLenBuf.size => TLenBuf.get8 buf j =
           if j < 1 + i then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
  + wp; skip => &m [#] h0 h1 hx ha hp hbb hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite TLenBuf.get_setE 1:/#.
    case: (j = 1 + i{m}) => [-> /=|h].
    + by rewrite ifT 1:/# compress_nth 1:/# src_mid 1:/# trunc_zext8 ha.
    by rewrite hj // /#.
  wp; skip => &m [#] hx ha hp hbb hj /=; split.
  + split; first by [].
    do !(split; first smt()); move=> j hj'; rewrite TLenBuf.get_setE 1:/#.
    case: (j = 0) => [-> /=|h]; first by rewrite compress_nth // /adrsc_src /= trunc_zext8 ha.
    by rewrite hj //; smt().
  by move=> b1 i1 hi [#] g0 g1 g2 g3 g4 g5 gj; do !(split; first smt()); move=> j hj2; rewrite gj //; smt().
seq 4 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TLenBuf.size => TLenBuf.get8 buf j =
           if j < 22 then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
+ while (0 <= i <= 12 /\ in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TLenBuf.size => TLenBuf.get8 buf j =
           if j < 10 + i then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
  + wp; skip => &m [#] h0 h1 hx ha hp hbb hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite TLenBuf.get_setE 1:/#.
    case: (j = 10 + i{m}) => [-> /=|h].
    + by rewrite ifT 1:/# compress_nth 1:/# src_hi 1:/# trunc_zext8 ha.
    by rewrite hj // /#.
  wp; skip => &m [#] hx ha hp hbb hj /=; split.
  + do !(split; first smt()); move=> j hj'; rewrite TLenBuf.get_setE 1:/#.
    case: (j = 9) => [-> /=|h]; first by rewrite compress_nth // /adrsc_src /= trunc_zext8 ha.
    by rewrite hj //; smt().
  by move=> b1 i1 hi [#] g0 g1 g2 g3 g4 g5 gj; do !(split; first smt()); move=> j hj2; rewrite gj //; smt().
seq 3 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TLenBuf.size => TLenBuf.get8 buf j =
           if j < 22 then nth W8.zero (compress (BArray32.to_list a0)) j
           else if j < 22 + TLenIn.size then TLenIn.get8 x0 (j - 22) else W8.zero).
+ while (0 <= to_uint k <= TLenIn.size %/ 8 /\ (more <=> to_uint k < TLenIn.size %/ 8) /\
         in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TLenBuf.size => TLenBuf.get8 buf j =
           if j < 22 then nth W8.zero (compress (BArray32.to_list a0)) j
           else if j < 22 + 8 * to_uint k then TLenIn.get8 x0 (j - 22) else W8.zero).
  + wp; skip => &m [#] h0 h1 hmore hx ha hp hbb hj hm /=.
    have hk : to_uint k{m} < TLenIn.size %/ 8 by rewrite -hmore.
    have ho := off_word k{m} _; first smt().
    have hk1 := inc_off k{m} 1 _ _; 1,2: smt().
    rewrite hk1 W64.ultE hk1 W64.of_uintK /=.
    do !(split; first smt()); move=> j hj'; rewrite TLenBuf.get8_set64dE ho hx.
    case: (8 * to_uint k{m} + 22 <= j < 8 * to_uint k{m} + 22 + 8) => h /=.
    + rewrite ifT 1:/# ifF 1:/# ifT 1:/# TLenIn.get64d_byte 1:/#; congr; ring.
    by rewrite hj //; smt().
  wp; skip => &m [#] hx ha hp hbb hj /=; rewrite ?W64.ultE ?W64.of_uintK /=; split.
  + do !(split; first smt()); move=> j hj'; rewrite hj //; smt().
  move=> b1 k1 m1 hm1 [#] g0 g1 g2 g3 g4 g5 g6 gj; do !(split; first smt()).
  by move=> j hj2; rewrite gj //; smt().
wp; skip => &m [#] hx ha hp hbb hA j hj /=; rewrite hp hbb.
have hv1 : truncateu8 (W64.of_int 128) = W8.of_int 128 by rewrite /truncateu8 W64.of_uintK.
rewrite !TLenBuf.get_setE 1..3:/# len_lo 1:/# len_hi 1:/# hv1 /tlay size_tlen TLenIn.get_to_list hA 1:/#.
by smt().
qed.

lemma tlen_layout_ll : islossless M.tLen____t_layout.
proof.
proc; wp.
while (0 <= to_uint k <= TLenIn.size %/ 8 /\ (more <=> to_uint k < TLenIn.size %/ 8))
      (TLenIn.size %/ 8 - to_uint k).
+ move=> z; wp; skip => &m [#] h0 h1 hmore hm hz /=.
  have hk : to_uint k{m} < TLenIn.size %/ 8 by rewrite -hmore.
  have hk1 := inc_one k{m} _; first smt().
  by rewrite W64.ultE hk1 W64.of_uintK /=; smt().
wp; while (true) (12 - i); first by auto => /#.
wp; while (true) (8 - i); first by auto => /#.
wp; while (true) (inc - i); first by auto => /#.
by auto => />; rewrite ?W64.ultE ?W64.of_uintK /=; smt().
qed.

lemma tlen_narrow_h (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TLenIn.t) :
  P.`n = 16 =>
  hoare [M.tLen___thash_t :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list x0)].
proof.
move=> h16; have hn := n_val; have hd := tlen_dims.
have hl : 22 + TLenIn.size + 3 <= tlen_pl256 <= TLenBuf.size by smt().
have hb : 0 <= 8 * (64 + (22 + TLenIn.size)) by smt().
proc.
seq 5 : (in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0); first by auto.
if; last by conseq (_ : false ==> _) => //; smt().
seq 3 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw256 h = cv256 c0 /\
         forall j, 0 <= j < tlen_pl256 =>
           TLenBuf.get8 p j = nth W8.zero (pad_tail256 64 (tin a0 (TLenIn.to_list x0))) j).
+ while (0 <= i <= 4 /\ ctx = c0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         (forall j, 0 <= j < tlen_pl256 =>
            TLenBuf.get8 p j = nth W8.zero (pad_tail256 64 (tin a0 (TLenIn.to_list x0))) j) /\
         forall j, 0 <= j < 8 * i => h.[j] = c0.[j]).
  + wp; skip => &m [#] g0 g1 gc hp hc hl' hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite BArray32.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
    + by rewrite ifT 1:/# gc BArray96.get64d_byte /#.
    by rewrite hj 1:/#.
  wp; ecall (tlen_layout_h a0 x0 tlen_pl256 (8 * (64 + (22 + TLenIn.size))) hl hb).
  skip => &m [#] -> -> -> hp hc _ /=; split; first smt().
  move=> _ r hr.
  have hpl : forall j, 0 <= j < tlen_pl256 =>
    TLenBuf.get8 r.`1 j = nth W8.zero (pad_tail256 64 (tin a0 (TLenIn.to_list x0))) j.
  + by move=> j hj; rewrite hr // tlen_lay256.
  split; first smt().
  move=> h1 i1 hlt [#] g0 g1 _ _ gl gh; split; first exact hp.
  split; first exact hc.
  split; last exact gl.
  by apply hw256_bytes => j hj; apply gh; smt().
seq 2 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw256 h = cv256 c0 /\ off = W64.zero /\
         forall j, 0 <= j < tlen_pl256 =>
           TLenBuf.get8 buf j = nth W8.zero (pad_tail256 64 (tin a0 (TLenIn.to_list x0))) j).
+ by auto.
if; last by conseq (_ : false ==> _) => //; smt().
ecall (trunc256_h h).
wp.
while (0 <= to_uint off <= tlen_pl256 /\ to_uint off %% 64 = 0 /\ (more <=> to_uint off < tlen_pl256) /\
       (forall j, 0 <= j < tlen_pl256 =>
          TLenBuf.get8 buf j = nth W8.zero (pad_tail256 64 (tin a0 (TLenIn.to_list x0))) j) /\
       hw256 h = foldl SHA256.compress (cv256 c0)
                   (take (to_uint off %/ 64) (SHA256.parse (pad_tail256 64 (tin a0 (TLenIn.to_list x0)))))).
+ wp; exlim h, buf, off => h0 b0 o0.
  call (compress256_h (hw256 h0) (TLenBlk256.get_sub b0 (to_uint o0))).
  wp; skip => &m [#] -> -> -> g0 g1 gd hmore gb gh hm /=; try (split; first by []).
  move=> r hh1 /=; rewrite /SLH64.protect_64.
  have hlt : to_uint off{m} < tlen_pl256 by rewrite -hmore.
  have ho := inc_off off{m} 64 _ _; 1,2: smt().
  have hle := step_le 64 (to_uint off{m}) tlen_pl256 _ gd _ hlt; 1,2: smt().
  rewrite ho W64.ultE ho W64.of_uintK /=; do !(split; first smt()).
  have hsp := tlen_size256 a0 x0.
  rewrite hh1 gh; apply (tlen_step256 buf{m}); 1..5: smt().
  by move=> k hk; rewrite gb; smt().
wp; skip => &m [#] hp hc hh -> hb' _ /=; rewrite ?W64.ultE ?W64.of_uintK /=; split.
+ by rewrite take0 /=; smt().
move=> h1 m1 o1 hm1 [#] g0 g1 gd hmore gb gh r hr.
have ho : to_uint o1 = tlen_pl256 by smt().
rewrite hr; apply (close256 pk c0 a0 (TLenIn.to_list x0) (hw256 h1) h16 hp hc).
by rewrite gh ho tlen_all256.
qed.

lemma tlen_wide_h (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TLenIn.t) :
  P.`n <> 16 =>
  hoare [M.tLen___thash_t :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list x0)].
proof.
move=> h16; have hn := n_val; have hd := tlen_dims.
have hl : 22 + TLenIn.size + 3 <= tlen_pl512 <= TLenBuf.size by smt().
have hb : 0 <= 8 * (128 + (22 + TLenIn.size)) by smt().
proc.
seq 5 : (in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0); first by auto.
if; first by conseq (_ : false ==> _) => //; smt().
seq 3 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw512 h512 = cv512 c0 /\
         forall j, 0 <= j < tlen_pl512 =>
           TLenBuf.get8 p j = nth W8.zero (pad_tail512 128 (tin a0 (TLenIn.to_list x0))) j).
+ while (0 <= i <= 8 /\ ctx = c0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         (forall j, 0 <= j < tlen_pl512 =>
            TLenBuf.get8 p j = nth W8.zero (pad_tail512 128 (tin a0 (TLenIn.to_list x0))) j) /\
         forall j, 0 <= j < 8 * i => h512.[j] = c0.[32 + j]).
  + wp; skip => &m [#] g0 g1 gc hp hc hl' hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite BArray64.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
    + by rewrite ifT 1:/# gc BArray96.get64d_byte /#.
    by rewrite hj 1:/#.
  wp; ecall (tlen_layout_h a0 x0 tlen_pl512 (8 * (128 + (22 + TLenIn.size))) hl hb).
  skip => &m [#] -> -> -> hp hc _ /=; split; first smt().
  move=> _ r hr.
  have hpl : forall j, 0 <= j < tlen_pl512 =>
    TLenBuf.get8 r.`1 j = nth W8.zero (pad_tail512 128 (tin a0 (TLenIn.to_list x0))) j.
  + by move=> j hj; rewrite hr // tlen_lay512.
  split; first smt().
  move=> h1 i1 hlt [#] g0 g1 _ _ gl gh; split; first exact hp.
  split; first exact hc.
  split; last exact gl.
  by apply hw512_bytes => j hj; apply gh; smt().
seq 2 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw512 h512 = cv512 c0 /\ off = W64.zero /\
         forall j, 0 <= j < tlen_pl512 =>
           TLenBuf.get8 buf j = nth W8.zero (pad_tail512 128 (tin a0 (TLenIn.to_list x0))) j).
+ by auto.
if; first by conseq (_ : false ==> _) => //; smt().
ecall (trunc512_h h512).
wp.
while (0 <= to_uint off <= tlen_pl512 /\ to_uint off %% 128 = 0 /\ (more <=> to_uint off < tlen_pl512) /\
       (forall j, 0 <= j < tlen_pl512 =>
          TLenBuf.get8 buf j = nth W8.zero (pad_tail512 128 (tin a0 (TLenIn.to_list x0))) j) /\
       hw512 h512 = foldl SHA512.compress (cv512 c0)
                   (take (to_uint off %/ 128) (SHA512.parse (pad_tail512 128 (tin a0 (TLenIn.to_list x0)))))).
+ wp; exlim h512, buf, off => h0 b0 o0.
  call (compress512_h (hw512 h0) (TLenBlk512.get_sub b0 (to_uint o0))).
  wp; skip => &m [#] -> -> -> g0 g1 gd hmore gb gh hm /=; try (split; first by []).
  move=> r hh1 /=; rewrite /SLH64.protect_64.
  have hlt : to_uint off{m} < tlen_pl512 by rewrite -hmore.
  have ho := inc_off off{m} 128 _ _; 1,2: smt().
  have hle := step_le 128 (to_uint off{m}) tlen_pl512 _ gd _ hlt; 1,2: smt().
  rewrite ho W64.ultE ho W64.of_uintK /=; do !(split; first smt()).
  have hsp := tlen_size512 a0 x0.
  rewrite hh1 gh; apply (tlen_step512 buf{m}); 1..5: smt().
  by move=> k hk; rewrite gb; smt().
wp; skip => &m [#] hp hc hh -> hb' _ /=; rewrite ?W64.ultE ?W64.of_uintK /=; split.
+ by rewrite take0 /=; smt().
move=> h1 m1 o1 hm1 [#] g0 g1 gd hmore gb gh r hr.
have ho : to_uint o1 = tlen_pl512 by smt().
rewrite hr; apply (close512 pk c0 a0 (TLenIn.to_list x0) (hw512 h1) h16 hp hc).
by rewrite gh ho tlen_all512.
qed.

lemma tlen_ll : islossless M.tLen___thash_t.
proof.
proc.
seq 7 : true 1%r 1%r 0%r _ => //.
+ sp; if.
  + wp; while (true) (4 - i); first by auto => /#.
    by wp; call tlen_layout_ll; auto => /#.
  wp; while (true) (8 - i); first by auto => /#.
  by wp; call tlen_layout_ll; auto => /#.
have hd := tlen_dims.
sp; if.
+ call trunc256_ll; wp.
  while (0 <= to_uint off <= tlen_pl256 /\ to_uint off %% 64 = 0 /\ (more <=> to_uint off < tlen_pl256))
        (tlen_pl256 - to_uint off).
  + move=> z; wp; call set_compress256_ll; wp; skip => &m [#] g0 g1 gd hmore hm hz /=.
    have hlt : to_uint off{m} < tlen_pl256 by rewrite -hmore.
    have ho := inc_off off{m} 64 _ _; 1,2: smt().
    by rewrite /SLH64.protect_64 ho W64.ultE ho W64.of_uintK /=; smt().
  by wp; skip => &m [#] -> _; rewrite ?W64.ultE ?W64.of_uintK ?W64.to_uint0 /=; smt().
call trunc512_ll; wp.
while (0 <= to_uint off <= tlen_pl512 /\ to_uint off %% 128 = 0 /\ (more <=> to_uint off < tlen_pl512))
      (tlen_pl512 - to_uint off).
+ move=> z; wp; call set_compress512_ll; wp; skip => &m [#] g0 g1 gd hmore hm hz /=.
  have hlt : to_uint off{m} < tlen_pl512 by rewrite -hmore.
  have ho := inc_off off{m} 128 _ _; 1,2: smt().
  by rewrite /SLH64.protect_64 ho W64.ultE ho W64.of_uintK /=; smt().
by wp; skip => &m [#] -> _; rewrite ?W64.ultE ?W64.of_uintK ?W64.to_uint0 /=; smt().
qed.

lemma tlen_h (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TLenIn.t) :
  hoare [M.tLen___thash_t :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list x0)].
proof.
case: (P.`n = 16) => h16; first exact (tlen_narrow_h pk c0 a0 x0 h16).
exact (tlen_wide_h pk c0 a0 x0 h16).
qed.

lemma thash_t_len_total (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TLenIn.t) :
  phoare [M._thash_t_len :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list x0)] = 1%r.
proof. by proc; call (_ : in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list x0)); [conseq tlen_ll (tlen_h pk c0 a0 x0) | auto]. qed.

(* ------------------------------------------------------------------ *)
(* T_k                                                              *)

op tk_pl256 : int = 64 * ((22 + TKIn.size + 72) %/ 64).
op tk_pl512 : int = 128 * ((22 + TKIn.size + 144) %/ 128).

lemma size_tk (x : TKIn.t) : size (TKIn.to_list x) = TKIn.size.
proof. by rewrite TKIn.size_to_list; smt(). qed.

lemma tk_dims :
  0 < TKIn.size /\ TKIn.size %% 8 = 0 /\ 8 * (128 + (22 + TKIn.size)) < 65536 /\
  tk_pl512 = TKBuf.size /\ 22 + TKIn.size + 3 <= tk_pl256 <= TKBuf.size /\
  tk_pl256 %% 64 = 0 /\ tk_pl512 %% 128 = 0 /\ 22 + TKIn.size + 3 <= tk_pl512.
proof. by rewrite /tk_pl256 /tk_pl512; smt(). qed.

lemma tk_size256 (a : BArray32.t) (x : TKIn.t) :
  size (pad_tail256 64 (tin a (TKIn.to_list x))) = tk_pl256.
proof. by rewrite size_pad_tail256 size_tin size_tk /tk_pl256; smt(). qed.

lemma tk_size512 (a : BArray32.t) (x : TKIn.t) :
  size (pad_tail512 128 (tin a (TKIn.to_list x))) = tk_pl512.
proof. by rewrite size_pad_tail512 size_tin size_tk /tk_pl512; smt(). qed.

lemma tk_lay256 (a : BArray32.t) (x : TKIn.t) (j : int) : 0 <= j < tk_pl256 =>
  tlay a (TKIn.to_list x) tk_pl256 (8 * (64 + (22 + TKIn.size))) j
  = nth W8.zero (pad_tail256 64 (tin a (TKIn.to_list x))) j.
proof.
move=> hj; have hs := size_tk x; have hp := tk_size256 a x; have hd := tk_dims.
have := tlay_pad256 a (TKIn.to_list x) j _ _; 1,2: smt().
by rewrite hp hs.
qed.

lemma tk_lay512 (a : BArray32.t) (x : TKIn.t) (j : int) : 0 <= j < tk_pl512 =>
  tlay a (TKIn.to_list x) tk_pl512 (8 * (128 + (22 + TKIn.size))) j
  = nth W8.zero (pad_tail512 128 (tin a (TKIn.to_list x))) j.
proof.
move=> hj; have hs := size_tk x; have hp := tk_size512 a x; have hd := tk_dims.
have := tlay_pad512 a (TKIn.to_list x) j _ _; 1,2: smt().
by rewrite hp hs.
qed.

(* One compression of the loop: block o / 64 of the padded string p. *)
lemma tk_step256 (m : TKBuf.t) (p : bytes) (h0 : W32.t list) (o : int) :
  0 <= o => o %% 64 = 0 => o + 64 <= size p => size p <= TKBuf.size => size p %% 64 = 0 =>
  (forall k, 0 <= k < size p => TKBuf.get8 m k = nth W8.zero p k) =>
  SHA256.compress (foldl SHA256.compress h0 (take (o %/ 64) (SHA256.parse p)))
    (map be32 (chunk 4 (BArray64.to_list (TKBlk256.get_sub m o))))
  = foldl SHA256.compress h0 (take ((o + 64) %/ 64) (SHA256.parse p)).
proof.
move=> h0o hd hp hpb hpd hm.
have hsb : BArray64.to_list (TKBlk256.get_sub m o) = take 64 (drop o p).
+ apply (eq_from_nth W8.zero).
  + by rewrite BArray64.size_to_list size_take // size_drop 1:/#; smt().
  move=> j; rewrite BArray64.size_to_list => hj.
  rewrite BArray64.get_to_list TKBlk256.get8_get_sub hj /= hm 1:/#.
  by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
have ho : o = 64 * (o %/ 64) by smt().
have hq := size_parse256 p (size p %/ 64) _ _; 1,2: smt().
have hn := nth_parse256 p (o %/ 64) _ _; 1,2: smt().
by rewrite (_ : (o + 64) %/ 64 = o %/ 64 + 1) 1:/# (take_nth []) 1:/# foldl_rcons hn -ho hsb.
qed.

lemma tk_step512 (m : TKBuf.t) (p : bytes) (h0 : W64.t list) (o : int) :
  0 <= o => o %% 128 = 0 => o + 128 <= size p => size p <= TKBuf.size => size p %% 128 = 0 =>
  (forall k, 0 <= k < size p => TKBuf.get8 m k = nth W8.zero p k) =>
  SHA512.compress (foldl SHA512.compress h0 (take (o %/ 128) (SHA512.parse p)))
    (map be64 (chunk 8 (BArray128.to_list (TKBlk512.get_sub m o))))
  = foldl SHA512.compress h0 (take ((o + 128) %/ 128) (SHA512.parse p)).
proof.
move=> h0o hd hp hpb hpd hm.
have hsb : BArray128.to_list (TKBlk512.get_sub m o) = take 128 (drop o p).
+ apply (eq_from_nth W8.zero).
  + by rewrite BArray128.size_to_list size_take // size_drop 1:/#; smt().
  move=> j; rewrite BArray128.size_to_list => hj.
  rewrite BArray128.get_to_list TKBlk512.get8_get_sub hj /= hm 1:/#.
  by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
have ho : o = 128 * (o %/ 128) by smt().
have hq := size_parse512 p (size p %/ 128) _ _; 1,2: smt().
have hn := nth_parse512 p (o %/ 128) _ _; 1,2: smt().
by rewrite (_ : (o + 128) %/ 128 = o %/ 128 + 1) 1:/# (take_nth []) 1:/# foldl_rcons hn -ho hsb.
qed.

lemma tk_all256 (a : BArray32.t) (x : TKIn.t) :
  take (tk_pl256 %/ 64) (SHA256.parse (pad_tail256 64 (tin a (TKIn.to_list x))))
  = SHA256.parse (pad_tail256 64 (tin a (TKIn.to_list x))).
proof.
have hp := tk_size256 a x; have hd := tk_dims.
rewrite take_oversize // (size_parse256 _ (tk_pl256 %/ 64)); smt().
qed.

lemma tk_all512 (a : BArray32.t) (x : TKIn.t) :
  take (tk_pl512 %/ 128) (SHA512.parse (pad_tail512 128 (tin a (TKIn.to_list x))))
  = SHA512.parse (pad_tail512 128 (tin a (TKIn.to_list x))).
proof.
have hp := tk_size512 a x; have hd := tk_dims.
rewrite take_oversize // (size_parse512 _ (tk_pl512 %/ 128)); smt().
qed.

lemma tk_layout_h (a0 : BArray32.t) (x0 : TKIn.t) (l b : int) :
  22 + TKIn.size + 3 <= l <= TKBuf.size => 0 <= b =>
  hoare [M.tK____t_layout : in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b ==>
    forall j, 0 <= j < l => TKBuf.get8 res.`1 j = tlay a0 (TKIn.to_list x0) l b j].
proof.
move=> hl hb; have hd := tk_dims; proc.
seq 4 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TKBuf.size => TKBuf.get8 buf j = W8.zero).
+ while (0 <= i <= inc /\ 8 * inc = TKBuf.size /\ z = W64.zero /\ in_0 = x0 /\ adrs = a0 /\
         padded = l /\ bits = b /\ forall j, 0 <= j < 8 * i => TKBuf.get8 buf j = W8.zero).
  + wp; skip => &m [#] h0 h1 hinc hz hx ha hp hbb hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite TKBuf.get8_set64dE hz; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
    + by rewrite ifT 1:/# W8u8.get_zero.
    by rewrite hj 1:/#.
  by auto => /> &m; smt().
seq 4 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TKBuf.size => TKBuf.get8 buf j =
           if j < 9 then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
+ while (0 <= i <= 8 /\ in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TKBuf.size => TKBuf.get8 buf j =
           if j < 1 + i then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
  + wp; skip => &m [#] h0 h1 hx ha hp hbb hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite TKBuf.get_setE 1:/#.
    case: (j = 1 + i{m}) => [-> /=|h].
    + by rewrite ifT 1:/# compress_nth 1:/# src_mid 1:/# trunc_zext8 ha.
    by rewrite hj // /#.
  wp; skip => &m [#] hx ha hp hbb hj /=; split.
  + split; first by [].
    do !(split; first smt()); move=> j hj'; rewrite TKBuf.get_setE 1:/#.
    case: (j = 0) => [-> /=|h]; first by rewrite compress_nth // /adrsc_src /= trunc_zext8 ha.
    by rewrite hj //; smt().
  by move=> b1 i1 hi [#] g0 g1 g2 g3 g4 g5 gj; do !(split; first smt()); move=> j hj2; rewrite gj //; smt().
seq 4 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TKBuf.size => TKBuf.get8 buf j =
           if j < 22 then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
+ while (0 <= i <= 12 /\ in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TKBuf.size => TKBuf.get8 buf j =
           if j < 10 + i then nth W8.zero (compress (BArray32.to_list a0)) j else W8.zero).
  + wp; skip => &m [#] h0 h1 hx ha hp hbb hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite TKBuf.get_setE 1:/#.
    case: (j = 10 + i{m}) => [-> /=|h].
    + by rewrite ifT 1:/# compress_nth 1:/# src_hi 1:/# trunc_zext8 ha.
    by rewrite hj // /#.
  wp; skip => &m [#] hx ha hp hbb hj /=; split.
  + do !(split; first smt()); move=> j hj'; rewrite TKBuf.get_setE 1:/#.
    case: (j = 9) => [-> /=|h]; first by rewrite compress_nth // /adrsc_src /= trunc_zext8 ha.
    by rewrite hj //; smt().
  by move=> b1 i1 hi [#] g0 g1 g2 g3 g4 g5 gj; do !(split; first smt()); move=> j hj2; rewrite gj //; smt().
seq 3 : (in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TKBuf.size => TKBuf.get8 buf j =
           if j < 22 then nth W8.zero (compress (BArray32.to_list a0)) j
           else if j < 22 + TKIn.size then TKIn.get8 x0 (j - 22) else W8.zero).
+ while (0 <= to_uint k <= TKIn.size %/ 8 /\ (more <=> to_uint k < TKIn.size %/ 8) /\
         in_0 = x0 /\ adrs = a0 /\ padded = l /\ bits = b /\
         forall j, 0 <= j < TKBuf.size => TKBuf.get8 buf j =
           if j < 22 then nth W8.zero (compress (BArray32.to_list a0)) j
           else if j < 22 + 8 * to_uint k then TKIn.get8 x0 (j - 22) else W8.zero).
  + wp; skip => &m [#] h0 h1 hmore hx ha hp hbb hj hm /=.
    have hk : to_uint k{m} < TKIn.size %/ 8 by rewrite -hmore.
    have ho := off_word k{m} _; first smt().
    have hk1 := inc_off k{m} 1 _ _; 1,2: smt().
    rewrite hk1 W64.ultE hk1 W64.of_uintK /=.
    do !(split; first smt()); move=> j hj'; rewrite TKBuf.get8_set64dE ho hx.
    case: (8 * to_uint k{m} + 22 <= j < 8 * to_uint k{m} + 22 + 8) => h /=.
    + rewrite ifT 1:/# ifF 1:/# ifT 1:/# TKIn.get64d_byte 1:/#; congr; ring.
    by rewrite hj //; smt().
  wp; skip => &m [#] hx ha hp hbb hj /=; rewrite ?W64.ultE ?W64.of_uintK /=; split.
  + do !(split; first smt()); move=> j hj'; rewrite hj //; smt().
  move=> b1 k1 m1 hm1 [#] g0 g1 g2 g3 g4 g5 g6 gj; do !(split; first smt()).
  by move=> j hj2; rewrite gj //; smt().
wp; skip => &m [#] hx ha hp hbb hA j hj /=; rewrite hp hbb.
have hv1 : truncateu8 (W64.of_int 128) = W8.of_int 128 by rewrite /truncateu8 W64.of_uintK.
rewrite !TKBuf.get_setE 1..3:/# len_lo 1:/# len_hi 1:/# hv1 /tlay size_tk TKIn.get_to_list hA 1:/#.
by smt().
qed.

lemma tk_layout_ll : islossless M.tK____t_layout.
proof.
proc; wp.
while (0 <= to_uint k <= TKIn.size %/ 8 /\ (more <=> to_uint k < TKIn.size %/ 8))
      (TKIn.size %/ 8 - to_uint k).
+ move=> z; wp; skip => &m [#] h0 h1 hmore hm hz /=.
  have hk : to_uint k{m} < TKIn.size %/ 8 by rewrite -hmore.
  have hk1 := inc_one k{m} _; first smt().
  by rewrite W64.ultE hk1 W64.of_uintK /=; smt().
wp; while (true) (12 - i); first by auto => /#.
wp; while (true) (8 - i); first by auto => /#.
wp; while (true) (inc - i); first by auto => /#.
by auto => />; rewrite ?W64.ultE ?W64.of_uintK /=; smt().
qed.

lemma tk_narrow_h (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TKIn.t) :
  P.`n = 16 =>
  hoare [M.tK___thash_t :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list x0)].
proof.
move=> h16; have hn := n_val; have hd := tk_dims.
have hl : 22 + TKIn.size + 3 <= tk_pl256 <= TKBuf.size by smt().
have hb : 0 <= 8 * (64 + (22 + TKIn.size)) by smt().
proc.
seq 5 : (in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0); first by auto.
if; last by conseq (_ : false ==> _) => //; smt().
seq 3 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw256 h = cv256 c0 /\
         forall j, 0 <= j < tk_pl256 =>
           TKBuf.get8 p j = nth W8.zero (pad_tail256 64 (tin a0 (TKIn.to_list x0))) j).
+ while (0 <= i <= 4 /\ ctx = c0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         (forall j, 0 <= j < tk_pl256 =>
            TKBuf.get8 p j = nth W8.zero (pad_tail256 64 (tin a0 (TKIn.to_list x0))) j) /\
         forall j, 0 <= j < 8 * i => h.[j] = c0.[j]).
  + wp; skip => &m [#] g0 g1 gc hp hc hl' hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite BArray32.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
    + by rewrite ifT 1:/# gc BArray96.get64d_byte /#.
    by rewrite hj 1:/#.
  wp; ecall (tk_layout_h a0 x0 tk_pl256 (8 * (64 + (22 + TKIn.size))) hl hb).
  skip => &m [#] -> -> -> hp hc _ /=; split; first smt().
  move=> _ r hr.
  have hpl : forall j, 0 <= j < tk_pl256 =>
    TKBuf.get8 r.`1 j = nth W8.zero (pad_tail256 64 (tin a0 (TKIn.to_list x0))) j.
  + by move=> j hj; rewrite hr // tk_lay256.
  split; first smt().
  move=> h1 i1 hlt [#] g0 g1 _ _ gl gh; split; first exact hp.
  split; first exact hc.
  split; last exact gl.
  by apply hw256_bytes => j hj; apply gh; smt().
seq 2 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw256 h = cv256 c0 /\ off = W64.zero /\
         forall j, 0 <= j < tk_pl256 =>
           TKBuf.get8 buf j = nth W8.zero (pad_tail256 64 (tin a0 (TKIn.to_list x0))) j).
+ by auto.
if; last by conseq (_ : false ==> _) => //; smt().
ecall (trunc256_h h).
wp.
while (0 <= to_uint off <= tk_pl256 /\ to_uint off %% 64 = 0 /\ (more <=> to_uint off < tk_pl256) /\
       (forall j, 0 <= j < tk_pl256 =>
          TKBuf.get8 buf j = nth W8.zero (pad_tail256 64 (tin a0 (TKIn.to_list x0))) j) /\
       hw256 h = foldl SHA256.compress (cv256 c0)
                   (take (to_uint off %/ 64) (SHA256.parse (pad_tail256 64 (tin a0 (TKIn.to_list x0)))))).
+ wp; exlim h, buf, off => h0 b0 o0.
  call (compress256_h (hw256 h0) (TKBlk256.get_sub b0 (to_uint o0))).
  wp; skip => &m [#] -> -> -> g0 g1 gd hmore gb gh hm /=; try (split; first by []).
  move=> r hh1 /=; rewrite /SLH64.protect_64.
  have hlt : to_uint off{m} < tk_pl256 by rewrite -hmore.
  have ho := inc_off off{m} 64 _ _; 1,2: smt().
  have hle := step_le 64 (to_uint off{m}) tk_pl256 _ gd _ hlt; 1,2: smt().
  rewrite ho W64.ultE ho W64.of_uintK /=; do !(split; first smt()).
  have hsp := tk_size256 a0 x0.
  rewrite hh1 gh; apply (tk_step256 buf{m}); 1..5: smt().
  by move=> k hk; rewrite gb; smt().
wp; skip => &m [#] hp hc hh -> hb' _ /=; rewrite ?W64.ultE ?W64.of_uintK /=; split.
+ by rewrite take0 /=; smt().
move=> h1 m1 o1 hm1 [#] g0 g1 gd hmore gb gh r hr.
have ho : to_uint o1 = tk_pl256 by smt().
rewrite hr; apply (close256 pk c0 a0 (TKIn.to_list x0) (hw256 h1) h16 hp hc).
by rewrite gh ho tk_all256.
qed.

lemma tk_wide_h (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TKIn.t) :
  P.`n <> 16 =>
  hoare [M.tK___thash_t :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list x0)].
proof.
move=> h16; have hn := n_val; have hd := tk_dims.
have hl : 22 + TKIn.size + 3 <= tk_pl512 <= TKBuf.size by smt().
have hb : 0 <= 8 * (128 + (22 + TKIn.size)) by smt().
proc.
seq 5 : (in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0); first by auto.
if; first by conseq (_ : false ==> _) => //; smt().
seq 3 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw512 h512 = cv512 c0 /\
         forall j, 0 <= j < tk_pl512 =>
           TKBuf.get8 p j = nth W8.zero (pad_tail512 128 (tin a0 (TKIn.to_list x0))) j).
+ while (0 <= i <= 8 /\ ctx = c0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         (forall j, 0 <= j < tk_pl512 =>
            TKBuf.get8 p j = nth W8.zero (pad_tail512 128 (tin a0 (TKIn.to_list x0))) j) /\
         forall j, 0 <= j < 8 * i => h512.[j] = c0.[32 + j]).
  + wp; skip => &m [#] g0 g1 gc hp hc hl' hj hlt /=; do !(split; first smt()).
    move=> j hj'; rewrite BArray64.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=.
    + by rewrite ifT 1:/# gc BArray96.get64d_byte /#.
    by rewrite hj 1:/#.
  wp; ecall (tk_layout_h a0 x0 tk_pl512 (8 * (128 + (22 + TKIn.size))) hl hb).
  skip => &m [#] -> -> -> hp hc _ /=; split; first smt().
  move=> _ r hr.
  have hpl : forall j, 0 <= j < tk_pl512 =>
    TKBuf.get8 r.`1 j = nth W8.zero (pad_tail512 128 (tin a0 (TKIn.to_list x0))) j.
  + by move=> j hj; rewrite hr // tk_lay512.
  split; first smt().
  move=> h1 i1 hlt [#] g0 g1 _ _ gl gh; split; first exact hp.
  split; first exact hc.
  split; last exact gl.
  by apply hw512_bytes => j hj; apply gh; smt().
seq 2 : (size pk = P.`n /\ ctx_ok pk c0 /\ hw512 h512 = cv512 c0 /\ off = W64.zero /\
         forall j, 0 <= j < tk_pl512 =>
           TKBuf.get8 buf j = nth W8.zero (pad_tail512 128 (tin a0 (TKIn.to_list x0))) j).
+ by auto.
if; first by conseq (_ : false ==> _) => //; smt().
ecall (trunc512_h h512).
wp.
while (0 <= to_uint off <= tk_pl512 /\ to_uint off %% 128 = 0 /\ (more <=> to_uint off < tk_pl512) /\
       (forall j, 0 <= j < tk_pl512 =>
          TKBuf.get8 buf j = nth W8.zero (pad_tail512 128 (tin a0 (TKIn.to_list x0))) j) /\
       hw512 h512 = foldl SHA512.compress (cv512 c0)
                   (take (to_uint off %/ 128) (SHA512.parse (pad_tail512 128 (tin a0 (TKIn.to_list x0)))))).
+ wp; exlim h512, buf, off => h0 b0 o0.
  call (compress512_h (hw512 h0) (TKBlk512.get_sub b0 (to_uint o0))).
  wp; skip => &m [#] -> -> -> g0 g1 gd hmore gb gh hm /=; try (split; first by []).
  move=> r hh1 /=; rewrite /SLH64.protect_64.
  have hlt : to_uint off{m} < tk_pl512 by rewrite -hmore.
  have ho := inc_off off{m} 128 _ _; 1,2: smt().
  have hle := step_le 128 (to_uint off{m}) tk_pl512 _ gd _ hlt; 1,2: smt().
  rewrite ho W64.ultE ho W64.of_uintK /=; do !(split; first smt()).
  have hsp := tk_size512 a0 x0.
  rewrite hh1 gh; apply (tk_step512 buf{m}); 1..5: smt().
  by move=> k hk; rewrite gb; smt().
wp; skip => &m [#] hp hc hh -> hb' _ /=; rewrite ?W64.ultE ?W64.of_uintK /=; split.
+ by rewrite take0 /=; smt().
move=> h1 m1 o1 hm1 [#] g0 g1 gd hmore gb gh r hr.
have ho : to_uint o1 = tk_pl512 by smt().
rewrite hr; apply (close512 pk c0 a0 (TKIn.to_list x0) (hw512 h1) h16 hp hc).
by rewrite gh ho tk_all512.
qed.

lemma tk_ll : islossless M.tK___thash_t.
proof.
proc.
seq 7 : true 1%r 1%r 0%r _ => //.
+ sp; if.
  + wp; while (true) (4 - i); first by auto => /#.
    by wp; call tk_layout_ll; auto => /#.
  wp; while (true) (8 - i); first by auto => /#.
  by wp; call tk_layout_ll; auto => /#.
have hd := tk_dims.
sp; if.
+ call trunc256_ll; wp.
  while (0 <= to_uint off <= tk_pl256 /\ to_uint off %% 64 = 0 /\ (more <=> to_uint off < tk_pl256))
        (tk_pl256 - to_uint off).
  + move=> z; wp; call set_compress256_ll; wp; skip => &m [#] g0 g1 gd hmore hm hz /=.
    have hlt : to_uint off{m} < tk_pl256 by rewrite -hmore.
    have ho := inc_off off{m} 64 _ _; 1,2: smt().
    by rewrite /SLH64.protect_64 ho W64.ultE ho W64.of_uintK /=; smt().
  by wp; skip => &m [#] -> _; rewrite ?W64.ultE ?W64.of_uintK ?W64.to_uint0 /=; smt().
call trunc512_ll; wp.
while (0 <= to_uint off <= tk_pl512 /\ to_uint off %% 128 = 0 /\ (more <=> to_uint off < tk_pl512))
      (tk_pl512 - to_uint off).
+ move=> z; wp; call set_compress512_ll; wp; skip => &m [#] g0 g1 gd hmore hm hz /=.
  have hlt : to_uint off{m} < tk_pl512 by rewrite -hmore.
  have ho := inc_off off{m} 128 _ _; 1,2: smt().
  by rewrite /SLH64.protect_64 ho W64.ultE ho W64.of_uintK /=; smt().
by wp; skip => &m [#] -> _; rewrite ?W64.ultE ?W64.of_uintK ?W64.to_uint0 /=; smt().
qed.

lemma tk_h (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TKIn.t) :
  hoare [M.tK___thash_t :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list x0)].
proof.
case: (P.`n = 16) => h16; first exact (tk_narrow_h pk c0 a0 x0 h16).
exact (tk_wide_h pk c0 a0 x0 h16).
qed.

lemma thash_t_k_total (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TKIn.t) :
  phoare [M._thash_t_k :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list x0)] = 1%r.
proof. by proc; call (_ : in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list x0)); [conseq tk_ll (tk_h pk c0 a0 x0) | auto]. qed.
