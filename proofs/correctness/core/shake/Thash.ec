(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thash.ec
 * ========
 *
 * The tweakable hashes of the SHAKE parameter sets (FIPS 205 section
 * 11.1): _thash_f, _thash_prf, _thash_h, _thash_t_len and _thash_t_k of
 * src/slhdsa/thash_shake.jinc compute F, PRF, H, T_len and T_k, and
 * _shake_absorb_prefix absorbs the message prefix of PRF_msg and H_msg.
 *
 * F, PRF and H write PK.seed and ADRS into a zeroed state
 * (__shake_seeded_head), store the n- or 2n-byte payload in the lanes
 * after them, add the SHAKE domain byte after the message and the pad
 * bit at byte 135 (__shake_pad_lanes), permute once and return the
 * first n bytes (__shake_extract_n). The message PK.seed || ADRS || M is
 * 2n + 32 or 3n + 32 bytes, at most 128, so it is shorter than one
 * SHAKE256 block (136 bytes): one permutation absorbs and squeezes it
 * (shake_one_block, from the lemmas of ShakeSponge.ec).
 *
 * T_l (thash_shake_t.jinc, l = len or k) absorbs the l n-byte message
 * over several blocks, lane by lane: lane pos of the block takes word i
 * of M, and a full block (pos = 17) is permuted. The loop keeps the
 * sponge state of ShakeSponge.ec for the bytes absorbed so far,
 *
 *     lanes st = abs_state 136 (PK.seed || ADRS || M[0 : 8 i])
 *     8 pos    = |PK.seed || ADRS || M[0 : 8 i]| mod 136,
 *
 * one step being absorb_lane_lt or absorb_lane_eq. The padding then goes
 * in at lane pos and lane 16, and shake_final gives SHAKE256 of the
 * whole message.
 *
 * _shake_absorb_prefix absorbs the first len bytes of the message prefix
 * one byte at a time, at sponge byte position pos, and permutes whenever
 * pos reaches 136. Its theorem is stated on the sponge state of
 * ShakeSponge.ec: if st holds abs_state 136 m and pos = |m| mod 136, the
 * result holds the state and the position for m || prefix[0 : len]. The
 * message hashes PRF_msg and H_msg absorb their framing prefix this way.
 * _keccak_finalize, called by them with rate 136 and the SHAKE domain
 * byte, adds the padding at pos and byte 135 and permutes: from the state
 * of m it gives the permuted ABSORB1600 state of m, the state from which
 * SHAKE256(m) is squeezed (abs_final).
 *
 * Model. The procedures depend on n, so this file is checked against the
 * model of each SHAKE set (correctness/core/shake/). Arrays are viewed as
 * byte lists by to_list: Node for n bytes, Node2 for 2n, BArray32 for the
 * address, TLenIn and TKIn for the len n and k n bytes of a T_l input.
 * The context ctx is the n-byte PK.seed (Node).
 *
 * Premise. The permutation is the kernel's _keccakf1600 in the set's
 * model. Its correctness is the section hypothesis keccakf1600_h: it
 * computes keccak_f1600_op on the lanes of its state. Each theorem below
 * holds under it, and states it as its first premise once the section is
 * closed. Discharging it with the kernel proofs of correctness/hash/,
 * which are about the kernel's own model, is not done here.
 *
 * Theorems (total correctness, every input):
 *     thash_f_correct     F(PK.seed, ADRS, M1), M1 of n bytes;
 *     thash_prf_correct   PRF(PK.seed, SK.seed, ADRS);
 *     thash_h_correct     H(PK.seed, ADRS, M2), M2 of 2n bytes;
 *     thash_t_len_correct T_len(PK.seed, ADRS, M), M of len n bytes;
 *     thash_t_k_correct   T_k(PK.seed, ADRS, M), M of k n bytes;
 *     shake_absorb_prefix_correct
 *                         the prefix absorption, len <= SLH_PREFIX_MAX
 *                         (2 + 255 + 11 + 64 = 332 bytes);
 *     keccak_finalize_correct
 *                         the SHAKE256 padding and the last permutation.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils Jslh.
from JazzEC require import Array25 WArray200.
require import Bytes FIPS205_Params FIPS205_Hash FIPS202_Bytes.
require import BArray32 BArray200 BArray332 KeccakState Keccakf1600_Spec Keccak1600_Spec.
require import ShakeSponge SetModel CoreExtracted.

lemma family_shake : P.`family = SHAKE by rewrite /P.
lemma n_words : 0 < P.`n /\ 8 * (P.`n %/ 8) = P.`n by smt(n_val).

lemma nth_cat_take (L X : W8.t list) (k j : int) : 0 <= k => k + 8 <= size X =>
  nth W8.zero (L ++ take (k + 8) X) j =
  if size L + k <= j < size L + k + 8 then nth W8.zero X (j - size L) else nth W8.zero (L ++ take k X) j.
proof.
move=> hk hx; rewrite !nth_cat.
case: (j < size L) => hj; first by rewrite ifF 1:/#.
smt(nth_take nth_default size_take).
qed.

lemma keccak_init_h : hoare [M.__keccak_init : true ==> forall j, 0 <= j < 200 => res.[j] = W8.zero].
proof.
proc; while (0 <= i <= 25 /\ z = W64.zero /\ forall j, 0 <= j < 8 * i => st.[j] = W8.zero).
+ wp; skip => &m [#] h0 h1 hz hj hlt; do !(split; first smt()); move=> j hj'.
  rewrite BArray200.get8_set64dE; case: (8 * i{m} <= j < 8 * i{m} + 8) => h /=;
  [by rewrite ifT 1:/# hz (_ : W64.zero = W64.of_int 0) // W8u8.get_zero | by rewrite hj 1:/#].
by wp; skip => /> /#.
qed.

lemma seeded_head_h (c0 : Node.t) (a0 : BArray32.t) :
  hoare [M.__shake_seeded_head : ctx = c0 /\ adrs = a0 ==>
    forall j, 0 <= j < 200 => res.[j] = nth W8.zero (Node.to_list c0 ++ BArray32.to_list a0) j].
proof.
proc.
while (0 <= i <= 4 /\ adrs = a0 /\
       forall j, 0 <= j < 200 => st.[j] = nth W8.zero (Node.to_list c0 ++ take (8 * i) (BArray32.to_list a0)) j).
+ wp; skip => &m [#] h0 h4 ha hj hlt; do !(split; first smt()); move=> j hjr.
  rewrite (_ : 8 * (i{m} + 1) = 8 * i{m} + 8) 1:/# nth_cat_take 1:/# 1:BArray32.size_to_list 1:/#.
  rewrite BArray200.get8_set64dE Node.size_to_list; have hn := n_val.
  case: (P.`n + 8 * i{m} <= j < P.`n + 8 * i{m} + 8) => h.
  + rewrite ifT 1:/# ifT 1:/# ha BArray32.get64d_byte 1:/# BArray32.get_to_list; congr; smt().
  by rewrite ifF 1:/# ifF 1:/# hj.
wp.
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ ctx = c0 /\
       forall j, 0 <= j < 200 => st.[j] = nth W8.zero ([] ++ take (8 * i) (Node.to_list c0)) j).
+ wp; skip => &m [#] h0 h4 hinc hc hj hlt; do !(split; first smt()); move=> j hjr.
  rewrite (_ : 8 * (i{m} + 1) = 8 * i{m} + 8) 1:/# nth_cat_take 1:/# 1:Node.size_to_list 1:/#.
  rewrite BArray200.get8_set64dE /=; have hn := n_val.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
  + by rewrite ifT 1:/# hc Node.get64d_byte 1:/#; smt().
  by rewrite ifF 1:/# hj.
wp; call keccak_init_h; wp; skip => /> st0 hz; split.
+ by move=> j hj0 hj1; rewrite take0 hz.
move=> i0 st1 h1 h2 h3 h4 h5; split.
+ move=> j hj0 hj1; rewrite take0 cats0 h5 1:/# take_oversize // Node.size_to_list; smt(n_val).
move=> i1 st2 g1 g2 g3 g4 j hj0 hj1; rewrite g4 1:/# take_oversize // BArray32.size_to_list /#.
qed.

lemma pad_lanes_h (s0 : BArray200.t) (l0 : int) :
  hoare [M.__shake_pad_lanes : st = s0 /\ lanes = l0 /\ 0 <= l0 < 17 ==>
    forall j, 0 <= j < 200 => res.[j] =
      (xorb_at (xorb_at (WArray200.init (fun k => s0.[k])) (8 * l0) [W8.of_int 31]) 135 [W8.of_int 128]).[j]].
proof.
proc; wp; skip => &m [#] -> -> h0 h1 /= j hj.
rewrite (_ : 128 = 8 * 16) // get8_xor64 //.
rewrite get8_xor64 1,2:/#.
rewrite !xorb_atE //= !WArray200.initiE //=.
have := bits8_ds (j - 8 * l0); have := bits8_top (j - 8 * 16).
case: (8 * l0 <= j < 8 * l0 + 8) => ha; case: (128 <= j < 136) => hb; smt(W8.xorw0).
qed.

lemma extract_n_h (s0 : BArray200.t) :
  hoare [M.__shake_extract_n : st = s0 ==>
    forall j, 0 <= j < P.`n => nth W8.zero (Node.to_list res) j = s0.[j]].
proof.
proc; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ st = s0 /\ forall j, 0 <= j < 8 * i => nth W8.zero (Node.to_list out) j = s0.[j]).
+ wp; skip => &m [#] h0 h1 hinc hs hj hlt; do !(split; first smt()); move=> j hj'.
  rewrite Node.get_to_list Node.get8_set64dE; have hn := n_val.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
  + by rewrite ifT 1:/# hs BArray200.get64d_byte 1:/#; congr; smt().
  by rewrite ifF 1:/# -Node.get_to_list hj 1:/#.
wp; skip => /> &m; split; first smt(n_val).
move=> i0 o0 h0 h1 h2 h3 h4 j hj0 hj1; rewrite h4 /#.
qed.

lemma shake_one_block (msg : W8.t list) (o : int) (sa sb sc : BArray200.t) (r : Node.t) :
  o = size msg => size msg < 135 =>
  (forall j, 0 <= j < 200 => sa.[j] = nth W8.zero msg j) =>
  (forall j, 0 <= j < 200 => sb.[j] =
     (xorb_at (xorb_at (WArray200.init (fun k => sa.[k])) o [W8.of_int 31]) 135 [W8.of_int 128]).[j]) =>
  lanes sc = keccak_f1600_op (lanes sb) =>
  (forall j, 0 <= j < P.`n => nth W8.zero (Node.to_list r) j = sc.[j]) =>
  Node.to_list r = shake256 msg (8 * P.`n).
proof.
move=> -> hlt hsh hsp hsk hr; have hn := n_val.
have hsp' : lanes sb = ABSORB1600 SHAKE_DS_BYTE 136 msg.
+ have hm : size msg %% 136 = size msg by rewrite modz_small; smt(size_ge0).
  rewrite -abs_final // hm /=.
  have -> : stbytes (abs_state 136 msg) = WArray200.init (fun k => sa.[k]).
  + by apply WArray200.tP => j hj; rewrite abs_short // 1:/# WArray200.initiE //= hsh.
  apply stbytes_inj; rewrite stwordsK; apply WArray200.tP => j hj.
  by rewrite stbytes_lanes // hsp.
rewrite shake256E shake256_one 1:/# -hsp' -hsk.
apply (eq_from_nth W8.zero); first by rewrite Node.size_to_list size_take 1:/# size_state2bytes /#.
move=> j; rewrite Node.size_to_list => hj.
by rewrite nth_take 1,2:/# state2bytesE stbytes_lanes 1:/# hr /#.
qed.

(* A lane XOR is a byte XOR of the lane's eight bytes at byte 8 p. *)
lemma lanes_xor_at (st : BArray200.t) (p : int) (w : W64.t) (bs : W8.t list) :
  0 <= p < 25 => size bs = 8 => (forall k, 0 <= k < 8 => w \bits8 k = nth W8.zero bs k) =>
  stbytes (lanes (BArray200.set64d st (8 * p) (BArray200.get64d st (8 * p) `^` w))) =
  xorb_at (stbytes (lanes st)) (8 * p) bs.
proof.
move=> hp hs hw; apply WArray200.tP => j hj.
rewrite stbytes_lanes // get8_xor64 // xorb_atE // stbytes_lanes // hs.
by case: (8 * p <= j < 8 * p + 8) => h //; rewrite hw /#.
qed.

(* One input lane XORed in at lane p < 16 extends the absorbed message by its
   eight bytes; at lane 16 it completes the block, which is then permuted. *)
lemma absorb_lane_lt (st : BArray200.t) (m bs : W8.t list) (p : int) (w : W64.t) :
  0 <= p => p + 1 < 17 => 8 * p = size m %% 136 => size bs = 8 =>
  (forall k, 0 <= k < 8 => w \bits8 k = nth W8.zero bs k) =>
  lanes st = abs_state 136 m =>
  lanes (BArray200.set64d st (8 * p) (BArray200.get64d st (8 * p) `^` w)) = abs_state 136 (m ++ bs).
proof.
move=> h0 h1 hp hs hw hst; apply stbytes_inj.
have hx := lanes_xor_at st p w bs _ hs hw; first smt().
have hc := abs_cat_lt 136 m bs _ _; [by [] | by rewrite hs -hp /# | idtac].
by rewrite hx hc hst hp.
qed.

lemma absorb_lane_eq (st : BArray200.t) (m bs : W8.t list) (p : int) (w : W64.t) :
  p + 1 = 17 => 8 * p = size m %% 136 => size bs = 8 =>
  (forall k, 0 <= k < 8 => w \bits8 k = nth W8.zero bs k) =>
  lanes st = abs_state 136 m =>
  keccak_f1600_op (lanes (BArray200.set64d st (8 * p) (BArray200.get64d st (8 * p) `^` w))) =
  abs_state 136 (m ++ bs).
proof.
move=> h1 hp hs hw hst.
have hc := abs_cat_eq 136 m bs _ _; [by [] | by rewrite hs -hp /# | idtac].
have hx := lanes_xor_at st p w bs _ hs hw; first smt().
rewrite hc; congr; apply stbytes_inj.
by rewrite stwordsK hx hst hp.
qed.

(* Padding at lane p and lane 16, one permutation, the first n bytes: the
   SHAKE256 hash of the absorbed message (shake_one_block for any length). *)
lemma shake_final (msg : W8.t list) (p : int) (sa sc : BArray200.t) (r : Node.t) :
  0 <= p < 17 => 8 * p = size msg %% 136 => lanes sa = abs_state 136 msg =>
  lanes sc = keccak_f1600_op (lanes
    (BArray200.set64d (BArray200.set64d sa (8 * p) (BArray200.get64d sa (8 * p) `^` W64.of_int 31))
       (8 * 16) (BArray200.get64d (BArray200.set64d sa (8 * p) (BArray200.get64d sa (8 * p) `^` W64.of_int 31)) (8 * 16)
          `^` W64.of_int 9223372036854775808))) =>
  (forall j, 0 <= j < P.`n => nth W8.zero (Node.to_list r) j = sc.[j]) =>
  Node.to_list r = shake256 msg (8 * P.`n).
proof.
move=> hp hpm hsa hsc hr; have hn := n_val; have hp25 : 0 <= p < 25 by smt().
pose sb1 := BArray200.set64d sa (8 * p) (BArray200.get64d sa (8 * p) `^` W64.of_int 31).
pose sb := BArray200.set64d sb1 (8 * 16) (BArray200.get64d sb1 (8 * 16) `^` W64.of_int 9223372036854775808).
have hsb : lanes sb = ABSORB1600 SHAKE_DS_BYTE 136 msg.
+ rewrite -abs_final //.
  rewrite -hpm /=.
  apply stbytes_inj; rewrite stwordsK; apply WArray200.tP => j hj.
  rewrite stbytes_lanes // /sb get8_xor64 // /sb1 get8_xor64 //.
  rewrite !xorb_atE //= -hsa stbytes_lanes // /SHAKE_DS_BYTE.
  have := bits8_ds (j - 8 * p); have := bits8_top (j - 128).
  case: (8 * p <= j < 8 * p + 8) => ha; case: (128 <= j < 136) => hb.
  + move=> h1 h2; rewrite h1 1:/# h2 1:/#; have -> : p = 16 by smt().
    by case: (j = 128) => ?; case: (j = 135) => ? /=; smt(W8.xorw0).
  + move=> h1 h2; rewrite h2 1:/# (ifF (135 <= j < 136)) 1:/#.
    by case: (j - 8 * p = 0) => hz /=; first by rewrite ifT 1:/#.
  + move=> h1 h2; rewrite h1 1:/# (ifF (8 * p <= j < 8 * p + 1)) 1:/#.
    case: (j = 135) => hz; first by rewrite hz.
    by rewrite (ifF (j - 128 = 7)) 1:/# (ifF (135 <= j < 136)) 1:/#.
  + by move=> h1 h2; rewrite (ifF (135 <= j < 136)) 1:/# (ifF (8 * p <= j < 8 * p + 1)) 1:/#.
rewrite shake256E shake256_one 1:/# -hsb -hsc.
apply (eq_from_nth W8.zero); first by rewrite Node.size_to_list size_take 1:/# size_state2bytes /#.
move=> j; rewrite Node.size_to_list => hj.
by rewrite nth_take 1,2:/# state2bytesE stbytes_lanes 1:/# hr /#.
qed.

lemma size_word8 ['a] (X : 'a list) (i : int) : 0 <= i => 8 * i + 8 <= size X =>
  size (take 8 (drop (8 * i) X)) = 8.
proof. by move=> h0 h1; smt(size_take size_drop). qed.

lemma mod_step (p a : int) : 0 <= p => p < 17 => 8 * p = a %% 136 =>
  8 * (p + 1) %% 136 = (a + 8) %% 136.
proof. by move=> h0 h1 h; rewrite -modzDml -h (_ : 8 * (p + 1) = 8 * p + 8) 1:/#. qed.

lemma w64_inc17 (x : W64.t) : to_uint x < 17 =>
  (x + W64.one = W64.of_int 17 <=> to_uint x + 1 = 17).
proof. by move=> h; rewrite W64.to_uint_eq W64.to_uintD_small /= /#. qed.

(* The position clamps of the T_l, T_k and prefix absorb loops never fire: the position stays below the rate. *)
lemma clamp17 (x c : W64.t) : to_uint x < 17 => ((W64.of_int 17 \ule x) ? c : x) = x.
proof. by move=> h; rewrite W64.uleE W64.of_uintK ifF 1:/#. qed.

lemma clamp136 (x c : W64.t) : to_uint x < 136 => ((W64.of_int 136 \ule x) ? c : x) = x.
proof. by move=> h; rewrite W64.uleE W64.of_uintK ifF 1:/#. qed.

lemma w64_inc_bound (x : W64.t) (b : int) : to_uint x < b => b < W64.modulus =>
  to_uint (x + W64.one) = to_uint x + 1.
proof.
move=> h hb; have h1 : to_uint W64.one = 1 by exact W64.to_uint1.
have hm : to_uint x + 1 < W64.modulus by move: h hb; pose M := W64.modulus; pose u := to_uint x; smt().
by rewrite W64.to_uintD_small h1.
qed.

(* The state after __shake_seeded_head holds PK.seed || ADRS, not yet permuted. *)
lemma head_absorbed (c0 : Node.t) (a0 : BArray32.t) (st : BArray200.t) :
  (forall j, 0 <= j < 200 => st.[j] = nth W8.zero (Node.to_list c0 ++ BArray32.to_list a0) j) =>
  lanes st = abs_state 136 (Node.to_list c0 ++ BArray32.to_list a0).
proof.
move=> hst; have hs : size (Node.to_list c0 ++ BArray32.to_list a0) = P.`n + 32.
+ by rewrite size_cat Node.size_to_list BArray32.size_to_list; smt(n_val).
apply stbytes_inj; apply WArray200.tP => j hj.
by rewrite stbytes_lanes // abs_short // 1:/# hst.
qed.

(* The eight bytes of word i of a T_len or T_k input. *)
lemma tlen_word (x0 : TLenIn.t) (i : int) : 0 <= i => 8 * i + 8 <= size (TLenIn.to_list x0) => forall k, 0 <= k < 8 =>
  TLenIn.get64d x0 (8 * i) \bits8 k = nth W8.zero (take 8 (drop (8 * i) (TLenIn.to_list x0))) k.
proof.
move=> hi hs k hk.
have -> : nth W8.zero (take 8 (drop (8 * i) (TLenIn.to_list x0))) k =
          nth W8.zero (TLenIn.to_list x0) (8 * i + k).
+ have h1 := nth_take W8.zero 8 (drop (8 * i) (TLenIn.to_list x0)) k _ _; [smt() | smt() | idtac].
  have h2 := nth_drop W8.zero (8 * i) (TLenIn.to_list x0) k _ _; [smt() | smt() | idtac].
  by rewrite h1 h2.
rewrite TLenIn.get_to_list.
by rewrite TLenIn.get64d_byte 1:/#; congr; smt().
qed.

lemma tk_word (x0 : TKIn.t) (i : int) : 0 <= i => 8 * i + 8 <= size (TKIn.to_list x0) => forall k, 0 <= k < 8 =>
  TKIn.get64d x0 (8 * i) \bits8 k = nth W8.zero (take 8 (drop (8 * i) (TKIn.to_list x0))) k.
proof.
move=> hi hs k hk.
have -> : nth W8.zero (take 8 (drop (8 * i) (TKIn.to_list x0))) k =
          nth W8.zero (TKIn.to_list x0) (8 * i + k).
+ have h1 := nth_take W8.zero 8 (drop (8 * i) (TKIn.to_list x0)) k _ _; [smt() | smt() | idtac].
  have h2 := nth_drop W8.zero (8 * i) (TKIn.to_list x0) k _ _; [smt() | smt() | idtac].
  by rewrite h1 h2.
rewrite TKIn.get_to_list.
by rewrite TKIn.get64d_byte 1:/#; congr; smt().
qed.

(* The byte XOR of the prefix loop, with its 64-bit zero-extension. *)
lemma trunc_xor8 (a b : W8.t) : truncateu8 (zeroextu64 a `^` zeroextu64 b) = a `^` b.
proof.
apply W8.wordP => k hk.
rewrite W8.xorwE /truncateu8 W8.of_intwE hk /= /int_bit.
have := W64.get_to_uint (zeroextu64 a +^ zeroextu64 b) k.
rewrite W64.xorwE !zeroextu64_bit (_ : 0 <= k < 64) 1:/# /= => h.
rewrite (_ : 256 = 2 ^ 8) // modz_pow2_div 1:/# modz_dvd.
+ by apply (dvdz_exp2l 2 1); smt().
by move: h; smt().
qed.

(* A byte XOR at byte p is xorb_at of a one-byte list. *)
lemma byte_xor_at (st : BArray200.t) (p : int) (b : W8.t) : 0 <= p < 200 =>
  stbytes (lanes (BArray200.set8 st p (st.[p] `^` b))) = xorb_at (stbytes (lanes st)) p [b].
proof.
move=> hp; apply WArray200.tP => j hj.
rewrite stbytes_lanes // xorb_atE // stbytes_lanes // BArray200.get_setE //=.
by case: (j = p) => h; [rewrite h ifT 1:/# /= | smt()].
qed.

(* The same with a byte constant c, as the padding XORs write it. *)
lemma trunc_xor8c (a : W8.t) (c : int) : 0 <= c < 256 =>
  truncateu8 (zeroextu64 a `^` W64.of_int c) = a `^` W8.of_int c.
proof.
move=> hc; have -> : W64.of_int c = zeroextu64 (W8.of_int c).
+ by rewrite /zeroextu64 W8.of_uintK modz_small; smt().
exact trunc_xor8.
qed.

(* One prefix byte at sponge position p: the byte form of absorb_lane_lt
   and absorb_lane_eq. *)
lemma absorb_byte_lt (st : BArray200.t) (m : W8.t list) (p : int) (b : W8.t) :
  0 <= p => p + 1 < 136 => p = size m %% 136 => lanes st = abs_state 136 m =>
  lanes (BArray200.set8 st p (st.[p] `^` b)) = abs_state 136 (m ++ [b]).
proof.
move=> h0 h1 hp hst; apply stbytes_inj.
have hc := abs_cat_lt 136 m [b] _ _; [by [] | by rewrite -hp /# | idtac].
by rewrite byte_xor_at 1:/# hc hst hp.
qed.

lemma absorb_byte_eq (st : BArray200.t) (m : W8.t list) (p : int) (b : W8.t) :
  p + 1 = 136 => p = size m %% 136 => lanes st = abs_state 136 m =>
  keccak_f1600_op (lanes (BArray200.set8 st p (st.[p] `^` b))) = abs_state 136 (m ++ [b]).
proof.
move=> h1 hp hst.
have hc := abs_cat_eq 136 m [b] _ _; [by [] | by rewrite -hp /# | idtac].
rewrite hc; congr; apply stbytes_inj.
by rewrite stwordsK byte_xor_at 1:/# hst hp.
qed.

lemma w64_inc_eq (x : W64.t) (c : int) : to_uint x < c => c < W64.modulus =>
  (x + W64.one = W64.of_int c <=> to_uint x + 1 = c).
proof.
move=> h hc; rewrite W64.to_uint_eq (w64_inc_bound x c h hc) W64.of_uintK.
by rewrite modz_small; [move: h hc; pose u := to_uint x; smt(W64.to_uint_cmp) | done].
qed.

lemma keccak_init_ll : islossless M.__keccak_init.
proof. by proc; while true (25 - i); auto => /#. qed.

lemma seeded_head_ll : islossless M.__shake_seeded_head.
proof.
proc; while true (4 - i); 1: by auto => /#.
wp; while true (inc - i); 1: by auto => /#.
by wp; call keccak_init_ll; auto => /#.
qed.

lemma pad_lanes_ll : islossless M.__shake_pad_lanes by proc; auto.

lemma extract_n_ll : islossless M.__shake_extract_n.
proof. by proc; while true (inc - i); auto => /#. qed.

section.

declare axiom keccakf1600_h (s0 : BArray200.t) :
  phoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)] = 1%r.

local lemma keccakf1600_hoare (s0 : BArray200.t) :
  hoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)].
proof. by conseq (keccakf1600_h s0). qed.

local lemma keccakf1600_ll : islossless M._keccakf1600.
proof. by proc*; exlim st => s0; call (keccakf1600_h s0); auto. qed.

local lemma thash_f_h (x0 c0 : Node.t) (a0 : BArray32.t) :
  hoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = F P (Node.to_list c0) (BArray32.to_list a0) (Node.to_list x0)].
proof.
proc.
seq 2 : (x = x0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero (Node.to_list c0 ++ BArray32.to_list a0) j).
+ by ecall (seeded_head_h c0 a0); auto.
seq 3 : (forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero ((Node.to_list c0 ++ BArray32.to_list a0) ++ Node.to_list x0) j).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ x = x0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * i) (Node.to_list x0)) j).
  + wp; skip => &m [#] h0 h1 hinc hx hj hlt; do !(split; first smt()); move=> j hjr.
    have hs : size (Node.to_list c0 ++ BArray32.to_list a0) = P.`n + 32.
    + by rewrite size_cat Node.size_to_list BArray32.size_to_list; smt(n_val).
    rewrite (_ : 8 * (i{m} + 1) = 8 * i{m} + 8) 1:/# nth_cat_take 1:/# 1:Node.size_to_list 1:/#.
    rewrite BArray200.get8_set64dE hs; have hn := n_val.
    case: (P.`n + 32 + 8 * i{m} <= j < P.`n + 32 + 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# hx Node.get64d_byte 1:/# Node.get_to_list; congr; smt().
    by rewrite ifF 1:/# hj //; smt().
  wp; skip => &m [#] hx hj /=; split.
  + by rewrite /= take0 cats0; smt(n_val).
  move=> i1 st1 hc [#] g1 g2 g3 g4 g5 j hjj.
  by rewrite g5 // take_oversize // Node.size_to_list /#.
ecall (extract_n_h st); wp; ecall (keccakf1600_hoare st).
ecall (pad_lanes_h st (2 * (P.`n %/ 8) + 4)).
skip => &m hst /=.
split; first smt(n_val).
move=> _ s1 hs1 [s2 ms2] /= hs2 r hr.
rewrite /F family_shake /=.
have hsz : size (Node.to_list c0 ++ BArray32.to_list a0 ++ Node.to_list x0) = 2 * P.`n + 32.
+ by rewrite !size_cat Node.size_to_list BArray32.size_to_list; smt(n_val).
apply (shake_one_block _ (8 * (2 * (P.`n %/ 8) + 4)) st{m} s1 s2 r) => //; smt(n_val).
qed.

local lemma thash_f_ll : islossless M._thash_f.
proof.
proc; call extract_n_ll; wp; call keccakf1600_ll; call pad_lanes_ll.
while true (inc - i); 1: by auto => /#.
by wp; call seeded_head_ll; auto => /#.
qed.

lemma thash_f_correct (x0 c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = F P (Node.to_list c0) (BArray32.to_list a0) (Node.to_list x0)] = 1%r.
proof. by conseq thash_f_ll (thash_f_h x0 c0 a0 ). qed.

local lemma thash_prf_h (k0 c0 : Node.t) (a0 : BArray32.t) :
  hoare [M._thash_prf : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = PRF P (Node.to_list c0) (Node.to_list k0) (BArray32.to_list a0)].
proof.
proc.
seq 2 : (sk_seed = k0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero (Node.to_list c0 ++ BArray32.to_list a0) j).
+ by ecall (seeded_head_h c0 a0); auto.
seq 3 : (forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero ((Node.to_list c0 ++ BArray32.to_list a0) ++ Node.to_list k0) j).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ sk_seed = k0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * i) (Node.to_list k0)) j).
  + wp; skip => &m [#] h0 h1 hinc hx hj hlt; do !(split; first smt()); move=> j hjr.
    have hs : size (Node.to_list c0 ++ BArray32.to_list a0) = P.`n + 32.
    + by rewrite size_cat Node.size_to_list BArray32.size_to_list; smt(n_val).
    rewrite (_ : 8 * (i{m} + 1) = 8 * i{m} + 8) 1:/# nth_cat_take 1:/# 1:Node.size_to_list 1:/#.
    rewrite BArray200.get8_set64dE hs; have hn := n_val.
    case: (P.`n + 32 + 8 * i{m} <= j < P.`n + 32 + 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# hx Node.get64d_byte 1:/# Node.get_to_list; congr; smt().
    by rewrite ifF 1:/# hj //; smt().
  wp; skip => &m [#] hx hj /=; split.
  + by rewrite /= take0 cats0; smt(n_val).
  move=> i1 st1 hc [#] g1 g2 g3 g4 g5 j hjj.
  by rewrite g5 // take_oversize // Node.size_to_list /#.
ecall (extract_n_h st); wp; ecall (keccakf1600_hoare st).
ecall (pad_lanes_h st (2 * (P.`n %/ 8) + 4)).
skip => &m hst /=; split; first smt(n_val).
move=> _ s1 hs1 [s2 ms2] /= hs2 r hr.
rewrite /PRF family_shake /=.
have hsz : size (Node.to_list c0 ++ BArray32.to_list a0 ++ Node.to_list k0) = 2 * P.`n + 32.
+ by rewrite !size_cat Node.size_to_list BArray32.size_to_list ?Node2.size_to_list; smt(n_val).
by apply (shake_one_block _ (8 * (2 * (P.`n %/ 8) + 4)) st{m} s1 s2 r) => //; smt(n_val).
qed.

local lemma thash_h_h (x0 : Node2.t) (c0 : Node.t) (a0 : BArray32.t) :
  hoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = H P (Node.to_list c0) (BArray32.to_list a0) (Node2.to_list x0)].
proof.
proc.
seq 2 : (in_0 = x0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero (Node.to_list c0 ++ BArray32.to_list a0) j).
+ by ecall (seeded_head_h c0 a0); auto.
seq 3 : (forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero ((Node.to_list c0 ++ BArray32.to_list a0) ++ Node2.to_list x0) j).
+ while (0 <= i <= inc /\ inc = 2 * (P.`n %/ 8) /\ in_0 = x0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * i) (Node2.to_list x0)) j).
  + wp; skip => &m [#] h0 h1 hinc hx hj hlt; do !(split; first smt()); move=> j hjr.
    have hs : size (Node.to_list c0 ++ BArray32.to_list a0) = P.`n + 32.
    + by rewrite size_cat Node.size_to_list BArray32.size_to_list; smt(n_val).
    rewrite (_ : 8 * (i{m} + 1) = 8 * i{m} + 8) 1:/# nth_cat_take 1:/# 1:Node2.size_to_list 1:/#.
    rewrite BArray200.get8_set64dE hs; have hn := n_val.
    case: (P.`n + 32 + 8 * i{m} <= j < P.`n + 32 + 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# hx Node2.get64d_byte 1:/# Node2.get_to_list; congr; smt().
    by rewrite ifF 1:/# hj //; smt().
  wp; skip => &m [#] hx hj /=; split.
  + by rewrite /= take0 cats0; smt(n_val).
  move=> i1 st1 hc [#] g1 g2 g3 g4 g5 j hjj.
  by rewrite g5 // take_oversize // Node2.size_to_list /#.
ecall (extract_n_h st); wp; ecall (keccakf1600_hoare st).
ecall (pad_lanes_h st (3 * (P.`n %/ 8) + 4)).
skip => &m hst /=; split; first smt(n_val).
move=> _ s1 hs1 [s2 ms2] /= hs2 r hr.
rewrite /H family_shake /=.
have hsz : size (Node.to_list c0 ++ BArray32.to_list a0 ++ Node2.to_list x0) = 3 * P.`n + 32.
+ by rewrite !size_cat Node.size_to_list BArray32.size_to_list ?Node2.size_to_list; smt(n_val).
by apply (shake_one_block _ (8 * (3 * (P.`n %/ 8) + 4)) st{m} s1 s2 r) => //; smt(n_val).
qed.

local lemma thash_prf_ll : islossless M._thash_prf.
proof.
proc; call extract_n_ll; wp; call keccakf1600_ll; call pad_lanes_ll.
while true (inc - i); 1: by auto => /#.
by wp; call seeded_head_ll; auto => /#.
qed.

lemma thash_prf_correct (k0 c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_prf : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = PRF P (Node.to_list c0) (Node.to_list k0) (BArray32.to_list a0)] = 1%r.
proof. by conseq thash_prf_ll (thash_prf_h k0 c0 a0 ). qed.

local lemma thash_h_ll : islossless M._thash_h.
proof.
proc; call extract_n_ll; wp; call keccakf1600_ll; call pad_lanes_ll.
while true (inc - i); 1: by auto => /#.
by wp; call seeded_head_ll; auto => /#.
qed.

lemma thash_h_correct (x0 : Node2.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = H P (Node.to_list c0) (BArray32.to_list a0) (Node2.to_list x0)] = 1%r.
proof. by conseq thash_h_ll (thash_h_h x0 c0 a0). qed.

local lemma thash_t_len_h (x0 : TLenIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  hoare [M.tLen___thash_t : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TLenIn.to_list x0)].
proof.
proc.
seq 4 : (in_0 = x0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero (Node.to_list c0 ++ BArray32.to_list a0) j).
+ by ecall (seeded_head_h c0 a0); auto.
seq 4 : (0 <= to_uint pos < 17 /\
         8 * to_uint pos = size ((Node.to_list c0 ++ BArray32.to_list a0) ++ TLenIn.to_list x0) %% 136 /\
         lanes st = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ TLenIn.to_list x0)).
+ while (in_0 = x0 /\ 0 <= to_uint i <= size (TLenIn.to_list x0) %/ 8 /\
         (more <=> to_uint i < size (TLenIn.to_list x0) %/ 8) /\ 0 <= to_uint pos < 17 /\
         8 * to_uint pos = size ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * to_uint i) (TLenIn.to_list x0)) %% 136 /\
         lanes st = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * to_uint i) (TLenIn.to_list x0))).
  + wp.
    seq 3 : (#pre).
    + by wp; skip => &m h; rewrite clamp17 1:/#; exact h.
    seq 6 : (in_0 = x0 /\ 0 <= to_uint i < size (TLenIn.to_list x0) %/ 8 /\ (full <=> to_uint pos = 17) /\ 0 < to_uint pos <= 17 /\
             (8 * to_uint pos) %% 136 = size ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i + 1)) (TLenIn.to_list x0)) %% 136 /\
             (to_uint pos < 17 => lanes st = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i + 1)) (TLenIn.to_list x0))) /\
             (to_uint pos = 17 => keccak_f1600_op (lanes st) = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i + 1)) (TLenIn.to_list x0)))).
    + wp; skip => &m [#] hx hi0 hi1 hmore hp0 hp1 hpm hst hm /=.
      have hW : to_uint i{m} < size (TLenIn.to_list x0) %/ 8 by rewrite -hmore.
      have hsz : 8 * to_uint i{m} + 8 <= size (TLenIn.to_list x0) by move: hW; rewrite TLenIn.size_to_list /=; smt().
      have hcat : take (8 * (to_uint i{m} + 1)) (TLenIn.to_list x0) =
                  take (8 * to_uint i{m}) (TLenIn.to_list x0) ++ take 8 (drop (8 * to_uint i{m}) (TLenIn.to_list x0)).
      + by rewrite (_ : 8 * (to_uint i{m} + 1) = 8 * to_uint i{m} + 8) 1:/# takeD /#.
      have hbs := size_word8 (TLenIn.to_list x0) (to_uint i{m}) hi0 hsz.
      have hw := tlen_word x0 (to_uint i{m}) hi0 hsz.
      have hpos : to_uint (pos{m} + W64.one) = to_uint pos{m} + 1 by rewrite W64.to_uintD_small /#.
      have hm' : 8 * (to_uint pos{m} + 1) %% 136 =
                 size ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i{m} + 1)) (TLenIn.to_list x0)) %% 136.
      + by rewrite hcat catA size_cat hbs; apply (mod_step _ _ hp0 hp1 hpm).
      have hfull := w64_inc17 pos{m} hp1.
      rewrite hpos hx /=; do !split.
      + by [].
      + by move=> _; move: hW; rewrite TLenIn.size_to_list.
      + by rewrite -hfull.
      + by rewrite hfull.
      + by move: hp0 => /#.
      + by move=> _; move: hp1 => /#.
      + exact hm'.
      + move=> hlt; rewrite hcat catA.
        exact (absorb_lane_lt _ _ _ _ _ hp0 hlt hpm hbs hw hst).
      move=> heq; rewrite hcat catA.
      exact (absorb_lane_eq _ _ _ _ _ heq hpm hbs hw hst).
    if.
    + wp; ecall (keccakf1600_hoare st); wp; skip => &m [#] hx hi0 hi1 hfull hp0 hp1 hpm hlt heq hf.
      move=> [s2 ms2] /= hs2; rewrite /protect_ptr /protect_64 /=.
      have hp17 : to_uint pos{m} = 17 by rewrite -hfull.
      have hb : size (TLenIn.to_list x0) %/ 8 < W64.modulus by rewrite TLenIn.size_to_list.
      have hi1' := w64_inc_bound i{m} _ hi1 hb.
      rewrite W64.ultE W64.of_uintK hi1' hx /=; move: hi0 hi1; rewrite !TLenIn.size_to_list /max /= => hi0 hi1.
      do !split.
      + by move: hi0; pose u := to_uint i{m}; smt().
      + by move=> _; move: hi1; pose u := to_uint i{m}; smt().
      + by rewrite -hpm hp17.
      by rewrite hs2 heq.
    wp; skip => &m [#] hx hi0 hi1 hfull hp0 hp1 hpm hlt heq hf.
    have hp17 : to_uint pos{m} < 17 by smt().
    have hb : size (TLenIn.to_list x0) %/ 8 < W64.modulus by rewrite TLenIn.size_to_list.
    have hi1' := w64_inc_bound i{m} _ hi1 hb.
    rewrite /= W64.ultE W64.of_uintK hi1' hx /=; move: hi0 hi1; rewrite !TLenIn.size_to_list /max /= => hi0 hi1.
    have hsm : 8 * to_uint pos{m} %% 136 = 8 * to_uint pos{m}.
    + by apply modz_small; move: hp0 hp17; pose u := to_uint pos{m}; smt().
    do !split.
    + by move: hi0; pose u := to_uint i{m}; smt().
    + by move=> _; move: hi1; pose u := to_uint i{m}; smt().
    + by move: hp0; pose u := to_uint pos{m}; smt().
    + by move=> _; exact hp17.
    + by rewrite -hpm hsm.
    exact (hlt hp17).
  wp; skip => &m [#] hx hst /=.
  have hpre : size (Node.to_list c0 ++ BArray32.to_list a0) = P.`n + 32 by rewrite size_cat Node.size_to_list BArray32.size_to_list; smt(n_val).
  split.
  + rewrite take0 cats0 /max /= hpre n_val /=.
    by split; [exact hx | exact (head_absorbed c0 a0 st{m} hst)].
  move=> i1 x1 m1 p1 s1 hm1 [#] h0 h1 h2 h3 h4 h5 h6 h7.
  have hX : take (8 * to_uint i1) (TLenIn.to_list x0) = TLenIn.to_list x0.
  + rewrite take_oversize // TLenIn.size_to_list; move: h2 h3 hm1; rewrite /max /=.
    by pose u := to_uint i1; smt().
  by move: h6 h7; rewrite hX => h6 h7; split; [by split | by split].
ecall (extract_n_h st); wp; ecall (keccakf1600_hoare st); wp.
skip => &m [#] hp0 hp1 hpm hst [s2 ms2] /= hs2 r hr.
rewrite /T_l family_shake /=.
by apply (shake_final _ (to_uint pos{m}) st{m} s2 r) => //.
qed.

local lemma thash_t_len_ll : islossless M.tLen___thash_t.
proof.
proc; call extract_n_ll; wp; call keccakf1600_ll; wp.
while (0 <= to_uint i <= size (TLenIn.to_list in_0) %/ 8 /\
       (more <=> to_uint i < size (TLenIn.to_list in_0) %/ 8))
      (size (TLenIn.to_list in_0) %/ 8 - to_uint i).
+ move=> z; sp; if.
  + wp; call keccakf1600_ll; wp; skip => &m [] [p0 s0 m0] [#] _ _ _ _ _ _ _ h0 h1 hmore hm hz hf r /=.
    have hb : size (TLenIn.to_list in_0{m}) %/ 8 < W64.modulus by rewrite TLenIn.size_to_list.
    have hlt : to_uint i{m} < size (TLenIn.to_list in_0{m}) %/ 8 by rewrite -hmore.
    have hi := w64_inc_bound i{m} _ hlt hb.
    rewrite /protect_64 /= W64.ultE W64.of_uintK hi; move: h0 h1 hz hlt.
    by rewrite !TLenIn.size_to_list /max /=; pose u := to_uint i{m}; smt().
  wp; skip => &m [] [p0 s0 m0] [#] _ _ _ _ _ _ _ h0 h1 hmore hm hz hf.
  have hb : size (TLenIn.to_list in_0{m}) %/ 8 < W64.modulus by rewrite TLenIn.size_to_list.
  have hlt : to_uint i{m} < size (TLenIn.to_list in_0{m}) %/ 8 by rewrite -hmore.
  have hi := w64_inc_bound i{m} _ hlt hb.
  rewrite /= W64.ultE W64.of_uintK hi; move: h0 h1 hz hlt.
  by rewrite !TLenIn.size_to_list /max /=; pose u := to_uint i{m}; smt().
wp; call seeded_head_ll; wp; skip => &m /=; rewrite /max /=.
by move=> i1 m1; pose u := to_uint i1; smt().
qed.

local lemma thash_t_len_p (x0 : TLenIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M.tLen___thash_t : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TLenIn.to_list x0)] = 1%r.
proof. by conseq thash_t_len_ll (thash_t_len_h x0 c0 a0). qed.

lemma thash_t_len_correct (x0 : TLenIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_t_len : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TLenIn.to_list x0)] = 1%r.
proof. by proc; call (thash_t_len_p x0 c0 a0); auto. qed.

local lemma thash_t_k_h (x0 : TKIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  hoare [M.tK___thash_t : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TKIn.to_list x0)].
proof.
proc.
seq 4 : (in_0 = x0 /\ forall j, 0 <= j < 200 =>
           st.[j] = nth W8.zero (Node.to_list c0 ++ BArray32.to_list a0) j).
+ by ecall (seeded_head_h c0 a0); auto.
seq 4 : (0 <= to_uint pos < 17 /\
         8 * to_uint pos = size ((Node.to_list c0 ++ BArray32.to_list a0) ++ TKIn.to_list x0) %% 136 /\
         lanes st = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ TKIn.to_list x0)).
+ while (in_0 = x0 /\ 0 <= to_uint i <= size (TKIn.to_list x0) %/ 8 /\
         (more <=> to_uint i < size (TKIn.to_list x0) %/ 8) /\ 0 <= to_uint pos < 17 /\
         8 * to_uint pos = size ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * to_uint i) (TKIn.to_list x0)) %% 136 /\
         lanes st = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * to_uint i) (TKIn.to_list x0))).
  + wp.
    seq 3 : (#pre).
    + by wp; skip => &m h; rewrite clamp17 1:/#; exact h.
    seq 6 : (in_0 = x0 /\ 0 <= to_uint i < size (TKIn.to_list x0) %/ 8 /\ (full <=> to_uint pos = 17) /\ 0 < to_uint pos <= 17 /\
             (8 * to_uint pos) %% 136 = size ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i + 1)) (TKIn.to_list x0)) %% 136 /\
             (to_uint pos < 17 => lanes st = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i + 1)) (TKIn.to_list x0))) /\
             (to_uint pos = 17 => keccak_f1600_op (lanes st) = abs_state 136 ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i + 1)) (TKIn.to_list x0)))).
    + wp; skip => &m [#] hx hi0 hi1 hmore hp0 hp1 hpm hst hm /=.
      have hW : to_uint i{m} < size (TKIn.to_list x0) %/ 8 by rewrite -hmore.
      have hsz : 8 * to_uint i{m} + 8 <= size (TKIn.to_list x0) by move: hW; rewrite TKIn.size_to_list /=; smt().
      have hcat : take (8 * (to_uint i{m} + 1)) (TKIn.to_list x0) =
                  take (8 * to_uint i{m}) (TKIn.to_list x0) ++ take 8 (drop (8 * to_uint i{m}) (TKIn.to_list x0)).
      + by rewrite (_ : 8 * (to_uint i{m} + 1) = 8 * to_uint i{m} + 8) 1:/# takeD /#.
      have hbs := size_word8 (TKIn.to_list x0) (to_uint i{m}) hi0 hsz.
      have hw := tk_word x0 (to_uint i{m}) hi0 hsz.
      have hpos : to_uint (pos{m} + W64.one) = to_uint pos{m} + 1 by rewrite W64.to_uintD_small /#.
      have hm' : 8 * (to_uint pos{m} + 1) %% 136 =
                 size ((Node.to_list c0 ++ BArray32.to_list a0) ++ take (8 * (to_uint i{m} + 1)) (TKIn.to_list x0)) %% 136.
      + by rewrite hcat catA size_cat hbs; apply (mod_step _ _ hp0 hp1 hpm).
      have hfull := w64_inc17 pos{m} hp1.
      rewrite hpos hx /=; do !split.
      + by [].
      + by move=> _; move: hW; rewrite TKIn.size_to_list.
      + by rewrite -hfull.
      + by rewrite hfull.
      + by move: hp0 => /#.
      + by move=> _; move: hp1 => /#.
      + exact hm'.
      + move=> hlt; rewrite hcat catA.
        exact (absorb_lane_lt _ _ _ _ _ hp0 hlt hpm hbs hw hst).
      move=> heq; rewrite hcat catA.
      exact (absorb_lane_eq _ _ _ _ _ heq hpm hbs hw hst).
    if.
    + wp; ecall (keccakf1600_hoare st); wp; skip => &m [#] hx hi0 hi1 hfull hp0 hp1 hpm hlt heq hf.
      move=> [s2 ms2] /= hs2; rewrite /protect_ptr /protect_64 /=.
      have hp17 : to_uint pos{m} = 17 by rewrite -hfull.
      have hb : size (TKIn.to_list x0) %/ 8 < W64.modulus by rewrite TKIn.size_to_list.
      have hi1' := w64_inc_bound i{m} _ hi1 hb.
      rewrite W64.ultE W64.of_uintK hi1' hx /=; move: hi0 hi1; rewrite !TKIn.size_to_list /max /= => hi0 hi1.
      do !split.
      + by move: hi0; pose u := to_uint i{m}; smt().
      + by move=> _; move: hi1; pose u := to_uint i{m}; smt().
      + by rewrite -hpm hp17.
      by rewrite hs2 heq.
    wp; skip => &m [#] hx hi0 hi1 hfull hp0 hp1 hpm hlt heq hf.
    have hp17 : to_uint pos{m} < 17 by smt().
    have hb : size (TKIn.to_list x0) %/ 8 < W64.modulus by rewrite TKIn.size_to_list.
    have hi1' := w64_inc_bound i{m} _ hi1 hb.
    rewrite /= W64.ultE W64.of_uintK hi1' hx /=; move: hi0 hi1; rewrite !TKIn.size_to_list /max /= => hi0 hi1.
    have hsm : 8 * to_uint pos{m} %% 136 = 8 * to_uint pos{m}.
    + by apply modz_small; move: hp0 hp17; pose u := to_uint pos{m}; smt().
    do !split.
    + by move: hi0; pose u := to_uint i{m}; smt().
    + by move=> _; move: hi1; pose u := to_uint i{m}; smt().
    + by move: hp0; pose u := to_uint pos{m}; smt().
    + by move=> _; exact hp17.
    + by rewrite -hpm hsm.
    exact (hlt hp17).
  wp; skip => &m [#] hx hst /=.
  have hpre : size (Node.to_list c0 ++ BArray32.to_list a0) = P.`n + 32 by rewrite size_cat Node.size_to_list BArray32.size_to_list; smt(n_val).
  split.
  + rewrite take0 cats0 /max /= hpre n_val /=.
    by split; [exact hx | exact (head_absorbed c0 a0 st{m} hst)].
  move=> i1 x1 m1 p1 s1 hm1 [#] h0 h1 h2 h3 h4 h5 h6 h7.
  have hX : take (8 * to_uint i1) (TKIn.to_list x0) = TKIn.to_list x0.
  + rewrite take_oversize // TKIn.size_to_list; move: h2 h3 hm1; rewrite /max /=.
    by pose u := to_uint i1; smt().
  by move: h6 h7; rewrite hX => h6 h7; split; [by split | by split].
ecall (extract_n_h st); wp; ecall (keccakf1600_hoare st); wp.
skip => &m [#] hp0 hp1 hpm hst [s2 ms2] /= hs2 r hr.
rewrite /T_l family_shake /=.
by apply (shake_final _ (to_uint pos{m}) st{m} s2 r) => //.
qed.

local lemma thash_t_k_ll : islossless M.tK___thash_t.
proof.
proc; call extract_n_ll; wp; call keccakf1600_ll; wp.
while (0 <= to_uint i <= size (TKIn.to_list in_0) %/ 8 /\
       (more <=> to_uint i < size (TKIn.to_list in_0) %/ 8))
      (size (TKIn.to_list in_0) %/ 8 - to_uint i).
+ move=> z; sp; if.
  + wp; call keccakf1600_ll; wp; skip => &m [] [p0 s0 m0] [#] _ _ _ _ _ _ _ h0 h1 hmore hm hz hf r /=.
    have hb : size (TKIn.to_list in_0{m}) %/ 8 < W64.modulus by rewrite TKIn.size_to_list.
    have hlt : to_uint i{m} < size (TKIn.to_list in_0{m}) %/ 8 by rewrite -hmore.
    have hi := w64_inc_bound i{m} _ hlt hb.
    rewrite /protect_64 /= W64.ultE W64.of_uintK hi; move: h0 h1 hz hlt.
    by rewrite !TKIn.size_to_list /max /=; pose u := to_uint i{m}; smt().
  wp; skip => &m [] [p0 s0 m0] [#] _ _ _ _ _ _ _ h0 h1 hmore hm hz hf.
  have hb : size (TKIn.to_list in_0{m}) %/ 8 < W64.modulus by rewrite TKIn.size_to_list.
  have hlt : to_uint i{m} < size (TKIn.to_list in_0{m}) %/ 8 by rewrite -hmore.
  have hi := w64_inc_bound i{m} _ hlt hb.
  rewrite /= W64.ultE W64.of_uintK hi; move: h0 h1 hz hlt.
  by rewrite !TKIn.size_to_list /max /=; pose u := to_uint i{m}; smt().
wp; call seeded_head_ll; wp; skip => &m /=; rewrite /max /=.
by move=> i1 m1; pose u := to_uint i1; smt().
qed.

local lemma thash_t_k_p (x0 : TKIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M.tK___thash_t : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TKIn.to_list x0)] = 1%r.
proof. by conseq thash_t_k_ll (thash_t_k_h x0 c0 a0). qed.

lemma thash_t_k_correct (x0 : TKIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_t_k : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TKIn.to_list x0)] = 1%r.
proof. by proc; call (thash_t_k_p x0 c0 a0); auto. qed.

local lemma shake_absorb_prefix_h (s0 : BArray200.t) (p0 l0 : W64.t) (x0 : BArray332.t) (m : W8.t list) :
  hoare [M._shake_absorb_prefix :
    st = s0 /\ pos = p0 /\ prefix = x0 /\ len = l0 /\ to_uint l0 <= 332 /\
    to_uint p0 = size m %% 136 /\ lanes s0 = abs_state 136 m ==>
    to_uint res.`2 < 136 /\
    to_uint res.`2 = size (m ++ take (to_uint l0) (BArray332.to_list x0)) %% 136 /\
    lanes res.`1 = abs_state 136 (m ++ take (to_uint l0) (BArray332.to_list x0))].
proof.
proc.
wp.
while (prefix = x0 /\ len = l0 /\ to_uint l0 <= 332 /\ 0 <= to_uint i <= to_uint l0 /\
       (more <=> to_uint i < to_uint l0) /\ 0 <= to_uint pos < 136 /\
       to_uint pos = size (m ++ take (to_uint i) (BArray332.to_list x0)) %% 136 /\
       lanes st = abs_state 136 (m ++ take (to_uint i) (BArray332.to_list x0))).
+ wp.
  seq 3 : (#pre).
  + by wp; skip => &m h; rewrite clamp136 1:/#; exact h.
  seq 6 : (prefix = x0 /\ len = l0 /\ to_uint l0 <= 332 /\ 0 <= to_uint i < to_uint l0 /\
           (full <=> to_uint pos = 136) /\ 0 < to_uint pos <= 136 /\
           to_uint pos %% 136 = size (m ++ take (to_uint i + 1) (BArray332.to_list x0)) %% 136 /\
           (to_uint pos < 136 => lanes st = abs_state 136 (m ++ take (to_uint i + 1) (BArray332.to_list x0))) /\
           (to_uint pos = 136 => keccak_f1600_op (lanes st) = abs_state 136 (m ++ take (to_uint i + 1) (BArray332.to_list x0)))).
  + wp; skip => &m [#] hx hl hL hi0 hi1 hmore hp0 hp1 hpm hst hm /=.
    have hW : to_uint i{m} < to_uint l0 by rewrite -hmore.
    have hsz : to_uint i{m} < size (BArray332.to_list x0) by rewrite BArray332.size_to_list /max /=; smt().
    have hcat : take (to_uint i{m} + 1) (BArray332.to_list x0) =
                take (to_uint i{m}) (BArray332.to_list x0) ++ [x0.[to_uint i{m}]].
    + by rewrite (take_nth W8.zero) 1:/# cats1 BArray332.get_to_list.
    have hpos : to_uint (pos{m} + W64.one) = to_uint pos{m} + 1 by apply (w64_inc_bound _ 136).
    have hfull := w64_inc_eq pos{m} 136 hp1 _; first done.
    have hsm : size (m ++ take (to_uint i{m} + 1) (BArray332.to_list x0)) =
               size (m ++ take (to_uint i{m}) (BArray332.to_list x0)) + 1.
    + by rewrite hcat catA size_cat.
    rewrite hpos hx trunc_xor8 /=; do !split.
    + by [].
    + by [].
    + by [].
    + by move=> _; exact hW.
    + by rewrite -hfull.
    + by rewrite hfull.
    + by move: hp0 => /#.
    + by move=> _; move: hp1 => /#.
    + by rewrite hsm hpm modzDml.
    + move=> hlt; rewrite hcat catA.
      exact (absorb_byte_lt _ _ _ _ hp0 hlt hpm hst).
    move=> heq; rewrite hcat catA.
    exact (absorb_byte_eq _ _ _ _ heq hpm hst).
  if.
  + wp; ecall (keccakf1600_hoare st); wp; skip => &m [#] hx hl hL hi0 hi1 hfull hp0 hp1 hpm hlt heq hf.
    move=> [s2 ms2] /= hs2; rewrite /protect_ptr /protect_64 /=.
    have hp136 : to_uint pos{m} = 136 by rewrite -hfull.
    have hi1' := w64_inc_bound i{m} _ hi1 _; first by smt(W64.to_uint_cmp).
    rewrite W64.ultE hi1' hx hl /=.
    do !split.
    + by move: hi0; pose u := to_uint i{m}; smt().
    + by move: hi1; pose u := to_uint i{m}; smt().
    + by move=> _; move: hi1; pose u := to_uint i{m}; smt().
    + by rewrite -hpm hp136.
    by rewrite hs2 heq.
  wp; skip => &m [#] hx hl hL hi0 hi1 hfull hp0 hp1 hpm hlt heq hf.
  have hp136 : to_uint pos{m} < 136 by smt().
  have hi1' := w64_inc_bound i{m} _ hi1 _; first by smt(W64.to_uint_cmp).
  rewrite /= W64.ultE hi1' hx hl /=.
  have hsm : to_uint pos{m} %% 136 = to_uint pos{m}.
  + by apply modz_small; move: hp0 hp136; pose u := to_uint pos{m}; smt().
  do !split.
  + by move: hi0; pose u := to_uint i{m}; smt().
  + by move: hi1; pose u := to_uint i{m}; smt().
  + by move=> _; move: hi1; pose u := to_uint i{m}; smt().
  + by move: hp0; pose u := to_uint pos{m}; smt().
  + by move=> _; exact hp136.
  + by rewrite -hpm hsm.
  exact (hlt hp136).
wp; skip => &m [#] -> -> -> -> hL hpm hst /=.
rewrite take0 cats0; split.
+ have h1 : (W64.zero \ult l0 <=> 0 < to_uint l0) by rewrite W64.ultE.
  have h2 : 0 <= to_uint p0 < 136 by rewrite hpm; smt().
  have h3 := W64.to_uint_cmp l0.
  by rewrite h1 hpm hst /=; move: hL h3; pose u := to_uint l0; smt().
move=> i1 l1 m1 p1 x1 s1 hm1 [#] _ _ _ h0 h1 h2 h3 h4 h5 h6.
have hi : to_uint i1 = to_uint l0 by move: h1 h2 hm1; pose u := to_uint i1; smt().
by rewrite clamp136 1:/# -hi h4 -h5 h6.
qed.

local lemma shake_absorb_prefix_ll : islossless M._shake_absorb_prefix.
proof.
proc; wp.
while ((more <=> to_uint i < to_uint len) /\ to_uint i <= to_uint len) (to_uint len - to_uint i).
+ move=> z.
  sp; if.
  + wp; call keccakf1600_ll; wp; skip => &m [] [p0 s0 m0] [#] _ _ _ _ _ _ _ hmore h1 hm hz hf r /=.
    have hlt : to_uint i{m} < to_uint len{m} by rewrite -hmore.
    have hi := w64_inc_bound i{m} (to_uint len{m}) hlt _; first by case: (W64.to_uint_cmp len{m}).
    rewrite /protect_64 /= W64.ultE hi.
    by move: hlt hz; pose u := to_uint i{m}; pose v := to_uint len{m}; smt().
  wp; skip => &m [] [p0 s0 m0] [#] _ _ _ _ _ _ _ hmore h1 hm hz hf /=.
  have hlt : to_uint i{m} < to_uint len{m} by rewrite -hmore.
  have hi := w64_inc_bound i{m} (to_uint len{m}) hlt _; first by case: (W64.to_uint_cmp len{m}).
  rewrite W64.ultE hi.
  by move: hlt hz; pose u := to_uint i{m}; pose v := to_uint len{m}; smt().
wp; skip => &m /=; split.
+ by rewrite W64.ultE /=; case: (W64.to_uint_cmp len{m}).
by move=> i1 l1 m1; pose u := to_uint i1; pose v := to_uint l1; smt().
qed.

lemma shake_absorb_prefix_correct (s0 : BArray200.t) (p0 l0 : W64.t) (x0 : BArray332.t) (m : W8.t list) :
  phoare [M._shake_absorb_prefix :
    st = s0 /\ pos = p0 /\ prefix = x0 /\ len = l0 /\ to_uint l0 <= 332 /\
    to_uint p0 = size m %% 136 /\ lanes s0 = abs_state 136 m ==>
    to_uint res.`2 < 136 /\
    to_uint res.`2 = size (m ++ take (to_uint l0) (BArray332.to_list x0)) %% 136 /\
    lanes res.`1 = abs_state 136 (m ++ take (to_uint l0) (BArray332.to_list x0))] = 1%r.
proof. by conseq shake_absorb_prefix_ll (shake_absorb_prefix_h s0 p0 l0 x0 m). qed.

local lemma keccak_finalize_h (s0 : BArray200.t) (p0 : W64.t) (m : W8.t list) :
  hoare [M._keccak_finalize :
    st = s0 /\ pos = p0 /\ rate = W64.of_int 136 /\ ds = W64.of_int 31 /\
    to_uint p0 = size m %% 136 /\ lanes s0 = abs_state 136 m ==>
    lanes res.`1 = keccak_f1600_op (ABSORB1600 SHAKE_DS_BYTE 136 m)].
proof.
proc; ecall (keccakf1600_hoare st); wp; skip => &m [#] -> -> -> -> hp hst /=.
move=> [s2 ms2] /= ->; congr.
rewrite trunc_xor8c // trunc_xor8c //.
rewrite -(abs_final 136 m SHAKE_DS_BYTE) // -hp /SHAKE_DS_BYTE /=.
apply stbytes_inj; rewrite stwordsK.
rewrite byte_xor_at //= byte_xor_at; first smt(W64.to_uint_cmp).
by rewrite hst.
qed.

local lemma keccak_finalize_ll : islossless M._keccak_finalize.
proof. by proc; call keccakf1600_ll; auto. qed.

lemma keccak_finalize_correct (s0 : BArray200.t) (p0 : W64.t) (m : W8.t list) :
  phoare [M._keccak_finalize :
    st = s0 /\ pos = p0 /\ rate = W64.of_int 136 /\ ds = W64.of_int 31 /\
    to_uint p0 = size m %% 136 /\ lanes s0 = abs_state 136 m ==>
    lanes res.`1 = keccak_f1600_op (ABSORB1600 SHAKE_DS_BYTE 136 m)] = 1%r.
proof. by conseq keccak_finalize_ll (keccak_finalize_h s0 p0 m). qed.

end section.
