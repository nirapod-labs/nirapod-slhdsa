(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thash.ec
 * ========
 *
 * The one-block tweakable hashes of the SHAKE parameter sets (FIPS 205
 * section 11.1): _thash_f, _thash_prf and _thash_h of
 * src/slhdsa/thash_shake.jinc compute F, PRF and H.
 *
 * Each procedure writes PK.seed and ADRS into a zeroed state
 * (__shake_seeded_head), stores the n- or 2n-byte payload in the lanes
 * after them, adds the SHAKE domain byte after the message and the pad
 * bit at byte 135 (__shake_pad_lanes), permutes once and returns the
 * first n bytes (__shake_extract_n). The message PK.seed || ADRS || M is
 * 2n + 32 or 3n + 32 bytes, at most 128, so it is shorter than one
 * SHAKE256 block (136 bytes): one permutation absorbs and squeezes it
 * (shake_one_block, from the lemmas of ShakeSponge.ec).
 *
 * Model. The procedures depend on n, so this file is checked against the
 * model of each SHAKE set (correctness/core/shake/). Arrays are viewed as
 * byte lists by to_list: Node for n bytes, Node2 for 2n, BArray32 for the
 * address. The context ctx is the n-byte PK.seed (Node).
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
 *     thash_h_correct     H(PK.seed, ADRS, M2), M2 of 2n bytes.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
from JazzEC require import Array25 WArray200.
require import Bytes FIPS205_Params FIPS205_Hash FIPS202_Bytes.
require import BArray32 BArray200 KeccakState Keccakf1600_Spec Keccak1600_Spec.
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

end section.
