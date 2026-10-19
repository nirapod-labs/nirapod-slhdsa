(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ThashX4.ec (SHA2 sets)
 * ======================
 *
 * The four-way tweakable hashes of a SHA2 set: _thash_prf_x4, _thash_f_x4
 * and _thash_t_len_x4.
 *
 * SHA-2 has no multi-way kernel in this library, so each four-way hash
 * runs its scalar hash once per lane k < 4: it gathers the 32-byte address
 * of lane k (words 4k .. 4k + 3 of adrs), and for F the n-byte input of
 * lane k, calls _thash_prf, _thash_f or tLen___thash_t, and scatters the
 * n-byte result to bytes n k .. n k + n - 1 of a staging buffer that is
 * copied to the output at the end. The proofs follow that shape: one
 * loop invariant on the staging buffer, the bytes of the lanes already
 * done equal to the scalar result of their lane (nx4), and the scalar
 * theorems of HashKernels.ec and ThashT.ec for the call of each lane.
 *
 * Theorems (total correctness, for a context ctx_ok for PK.seed):
 *     thash_prf_x4_total    lane k of the result is PRF of lane k of adrs;
 *     thash_f_x4_total      lane k of the result is F of lane k of adrs
 *                           and of x;
 *     thash_t_len_x4_total  lane k of the result is T_len of lane k of
 *                           adrs and of in.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Params FIPS205_Hash.
require import BArray32 BArray96 BArray128 SetModel CoreExtracted WotsLeaf Wots.
require import Thash HashKernels ThashT.

(* ------------------------------------------------------------------ *)
(* Lanes                                                              *)

(* Byte j of four n-byte lanes, lane k being f k. *)
op nx4 (f : int -> bytes) (j : int) : W8.t = nth W8.zero (f (j %/ P.`n)) (j %% P.`n).

lemma lane_nth (m k j : int) (l : 'a list) (d : 'a) :
  0 <= m => 0 <= k => 0 <= j < m => nth d (lane m k l) j = nth d l (m * k + j).
proof. by move=> hm hk hj; rewrite /lane nth_take 1,2:/# nth_drop /#. qed.

lemma size_lane (m k : int) (l : 'a list) :
  0 <= m => 0 <= k => m * (k + 1) <= size l => size (lane m k l) = m.
proof. by move=> hm hk hs; rewrite /lane size_take // size_drop 1:/#; smt(). qed.

(* The four lanes of a Node4 whose bytes are nx4 f. *)
lemma lanes_nx4 (o : Node4.t) (f : int -> bytes) :
  (forall j, 0 <= j < 4 * P.`n => (Node4.get8 o (j)) = nx4 f j) =>
  (forall k, 0 <= k < 4 => size (f k) = P.`n) =>
  forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list o) = f k.
proof.
move=> ho hs k hk; have hn := n_val.
have hsz : size (lane P.`n k (Node4.to_list o)) = P.`n.
+ by rewrite size_lane //; smt(Node4.size_to_list).
apply (eq_from_nth W8.zero); first by rewrite hsz hs.
move=> j; rewrite hsz => hj.
rewrite lane_nth //; first smt().
rewrite Node4.get_to_list ho; first smt().
rewrite /nx4; congr; first by congr; smt().
smt().
qed.

(* The 32-byte address of lane k. *)
op adrs_lane (a0 : BArray128.t) (k : int) : BArray32.t =
  BArray32.of_list (lane 32 k (BArray128.to_list a0)).

lemma adrs_laneK (a0 : BArray128.t) (k : int) : 0 <= k < 4 =>
  BArray32.to_list (adrs_lane a0 k) = lane 32 k (BArray128.to_list a0).
proof. by move=> hk; rewrite /adrs_lane BArray32.of_listK // size_lane //; smt(BArray128.size_to_list). qed.

lemma adrs_lane_bytes (a : BArray32.t) (a0 : BArray128.t) (k : int) : 0 <= k < 4 =>
  (forall j, 0 <= j < 8 * 4 => a.[j] = a0.[32 * k + j]) => a = adrs_lane a0 k.
proof.
move=> hk h; apply BArray32.tP => j hj.
rewrite /adrs_lane BArray32.get_of_list // lane_nth //; first smt().
by rewrite BArray128.get_to_list h /#.
qed.

(* The n-byte input of lane k of a Node4. *)
op node_lane (x0 : Node4.t) (k : int) : Node.t = Node.of_list (lane P.`n k (Node4.to_list x0)).

lemma node_laneK (x0 : Node4.t) (k : int) : 0 <= k < 4 =>
  Node.to_list (node_lane x0 k) = lane P.`n k (Node4.to_list x0).
proof.
move=> hk; have hn := n_val.
by rewrite /node_lane Node.of_listK // size_lane //; smt(Node4.size_to_list).
qed.

lemma node_lane_bytes (o : Node.t) (x0 : Node4.t) (k : int) : 0 <= k < 4 =>
  (forall j, 0 <= j < 8 * (P.`n %/ 8) => (Node.get8 o (j)) = (Node4.get8 x0 (P.`n * k + j))) => o = node_lane x0 k.
proof.
move=> hk h; have hn := n_val; apply Node.tP => j hj.
rewrite /node_lane Node.get_of_list // lane_nth //; first smt().
by rewrite Node4.get_to_list h /#.
qed.

(* ------------------------------------------------------------------ *)
(* The word copies                                                    *)

lemma copy_adrs (a : BArray32.t) (ad : BArray128.t) (k i : int) :
  0 <= k < 4 => 0 <= i < 4 => (forall j, 0 <= j < 8 * i => a.[j] = ad.[32 * k + j]) =>
  forall j, 0 <= j < 8 * (i + 1) =>
    (BArray32.set64 a i (BArray128.get64 ad (4 * k + i))).[j] = ad.[32 * k + j].
proof.
move=> hk hi hj j hj'; rewrite BArray32.get8_set64dE.
case: (8 * i <= j < 8 * i + 8) => h.
+ by rewrite ifT 1:/# BArray128.get64d_byte 1:/#; smt().
by rewrite ifF 1:/# hj 1:/#.
qed.

lemma copy_out (o r : Node4.t) (i : int) :
  0 <= i < P.`n %/ 2 => (forall j, 0 <= j < 8 * i => (Node4.get8 o (j)) = (Node4.get8 r (j))) =>
  forall j, 0 <= j < 8 * (i + 1) => (Node4.get8 (Node4.set64 o i (Node4.get64 r i)) (j)) = (Node4.get8 r (j)).
proof.
move=> hi hj j hj'; have hn := n_val; rewrite Node4.get8_set64dE.
case: (8 * i <= j < 8 * i + 8) => h.
+ by rewrite ifT 1:/# Node4.get64d_byte 1:/#; smt().
by rewrite ifF 1:/# hj 1:/#.
qed.

lemma copy_res_lo (r : Node4.t) (w : W64.t) (k i ix j : int) :
  ix = P.`n %/ 8 * k + i => 0 <= k < 4 => 0 <= i => 0 <= j < P.`n * k =>
  (Node4.get8 (Node4.set64 r ix w) (j)) = (Node4.get8 r (j)).
proof. by move=> -> hk hi hj; have hn := n_val; rewrite Node4.get8_set64dE ifF /#. qed.

lemma copy_res_hi (r : Node4.t) (o : Node.t) (k i ix : int) :
  ix = P.`n %/ 8 * k + i => 0 <= k < 4 => 0 <= i < P.`n %/ 8 =>
  (forall j, 0 <= j < 8 * i => (Node4.get8 r (P.`n * k + j)) = (Node.get8 o (j))) =>
  forall j, 0 <= j < 8 * (i + 1) =>
    (Node4.get8 (Node4.set64 r ix (Node.get64 o i)) (P.`n * k + j)) = (Node.get8 o (j)).
proof.
move=> -> hk hi hj j hj'; have hn := n_val; rewrite Node4.get8_set64dE.
case: (8 * i <= j < 8 * i + 8) => h.
+ by rewrite ifT 1:/# Node.get64d_byte 1:/#; smt().
by rewrite ifF 1:/# hj 1:/#.
qed.

lemma copy_res_up (r : Node4.t) (w : W64.t) (k i ix j : int) :
  ix = P.`n %/ 8 * k + i => 0 <= k < 4 => 0 <= i < P.`n %/ 8 => P.`n * (k + 1) <= j < 4 * P.`n =>
  (Node4.get8 (Node4.set64 r ix w) (j)) = (Node4.get8 r (j)).
proof. by move=> -> hk hi hj; have hn := n_val; rewrite Node4.get8_set64dE ifF /#. qed.

lemma copy_one (o : Node.t) (r : Node4.t) (k i ix : int) :
  ix = P.`n %/ 8 * k + i => 0 <= k < 4 => 0 <= i < P.`n %/ 8 =>
  (forall j, 0 <= j < 8 * i => (Node.get8 o (j)) = (Node4.get8 r (P.`n * k + j))) =>
  forall j, 0 <= j < 8 * (i + 1) =>
    (Node.get8 (Node.set64 o i (Node4.get64 r ix)) (j)) = (Node4.get8 r (P.`n * k + j)).
proof.
move=> -> hk hi hj j hj'; have hn := n_val; rewrite Node.get8_set64dE.
case: (8 * i <= j < 8 * i + 8) => h.
+ by rewrite ifT 1:/# Node4.get64d_byte 1:/#; smt().
by rewrite ifF 1:/# hj 1:/#.
qed.

lemma lane_bound (k j : int) : 0 <= k < 4 => 0 <= j < 8 * (P.`n %/ 8) =>
  P.`n * k <= P.`n * k + j < 4 * P.`n.
proof. by have := n_val; smt(). qed.

(* The lane k result joins the lanes below it. *)
lemma res_next (r : Node4.t) (o : Node.t) (f : int -> bytes) (k : int) :
  0 <= k < 4 =>
  (forall j, 0 <= j < P.`n * k => (Node4.get8 r (j)) = nx4 f j) =>
  (forall j, 0 <= j < 8 * (P.`n %/ 8) => (Node4.get8 r (P.`n * k + j)) = (Node.get8 o (j))) =>
  Node.to_list o = f k =>
  forall j, 0 <= j < P.`n * (k + 1) => (Node4.get8 r (j)) = nx4 f j.
proof.
move=> hk hlo hhi ho j hj; have hn := n_val.
case: (j < P.`n * k) => hjk; first by apply hlo => /#.
have -> : j = P.`n * k + (j - P.`n * k) by ring.
rewrite hhi 1:/# /nx4 -Node.get_to_list ho.
have -> : (P.`n * k + (j - P.`n * k)) %/ P.`n = k by smt().
by have -> : (P.`n * k + (j - P.`n * k)) %% P.`n = j - P.`n * k by smt().
qed.

(* ------------------------------------------------------------------ *)
(* PRF                                                                *)

lemma thash_prf_x4_total (pk : bytes) (c0 : BArray96.t) (k0 : Node.t) (a0 : BArray128.t) :
  phoare [M._thash_prf_x4 :
    sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r.
proof.
have hn := n_val.
pose f := fun k => PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0)).
proc.
while (0 <= i <= inc /\ inc = P.`n %/ 2 /\ (forall j, 0 <= j < 8 * i => (Node4.get8 out j) = (Node4.get8 res_0 j)) /\
       (forall j, 0 <= j < 4 * P.`n => (Node4.get8 res_0 j) = nx4 f j) /\
       (forall k, 0 <= k < 4 => size (f k) = P.`n))
      (inc - i).
+ move=> z; wp; skip => &m [#] hi0 hi1 hinc ho hr hs hlt hz.
  have hc := copy_out out{m} res_0{m} i{m} _ ho; first smt().
  by smt().
wp.
while (0 <= k <= 4 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
       (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
       (forall k', 0 <= k' < k => size (f k') = P.`n))
      (4 - k).
+ move=> z.
  wp.
  while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
         (forall k', 0 <= k' < k => size (f k') = P.`n) /\
         sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         Node.to_list one = f k /\
         (forall j, 0 <= j < 8 * i => (Node4.get8 res_0 (P.`n * k + j)) = (Node.get8 one j)))
        (inc - i).
  + move=> z1; wp; skip => &m [#] hi0 hi1 hinc hk0 hk1 hkz hlo hsz hsk hc ha hpk hok hone hhi hlt hz1.
    have hA : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => 0 <= j < P.`n * k{m} =>
      Node4.get8 (Node4.set64 res_0{m} ix (Node.get64 one{m} i{m})) j = nx4 f j.
    + by move=> ix j hix hj; rewrite (copy_res_lo _ _ k{m} i{m}) // 1:/# hlo.
    have hB : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => 0 <= j < 8 * (i{m} + 1) =>
      Node4.get8 (Node4.set64 res_0{m} ix (Node.get64 one{m} i{m})) (P.`n * k{m} + j) = Node.get8 one{m} j.
    + by move=> ix j hix hj; apply (copy_res_hi _ _ k{m} i{m}) => // /#.
    rewrite /=; do !split; try (move=> j hj; (apply (hA _ j _ hj) || apply (hB _ j _ hj)); smt()); smt().
  wp; call (thash_prf_total pk c0 (adrs_lane a0 (4 - z)) k0).
  while (0 <= i <= 4 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
         (forall k', 0 <= k' < k => size (f k') = P.`n) /\
         sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         (forall j, 0 <= j < 8 * i => a.[j] = adrs.[32 * k + j]))
        (4 - i).
  + move=> z1; wp; skip => &m [#] hi0 hi1 hk0 hk1 hkz hlo hsz hsk hc ha hpk hok hj hlt hz1.
    have hc' := copy_adrs a{m} adrs{m} k{m} i{m} _ _ hj; 1,2: smt().
    by smt().
  wp; skip => &m [#] hk0 hk1 hsk hc ha hpk hok hlo hsz hlt hz; rewrite /protect_ptr /=.
  split; first smt().
  move=> a1 i1; split; first smt().
  move=> hge [#] hi0 hi1 _ _ _ _ _ _ _ _ _ _ hj.
  have ha1 : a1 = adrs_lane a0 (4 - z) by apply adrs_lane_bytes; [smt() | rewrite -ha; smt()].
  split; first smt().
  move=> _ r hr; move: hr; rewrite adrs_laneK 1:/# => hr.
  have hf : Node.to_list r.`1 = f k{m} by rewrite hr /f /=; congr; congr; smt().
  split; first smt().
  move=> i2 r2; split; first smt().
  move=> hge2 [#] hi20 hi21 hinc2 hk20 hk21 hkz2 hlo2 hsz2 hsk2 hc2 ha2 hpk2 hok2 hone2 hhi.
  have hn2 := res_next r2 r.`1 f k{m} _ hlo2 _ hf; first smt().
  + by move=> j hj2; apply hhi; smt().
  have hs2 : size (f k{m}) = P.`n by rewrite -hf Node.size_to_list; smt().
  have hs3 : forall k', 0 <= k' < k{m} + 1 => size (f k') = P.`n.
  + by move=> k' hk'; case: (k' = k{m}) => [-> // | hne]; apply hsz2; smt().
  by do !split; try (exact hn2); try (exact hs3); smt().
wp; skip => &m [#] hsk hc ha hpk hok; split; first smt().
move=> ad1 c1 k1 ms1 r1 sk1; split; first smt().
move=> hge [#] hk0 hk1 _ _ _ _ _ hlo hsz.
split; first smt().
move=> i1 o1; split; first smt().
move=> hge1 [#] hi0 hi1 hinc ho hr0 hs.
have hr : forall j, 0 <= j < 4 * P.`n => Node4.get8 o1 j = nx4 f j.
+ by move=> j hj; rewrite ho 1:/# hr0.
by move=> k hk; rewrite (lanes_nx4 o1 f hr _ k hk) 1:/#.
qed.

(* ------------------------------------------------------------------ *)
(* T_len                                                              *)

lemma tlen_total (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : TLenIn.t) :
  phoare [M.tLen___thash_t :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list x0)] = 1%r.
proof. by conseq tlen_ll (tlen_h pk c0 a0 x0). qed.

(* The T_len input of lane k: bytes len n k .. len n (k + 1) - 1 of in. *)
lemma tlen_laneK (m0 : TLenIn4.t) (k : int) : 0 <= k < 4 =>
  TLenIn.to_list (TLenIn4Lane.get_sub m0 (len P * P.`n * k)) =
  lane (len P * P.`n) k (TLenIn4.to_list m0).
proof.
move=> hk; have hn := n_val.
have hlen : len P = 2 * P.`n + 3 by rewrite /len Wots.len1_val Wots.len2_val.
apply (eq_from_nth W8.zero).
+ by rewrite TLenIn.size_to_list size_lane //; smt(TLenIn4.size_to_list).
move=> j; rewrite TLenIn.size_to_list => hj.
rewrite TLenIn.get_to_list TLenIn4Lane.get8_get_sub (_ : 0 <= j < TLenIn.size) 1:/# /=.
by rewrite lane_nth //; smt(TLenIn4.get_to_list).
qed.

lemma thash_t_len_x4_total (pk : bytes) (c0 : BArray96.t) (m0 : TLenIn4.t) (a0 : BArray128.t) :
  phoare [M._thash_t_len_x4 :
    in_0 = m0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      T_l P pk (lane 32 k (BArray128.to_list a0)) (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r.
proof.
have hn := n_val.
have hlen : len P = 2 * P.`n + 3 by rewrite /len Wots.len1_val Wots.len2_val.
pose f := fun k => T_l P pk (lane 32 k (BArray128.to_list a0)) (lane (len P * P.`n) k (TLenIn4.to_list m0)).
proc.
while (0 <= i <= inc /\ inc = P.`n %/ 2 /\ (forall j, 0 <= j < 8 * i => (Node4.get8 out j) = (Node4.get8 res_0 j)) /\
       (forall j, 0 <= j < 4 * P.`n => (Node4.get8 res_0 j) = nx4 f j) /\
       (forall k, 0 <= k < 4 => size (f k) = P.`n))
      (inc - i).
+ move=> z; wp; skip => &m [#] hi0 hi1 hinc ho hr hs hlt hz.
  have hc := copy_out out{m} res_0{m} i{m} _ ho; first smt().
  by smt().
wp.
while (0 <= k <= 4 /\ in_0 = m0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
       (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
       (forall k', 0 <= k' < k => size (f k') = P.`n))
      (4 - k).
+ move=> z.
  wp.
  while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
         (forall k', 0 <= k' < k => size (f k') = P.`n) /\
         in_0 = m0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         Node.to_list one = f k /\
         (forall j, 0 <= j < 8 * i => (Node4.get8 res_0 (P.`n * k + j)) = (Node.get8 one j)))
        (inc - i).
  + move=> z1; wp; skip => &m [#] hi0 hi1 hinc hk0 hk1 hkz hlo hsz hsk hc ha hpk hok hone hhi hlt hz1.
    have hA : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => 0 <= j < P.`n * k{m} =>
      Node4.get8 (Node4.set64 res_0{m} ix (Node.get64 one{m} i{m})) j = nx4 f j.
    + by move=> ix j hix hj; rewrite (copy_res_lo _ _ k{m} i{m}) // 1:/# hlo.
    have hB : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => 0 <= j < 8 * (i{m} + 1) =>
      Node4.get8 (Node4.set64 res_0{m} ix (Node.get64 one{m} i{m})) (P.`n * k{m} + j) = Node.get8 one{m} j.
    + by move=> ix j hix hj; apply (copy_res_hi _ _ k{m} i{m}) => // /#.
    rewrite /=; do !split; try (move=> j hj; (apply (hA _ j _ hj) || apply (hB _ j _ hj)); smt()); smt().
  wp; call (tlen_total pk c0 (adrs_lane a0 (4 - z)) (TLenIn4Lane.get_sub m0 (len P * P.`n * (4 - z)))).
  while (0 <= i <= 4 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
         (forall k', 0 <= k' < k => size (f k') = P.`n) /\
         in_0 = m0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         (forall j, 0 <= j < 8 * i => a.[j] = adrs.[32 * k + j]))
        (4 - i).
  + move=> z1; wp; skip => &m [#] hi0 hi1 hk0 hk1 hkz hlo hsz hsk hc ha hpk hok hj hlt hz1.
    have hc' := copy_adrs a{m} adrs{m} k{m} i{m} _ _ hj; 1,2: smt().
    by smt().
  wp; skip => &m [#] hk0 hk1 hsk hc ha hpk hok hlo hsz hlt hz; rewrite /protect_ptr /=.
  split; first smt().
  move=> a1 i1; split; first smt().
  move=> hge [#] hi0 hi1 _ _ _ _ _ _ _ _ _ _ hj.
  have ha1 : a1 = adrs_lane a0 (4 - z) by apply adrs_lane_bytes; [smt() | rewrite -ha; smt()].
  split; first smt().
  move=> _ r hr; move: hr; rewrite adrs_laneK 1:/# tlen_laneK 1:/# => hr.
  have hf : Node.to_list r.`1 = f k{m} by rewrite hr /f /=; congr; congr; smt().
  split; first smt().
  move=> i2 r2; split; first smt().
  move=> hge2 [#] hi20 hi21 hinc2 hk20 hk21 hkz2 hlo2 hsz2 hsk2 hc2 ha2 hpk2 hok2 hone2 hhi.
  have hn2 := res_next r2 r.`1 f k{m} _ hlo2 _ hf; first smt().
  + by move=> j hj2; apply hhi; smt().
  have hs2 : size (f k{m}) = P.`n by rewrite -hf Node.size_to_list; smt().
  have hs3 : forall k', 0 <= k' < k{m} + 1 => size (f k') = P.`n.
  + by move=> k' hk'; case: (k' = k{m}) => [-> // | hne]; apply hsz2; smt().
  by do !split; try (exact hn2); try (exact hs3); smt().
wp; skip => &m [#] hsk hc ha hpk hok; split; first smt().
move=> ad1 c1 k1 ms1 r1 sk1; split; first smt().
move=> hge [#] hk0 hk1 _ _ _ _ _ hlo hsz.
split; first smt().
move=> i1 o1; split; first smt().
move=> hge1 [#] hi0 hi1 hinc ho hr0 hs.
have hr : forall j, 0 <= j < 4 * P.`n => Node4.get8 o1 j = nx4 f j.
+ by move=> j hj; rewrite ho 1:/# hr0.
by move=> k hk; rewrite (lanes_nx4 o1 f hr _ k hk) 1:/#.
qed.

(* ------------------------------------------------------------------ *)
(* F                                                                  *)

lemma thash_f_x4_total (pk : bytes) (c0 : BArray96.t) (x0 : Node4.t) (a0 : BArray128.t) :
  phoare [M._thash_f_x4 :
    x = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r.
proof.
have hn := n_val.
pose f := fun k => F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0)).
proc.
while (0 <= i <= inc /\ inc = P.`n %/ 2 /\ (forall j, 0 <= j < 8 * i => (Node4.get8 x j) = (Node4.get8 res_0 j)) /\
       (forall j, 0 <= j < 4 * P.`n => (Node4.get8 res_0 j) = nx4 f j) /\
       (forall k, 0 <= k < 4 => size (f k) = P.`n))
      (inc - i).
+ move=> z; wp; skip => &m [#] hi0 hi1 hinc ho hr hs hlt hz.
  have hc := copy_out x{m} res_0{m} i{m} _ ho; first smt().
  by smt().
wp.
while (0 <= k <= 4 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
       (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
       (forall j, P.`n * k <= j < 4 * P.`n => (Node4.get8 res_0 j) = Node4.get8 x0 j) /\
       (forall k', 0 <= k' < k => size (f k') = P.`n))
      (4 - k).
+ move=> z.
  wp.
  while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
         (forall j, P.`n * (k + 1) <= j < 4 * P.`n => (Node4.get8 res_0 j) = Node4.get8 x0 j) /\
         (forall k', 0 <= k' < k => size (f k') = P.`n) /\
         ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         Node.to_list one = f k /\
         (forall j, 0 <= j < 8 * i => (Node4.get8 res_0 (P.`n * k + j)) = (Node.get8 one j)))
        (inc - i).
  + move=> z1; wp; skip => &m [#] hi0 hi1 hinc hk0 hk1 hkz hlo hup hsz hc ha hpk hok hone hhi hlt hz1.
    have hA : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => 0 <= j < P.`n * k{m} =>
      Node4.get8 (Node4.set64 res_0{m} ix (Node.get64 one{m} i{m})) j = nx4 f j.
    + by move=> ix j hix hj; rewrite (copy_res_lo _ _ k{m} i{m}) // 1:/# hlo.
    have hB : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => 0 <= j < 8 * (i{m} + 1) =>
      Node4.get8 (Node4.set64 res_0{m} ix (Node.get64 one{m} i{m})) (P.`n * k{m} + j) = Node.get8 one{m} j.
    + by move=> ix j hix hj; apply (copy_res_hi _ _ k{m} i{m}) => // /#.
    have hC : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => P.`n * (k{m} + 1) <= j < 4 * P.`n =>
      Node4.get8 (Node4.set64 res_0{m} ix (Node.get64 one{m} i{m})) j = Node4.get8 x0 j.
    + by move=> ix j hix hj; rewrite (copy_res_up _ _ k{m} i{m}) // 1:/# hup.
    rewrite /=; do !split;
      try (move=> j hj; (apply (hA _ j _ hj) || apply (hB _ j _ hj) || apply (hC _ j _ hj)); smt()); smt().
  wp; call (thash_f_total pk c0 (adrs_lane a0 (4 - z)) (node_lane x0 (4 - z))).
  while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
         (forall j, P.`n * k <= j < 4 * P.`n => (Node4.get8 res_0 j) = Node4.get8 x0 j) /\
         (forall k', 0 <= k' < k => size (f k') = P.`n) /\
         ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\ a = adrs_lane a0 k /\
         (forall j, 0 <= j < 8 * i => (Node.get8 one j) = (Node4.get8 res_0 (P.`n * k + j))))
        (inc - i).
  + move=> z1; wp; skip => &m [#] hi0 hi1 hinc hk0 hk1 hkz hlo hup hsz hc ha hpk hok ha1 hj hlt hz1.
    have hD : forall ix j, ix = P.`n %/ 8 * k{m} + i{m} => 0 <= j < 8 * (i{m} + 1) =>
      Node.get8 (Node.set64 one{m} i{m} (Node4.get64 res_0{m} ix)) j = Node4.get8 res_0{m} (P.`n * k{m} + j).
    + by move=> ix j hix hj'; apply (copy_one _ _ k{m} i{m}) => // /#.
    rewrite /=; do !split; try (move=> j hj'; apply (hD _ j _ hj'); smt()); smt().
  wp.
  while (0 <= i <= 4 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall j, 0 <= j < P.`n * k => (Node4.get8 res_0 j) = nx4 f j) /\
         (forall j, P.`n * k <= j < 4 * P.`n => (Node4.get8 res_0 j) = Node4.get8 x0 j) /\
         (forall k', 0 <= k' < k => size (f k') = P.`n) /\
         ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
         (forall j, 0 <= j < 8 * i => a.[j] = adrs.[32 * k + j]))
        (4 - i).
  + move=> z1; wp; skip => &m [#] hi0 hi1 hk0 hk1 hkz hlo hup hsz hc ha hpk hok hj hlt hz1.
    have hc' := copy_adrs a{m} adrs{m} k{m} i{m} _ _ hj; 1,2: smt().
    by smt().
  wp; skip => &m [#] hk0 hk1 hc ha hpk hok hlo hup hsz hlt hz; rewrite /protect_ptr /=.
  split; first smt().
  move=> a1 i1; split; first smt().
  move=> hge [#] hi0 hi1 _ _ _ _ _ _ _ _ _ _ hj.
  have ha1 : a1 = adrs_lane a0 (4 - z) by apply adrs_lane_bytes; [smt() | rewrite -ha; smt()].
  split; first smt().
  move=> i2 o2; split; first smt().
  move=> hge2 [#] hi20 hi21 hinc2 _ _ _ _ _ _ _ _ _ _ _ hj2.
  have ho2 : o2 = node_lane x0 (4 - z).
  + apply node_lane_bytes; first smt().
    move=> j hj5; have e1 := hj2 j _; first smt().
    have e2 := hup (P.`n * k{m} + j) (lane_bound k{m} j _ hj5); first smt().
    by rewrite e1 e2; congr; smt().
  split; first smt().
  move=> _ r hr; move: hr; rewrite adrs_laneK 1:/# node_laneK 1:/# => hr.
  have hf : Node.to_list r.`1 = f k{m} by rewrite hr /f /=; congr; congr; smt().
  split; first smt().
  move=> i3 r3; split; first smt().
  move=> hge3 [#] hi30 hi31 hinc3 hk30 hk31 hkz3 hlo3 hup3 hsz3 hc3 ha3 hpk3 hok3 hone3 hhi.
  have hn3 := res_next r3 r.`1 f k{m} _ hlo3 _ hf; first smt().
  + by move=> j hj3; apply hhi; smt().
  have hs2 : size (f k{m}) = P.`n by rewrite -hf Node.size_to_list; smt().
  have hs3 : forall k', 0 <= k' < k{m} + 1 => size (f k') = P.`n.
  + by move=> k' hk'; case: (k' = k{m}) => [-> // | hne]; apply hsz3; smt().
  by do !split; try (exact hn3); try (exact hs3); try (exact hup3); smt().
wp.
while (0 <= i <= inc /\ inc = P.`n %/ 2 /\ x = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 /\
       (forall j, 0 <= j < 8 * i => (Node4.get8 res_0 j) = (Node4.get8 x j)))
      (inc - i).
+ move=> z; wp; skip => &m [#] hi0 hi1 hinc hx hc ha hpk hok ho hlt hz.
  have hc' := copy_out res_0{m} x{m} i{m} _ ho; first smt().
  by smt().
wp; skip => &m [#] hx hc ha hpk hok; split; first smt().
move=> i0 r0; split; first smt().
move=> hge0 [#] hi0 hi1 hinc hx0 _ _ _ _ hr0.
split; first smt().
move=> ad1 c1 k1 ms1 r1; split; first smt().
move=> hge [#] hk0 hk1 _ _ _ _ hlo _ hsz.
split; first smt().
move=> i1 o1; split; first smt().
move=> hge1 [#] hi10 hi11 hinc1 ho hr1 hs.
have hr : forall j, 0 <= j < 4 * P.`n => Node4.get8 o1 j = nx4 f j.
+ by move=> j hj; rewrite ho 1:/# hr1.
by move=> k hk; rewrite (lanes_nx4 o1 f hr _ k hk) 1:/#.
qed.
