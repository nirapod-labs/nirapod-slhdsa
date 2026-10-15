(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TreeFold.ec
 * ===========
 *
 * Facts shared by the XMSS and FORS tree proofs: the TREE address
 * setters on this set's model, addresses as mk_adrs records, the 2n-byte
 * pair a node hash reads, and the 32-bit index arithmetic of the climbs;
 * and the fold step _treehash_fold of src/slhdsa/treehash.jinc.
 *
 * Fold. The tree is any N : height -> index -> node whose inner nodes
 * are H over their two children under the TREE address of height z and
 * index base / 2^z + j (hN below), so one statement serves XMSS (base 0)
 * and FORS (base = tree 2^a). fs and au state the fold invariant of
 * treehash.jinc before leaf i: the pending left nodes, and the AUTH
 * entries of the target that are complete. Within one call, fmid is the
 * state at height z of the climb; each loop step hashes the parked left
 * sibling with the node (fmid_climb), each test records AUTH[z] or not
 * (fmid_found, fmid_skip), and the final park gives fs and au at i + 1
 * (fmid_park). The loop ends because idx halves while it is odd.
 *
 * Hash premise. H, for one fixed PK.seed pk and ctx c0, in the shape of
 * the per-family thash theorems.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorem:
 *     treehash_fold_correct   from the fold invariant before leaf i,
 *                             _treehash_fold establishes it before leaf
 *                             i + 1; total correctness.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash MerkleTrees_FIPS205.
require import BArray32.
require import SetModel CoreExtracted Wots Encoding WotsChain WotsPk.
require ADRS AddressExtracted.

(* ------------------------------------------------------------------ *)
(* The tree height and index setters, moved to this set's model.      *)

lemma core_set_tree_height (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_tree_height : arg = (a0, i0) ==>
          BArray32.to_list res = setTreeHeight (BArray32.to_list a0) (to_uint i0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_set_tree_height(adrs{m}, height{m}) @ &m :
               BArray32.to_list res = setTreeHeight (BArray32.to_list a0) (to_uint i0)] =
          Pr[AddressExtracted.M.__adrs_set_tree_height(a0, i0) @ &m :
               BArray32.to_list res = setTreeHeight (BArray32.to_list a0) (to_uint i0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_tree_height_correct a0 i0).
qed.

lemma core_set_tree_index (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_tree_index : arg = (a0, i0) ==>
          BArray32.to_list res = setTreeIndex (BArray32.to_list a0) (to_uint i0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_set_tree_index(adrs{m}, index{m}) @ &m :
               BArray32.to_list res = setTreeIndex (BArray32.to_list a0) (to_uint i0)] =
          Pr[AddressExtracted.M.__adrs_set_tree_index(a0, i0) @ &m :
               BArray32.to_list res = setTreeIndex (BArray32.to_list a0) (to_uint i0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_tree_index_correct a0 i0).
qed.

lemma height_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_tree_height : arg = (a0, i0) ==>
  BArray32.to_list res = setTreeHeight (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_tree_height a0 i0). qed.

lemma index_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_tree_index : arg = (a0, i0) ==>
  BArray32.to_list res = setTreeIndex (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_tree_index a0 i0). qed.

lemma tc2_h (a0 : BArray32.t) : hoare [M.__adrs_set_type_and_clear : arg = (a0, 2) ==>
  BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) TREE].
proof. by conseq (core_set_type_and_clear a0 2 _) => // &hr r; rewrite /TREE. qed.

lemma tc3_h (a0 : BArray32.t) : hoare [M.__adrs_set_type_and_clear : arg = (a0, 3) ==>
  BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) FORS_TREE].
proof. by conseq (core_set_type_and_clear a0 3 _) => // &hr r; rewrite /FORS_TREE. qed.

lemma copy_hh (d0 s0 : BArray32.t) :
  hoare [M.__adrs_copy : arg = (d0, s0) ==> BArray32.to_list res = BArray32.to_list s0].
proof. by conseq (core_copy d0 s0). qed.

lemma set_tree_height_ll : islossless M.__adrs_set_tree_height.
proof. proc*; exlim adrs, height => a i; call (core_set_tree_height a i); auto. qed.

lemma set_tree_index_ll : islossless M.__adrs_set_tree_index.
proof. proc*; exlim adrs, index => a i; call (core_set_tree_index a i); auto. qed.

lemma protect32E (x : W32.t) (m : W64.t) : SLH64.protect_32 x m = x by done.
lemma protectpE (x : 'a) (m : W64.t) : SLH64.protect_ptr x m = x by done.
hint simplify protect32E, protectpE.

(* ------------------------------------------------------------------ *)
(* Every 32-byte address is an mk_adrs record.                        *)

lemma slice_join (x : bytes) i j k : 0 <= i <= j => j <= k =>
  slice x i j ++ slice x j k = slice x i k.
proof.
move=> hij hjk; rewrite /slice; have -> : drop j x = drop (j - i) (drop i x).
+ by rewrite drop_drop 1,2:/#; congr; ring.
move: (drop i x) => y; case: (j - i <= size y) => hs.
+ rewrite -{3}(cat_take_drop (j - i) y) take_cat size_take 1:/#.
  have -> : (if j - i < size y then j - i else size y) = j - i by smt().
  by rewrite ifF 1:/# (_ : k - i - (j - i) = k - j) 1:/#.
rewrite take_oversize 1:/# drop_oversize 1:/# take_oversize 1:/#.
by rewrite take_oversize 1:/# cats0.
qed.

lemma adrs_mk (a : adrs) : size a = 32 =>
  a = mk_adrs (toInt (slice a 0 4) 4) (toInt (slice a 4 16) 12) (toInt (slice a 16 20) 4)
              (toInt (slice a 20 24) 4) (toInt (slice a 24 28) 4) (toInt (slice a 28 32) 4).
proof.
move=> ha; have hs : forall i j, 0 <= i <= j <= 32 => size (slice a i j) = j - i.
+ by move=> i j hij; rewrite size_slice /#.
rewrite /mk_adrs !ADRS.toByte_toInt ?hs //.
rewrite -!catA !slice_join //.
by rewrite -{1}ha slice_whole.
qed.

lemma adrs_mkP (a : adrs) : size a = 32 => exists l t y w2 w1 w0, a = mk_adrs l t y w2 w1 w0.
proof.
move=> ha; exists (toInt (slice a 0 4) 4) (toInt (slice a 4 16) 12) (toInt (slice a 16 20) 4).
by exists (toInt (slice a 20 24) 4) (toInt (slice a 24 28) 4) (toInt (slice a 28 32) 4); apply adrs_mk.
qed.

(* ------------------------------------------------------------------ *)
(* The pair that a node hash reads: x in bytes 0 .. n - 1, y in       *)
(* n .. 2n - 1. c is the value of n that the code writes.             *)

lemma pair_cat (p : Node2.t) (x y : Node.t) c : P.`n = c =>
  Node2.to_list (Node2Half.set_sub (Node2Half.set_sub p 0 x) c y) = Node.to_list x ++ Node.to_list y.
proof.
move=> hc; have hn := n_val; apply (eq_from_nth W8.zero).
+ by rewrite size_cat !Node.size_to_list Node2.size_to_list; smt().
rewrite Node2.size_to_list => j hj; rewrite Node2.get_to_list !Node2Half.get8_set_sub.
rewrite nth_cat Node.size_to_list !Node.get_to_list.
case: (j < Node.size) => h.
+ by rewrite ifF 1:/# ifT 1:/# ifT 1:/#.
by rewrite ifT 1:/# ifF 1:/#; congr; smt().
qed.

(* ------------------------------------------------------------------ *)
(* 32-bit index arithmetic                                            *)

lemma odd_bit (x : W32.t) : ((x `&` W32.one) = W32.one) = (to_uint x %% 2 <> 0).
proof.
have h : to_uint (x `&` W32.one) = to_uint x %% 2.
+ by rewrite (_ : W32.one = W32.of_int (2 ^ 1 - 1)) // W32.to_uint_and_mod.
rewrite eq_iff; split => [he | hne].
+ by have := congr1 W32.to_uint _ _ he; rewrite h W32.to_uint1 => ->.
apply W32.to_uint_eq; rewrite h W32.to_uint1; smt(modz_ge0 ltz_pmod).
qed.

lemma shr1 (x : W32.t) : to_uint (x `>>` W8.one) = to_uint x %/ 2.
proof.
by rewrite (_ : W8.one = W8.of_int 1) // W32.shr_shrw 1:/# W32.to_uint_shr 1:/# expr1.
qed.

lemma inc32 (x : W32.t) c : 0 <= to_uint x < c => c < W32.modulus =>
  to_uint (x + W32.one) = to_uint x + 1.
proof. by move=> hx hc; rewrite W32.to_uintD_small W32.to_uint1 //; move: hx hc => /#. qed.

lemma ult_c (x : W32.t) (c d : int) : d = c => 0 <= c < W32.modulus =>
  (x \ult W32.of_int c) = (to_uint x < d).
proof. by move=> -> hc; rewrite W32.ultE W32.of_uintK modz_small //; smt(). qed.

lemma hp_lt : 0 < P.`hp < 32 by rewrite hp_val.

lemma xor1 (w : W32.t) : to_uint (w `^` W32.one) = gsibling (to_uint w).
proof.
have hw := W32.to_uint_cmp w.
have hand : forall (x : W32.t), to_uint (x `&` W32.one) = to_uint x %% 2.
+ by move=> x; rewrite (_ : W32.one = W32.of_int (2 ^ 1 - 1)) // W32.to_uint_and_mod.
rewrite /gsibling; case: (to_uint w %% 2 = 0) => hb.
+ have h0 : w `&` W32.one = W32.zero by apply W32.to_uint_eq; rewrite hand hb.
  have := W32.orw_xorw w W32.one; rewrite h0 W32.xorw0 => <-.
  by rewrite W32.to_uint_orw_disjoint // W32.to_uint1.
have h0 : W32.invw w `&` W32.one = W32.zero.
+ apply W32.to_uint_eq; rewrite hand W32.to_uint_invw /=; smt(modz_ge0 ltz_pmod).
rewrite -W32.subw_xorw // W32.to_uintB ?W32.uleE W32.to_uint1 //; smt(modz_ge0 ltz_pmod).
qed.

(* ------------------------------------------------------------------ *)
(* Index arithmetic of the fold                                       *)

lemma pow_split (Z z : int) : 0 <= z <= Z => 2 ^ Z = 2 ^ (Z - z) * 2 ^ z.
proof. by move=> hz; rewrite -exprD_nneg 1,2:/#; congr; ring. qed.

lemma div_shift (q r Z z : int) : 0 <= z <= Z =>
  (q * 2 ^ Z + r) %/ 2 ^ z = q * 2 ^ (Z - z) + r %/ 2 ^ z.
proof.
move=> hz; have hp : 0 < 2 ^ z by apply StdOrder.IntOrder.expr_gt0.
by rewrite (pow_split Z z) // mulrA divzMDl /#.
qed.

lemma ones_div (Z z : int) : 0 <= z <= Z => (2 ^ Z - 1) %/ 2 ^ z = 2 ^ (Z - z) - 1.
proof.
move=> hz; have hp : 0 < 2 ^ z by apply StdOrder.IntOrder.expr_gt0.
have -> : 2 ^ Z - 1 = (2 ^ (Z - z) - 1) * 2 ^ z + (2 ^ z - 1) by rewrite (pow_split Z z) //; ring.
by rewrite divzMDl 1:/# divz_small //; smt().
qed.

lemma pow_even (k : int) : 0 < k => 2 ^ k %% 2 = 0.
proof. by move=> hk; rewrite (_ : k = (k - 1) + 1) 1:/# exprS 1:/# modzMr. qed.

(* The low Z bits of i are ones: i = q 2^Z + 2^Z - 1. *)
lemma low_ones (i Z : int) : 0 <= Z => i %% 2 ^ Z = 2 ^ Z - 1 =>
  i = (i %/ 2 ^ Z + 1) * 2 ^ Z - 1.
proof. by move=> hZ h; have := divz_eq i (2 ^ Z); rewrite h => {1}->; ring. qed.

(* Below the lowest zero bit Z, every bit of i is one. *)
lemma bit_low (i Z z : int) : 0 <= z < Z => i %% 2 ^ Z = 2 ^ Z - 1 => (i %/ 2 ^ z) %% 2 = 1.
proof.
move=> hz h; have e := low_ones i Z _ h; 1: smt().
have -> : i %/ 2 ^ z = (i %/ 2 ^ Z + 1) * 2 ^ (Z - z) - 1.
+ rewrite {1}e (_ : (i %/ 2 ^ Z + 1) * 2 ^ Z - 1 = (i %/ 2 ^ Z) * 2 ^ Z + (2 ^ Z - 1)) 1:/#.
  by rewrite div_shift 1:/# ones_div 1:/#; ring.
have he := pow_even (Z - z) _; 1: smt().
have [c hc] : exists c, 2 ^ (Z - z) = 2 * c by exists (2 ^ (Z - z) %/ 2); smt(divz_eq).
rewrite hc; move: (i %/ 2 ^ Z + 1) => a.
by rewrite (_ : a * (2 * c) - 1 = (a * c - 1) * 2 + 1) 1:/# modzMDl.
qed.

(* One more set bit at Z: the step of the climb. *)
lemma low_onesS (i Z : int) : 0 <= Z => i %% 2 ^ Z = 2 ^ Z - 1 => (i %/ 2 ^ Z) %% 2 = 1 =>
  i %% 2 ^ (Z + 1) = 2 ^ (Z + 1) - 1.
proof.
move=> hZ h hb; have e := low_ones i Z hZ h.
have hq := divz_eq (i %/ 2 ^ Z) 2; rewrite hb in hq.
have -> : i = (i %/ 2 ^ Z %/ 2) * 2 ^ (Z + 1) + (2 ^ (Z + 1) - 1).
+ by rewrite {1}e {1}hq exprS //; ring.
rewrite modzMDl modz_small //; smt(StdOrder.IntOrder.expr_gt0).
qed.

(* i + 1 when bit Z of i is the lowest zero bit. *)
lemma succ_div (i Z z : int) : 0 <= Z => 0 <= z => i %% 2 ^ Z = 2 ^ Z - 1 => (i %/ 2 ^ Z) %% 2 = 0 =>
  (i + 1) %/ 2 ^ z = i %/ 2 ^ z + (if z <= Z then 1 else 0).
proof.
move=> hZ hz h hb; have e := low_ones i Z hZ h.
pose q := i %/ 2 ^ Z.
have hi1 : i + 1 = (q + 1) * 2 ^ Z by rewrite {1}e /q; ring.
case: (z <= Z) => hzZ /=.
+ have hi : i = q * 2 ^ Z + (2 ^ Z - 1) by rewrite {1}e /q; ring.
  rewrite hi1 (_ : (q + 1) * 2 ^ Z = (q + 1) * 2 ^ Z + 0) 1:// div_shift 1:/# div0z.
  by rewrite {1}hi div_shift 1:/# ones_div 1:/#; ring.
have hk : 0 < z - Z by smt().
have hs : 2 ^ z = 2 ^ Z * 2 ^ (z - Z) by rewrite mulrC -pow_split /#.
have hp : 0 < 2 ^ Z by apply StdOrder.IntOrder.expr_gt0.
have hp' : 0 < 2 ^ (z - Z) by apply StdOrder.IntOrder.expr_gt0.
rewrite hs !divzMr 1..4:/# hi1 mulzK 1:/# -/q.
have hs2 : 2 ^ (z - Z) = 2 * 2 ^ (z - Z - 1) by rewrite -exprS /#.
rewrite hs2 !divzMr 1..4:/#; smt(StdOrder.IntOrder.expr_gt0).
qed.

lemma gsib_div2 (x : int) : 0 <= x => gsibling x %/ 2 = x %/ 2.
proof. by move=> hx; rewrite /gsibling; smt(divz_eq modz_ge0 ltz_pmod). qed.

(* ------------------------------------------------------------------ *)
(* Fold buffers: slot z is bytes z n .. z n + n - 1, 0 <= z <= a.     *)

op slot (b : FoldBuf.t) (z : int) : bytes = Node.to_list (FoldNode.get_sub b (z * P.`n)).

lemma fbuf_size : FoldBuf.size = (P.`a + 1) * P.`n by rewrite a_val n_val.

lemma blk_ne (L k k' x : int) : 0 < L => 0 <= x < L => k <> k' => !(k * L <= k' * L + x < k * L + L).
proof.
move=> hL hx hk; case: (k' < k) => h.
+ have : (k' + 1) * L <= k * L by apply StdOrder.IntOrder.ler_wpmul2r; smt().
  smt().
have : (k + 1) * L <= k' * L by apply StdOrder.IntOrder.ler_wpmul2r; smt().
smt().
qed.

lemma slot_set (b : FoldBuf.t) (x : Node.t) z z' : 0 <= z <= P.`a => 0 <= z' <= P.`a =>
  slot (FoldNode.set_sub b (z * P.`n) x) z' = if z' = z then Node.to_list x else slot b z'.
proof.
move=> hz hz'; have hn := n_val; have hs := fbuf_size.
have hr : forall y, 0 <= y <= P.`a => forall j, 0 <= j < P.`n =>
  0 <= y * P.`n + j < FoldBuf.size.
+ move=> y hy j hj; rewrite hs; split; first smt().
  move=> _; have : y * P.`n <= P.`a * P.`n by apply StdOrder.IntOrder.ler_wpmul2r; smt().
  smt().
rewrite /slot; case: (z' = z) => he.
+ apply (eq_from_nth W8.zero); first by rewrite !Node.size_to_list.
  rewrite Node.size_to_list => j hj; rewrite !Node.get_to_list FoldNode.get8_get_sub ifT 1:/#.
  rewrite FoldNode.get8_set_sub ifT; first by rewrite he; smt().
  by congr; rewrite he; ring.
apply (eq_from_nth W8.zero); first by rewrite !Node.size_to_list.
rewrite Node.size_to_list => j hj; rewrite !Node.get_to_list !FoldNode.get8_get_sub.
have hjn : 0 <= j < Node.size by smt().
rewrite hjn /= FoldNode.get8_set_sub ifF //.
have := blk_ne P.`n z z' j _ _ _; 1..3: smt().
smt().
qed.

(* The slot offset that __fold_slot computes: the clamp to a never
   changes a height z <= a. *)
lemma clamp_eq (z : W32.t) c : P.`a = c => to_uint z <= P.`a =>
  (if z \ult W32.of_int c then z else W32.of_int c) = z.
proof.
move=> hc hz; have ha := a_val; case: (z \ult W32.of_int c) => // h.
apply W32.to_uint_eq; rewrite W32.of_uintK modz_small; 1: smt().
by move: h; rewrite W32.ultE W32.of_uintK modz_small; smt().
qed.

lemma slotE (z : W32.t) c : P.`n = c => to_uint z <= P.`a =>
  to_uint (zeroextu64 z * W64.of_int c) = to_uint z * P.`n.
proof.
move=> hc hz; have hn := n_val; have ha := a_val; have h0 := W32.to_uint_cmp z.
rewrite W64.to_uintM_small zext64E W64.of_uintK -hc hn /= //; smt().
qed.

lemma fold_slot_h (z0 : W32.t) :
  hoare [M.__fold_slot : z = z0 /\ to_uint z0 <= P.`a ==> to_uint res = to_uint z0 * P.`n].
proof.
proc; inline M.__offset; wp; skip => &m /> h.
by rewrite (clamp_eq z{m} _ a_val h) (slotE z{m} _ n_val h).
qed.

lemma fold_slot_ll : islossless M.__fold_slot by islossless.

(* ------------------------------------------------------------------ *)
(* The fold invariant (src/slhdsa/treehash.jinc)                      *)

(* Before leaf i: slot z of nodes holds node((i >> z) - 1, z) at every
   height z whose bit of i is set. *)
op fs (N : int -> int -> bytes) (b : FoldBuf.t) (t i : int) : bool =
  forall z, 0 <= z <= t => (i %/ 2 ^ z) %% 2 = 1 => slot b z = N z (i %/ 2 ^ z - 1).

(* Slot z of auth holds AUTH[z] = node(sibling(tg >> z), z) once that node
   is complete (its index is below i >> z), or, for the heights below K
   of the current climb, once it has been built. *)
op aum (N : int -> int -> bytes) (b : FoldBuf.t) (t i tg K : int) : bool =
  forall z, 0 <= z <= t =>
    (gsibling (tg %/ 2 ^ z) < i %/ 2 ^ z \/ (z < K /\ gsibling (tg %/ 2 ^ z) = i %/ 2 ^ z)) =>
    slot b z = N z (gsibling (tg %/ 2 ^ z)).

op au (N : int -> int -> bytes) (b : FoldBuf.t) (t i tg : int) : bool =
  forall z, 0 <= z <= t => gsibling (tg %/ 2 ^ z) < i %/ 2 ^ z => slot b z = N z (gsibling (tg %/ 2 ^ z)).

lemma au_aum N b t i tg : au N b t i tg => aum N b t i tg 0.
proof. by move=> h z hz [hl | /#]; apply h. qed.

(* Recording the node at height Z. *)
lemma record_found N (b : FoldBuf.t) (x : Node.t) t i tg Z :
  0 <= Z <= t => t <= P.`a => aum N b t i tg Z => gsibling (tg %/ 2 ^ Z) = i %/ 2 ^ Z =>
  Node.to_list x = N Z (i %/ 2 ^ Z) =>
  aum N (FoldNode.set_sub b (Z * P.`n) x) t i tg (Z + 1).
proof.
move=> hZ ht h hs hx z hz hc; rewrite slot_set 1,2:/#.
case: (z = Z) => he; first by rewrite hx he hs.
by apply h => //; smt().
qed.

lemma record_skip N (b : FoldBuf.t) t i tg Z :
  aum N b t i tg Z => gsibling (tg %/ 2 ^ Z) <> i %/ 2 ^ Z => aum N b t i tg (Z + 1).
proof.
move=> h hs z hz hc; apply (h z hz); case: (z = Z) => [he | hne].
+ by move: hc; rewrite he hs /=; smt().
by move: hc => [-> // | [h1 h2]]; right; split => //; smt().
qed.

(* Parking the node of the lowest zero bit Z gives the state before leaf
   i + 1. *)
lemma park_fs N (b : FoldBuf.t) (x : Node.t) t i Z : 0 <= Z <= t => t <= P.`a =>
  i %% 2 ^ Z = 2 ^ Z - 1 => (i %/ 2 ^ Z) %% 2 = 0 => fs N b t i =>
  Node.to_list x = N Z (i %/ 2 ^ Z) =>
  fs N (FoldNode.set_sub b (Z * P.`n) x) t (i + 1).
proof.
move=> hZ ht hl hb h hx z hz; rewrite slot_set 1,2:/#.
rewrite (succ_div i Z z) 1..4:/#.
case: (z = Z) => he.
+ by rewrite he /= hx.
case: (z < Z) => hlt.
+ have hb1 := bit_low i Z z _ hl; 1: smt().
  rewrite ifT 1:/#; smt(modzDm).
rewrite ifF 1:/# /= => hb2; apply h => //.
qed.

lemma park_au N (b : FoldBuf.t) t i tg Z : 0 <= Z =>
  i %% 2 ^ Z = 2 ^ Z - 1 => (i %/ 2 ^ Z) %% 2 = 0 => aum N b t i tg (Z + 1) =>
  au N b t (i + 1) tg.
proof.
move=> hZ hl hb h z hz; rewrite (succ_div i Z z) 1..4:/# => hc.
by apply h => //; smt().
qed.

(* ------------------------------------------------------------------ *)
(* The state of the fold at height z                                  *)

(* A climb that reaches height Z + 1 below 2^t stays inside the tree. *)
lemma climb_le (i Z t : int) : 0 <= Z => 0 <= t => 0 <= i < 2 ^ t =>
  i %% 2 ^ (Z + 1) = 2 ^ (Z + 1) - 1 => Z + 1 <= t.
proof.
move=> hZ ht hi h; have hp : 0 < 2 ^ (Z + 1) by apply StdOrder.IntOrder.expr_gt0.
have hq : 0 <= i %/ 2 ^ (Z + 1) by rewrite divz_ge0 // /#.
have hm : 0 <= i %/ 2 ^ (Z + 1) * 2 ^ (Z + 1) by apply StdOrder.IntOrder.mulr_ge0 => /#.
have e := divz_eq i (2 ^ (Z + 1)).
have hle : 2 ^ (Z + 1) - 1 <= i.
+ rewrite -h; move: hm e; move: (i %/ 2 ^ (Z + 1) * 2 ^ (Z + 1)) (i %% 2 ^ (Z + 1)) => q r /#.
case: (Z + 1 <= t) => // hlt.
have : 2 ^ t <= 2 ^ Z by apply StdOrder.IntOrder.ler_weexpn2l => /#.
have h1 : 0 < 2 ^ Z by apply StdOrder.IntOrder.expr_gt0.
by rewrite exprS // in hle; smt().
qed.

lemma base_div (base i t z : int) : 0 <= z <= t => 2 ^ t %| base =>
  (base + i) %/ 2 ^ z = base %/ 2 ^ z + i %/ 2 ^ z.
proof. by move=> hz hb; apply divzDl; apply (dvdz_trans (2 ^ t)) => //; apply dvdz_exp2l. qed.

lemma tree_adrs_eq (x y : adrs) h v : size x = 32 => take 24 x = take 24 y =>
  setTreeIndex (setTreeHeight x h) v = setTreeIndex (setTreeHeight y h) v.
proof. by move=> hx h24; apply sha_eq; apply take28_sca => /#. qed.

lemma tree_adrs_take (x : adrs) h v : size x = 32 =>
  take 24 (setTreeIndex (setTreeHeight x h) v) = take 24 x.
proof.
move=> hx; have [_ h28] := sha_take (setTreeHeight x h) v _.
+ by rewrite /setChainAddress /slice drop0 !size_cat size_toByte4 size_take // size_take // size_drop; smt().
move: (setTreeIndex (setTreeHeight x h) v) h28 => L h28.
have -> : take 24 L = take 24 (take 28 L) by rewrite take_take.
by rewrite h28 take_take /= take24_sca 1:/#.
qed.

(* The fold at height z: node is node(i >> z, z), the low z bits of i
   are ones, idx, adrs_idx and sib follow i, base + i and target down,
   and auth holds every AUTH entry that is complete, plus the one at
   height z when k = 1 (it has just been tested). *)
op fmid (N : int -> int -> bytes) (na : adrs) (t base i tg : int) (auth : FoldBuf.t)
        (node : Node.t) (cur : BArray32.t) (z idx aidx sib : W32.t) (k : int) : bool =
  0 <= to_uint z <= t /\ i %% 2 ^ to_uint z = 2 ^ to_uint z - 1 /\
  to_uint idx = i %/ 2 ^ to_uint z /\ to_uint aidx = (base + i) %/ 2 ^ to_uint z /\
  to_uint sib = gsibling (tg %/ 2 ^ to_uint z) /\
  Node.to_list node = N (to_uint z) (i %/ 2 ^ to_uint z) /\
  take 24 (BArray32.to_list cur) = take 24 na /\
  aum N auth t i tg (to_uint z + k).

lemma fmid0 N na t base (au0 : FoldBuf.t) (x0 : Node.t) (na0 : BArray32.t) (id0 ai0 tg0 : W32.t) :
  0 <= t => to_uint ai0 = base + to_uint id0 => Node.to_list x0 = N 0 (to_uint id0) =>
  take 24 (BArray32.to_list na0) = take 24 na => au N au0 t (to_uint id0) (to_uint tg0) =>
  fmid N na t base (to_uint id0) (to_uint tg0) au0 x0 na0 W32.zero id0 ai0 (tg0 `^` W32.one) 0.
proof.
move=> ht hai hx hna hau; rewrite /fmid /= ?expr0 ?divz1 ?modz1 hai hx hna xor1 /=.
by split => //; apply au_aum.
qed.

lemma fmid_found N na t base i tg (auth : FoldBuf.t) node cur (z idx aidx sib : W32.t) :
  t <= P.`a => fmid N na t base i tg auth node cur z idx aidx sib 0 => idx = sib =>
  fmid N na t base i tg (FoldNode.set_sub auth (to_uint z * P.`n) node) node cur z idx aidx sib 1.
proof.
move=> ha; rewrite /fmid => [#] hz0 hz1 hl hi hai hs hx h24 h he.
rewrite hz0 hz1 hl hi hai hs hx h24 /=.
by apply (record_found N auth node t i tg (to_uint z)) => //; smt().
qed.

lemma fmid_skip N na t base i tg (auth : FoldBuf.t) node cur (z idx aidx sib : W32.t) :
  fmid N na t base i tg auth node cur z idx aidx sib 0 => idx <> sib =>
  fmid N na t base i tg auth node cur z idx aidx sib 1.
proof.
rewrite /fmid => [#] hz0 hz1 hl hi hai hs hx h24 h hne.
rewrite hz0 hz1 hl hi hai hs hx h24 /=.
have h0 : aum N auth t i tg (to_uint z) by move: h; rewrite addz0.
have hne' : gsibling (tg %/ 2 ^ to_uint z) <> i %/ 2 ^ to_uint z.
+ rewrite -hi -hs; apply/negP => e; apply hne; apply W32.to_uint_eq; by rewrite e.
exact (record_skip N auth t i tg (to_uint z) h0 hne').
qed.

(* The climb: a right child at height z is hashed with its parked left
   sibling into the parent at height z + 1. *)
lemma fmid_climb (pk : bytes) N na t base i tg (nd0 auth : FoldBuf.t) (node node' : Node.t)
  (cur cur' : BArray32.t) (z idx aidx sib z' idx' aidx' sib' : W32.t) :
  (forall z j, 0 <= z < t => 0 <= j =>
     N (z + 1) j = H P pk (setTreeIndex (setTreeHeight na (z + 1)) (base %/ 2 ^ (z + 1) + j))
                         (N z (2 * j) ++ N z (2 * j + 1))) =>
  0 <= t <= P.`a => 2 ^ t %| base => 0 <= i < 2 ^ t => 0 <= tg =>
  fs N nd0 t i => fmid N na t base i tg auth node cur z idx aidx sib 1 =>
  to_uint idx %% 2 <> 0 =>
  z' = z + W32.one => to_uint idx' = to_uint idx %/ 2 => to_uint aidx' = to_uint aidx %/ 2 =>
  to_uint sib' = gsibling (to_uint sib %/ 2) =>
  BArray32.to_list cur' =
    setTreeIndex (setTreeHeight (BArray32.to_list cur) (to_uint z')) (to_uint aidx') =>
  Node.to_list node' = H P pk (BArray32.to_list cur') (slot nd0 (to_uint z) ++ Node.to_list node) =>
  fmid N na t base i tg auth node' cur' z' idx' aidx' sib' 0.
proof.
move=> hN [ht0 hta] hbd hi htg hfs; rewrite /fmid => [#] hz0 hz1 hl hix hai hs hx h24 h.
move=> hodd hz' hix' hai' hs' hc' hn'.
have hb : (i %/ 2 ^ to_uint z) %% 2 = 1 by rewrite -hix; smt().
have hl' := low_onesS i (to_uint z) hz0 hl hb.
have hZt := climb_le i (to_uint z) t hz0 ht0 hi hl'.
have hzv : to_uint z' = to_uint z + 1.
+ rewrite hz' (inc32 z t) //; first by smt().
  by rewrite m32; move: hta; rewrite a_val => /#.
have hq := div2_split i (to_uint z) hz0; rewrite hb in hq.
rewrite hzv; split; first by smt().
split; first exact hl'.
split; first by rewrite hix' hix div2S.
split; first by rewrite hai' hai div2S.
split; first by rewrite hs' hs gsib_div2 ?divz_ge0 ?div2S //; smt(StdOrder.IntOrder.expr_gt0).
split.
+ rewrite hn' hc' hzv hai' hai -div2S // (base_div base i t (to_uint z + 1)) 1:/# //.
  rewrite (tree_adrs_eq _ na) ?BArray32.size_to_list //.
  rewrite (hN (to_uint z) (i %/ 2 ^ (to_uint z + 1))) 1:/#.
  + by rewrite divz_ge0; [apply StdOrder.IntOrder.expr_gt0 | smt()].
  by rewrite (hfs (to_uint z) _ hb) 1:/# hx hq; congr; smt().
split; first by rewrite hc' tree_adrs_take ?BArray32.size_to_list.
by rewrite addz0.
qed.

(* Parking the node of the lowest zero bit completes leaf i. *)
lemma fmid_park N na t base i tg (nd0 auth : FoldBuf.t) node cur (z idx aidx sib : W32.t) :
  0 <= t <= P.`a => fs N nd0 t i => fmid N na t base i tg auth node cur z idx aidx sib 1 =>
  !(to_uint idx %% 2 <> 0) =>
  fs N (FoldNode.set_sub nd0 (to_uint z * P.`n) node) t (i + 1) /\ au N auth t (i + 1) tg /\
  take 24 (BArray32.to_list cur) = take 24 na.
proof.
move=> [ht0 hta] hfs; rewrite /fmid => [#] hz0 hz1 hl hix hai hs hx h24 h hodd.
have hb : (i %/ 2 ^ to_uint z) %% 2 = 0 by rewrite -hix; smt().
split; first by apply (park_fs N nd0 node t i (to_uint z)) => //.
by split => //; apply (park_au N auth t i tg (to_uint z)).
qed.

(* ------------------------------------------------------------------ *)
(* _treehash_fold                                                     *)

lemma fmid_le N na t base i tg auth node cur (z idx aidx sib : W32.t) k :
  t <= P.`a => fmid N na t base i tg auth node cur z idx aidx sib k => to_uint z <= P.`a.
proof. by move=> ht; rewrite /fmid => /#. qed.

lemma treehash_fold_h (pk : bytes) c0 (N : int -> int -> bytes) (na : adrs) (base t : int) :
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     hoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)]) =>
  (forall z j, 0 <= z < t => 0 <= j =>
     N (z + 1) j = H P pk (setTreeIndex (setTreeHeight na (z + 1)) (base %/ 2 ^ (z + 1) + j))
                         (N z (2 * j) ++ N z (2 * j + 1))) =>
  0 <= t <= P.`a => 2 ^ t %| base =>
  forall (nd0 au0 : FoldBuf.t) (x0 : Node.t) (id0 ai0 tg0 : W32.t) (na0 : BArray32.t),
  hoare [M._treehash_fold :
    nodes = nd0 /\ auth = au0 /\ node = x0 /\ idx = id0 /\ adrs_idx = ai0 /\ target = tg0 /\
    ctx = c0 /\ node_adrs = na0 /\
    to_uint id0 < 2 ^ t /\ to_uint ai0 = base + to_uint id0 /\
    Node.to_list x0 = N 0 (to_uint id0) /\ take 24 (BArray32.to_list na0) = take 24 na /\
    fs N nd0 t (to_uint id0) /\ au N au0 t (to_uint id0) (to_uint tg0) ==>
    fs N res.`1 t (to_uint id0 + 1) /\ au N res.`2 t (to_uint id0 + 1) (to_uint tg0) /\
    take 24 (BArray32.to_list res.`4) = take 24 na].
proof.
move=> hh hN ht hbd nd0 au0 x0 id0 ai0 tg0 na0.
have hi0 := W32.to_uint_cmp id0; have htg := W32.to_uint_cmp tg0.
have [ht0 hta] := ht.
proc.
seq 5 : (nodes = nd0 /\ ctx = c0 /\ to_uint id0 < 2 ^ t /\ fs N nd0 t (to_uint id0) /\
         fmid N na t base (to_uint id0) (to_uint tg0) auth node node_adrs z idx adrs_idx sib 0 /\
         (found <=> idx = sib)).
+ wp; skip => &m [#] -> -> -> -> -> -> -> -> hlt hai hx hna hfs hau /=.
  by rewrite hlt hfs /=; apply fmid0.
seq 4 : (nodes = nd0 /\ ctx = c0 /\ to_uint id0 < 2 ^ t /\ fs N nd0 t (to_uint id0) /\
         fmid N na t base (to_uint id0) (to_uint tg0) auth node node_adrs z idx adrs_idx sib 1 /\
         odd = (to_uint idx %% 2 <> 0)).
+ if.
  + wp; ecall (node_copy_h node); ecall (fold_slot_h z); wp; skip => &m [#] -> -> hlt hfs hm hq hc /=.
    split; first exact (fmid_le _ _ _ _ _ _ _ _ _ _ _ _ _ _ hta hm).
    move=> _ r hr r' ->; rewrite hlt hfs hr odd_bit /=.
    by apply fmid_found => //; rewrite -hq.
  wp; skip => &m [#] -> -> hlt hfs hm hq hc /=.
  rewrite hlt hfs odd_bit /=.
  by apply fmid_skip => //; rewrite -hq.
wp; ecall (node_copy_h node); ecall (fold_slot_h z); wp.
while (nodes = nd0 /\ ctx = c0 /\ to_uint id0 < 2 ^ t /\ fs N nd0 t (to_uint id0) /\
       fmid N na t base (to_uint id0) (to_uint tg0) auth node node_adrs z idx adrs_idx sib 1 /\
       odd = (to_uint idx %% 2 <> 0)).
+ seq 22 : (nodes = nd0 /\ ctx = c0 /\ to_uint id0 < 2 ^ t /\ fs N nd0 t (to_uint id0) /\
            fmid N na t base (to_uint id0) (to_uint tg0) auth node node_adrs z idx adrs_idx sib 0).
  + wp; ecall (hh pair node_adrs); wp; ecall (index_h node_adrs adrs_idx).
    ecall (height_h node_adrs z); wp; ecall (node_copy_h node); wp.
    ecall (node_copy_h (FoldNode.get_sub nodes (to_uint off))); ecall (fold_slot_h z); wp.
    skip => &m [#] -> -> hlt hfs hm hodd hg /=.
    split; first exact (fmid_le _ _ _ _ _ _ _ _ _ _ _ _ _ _ hta hm).
    move=> _ r hr r1 -> r2 -> a1 ha1 a2 ha2 x hx; rewrite hlt hfs /=.
    apply (fmid_climb pk N na t base (to_uint id0) (to_uint tg0) nd0 auth{m} node{m} _
             node_adrs{m} _ z{m} idx{m} adrs_idx{m} sib{m} _ _ _ _ hN ht hbd _ _ hfs hm).
    + by move: hi0 hlt => /#.
    + by move: htg => /#.
    + by rewrite -hodd.
    + done.
    + exact shr1.
    + exact shr1.
    + by rewrite xor1 shr1.
    + by rewrite ha2 ha1.
    by rewrite hx (pair_cat _ _ _ _ n_val) /slot hr.
  sp; if.
  + wp; ecall (node_copy_h node); ecall (fold_slot_h z); wp; skip => &m [#] -> -> -> hlt hfs hm hc /=.
    split; first exact (fmid_le _ _ _ _ _ _ _ _ _ _ _ _ _ _ hta hm).
    move=> _ r hr r' ->; rewrite hlt hfs hr odd_bit /=.
    by apply fmid_found.
  wp; skip => &m [#] -> -> -> hlt hfs hm hc /=.
  rewrite hlt hfs odd_bit /=.
  by apply fmid_skip.
skip => &m [#] -> -> hlt hfs hm hodd /=.
rewrite hlt hfs hm hodd /=.
move=> ai1 au1 c1 i1 x1 a1 n1 o1 s1 z1 ho [#] -> _ hm1 ho1.
split; first exact (fmid_le _ _ _ _ _ _ _ _ _ _ _ _ _ _ hta hm1).
move=> _ r hr r' ->; rewrite hr.
by apply (fmid_park N na t base (to_uint id0) (to_uint tg0) nd0 au1 x1 a1 z1 i1 ai1 s1) => //; rewrite -ho1.
qed.

lemma half_lt (x : int) : 0 <= x => x %% 2 <> 0 => x %/ 2 < x.
proof. by move=> h0 h; have := divz_eq x 2; smt(modz_ge0). qed.

(* The climb ends: idx halves at every step and the loop runs while it
   is odd, so to_uint idx is a variant. *)
lemma treehash_fold_ll c0 :
  phoare [M._thash_h : ctx = c0 ==> true] = 1%r =>
  phoare [M._treehash_fold : ctx = c0 ==> true] = 1%r.
proof.
move=> hhl; proc.
wp; call node_copy_ll; call fold_slot_ll; wp.
while (ctx = c0 /\ odd = (to_uint idx %% 2 <> 0)) (to_uint idx).
+ move=> v; seq 23 : (ctx = c0 /\ to_uint idx < v) 1%r 1%r 0%r _.
  + wp; call (_ : ctx = c0 ==> true); first by conseq hhl.
    call (_ : true ==> true); first by conseq set_tree_index_ll.
    call (_ : true ==> true); first by conseq set_tree_height_ll.
    wp; call (_ : true ==> true); first by conseq node_copy_ll.
    wp; call (_ : true ==> true); first by conseq node_copy_ll.
    call (_ : true ==> true); first by conseq fold_slot_ll.
    by wp; skip => &m [#] -> *.
  + wp; call hhl; call set_tree_index_ll; call set_tree_height_ll; wp.
    call node_copy_ll; wp; call node_copy_ll; call fold_slot_ll; wp.
    skip => &m [#] -> ho hg hv /=; rewrite shr1 -hv.
    by move: hg; rewrite ho => h; apply half_lt => //; smt(W32.to_uint_cmp).
  + if.
    + wp; call node_copy_ll; call fold_slot_ll; wp; skip => &m [#] -> hv _ /=.
      by rewrite odd_bit.
    by wp; skip => &m [#] -> hv _ /=; rewrite odd_bit.
  + hoare; wp.
    call (_ : ctx = c0 ==> true); first by conseq hhl.
    call (_ : true ==> true); first by conseq set_tree_index_ll.
    call (_ : true ==> true); first by conseq set_tree_height_ll.
    wp; call (_ : true ==> true); first by conseq node_copy_ll.
    wp; call (_ : true ==> true); first by conseq node_copy_ll.
    call (_ : true ==> true); first by conseq fold_slot_ll.
    wp; skip => &m [#] -> ho hg hv /=; rewrite shr1 -hv.
    by move: hg; rewrite ho => h; apply half_lt => //; smt(W32.to_uint_cmp).
  by move=> &hr.
sp; if.
+ wp; call node_copy_ll; call fold_slot_ll; wp; skip => &m /> *.
  by rewrite odd_bit /=; smt(W32.to_uint_cmp).
by wp; skip => &m /> *; rewrite odd_bit /=; smt(W32.to_uint_cmp).
qed.

(* ------------------------------------------------------------------ *)
(* _treehash_fold: total correctness                                  *)

lemma treehash_fold_correct (pk : bytes) c0 (N : int -> int -> bytes) (na : adrs) (base t : int) :
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall z j, 0 <= z < t => 0 <= j =>
     N (z + 1) j = H P pk (setTreeIndex (setTreeHeight na (z + 1)) (base %/ 2 ^ (z + 1) + j))
                         (N z (2 * j) ++ N z (2 * j + 1))) =>
  0 <= t <= P.`a => 2 ^ t %| base =>
  forall (nd0 au0 : FoldBuf.t) (x0 : Node.t) (id0 ai0 tg0 : W32.t) (na0 : BArray32.t),
  phoare [M._treehash_fold :
    nodes = nd0 /\ auth = au0 /\ node = x0 /\ idx = id0 /\ adrs_idx = ai0 /\ target = tg0 /\
    ctx = c0 /\ node_adrs = na0 /\
    to_uint id0 < 2 ^ t /\ to_uint ai0 = base + to_uint id0 /\
    Node.to_list x0 = N 0 (to_uint id0) /\ take 24 (BArray32.to_list na0) = take 24 na /\
    fs N nd0 t (to_uint id0) /\ au N au0 t (to_uint id0) (to_uint tg0) ==>
    fs N res.`1 t (to_uint id0 + 1) /\ au N res.`2 t (to_uint id0 + 1) (to_uint tg0) /\
    take 24 (BArray32.to_list res.`4) = take 24 na] = 1%r.
proof.
move=> hh hN ht hbd nd0 au0 x0 id0 ai0 tg0 na0.
have hhl : phoare [M._thash_h : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (hh x1 a1); auto.
have hh' : forall (x1 : Node2.t) (a1 : BArray32.t),
  hoare [M._thash_h : in_0 = x1 /\ ctx = c0 /\ adrs = a1 ==>
    Node.to_list res.`1 = H P pk (BArray32.to_list a1) (Node2.to_list x1)].
+ by move=> x1 a1; conseq (hh x1 a1).
by conseq (treehash_fold_ll c0 hhl) (treehash_fold_h pk c0 N na base t hh' hN ht hbd nd0 au0 x0 id0 ai0 tg0 na0).
qed.
