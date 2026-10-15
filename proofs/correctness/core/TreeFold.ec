(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TreeFold.ec
 * ===========
 *
 * Facts shared by the XMSS and FORS tree proofs: the TREE address
 * setters on this set's model, addresses as mk_adrs records, the 2n-byte
 * pair a node hash reads, and the 32-bit index arithmetic of the climbs.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash.
require import BArray32.
require import SetModel CoreExtracted Wots WotsPk.
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
