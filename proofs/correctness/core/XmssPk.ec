(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * XmssPk.ec
 * =========
 *
 * XMSS verification of src/slhdsa/xmss.jinc: _xmss_pk_from_sig computes
 * xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS) of FIPS 205
 * Algorithm 11.
 *
 * Climb. The code starts from the WOTS+ public key of key pair idx and,
 * at height k, hashes the current node with AUTH[k] under the TREE
 * address of height k + 1 and index idx >> (k + 1), the current node on
 * the left when bit k of idx is 0. The spec's loop writes the same
 * address through getTreeIndex (lines 11 and 14), which TreeForms reduces
 * to the same index (xmss_pkFromSigE): both are gfold of the node hash
 * over the authentication path, and the loop invariant is that gfold
 * after k steps.
 *
 * Addresses. Every 32-byte ADRS is an mk_adrs record (adrs_mk), so the
 * caller's address is mk_adrs l t y w2 w1 w0 and the TREE address of the
 * code is mk_adrs l t TREE 0 z i after its two setters.
 *
 * Hash premises. F and T_l for the WOTS+ public key (as in WotsPk.ec) and
 * H for the climb enter as hypotheses for one fixed PK.seed pk and ctx
 * c0, in the shape of the per-family thash theorems.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorem:
 *     xmss_pk_from_sig_correct   given the F, T_l and H premises,
 *                                _xmss_pk_from_sig returns
 *                                xmss_pkFromSig(idx, sig, msg, pk, adrs);
 *                                total correctness.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_WOTS FIPS205_XMSS.
require import MerkleTrees_FIPS205 FIPS205_TreeForms.
require import BArray32.
require import SetModel CoreExtracted Wots Encoding WotsChain WotsPk TreeFold.

(* ------------------------------------------------------------------ *)
(* The two parts of SIG_XMSS                                          *)

lemma xsig_size : XmssSig.size = (len P + P.`hp) * P.`n.
proof. by rewrite /len len1_val len2_val n_val hp_val. qed.

lemma wsig_slice (s : XmssSig.t) :
  TLenIn.to_list (XmssSigWots.get_sub s 0) = slice (XmssSig.to_list s) 0 (len P * P.`n).
proof.
have hn := n_val; have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have hs := xsig_size; have ht := tlen_size; have hh := hp_lt.
apply (eq_from_nth W8.zero).
+ rewrite TLenIn.size_to_list size_slice ?XmssSig.size_to_list ?hs ?ht //.
  by move: hh; rewrite hl hn => /#.
rewrite TLenIn.size_to_list => k hk; rewrite TLenIn.get_to_list XmssSigWots.get8_get_sub.
rewrite /slice drop0 nth_take; 1,2: smt().
by rewrite XmssSig.get_to_list; smt().
qed.

lemma auth_slot (s : XmssSig.t) k : 0 <= k < P.`hp =>
  Node.to_list (XmssSigNode.get_sub s (len P * P.`n + k * P.`n)) =
  slice (slice (XmssSig.to_list s) (len P * P.`n) ((len P + P.`hp) * P.`n)) (k * P.`n) ((k + 1) * P.`n).
proof.
move=> hk; have hn := n_val; have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have hs := xsig_size.
have hsz : size (XmssSig.to_list s) = (len P + P.`hp) * P.`n by rewrite XmssSig.size_to_list /len len1_val len2_val n_val hp_val.
apply (eq_from_nth W8.zero).
+ have h1 : size (slice (XmssSig.to_list s) (len P * P.`n) ((len P + P.`hp) * P.`n)) = P.`hp * P.`n.
  + by rewrite size_slice; smt().
  by rewrite Node.size_to_list size_slice ?h1; smt().
rewrite Node.size_to_list => j hj; rewrite Node.get_to_list XmssSigNode.get8_get_sub.
rewrite ifT 1:/# /slice nth_take; 1,2: smt().
rewrite nth_drop; 1,2: smt(); rewrite nth_take; 1,2: smt().
rewrite nth_drop; 1,2: smt().
by rewrite XmssSig.get_to_list; congr; ring.
qed.

(* The byte offset of AUTH[k], as the code computes it. *)
lemma auth_off (k : W32.t) c d : P.`n = c => d = len P * P.`n => to_uint k < P.`hp =>
  to_uint (zeroextu64 k * W64.of_int c + W64.of_int d) = len P * P.`n + to_uint k * P.`n.
proof.
move=> hc hd hk; have hn := n_val; have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have hh := hp_lt; have h0 := W32.to_uint_cmp k.
have hm : to_uint (zeroextu64 k * W64.of_int c) = to_uint k * P.`n.
+ by rewrite W64.to_uintM_small zext64E W64.of_uintK -hc hn /= //; smt().
have hd' : to_uint (W64.of_int d) = len P * P.`n.
+ by rewrite W64.of_uintK hd modz_small //; smt().
by rewrite W64.to_uintD_small hm hd'; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Termination                                                        *)

lemma xmss_pk_from_sig_ll (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall (m0 : TLenIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_len : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TLenIn.to_list m0)] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  phoare [M._xmss_pk_from_sig : ctx = c0 ==> true] = 1%r.
proof.
move=> hf htl hh.
have hwl : phoare [M._wots_pk_from_sig : ctx = c0 ==> true] = 1%r.
+ proc*; exlim sig, msg, adrs, keypair => s1 m1 a1 k1.
  by call (wots_pk_from_sig_correct pk_seed c0 hf htl s1 m1 a1 k1); auto.
have hhl : phoare [M._thash_h : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (hh x1 a1); auto.
have hp := hp_lt.
proc; call node_copy_ll; wp.
while (ctx = c0 /\ 0 <= to_uint k <= P.`hp /\ more = (to_uint k < P.`hp)) (P.`hp - to_uint k).
+ move=> z; wp; call hhl; wp; call set_tree_index_ll; call set_tree_height_ll; wp.
  inline M.__offset; sp.
  if; (wp; call node_copy_ll; wp; call node_copy_ll; wp; skip => &m /> hk0 hk1 hmo hm *).
  + have e := inc32 k{m} P.`hp _ _; 1,2: smt().
    by rewrite (ult_c _ _ _ hp_val) 1:/# e /#.
  have e := inc32 k{m} P.`hp _ _; 1,2: smt().
  by rewrite (ult_c _ _ _ hp_val) 1:/# e /#.
wp; call hwl; wp; call set_tc_ll; call copy_ll; auto => &m hc /=.
by rewrite hc /=; smt().
qed.

(* ------------------------------------------------------------------ *)
(* The climb                                                          *)

op auth_of (s : XmssSig.t) (k : int) : bytes =
  slice (slice (XmssSig.to_list s) (len P * P.`n) ((len P + P.`hp) * P.`n)) (k * P.`n) ((k + 1) * P.`n).

(* The WOTS+ public key the climb starts from (Algorithm 11, line 5). *)
op xnode0 (pk : bytes) (l t : int) (s : XmssSig.t) (m : Node.t) (i : int) : bytes =
  wots_pkFromSig P (slice (XmssSig.to_list s) 0 (len P * P.`n)) (Node.to_list m) pk
    (mk_adrs l t WOTS_HASH i 0 0).

lemma xmss_pk_from_sig_h (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall (m0 : TLenIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_len : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TLenIn.to_list m0)] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     hoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)]) =>
  forall (s0 : XmssSig.t) (m0 : Node.t) (a0 : BArray32.t) (i0 : W32.t) l t y w2 w1 w0,
  BArray32.to_list a0 = mk_adrs l t y w2 w1 w0 =>
  hoare [M._xmss_pk_from_sig :
    sig = s0 /\ msg = m0 /\ ctx = c0 /\ adrs = a0 /\ idx = i0 ==>
    Node.to_list res.`1 =
      gfold (xmss_hash P pk_seed l t) (auth_of s0) (to_uint i0)
        (xnode0 pk_seed l t s0 m0 (to_uint i0)) P.`hp].
proof.
move=> hf htl hh s0 m0 a0 i0 l t y w2 w1 w0 hA.
have hw : forall s1 m1 a1 k1, hoare [M._wots_pk_from_sig :
    sig = s1 /\ msg = m1 /\ ctx = c0 /\ adrs = a1 /\ keypair = k1 ==>
    Node.to_list res.`1 = wots_pkFromSig P (TLenIn.to_list s1) (Node.to_list m1) pk_seed
      (setKeyPairAddress (setTypeAndClear (BArray32.to_list a1) WOTS_HASH) (to_uint k1))].
+ by move=> s1 m1 a1 k1; conseq (wots_pk_from_sig_correct pk_seed c0 hf htl s1 m1 a1 k1).
have hp := hp_lt.
proc.
ecall (node_copy_h node); wp.
while (sig = s0 /\ ctx = c0 /\ 0 <= to_uint k <= P.`hp /\ more = (to_uint k < P.`hp) /\
       to_uint idx = to_uint i0 %/ 2 ^ to_uint k /\
       (exists w1' w0', BArray32.to_list tree_adrs = mk_adrs l t TREE 0 w1' w0') /\
       Node.to_list node = gfold (xmss_hash P pk_seed l t) (auth_of s0) (to_uint i0)
                             (xnode0 pk_seed l t s0 m0 (to_uint i0)) (to_uint k)).
+ wp; ecall (hh pair tree_adrs); wp; ecall (index_h tree_adrs idx); ecall (height_h tree_adrs k); wp.
  inline M.__offset; sp; if.
  + wp; ecall (node_copy_h node); wp; ecall (node_copy_h (XmssSigNode.get_sub sig (to_uint off))).
    wp; skip => &m /> hc hk0 hk1 hidx w1' w0' hta hnode hk hodd r1 hr1 r2 hr2 r3 hr3.
    have e := inc32 k{m} P.`hp _ _; 1,2: smt().
    have hb : to_uint idx{m} %% 2 <> 0 by rewrite -odd_bit.
    have hd := div2S (to_uint i0) (to_uint k{m}) _; 1: smt().
    have hi : to_uint (idx{m} `>>` W8.one) = to_uint i0 %/ 2 ^ (to_uint k{m} + 1) by rewrite shr1 hidx hd.
    have ha2 : BArray32.to_list r2 = mk_adrs l t TREE 0 (to_uint k{m} + 1) (to_uint i0 %/ 2 ^ (to_uint k{m} + 1)).
    + by rewrite hr2 hr1 hta setChainAddressE setHashAddressE e hi.
    rewrite (ult_c _ _ _ hp_val) 1:/# e hi /=.
    split; first smt().
    split; first by exists (to_uint k{m} + 1) (to_uint i0 %/ 2 ^ (to_uint k{m} + 1)).
    rewrite hr3 ha2 (pair_cat _ _ _ _ n_val) (auth_off k{m} _ _ n_val _) //.
    + by rewrite /len len1_val len2_val n_val.
    rewrite (auth_slot sig{m} (to_uint k{m})) 1:/# gfoldS 1:/# /= -hidx hb /=.
    by rewrite /xmss_hash hnode.
  wp; ecall (node_copy_h (XmssSigNode.get_sub sig (to_uint off))); wp; ecall (node_copy_h node).
  wp; skip => &m /> hc hk0 hk1 hidx w1' w0' hta hnode hk hodd r1 hr1 r2 hr2 r3 hr3.
  have e := inc32 k{m} P.`hp _ _; 1,2: smt().
  have hb : to_uint idx{m} %% 2 = 0 by move: hodd; rewrite odd_bit.
  have hd := div2S (to_uint i0) (to_uint k{m}) _; 1: smt().
  have hi : to_uint (idx{m} `>>` W8.one) = to_uint i0 %/ 2 ^ (to_uint k{m} + 1) by rewrite shr1 hidx hd.
  have ha2 : BArray32.to_list r2 = mk_adrs l t TREE 0 (to_uint k{m} + 1) (to_uint i0 %/ 2 ^ (to_uint k{m} + 1)).
  + by rewrite hr2 hr1 hta setChainAddressE setHashAddressE e hi.
  rewrite (ult_c _ _ _ hp_val) 1:/# e hi /=.
  split; first smt().
  split; first by exists (to_uint k{m} + 1) (to_uint i0 %/ 2 ^ (to_uint k{m} + 1)).
  rewrite hr3 ha2 (pair_cat _ _ _ _ n_val) (auth_off k{m} _ _ n_val _) //.
  + by rewrite /len len1_val len2_val n_val.
  rewrite (auth_slot sig{m} (to_uint k{m})) 1:/# gfoldS 1:/# /= -hidx hb /=.
  by rewrite /xmss_hash hnode.
wp; ecall (hw (XmssSigWots.get_sub sig 0) msg adrs kp); wp.
ecall (tc2_h tree_adrs); ecall (copy_hh tree_adrs adrs); wp; skip => &m /> r0 hr0 r1 hr1 r2 hr2.
split.
+ split; first by exists 0 0; rewrite hr1 hr0 hA setTypeAndClearE.
  by rewrite /gfold range_geq // hr2 /xnode0 wsig_slice hA setTypeAndClearE setKeyPairAddressE.
move=> idx1 k1 more1 node1 ta1 hm hk0 hk1 hlt _ w1' w0' _ ->.
by congr; smt().
qed.

(* ------------------------------------------------------------------ *)
(* _xmss_pk_from_sig (Algorithm 11)                                   *)

lemma xmss_pk_from_sig_correct (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall (m0 : TLenIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_len : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TLenIn.to_list m0)] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  forall (s0 : XmssSig.t) (m0 : Node.t) (a0 : BArray32.t) (i0 : W32.t),
  phoare [M._xmss_pk_from_sig :
    sig = s0 /\ msg = m0 /\ ctx = c0 /\ adrs = a0 /\ idx = i0 ==>
    Node.to_list res.`1 =
      xmss_pkFromSig P (to_uint i0) (XmssSig.to_list s0) (Node.to_list m0) pk_seed
        (BArray32.to_list a0)] = 1%r.
proof.
move=> hf htl hh s0 m0 a0 i0.
have [l t y w2 w1 w0 hA] := adrs_mkP (BArray32.to_list a0) (ADRS.size_bytes_of a0).
have hh' : forall (x1 : Node2.t) (a1 : BArray32.t),
  hoare [M._thash_h : in_0 = x1 /\ ctx = c0 /\ adrs = a1 ==>
    Node.to_list res.`1 = H P pk_seed (BArray32.to_list a1) (Node2.to_list x1)].
+ by move=> x1 a1; conseq (hh x1 a1).
have hi := W32.to_uint_cmp i0; have hp := hp_lt.
have h32 : 0 <= to_uint i0 < 2 ^ 32 by move: hi; rewrite m32.
have h : hoare [M._xmss_pk_from_sig :
    sig = s0 /\ msg = m0 /\ ctx = c0 /\ adrs = a0 /\ idx = i0 ==>
    Node.to_list res.`1 =
      xmss_pkFromSig P (to_uint i0) (XmssSig.to_list s0) (Node.to_list m0) pk_seed
        (BArray32.to_list a0)].
+ conseq (xmss_pk_from_sig_h pk_seed c0 hf htl hh' s0 m0 a0 i0 l t y w2 w1 w0 hA) => //.
  move=> &hr _ r ->; rewrite hA xmss_pkFromSigE ?h32 1:/#.
  by rewrite /auth_of /xnode0.
by conseq (xmss_pk_from_sig_ll pk_seed c0 hf htl hh) h.
qed.
