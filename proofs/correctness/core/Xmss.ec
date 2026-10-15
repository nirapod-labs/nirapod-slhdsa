(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Xmss.ec
 * =======
 *
 * XMSS signing of src/slhdsa/xmss.jinc: one pass of _xmss_treehash
 * computes xmss_node(SK.seed, 0, h', PK.seed, ADRS) of FIPS 205
 * Algorithm 9 and, for a target leaf below 2^h', the signature
 * xmss_sign(M, SK.seed, target, PK.seed, ADRS) of Algorithm 10.
 *
 * Tree. TreeForms writes Algorithm 9 as gnode over the leaf function
 * xmss_leaf (the WOTS+ public key of a key pair) and the node hash
 * xmss_hash, under the caller's address mk_adrs l t y w2 w1 w0. That is
 * the tree N of the fold theorem (TreeFold.ec) with base 0 and the TREE
 * address of the code, so the fold invariant at leaf i carries the
 * pending left nodes and the authentication nodes completed so far.
 *
 * Loop. The code visits the leaves four at a time: _wots_leaf_x4 returns
 * the public keys of key pairs i .. i + 3 and, when the target is among
 * them, the WOTS+ signature of the target. The outer invariant at i
 * (4 | i) is the fold invariant at leaf i plus the signature once the
 * target is below i. At i = 2^h' the fold invariant gives the root in
 * slot h' and AUTH[z] in slot z of auth, which the code copies out.
 *
 * Hash premises. PRF, F and T_l in their four-way forms (as in
 * WotsLeaf.ec) and H, for one fixed PK.seed pk and ctx c0.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorems:
 *     xmss_node_correct   _xmss_treehash returns the root of the tree,
 *                         xmss_node(SK.seed, 0, h', PK.seed, ADRS);
 *                         total correctness.
 *     xmss_sign_correct   for a target below 2^h' and digits of M, it
 *                         also returns xmss_sign(M, SK.seed, target,
 *                         PK.seed, ADRS); total correctness.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_WOTS FIPS205_XMSS.
require import MerkleTrees_FIPS205 FIPS205_TreeForms.
require import BArray32 BArray128.
require import SetModel CoreExtracted Wots Encoding WotsChain WotsPk WotsLeaf TreeFold XmssPk.

(* ------------------------------------------------------------------ *)
(* The tree of Algorithm 9                                            *)

op xn (pk sk : bytes) (l t : int) (z j : int) : bytes =
  gnode (xmss_leaf P sk pk l t) (xmss_hash P pk l t) (hts z) j.

(* The WOTS+ signature that _wots_leaf_x4 returns for key pair kp and
   digits D (Algorithm 7, lines 8 to 15). *)
op wsg (pk sk : bytes) (a : adrs) (kp : int) (D : int list) : bytes =
  flatten (map (fun i => cend pk sk a kp (nth 0 D i) i) (range 0 (len P))).

lemma xn0 pk sk l t y w2 w1 w0 j :
  xn pk sk l t 0 j = wots_pkGen P sk pk (adA (mk_adrs l t y w2 w1 w0) WOTS_HASH j).
proof. by rewrite /xn hts0 /= /xmss_leaf /adA setTypeAndClearE setKeyPairAddressE. qed.

lemma xnS pk sk l t : forall z j, 0 <= z < P.`hp => 0 <= j =>
  xn pk sk l t (z + 1) j =
  H P pk (setTreeIndex (setTreeHeight (mk_adrs l t TREE 0 0 0) (z + 1)) (0 %/ 2 ^ (z + 1) + j))
    (xn pk sk l t z (2 * j) ++ xn pk sk l t z (2 * j + 1)).
proof.
move=> z j hz hj; rewrite /xn htsS 1:/# /= /xmss_hash ?div0z /=.
by rewrite setChainAddressE setHashAddressE.
qed.

lemma xmss_nodeX pk sk l t y w2 w1 w0 z j :
  xmss_node P sk j z pk (mk_adrs l t y w2 w1 w0) = xn pk sk l t z j.
proof. by rewrite xmss_nodeE. qed.

lemma wots_signE (msg sk pk : bytes) (a : adrs) kp : size a = 32 => 0 <= kp < 2 ^ 32 =>
  wots_sign P msg sk pk (adA a WOTS_HASH kp) = wsg pk sk a kp (wots_digits P msg).
proof. by move=> ha hk; rewrite /wots_sign /= /adA !pk_adrsE. qed.

(* ------------------------------------------------------------------ *)
(* Index facts                                                        *)

lemma hp_ge3 : 3 <= P.`hp by rewrite hp_val.
lemma hp_le_a : P.`hp <= P.`a by rewrite hp_val a_val.

lemma pow_hp_lt : 2 ^ P.`hp < 2 ^ 32 by rewrite hp_val.
lemma pow_hp_b : 2 ^ P.`hp <= 512 by rewrite hp_val.

lemma four_dvd_pow : 4 %| 2 ^ P.`hp.
proof.
have h := hp_ge3; have -> : 2 ^ P.`hp = 2 ^ 2 * 2 ^ (P.`hp - 2) by rewrite -exprD_nneg 1,2:/#.
by apply dvdz_mulr.
qed.

lemma leaves_ult (x : W32.t) c : P.`hp = c =>
  (x \ult W32.of_int (1 `<<` c)) = (to_uint x < 2 ^ P.`hp).
proof.
move=> hc; rewrite -hc /(`<<`) ifT; 1: smt(hp_ge3).
by rewrite (ult_c x (2 ^ P.`hp) (2 ^ P.`hp)) //; smt(pow_hp_lt StdOrder.IntOrder.expr_gt0).
qed.

(* The lane of the target in the group i .. i + 3, or 4. *)
lemma lane_val (tg i : W32.t) : to_uint i + 4 <= 4294967296 =>
  to_uint (if (tg - i) \ult W32.of_int 4 then zeroextu64 (tg - i) else W64.of_int 4) =
  if to_uint i <= to_uint tg < to_uint i + 4 then to_uint tg - to_uint i else 4.
proof.
move=> hb; have hi := W32.to_uint_cmp i; have ht := W32.to_uint_cmp tg.
have hM : W32.modulus = 4294967296 by done.
move: hi ht; rewrite hM => hi ht.
have hd : to_uint (tg - i) = (to_uint tg - to_uint i) %% 4294967296.
+ by rewrite W32.to_uintD W32.to_uintN modzDmr hM.
rewrite (ult_c (tg - i) 4 4) // hd.
case: (to_uint i <= to_uint tg < to_uint i + 4) => h.
+ have e : (to_uint tg - to_uint i) %% 4294967296 = to_uint tg - to_uint i by rewrite modz_small; smt().
  by rewrite e ifT 1:/# zext64E hd e.
have h4 : 4 <= (to_uint tg - to_uint i) %% 4294967296.
+ case: (to_uint i <= to_uint tg) => h2; first by rewrite modz_small; smt().
  by rewrite -(modzDr (to_uint tg - to_uint i)) modz_small; smt().
by rewrite ifF; [rewrite -lezNgt | rewrite W64.of_uintK].
qed.

(* ------------------------------------------------------------------ *)
(* The fold state after the last leaf                                 *)

lemma fs_root N (b : FoldBuf.t) T : 0 <= T => fs N b T (2 ^ T) => slot b T = N T 0.
proof.
move=> hT h; have hp : 0 < 2 ^ T by apply StdOrder.IntOrder.expr_gt0.
have e : 2 ^ T %/ 2 ^ T = 1 by rewrite -{1}(mul1z (2 ^ T)) mulzK 1:/#.
by have := h T _ _; rewrite ?e //= /#.
qed.

lemma au_full N (b : FoldBuf.t) T tg z : 0 <= z < T => 0 <= tg < 2 ^ T => au N b T (2 ^ T) tg =>
  slot b z = N z (gsibling (tg %/ 2 ^ z)).
proof.
move=> hz htg h; apply h; first smt().
have hp : 0 < 2 ^ z by apply StdOrder.IntOrder.expr_gt0.
have e : 2 ^ T %/ 2 ^ z = 2 ^ (T - z) by rewrite (pow_split T z) 1:/# mulzK 1:/#.
rewrite e; have hx : tg %/ 2 ^ z < 2 ^ (T - z) by rewrite ltz_divLR // -(pow_split T z) /#.
have he := pow_even (T - z) _; 1: smt().
have hx0 : 0 <= tg %/ 2 ^ z by rewrite divz_ge0 // /#.
move: hx hx0 he; move: (tg %/ 2 ^ z) (2 ^ (T - z)) => x E hx hx0 he.
rewrite /gsibling; case: (x %% 2 = 0) => hb; last by smt().
have := divz_eq x 2; have := divz_eq E 2; rewrite hb he /=; smt().
qed.

lemma take_add (l : 'a list) o L : 0 <= o => 0 <= L => take (o + L) l = take o l ++ take L (drop o l).
proof.
move=> ho hL; rewrite -{1}(cat_take_drop o l) take_cat size_take //.
case: (o < size l) => h.
+ by rewrite ifF 1:/# (_ : o + L - o = L) 1:/#.
by rewrite ifF 1:/# drop_oversize 1:/#.
qed.

lemma slot_take (b : FoldBuf.t) m : 0 <= m <= P.`a =>
  slot b m = take P.`n (drop (m * P.`n) (FoldBuf.to_list b)).
proof.
move=> hm; have hn := n_val; have hs := fbuf_size.
have hsz : size (FoldBuf.to_list b) = (P.`a + 1) * P.`n by rewrite FoldBuf.size_to_list a_val n_val.
have hle : m * P.`n + P.`n <= (P.`a + 1) * P.`n.
+ have : m * P.`n <= P.`a * P.`n by apply StdOrder.IntOrder.ler_wpmul2r; smt().
  smt().
apply (eq_from_nth W8.zero).
+ by rewrite Node.size_to_list size_take 1:/# size_drop; smt().
rewrite Node.size_to_list => j hj; rewrite /slot Node.get_to_list FoldNode.get8_get_sub ifT 1:/#.
rewrite nth_take 1,2:/# nth_drop 1,2:/# FoldBuf.get_to_list; congr; ring.
qed.

lemma take_slots (b : FoldBuf.t) m : 0 <= m <= P.`a + 1 =>
  take (m * P.`n) (FoldBuf.to_list b) = flatten (map (slot b) (range 0 m)).
proof.
elim/natind: m => [m hm | m hm ih] hb.
+ have -> : m = 0 by smt().
  by rewrite range_geq //= take0 flatten_nil.
rewrite rangeSr 1:/# map_rcons flatten_rcons -ih 1:/#.
by rewrite (_ : (m + 1) * P.`n = m * P.`n + P.`n) 1:/# take_add 1,2:/# (slot_take b m) 1:/#.
qed.

(* SIG_XMSS as the code assembles it: the WOTS+ signature, then the
   first h' slots of auth. *)
lemma sig_join (s : XmssSig.t) (w : TLenIn.t) (b : FoldBuf.t) :
  (forall j, 0 <= j < len P * P.`n => XmssSig.get8 s j = TLenIn.get8 w j) =>
  (forall j, 0 <= j < P.`hp * P.`n => XmssSig.get8 s (len P * P.`n + j) = FoldBuf.get8 b j) =>
  XmssSig.to_list s = TLenIn.to_list w ++ take (P.`hp * P.`n) (FoldBuf.to_list b).
proof.
move=> h1 h2; have hs := xsig_size; have ht := tlen_size; have hf := fbuf_size.
have ha := hp_le_a; have hn := n_val.
have hb : P.`hp * P.`n <= (P.`a + 1) * P.`n.
+ by apply StdOrder.IntOrder.ler_wpmul2r; smt().
have hsz : size (XmssSig.to_list s) = (len P + P.`hp) * P.`n.
+ by rewrite XmssSig.size_to_list /len len1_val len2_val n_val hp_val.
have hsl : size (TLenIn.to_list w) = len P * P.`n.
+ by rewrite TLenIn.size_to_list /len len1_val len2_val n_val.
have hsb : size (FoldBuf.to_list b) = (P.`a + 1) * P.`n by rewrite FoldBuf.size_to_list a_val n_val.
apply (eq_from_nth W8.zero).
+ by rewrite size_cat hsz hsl size_take; smt().
rewrite hsz => j hj; rewrite XmssSig.get_to_list nth_cat hsl.
case: (j < len P * P.`n) => hjl.
+ by rewrite TLenIn.get_to_list h1 /#.
rewrite nth_take 1,2:/# FoldBuf.get_to_list -h2 1:/#; congr; ring.
qed.

(* ------------------------------------------------------------------ *)
(* Loop invariants of _xmss_treehash                                  *)

(* Before leaf i (4 | i): the fold invariant at i, the TREE address,
   and the target's WOTS+ signature once the target is below i. *)
op oinv (pk sk : bytes) (A : adrs) (l t tg : int) (D : int list) (i : int)
        (nodes auth : FoldBuf.t) (ta : BArray32.t) (ws : TLenIn.t) : bool =
  0 <= i <= 2 ^ P.`hp /\ 4 %| i /\
  fs (xn pk sk l t) nodes P.`hp i /\ au (xn pk sk l t) auth P.`hp i tg /\
  take 24 (BArray32.to_list ta) = take 24 (mk_adrs l t TREE 0 0 0) /\
  (tg < i => TLenIn.to_list ws = wsg pk sk A tg D).

(* Inside the group i .. i + 3, before leaf i + k: the four leaves are
   in lv, and the signature is there once the target is below i + 4. *)
op kinv (pk sk : bytes) (A : adrs) (l t tg : int) (D : int list) (i k : int)
        (nodes auth : FoldBuf.t) (ta : BArray32.t) (ws : TLenIn.t) (lv : Node4.t) : bool =
  0 <= k <= 4 /\ 0 <= i /\ i + 4 <= 2 ^ P.`hp /\ 4 %| i /\
  fs (xn pk sk l t) nodes P.`hp (i + k) /\ au (xn pk sk l t) auth P.`hp (i + k) tg /\
  take 24 (BArray32.to_list ta) = take 24 (mk_adrs l t TREE 0 0 0) /\
  (tg < i + 4 => TLenIn.to_list ws = wsg pk sk A tg D) /\
  (forall k', 0 <= k' < 4 => lane P.`n k' (Node4.to_list lv) = xn pk sk l t 0 (i + k')).

lemma gsib_ge0 x : 0 <= x => 0 <= gsibling x.
proof. by rewrite /gsibling; smt(modz_ge0). qed.

lemma oinv0 pk sk A l t tg D (nodes auth : FoldBuf.t) (ta : BArray32.t) ws : 0 <= tg =>
  take 24 (BArray32.to_list ta) = take 24 (mk_adrs l t TREE 0 0 0) =>
  oinv pk sk A l t tg D 0 nodes auth ta ws.
proof.
move=> htg h24; rewrite /oinv /fs /au h24 /=; split; first smt(StdOrder.IntOrder.expr_gt0).
split; first by apply dvdz0.
split; last smt().
move=> z hz hl; have := gsib_ge0 (tg %/ 2 ^ z) _; last smt().
by rewrite divz_ge0 // StdOrder.IntOrder.expr_gt0.
qed.

lemma oinv_kinv pk sk l t y w2 w1 w0 tg D i (nodes auth : FoldBuf.t) ta ws ws' (lv : Node4.t) L :
  oinv pk sk (mk_adrs l t y w2 w1 w0) l t tg D i nodes auth ta ws => i < 2 ^ P.`hp =>
  L = (if i <= tg < i + 4 then tg - i else 4) =>
  (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list lv) =
     wots_pkGen P sk pk (adA (mk_adrs l t y w2 w1 w0) WOTS_HASH (i + k))) =>
  (L < 4 => TLenIn.to_list ws' = wsg pk sk (mk_adrs l t y w2 w1 w0) (i + L) D) =>
  (4 <= L => ws' = ws) =>
  kinv pk sk (mk_adrs l t y w2 w1 w0) l t tg D i 0 nodes auth ta ws' lv.
proof.
rewrite /oinv /kinv => [#] hi0 hi1 hd hfs hau h24 hws hlt hL hlv hw1 hw2 /=.
have h4 : i + 4 <= 2 ^ P.`hp.
+ have /dvdzP [q hq] := hd; have /dvdzP [r hr] := four_dvd_pow.
  by move: hlt; rewrite hq hr => /#.
rewrite hi0 h4 hd hfs hau h24 /=.
split.
+ move=> htg; case: (i <= tg) => hle.
  + by rewrite hw1 1:/# hL ifT 1:/#; congr; ring.
  by rewrite hw2 1:/# hws /#.
by move=> k hk; rewrite hlv // (xn0 pk sk l t y w2 w1 w0).
qed.

lemma kinv_oinv pk sk A l t tg D i (nodes auth : FoldBuf.t) ta ws lv :
  kinv pk sk A l t tg D i 4 nodes auth ta ws lv => oinv pk sk A l t tg D (i + 4) nodes auth ta ws.
proof.
rewrite /oinv /kinv => [#] _ _ hi0 h4 hd hfs hau h24 hws _ /=.
by rewrite hfs hau h24 /=; smt(dvdzD dvdzz).
qed.

lemma node_lane (x : Node.t) (lv : Node4.t) k : 0 <= k < 4 =>
  (forall j, 0 <= j < P.`n => Node.get8 x j = Node4.get8 lv (P.`n * k + j)) =>
  Node.to_list x = lane P.`n k (Node4.to_list lv).
proof.
move=> hk h; have hn := n_val.
have hs : size (Node4.to_list lv) = 4 * P.`n by rewrite Node4.size_to_list hn.
apply (eq_from_nth W8.zero).
+ by rewrite Node.size_to_list lane_size 1,2:/#; smt().
rewrite Node.size_to_list => j hj; rewrite nth_lane 1..3:/# Node.get_to_list Node4.get_to_list.
by rewrite h /#.
qed.

lemma kinv_step pk sk A l t tg D i k (nodes auth : FoldBuf.t) ta ws lv (nodes' auth' : FoldBuf.t) (ta' : BArray32.t) :
  kinv pk sk A l t tg D i k nodes auth ta ws lv => k < 4 =>
  fs (xn pk sk l t) nodes' P.`hp (i + k + 1) => au (xn pk sk l t) auth' P.`hp (i + k + 1) tg =>
  take 24 (BArray32.to_list ta') = take 24 (mk_adrs l t TREE 0 0 0) =>
  kinv pk sk A l t tg D i (k + 1) nodes' auth' ta' ws lv.
proof.
rewrite /kinv => [#] hk0 hk1 hi0 h4 hd _ _ _ hws hlv hk hfs hau h24.
rewrite !addzA hfs hau h24 hi0 h4 hd /=.
by split; [smt() | split; [exact hws | exact hlv]].
qed.

(* ------------------------------------------------------------------ *)
(* The four-way leaf with its index bound in the precondition         *)

lemma wots_leaf_x4_hq (pk : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     hoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))]) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     hoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))]) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     hoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))]) =>
  forall (s0 : TLenIn.t) (k0 : Node.t) (a0 : BArray32.t) (q0 : W32.t) (st0 : WotsDigits.t)
         (ln0 : W64.t),
  hoare [M._wots_leaf_x4 :
    sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ kp0 = q0 /\ steps = st0 /\
    lane = ln0 /\ to_uint q0 + 3 < 2 ^ 32 /\
    (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) ==>
    (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
       wots_pkGen P (Node.to_list k0) pk (adA (BArray32.to_list a0) WOTS_HASH (to_uint q0 + k))) /\
    (to_uint ln0 < 4 => TLenIn.to_list res.`2 =
       flatten (map (fun i => cend pk (Node.to_list k0) (BArray32.to_list a0) (to_uint q0 + to_uint ln0)
                    (nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i) i) (range 0 (len P)))) /\
    (4 <= to_uint ln0 => res.`2 = s0)].
proof.
move=> hprf hf htl s0 k0 a0 q0 st0 ln0.
case: (to_uint q0 + 3 < 2 ^ 32) => hq.
+ by conseq (wots_leaf_x4_h pk c0 hprf hf htl s0 k0 a0 q0 st0 ln0 hq).
by conseq (_ : false ==> _); exfalso.
qed.

(* ------------------------------------------------------------------ *)
(* _xmss_treehash                                                     *)

lemma xmss_treehash_h (pk : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     hoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))]) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     hoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))]) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     hoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))]) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     hoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)]) =>
  forall (r0 : Node.t) (s0 : XmssSig.t) (k0 : Node.t) (a0 : BArray32.t) (tg0 : W32.t)
         (st0 : WotsDigits.t) l t y w2 w1 w0,
  BArray32.to_list a0 = mk_adrs l t y w2 w1 w0 =>
  hoare [M._xmss_treehash :
    root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
    steps = st0 /\
    (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) ==>
    Node.to_list res.`1 = xn pk (Node.to_list k0) l t P.`hp 0 /\
    (to_uint tg0 < 2 ^ P.`hp => XmssSig.to_list res.`2 =
       wsg pk (Node.to_list k0) (BArray32.to_list a0) (to_uint tg0)
         (map W8.to_uint (WotsDigits.to_list st0)) ++
       flatten (map (fun j => xn pk (Node.to_list k0) l t j (gsibling (to_uint tg0 %/ 2 ^ j)))
                    (range 0 P.`hp))) /\
    (2 ^ P.`hp <= to_uint tg0 => res.`2 = s0)].
proof.
move=> hprf hf htl hh r0 s0 k0 a0 tg0 st0 l t y w2 w1 w0 hA.
have hwl := wots_leaf_x4_hq pk c0 hprf hf htl.
have hfold := treehash_fold_h pk c0 (xn pk (Node.to_list k0) l t) (mk_adrs l t TREE 0 0 0) 0 P.`hp
                hh (xnS pk (Node.to_list k0) l t) _ (dvdz0 _).
+ smt(hp_le_a hp_ge3).
have htg := W32.to_uint_cmp tg0.
proc.
seq 18 : (root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
          steps = st0 /\ to_uint i = 2 ^ P.`hp /\
          oinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
            (map W8.to_uint (WotsDigits.to_list st0)) (to_uint i) nodes auth tree_adrs wsig).
+ while (root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
         steps = st0 /\
         (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) /\
         more = (to_uint i < 2 ^ P.`hp) /\
         oinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
           (map W8.to_uint (WotsDigits.to_list st0)) (to_uint i) nodes auth tree_adrs wsig).
  + exlim i => i0.
    wp; while (root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
               steps = st0 /\
               (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) /\
               i = i0 /\
               kinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
                 (map W8.to_uint (WotsDigits.to_list st0)) (to_uint i0) k nodes auth tree_adrs wsig
                 leaves).
    + wp; ecall (hfold nodes auth node li ai tg tree_adrs); wp.
      while (root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
             steps = st0 /\
             (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) /\
             i = i0 /\
             kinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
               (map W8.to_uint (WotsDigits.to_list st0)) (to_uint i0) k nodes auth tree_adrs wsig
               leaves /\ k < 4 /\
             0 <= w <= inc /\ inc = P.`n %/ 8 /\
             forall j, 0 <= j < 8 * w => Node.get8 node j = Node4.get8 leaves (P.`n * k + j)).
      + wp; skip => &m [#] -> -> -> -> -> -> -> hd -> hki hk hw0 hw1 hinc hj hlt /=.
        split; first exact hd. split; first exact hki. split; first exact hk.
        split; first smt(). split; first exact hinc.
        move=> j [hj0 hj1]; rewrite Node.get8_set64dE.
        case: (8 * w{m} <= j < 8 * w{m} + 8) => hr.
        + have -> /= : 0 <= j && j < Node.size by smt(n_val).
          by rewrite Node4.get64d_byte 1:/#; congr; smt(n_val).
        by rewrite hj /#.
      wp; skip => &m [#] -> -> -> -> -> -> -> hd -> hki hk /=.
      have hki2 := hki; rewrite /kinv in hki2.
      have [#] hk0 hk1 hi0 h4 hd4 hfs hau h24 hws hlv := hki2.
      split.
      + split; first exact hd. split; first exact hki. split; first exact hk.
        by split; smt(n_val).
      move=> x w3 hw [#] _ _ _ hw0 hw1 _ hj.
      have e : to_uint (i0 + W32.of_int k{m}) = to_uint i0 + k{m}.
      + by rewrite W32.to_uintD_small W32.of_uintK modz_small; 1..3: smt(pow_hp_b).
      have hx : Node.to_list x = xn pk (Node.to_list k0) l t 0 (to_uint i0 + k{m}).
      + rewrite (node_lane x leaves{m} k{m}) 1:/#.
        + by move=> j hj'; apply hj; smt(n_val).
        by apply hlv => /#.
      rewrite e hx h24 hfs hau /=; split; first smt().
      move=> _ r [#] hfs' hau' h24'; split; first exact hd.
      exact (kinv_step _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hki hk hfs' hau' h24').
    wp; ecall (hwl wsig sk_seed adrs kp steps lane); wp.
    skip => &m [#] <- -> -> -> -> -> -> -> hmo ho hg hm /=.
    have hlt : to_uint i0 < 2 ^ P.`hp by rewrite -ho.
    have hp32 := pow_hp_b.
    have hb4 : to_uint i0 + 4 <= 4294967296 by smt().
    split; first by split; [smt() | exact hmo].
    move=> _ [lv ws' ms'] /= [#] hlv hw1 hw2.
    rewrite (lane_val tg0 i0 hb4) in hw1; rewrite (lane_val tg0 i0 hb4) in hw2.
    move: hg hlv hw1; rewrite hA => hg hlv hw1.
    split.
    + split; first exact hmo.
      exact (oinv_kinv pk (Node.to_list k0) l t y w2 w1 w0 (to_uint tg0) _ (to_uint i0) _ _ _ _ ws' lv _
               hg hlt (eq_refl _) hlv hw1 hw2).
    move=> au1 c1 i1 k1 n1 tg1 ta1 hk [#] -> -> _ -> hki.
    have hk4 : k1 = 4 by move: hki hk; rewrite /kinv /#.
    move: hki; rewrite hk4 => hki.
    have e : to_uint (i0 + W32.of_int 4) = to_uint i0 + 4.
    + by rewrite W32.to_uintD_small W32.of_uintK /=; smt().
    rewrite (leaves_ult _ _ hp_val) e /=; split; first exact hmo.
    exact (kinv_oinv _ _ _ _ _ _ _ _ _ _ _ _ _ hki).
  wp; while (root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
             steps = st0 /\
             (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) /\
             BArray32.to_list tree_adrs = mk_adrs l t TREE 0 0 0).
  + by auto.
  wp; while (root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
             steps = st0 /\
             (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) /\
             BArray32.to_list tree_adrs = mk_adrs l t TREE 0 0 0).
  + by auto.
  wp; ecall (tc2_h tree_adrs); ecall (copy_hh tree_adrs adrs); wp.
  skip => &m [#] -> -> -> -> -> -> -> hd /= r1 hr1 r2 hr2.
  have ha2 : BArray32.to_list r2 = mk_adrs l t TREE 0 0 0 by rewrite hr2 hr1 hA setTypeAndClearE.
  split; first by split; [exact hd | exact ha2].
  move=> au0 _ nd _ _; split; first by split; [exact hd | exact ha2].
  move=> _ ws0 _ _; split.
  + split; first exact hd.
    have ho : oinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
                (map W8.to_uint (WotsDigits.to_list st0)) 0 nd au0 r2 ws0.
    + by apply oinv0; [smt() | rewrite ha2].
    by rewrite (leaves_ult _ _ hp_val) ho.
  move=> a1 au1 c1 i1 m1 n1 sk1 st1 tg1 ta1 ws1 hm [#] -> -> -> -> -> _ hmo ho /=.
  by split => //; move: hm; rewrite hmo; move: ho; rewrite /oinv /#.
seq 5 : (sig = s0 /\ target = tg0 /\ to_uint i = 2 ^ P.`hp /\
         oinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
            (map W8.to_uint (WotsDigits.to_list st0)) (to_uint i) nodes auth tree_adrs wsig /\
         Node.to_list root = xn pk (Node.to_list k0) l t P.`hp 0).
+ ecall (node_copy_h (FoldNode.get_sub nodes (P.`hp * P.`n))); wp.
  skip => &m [#] _ -> _ _ _ -> _ hi ho /=.
  split; first by rewrite hp_val n_val.
  move=> _ r ->; rewrite ho hi /=.
  have ho2 := ho; rewrite /oinv hi in ho2.
  have [#] _ _ _ hfs _ _ _ := ho2.
  exact (fs_root _ nodes{m} P.`hp _ hfs); smt(hp_ge3).
sp; if.
+ while (target = tg0 /\ to_uint tg0 < 2 ^ P.`hp /\ to_uint i = 2 ^ P.`hp /\
         oinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
            (map W8.to_uint (WotsDigits.to_list st0)) (to_uint i) nodes auth tree_adrs wsig /\
         Node.to_list root = xn pk (Node.to_list k0) l t P.`hp 0 /\
         0 <= k <= inc /\ inc = P.`hp * P.`n %/ 8 /\
         (forall j, 0 <= j < len P * P.`n => XmssSig.get8 sig j = TLenIn.get8 wsig j) /\
         (forall j, 0 <= j < 8 * k => XmssSig.get8 sig (len P * P.`n + j) = FoldBuf.get8 auth j)).
  + wp; skip => &m [#] -> htl0 hi ho hr hk0 hk1 hinc h1 h2 hlt /=.
    have hn := n_val; have hh0 := hp_val; have hs := xsig_size.
    have hlen : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
    rewrite htl0 ho hi hr /=; split; first smt().
    split; first exact hinc.
    split.
    + move=> j hj; rewrite XmssSig.get8_set64dE ifF; first smt().
      by apply h1.
    move=> j hj; rewrite XmssSig.get8_set64dE.
    case: (8 * k{m} <= j < 8 * k{m} + 8) => hr8.
    + rewrite ifT; first smt().
      by rewrite FoldBuf.get64d_byte 1:/#; congr; smt().
    by rewrite ifF; [smt() | apply h2; smt()].
  wp; while (target = tg0 /\ to_uint tg0 < 2 ^ P.`hp /\ to_uint i = 2 ^ P.`hp /\
             oinv pk (Node.to_list k0) (BArray32.to_list a0) l t (to_uint tg0)
            (map W8.to_uint (WotsDigits.to_list st0)) (to_uint i) nodes auth tree_adrs wsig /\
             Node.to_list root = xn pk (Node.to_list k0) l t P.`hp 0 /\
             0 <= k <= inc /\ inc = len P * P.`n %/ 8 /\
             (forall j, 0 <= j < 8 * k => XmssSig.get8 sig j = TLenIn.get8 wsig j)).
  + wp; skip => &m [#] -> htl0 hi ho hr hk0 hk1 hinc h1 hlt /=.
    have hn := n_val; have hh0 := hp_val; have hs := xsig_size.
    have hlen : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
    rewrite htl0 ho hi hr /=; split; first smt().
    split; first exact hinc.
    move=> j hj; rewrite XmssSig.get8_set64dE.
    case: (8 * k{m} <= j < 8 * k{m} + 8) => hr8.
    + rewrite ifT; first smt().
      by rewrite TLenIn.get64d_byte 1:/#; congr; smt().
    by rewrite ifF; [smt() | apply h1; smt()].
  wp; skip => &m [#] -> -> -> hi ho hr hfd /=.
  have hn := n_val; have hh0 := hp_val; have hlen : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
  have htl0 : to_uint tg0 < 2 ^ P.`hp by move: hfd; rewrite (leaves_ult _ _ hp_val).
  have ho2 := ho; rewrite /oinv hi in ho2.
  have [#] _ _ _ _ hau _ hws := ho2.
  rewrite ho hi hr htl0 /=.
  split; first smt().
  move=> k1 sg1 hk1 [#] hk10 hk11 hinc1 hj1.
  split.
  + split; first smt().
    by split; [move=> j hj; apply hj1; smt() | move=> j /#].
  move=> k2 sg2 hk2 [#] hk20 hk21 hinc2 hw2 ha2.
  split; last smt().
  rewrite (sig_join sg2 wsig{m} auth{m} hw2 _).
  + by move=> j hj; apply ha2; smt().
  rewrite hws // (take_slots auth{m} P.`hp); first smt(hp_le_a hp_ge3).
  congr; congr; apply eq_in_map => j /mem_range hj /=.
  by apply (au_full (xn pk (Node.to_list k0) l t) auth{m} P.`hp (to_uint tg0) j) => //;
    smt(W32.to_uint_cmp).
wp; skip => &m [#] -> -> -> _ _ hr hfd /=.
have hge : !(to_uint tg0 < 2 ^ P.`hp) by move: hfd; rewrite (leaves_ult _ _ hp_val).
by rewrite hr hge.
qed.

(* ------------------------------------------------------------------ *)
(* Termination                                                        *)

lemma xmss_treehash_ll (pk : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  phoare [M._xmss_treehash : ctx = c0 ==> true] = 1%r.
proof.
move=> hprf hf htl hh.
have hwl := wots_leaf_x4_ll pk c0 hprf hf htl.
have hhl : phoare [M._thash_h : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (hh x1 a1); auto.
have hfl := treehash_fold_ll c0 hhl.
have hpb := pow_hp_b; have hp3 := hp_ge3; have h4 := four_dvd_pow.
proc.
seq 24 : true 1%r 1%r 0%r _ => //.
+ wp; call node_copy_ll; wp.
  while (ctx = c0 /\ 0 <= to_uint i <= 2 ^ P.`hp /\ 4 %| to_uint i /\
         more = (to_uint i < 2 ^ P.`hp)) (2 ^ P.`hp - to_uint i).
  + move=> v; exlim i => i0; wp.
    while (ctx = c0 /\ 0 <= k <= 4 /\ i = i0) (4 - k).
    + move=> v2; wp; call hfl; wp.
      by while true (inc - w); auto => /#.
    wp; call hwl; wp; skip => &m [#] <- -> hi0 hi1 hd hmo hg hv /=.
    move=> c1 i1 k1; split; first smt().
    move=> hk [#] -> hk0 hk1 ->.
    have hlt : to_uint i0 < 2 ^ P.`hp by rewrite -hmo.
    have /dvdzP [q hq] := hd; have /dvdzP [r hr] := h4.
    have hle : to_uint i0 + 4 <= 2 ^ P.`hp by move: hlt; rewrite hq hr => /#.
    have e : to_uint (i0 + W32.of_int 4) = to_uint i0 + 4.
    + by rewrite W32.to_uintD_small W32.of_uintK modz_small; smt().
    rewrite (leaves_ult _ _ hp_val) e; split; first smt(dvdzD dvdzz).
    by rewrite -hv /#.
  wp; while true (inc - k); first by auto => /#.
  wp; while true (inc - k); first by auto => /#.
  wp; call set_tc_ll; call copy_ll; auto => &m -> /=.
  move=> k1; split; first smt().
  move=> hk k2; split; first smt().
  move=> hk2; split.
  + rewrite (leaves_ult _ _ hp_val) /=.
    by split; [smt(StdOrder.IntOrder.expr_gt0) | apply dvdz0].
  move=> c1 i1 m1 [#] _ hi0 hi1 _ hmo; smt().
if.
+ wp; while true (inc - k); first by auto => /#.
  by wp; while true (inc - k); auto => /#.
by auto.
qed.

(* ------------------------------------------------------------------ *)
(* _xmss_treehash: total correctness                                  *)

lemma xmss_node_correct (pk : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  forall (r0 : Node.t) (s0 : XmssSig.t) (k0 : Node.t) (a0 : BArray32.t) (tg0 : W32.t)
         (st0 : WotsDigits.t),
  phoare [M._xmss_treehash :
    root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
    steps = st0 /\
    (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) ==>
    Node.to_list res.`1 = xmss_node P (Node.to_list k0) 0 P.`hp pk (BArray32.to_list a0) /\
    (2 ^ P.`hp <= to_uint tg0 => res.`2 = s0)] = 1%r.
proof.
move=> hprf hf htl hh r0 s0 k0 a0 tg0 st0.
have [l t y w2 w1 w0 hA] := adrs_mkP (BArray32.to_list a0) (ADRS.size_bytes_of a0).
have hprf' : forall (k1 : Node.t) (a1 : BArray128.t),
  hoare [M._thash_prf_x4 : sk_seed = k1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      PRF P pk (Node.to_list k1) (lane 32 k (BArray128.to_list a1))].
+ by move=> k1 a1; conseq (hprf k1 a1).
have hf' : forall (x1 : Node4.t) (a1 : BArray128.t),
  hoare [M._thash_f_x4 : x = x1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      F P pk (lane 32 k (BArray128.to_list a1)) (lane P.`n k (Node4.to_list x1))].
+ by move=> x1 a1; conseq (hf x1 a1).
have htl' : forall (m1 : TLenIn4.t) (a1 : BArray128.t),
  hoare [M._thash_t_len_x4 : in_0 = m1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      T_l P pk (lane 32 k (BArray128.to_list a1))
          (lane (len P * P.`n) k (TLenIn4.to_list m1))].
+ by move=> m1 a1; conseq (htl m1 a1).
have hh' : forall (x1 : Node2.t) (a1 : BArray32.t),
  hoare [M._thash_h : in_0 = x1 /\ ctx = c0 /\ adrs = a1 ==>
    Node.to_list res.`1 = H P pk (BArray32.to_list a1) (Node2.to_list x1)].
+ by move=> x1 a1; conseq (hh x1 a1).
have h : hoare [M._xmss_treehash :
    root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
    steps = st0 /\
    (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) ==>
    Node.to_list res.`1 = xmss_node P (Node.to_list k0) 0 P.`hp pk (BArray32.to_list a0) /\
    (2 ^ P.`hp <= to_uint tg0 => res.`2 = s0)].
+ conseq (xmss_treehash_h pk c0 hprf' hf' htl' hh' r0 s0 k0 a0 tg0 st0 l t y w2 w1 w0 hA).
  + by move=> &hr h.
  move=> &hr _ r [#] h1 _ h3; by rewrite hA xmss_nodeX h1 /=; exact h3.
by conseq (xmss_treehash_ll pk c0 hprf hf htl hh) h.
qed.

lemma xmss_sign_correct (pk : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  forall (r0 : Node.t) (s0 : XmssSig.t) (k0 : Node.t) (a0 : BArray32.t) (tg0 : W32.t)
         (st0 : WotsDigits.t) (m0 : Node.t),
  phoare [M._xmss_treehash :
    root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
    steps = st0 /\ to_uint tg0 < 2 ^ P.`hp /\
    map W8.to_uint (WotsDigits.to_list st0) = wots_digits P (Node.to_list m0) ==>
    Node.to_list res.`1 = xmss_node P (Node.to_list k0) 0 P.`hp pk (BArray32.to_list a0) /\
    XmssSig.to_list res.`2 =
      xmss_sign P (Node.to_list m0) (Node.to_list k0) (to_uint tg0) pk (BArray32.to_list a0)] = 1%r.
proof.
move=> hprf hf htl hh r0 s0 k0 a0 tg0 st0 m0.
have [l t y w2 w1 w0 hA] := adrs_mkP (BArray32.to_list a0) (ADRS.size_bytes_of a0).
have htg := W32.to_uint_cmp tg0.
have hprf' : forall (k1 : Node.t) (a1 : BArray128.t),
  hoare [M._thash_prf_x4 : sk_seed = k1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      PRF P pk (Node.to_list k1) (lane 32 k (BArray128.to_list a1))].
+ by move=> k1 a1; conseq (hprf k1 a1).
have hf' : forall (x1 : Node4.t) (a1 : BArray128.t),
  hoare [M._thash_f_x4 : x = x1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      F P pk (lane 32 k (BArray128.to_list a1)) (lane P.`n k (Node4.to_list x1))].
+ by move=> x1 a1; conseq (hf x1 a1).
have htl' : forall (m1 : TLenIn4.t) (a1 : BArray128.t),
  hoare [M._thash_t_len_x4 : in_0 = m1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      T_l P pk (lane 32 k (BArray128.to_list a1))
          (lane (len P * P.`n) k (TLenIn4.to_list m1))].
+ by move=> m1 a1; conseq (htl m1 a1).
have hh' : forall (x1 : Node2.t) (a1 : BArray32.t),
  hoare [M._thash_h : in_0 = x1 /\ ctx = c0 /\ adrs = a1 ==>
    Node.to_list res.`1 = H P pk (BArray32.to_list a1) (Node2.to_list x1)].
+ by move=> x1 a1; conseq (hh x1 a1).
have h : hoare [M._xmss_treehash :
    root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
    steps = st0 /\ to_uint tg0 < 2 ^ P.`hp /\
    map W8.to_uint (WotsDigits.to_list st0) = wots_digits P (Node.to_list m0) ==>
    Node.to_list res.`1 = xmss_node P (Node.to_list k0) 0 P.`hp pk (BArray32.to_list a0) /\
    XmssSig.to_list res.`2 =
      xmss_sign P (Node.to_list m0) (Node.to_list k0) (to_uint tg0) pk (BArray32.to_list a0)].
+ conseq (_ : root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
              steps = st0 /\ to_uint tg0 < 2 ^ P.`hp /\
              map W8.to_uint (WotsDigits.to_list st0) = wots_digits P (Node.to_list m0) /\
              (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) ==> _).
  + move=> &hr [#] 7!-> hlt hd /=; rewrite hlt hd /= => i hi.
    by have := digits_lt16 (Node.to_list m0) i _ hi; [rewrite Node.size_to_list n_val | smt()].
  conseq (xmss_treehash_h pk c0 hprf' hf' htl' hh' r0 s0 k0 a0 tg0 st0 l t y w2 w1 w0 hA).
  + by move=> &hr [#] 7!-> _ _ hd /=; exact hd.
  move=> &hr [#] _ _ _ _ _ _ _ hlt hd _ r [#] hr hs _.
  have hs' := hs hlt.
  have h32 : 0 <= to_uint tg0 < 2 ^ 32 by have := W32.to_uint_cmp tg0; rewrite m32.
  have hsz : size (mk_adrs l t y w2 w1 w0) = 32 by rewrite -hA BArray32.size_to_list.
  rewrite hr hs' hA xmss_nodeX /= xmss_signE //.
  have -> : mk_adrs l t WOTS_HASH (to_uint tg0) 0 0 =
            adA (mk_adrs l t y w2 w1 w0) WOTS_HASH (to_uint tg0).
  + by rewrite /adA setTypeAndClearE setKeyPairAddressE.
  by rewrite wots_signE // hd.
by conseq (xmss_treehash_ll pk c0 hprf hf htl hh) h.
qed.
