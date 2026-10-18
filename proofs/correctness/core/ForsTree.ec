(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ForsTree.ec
 * ===========
 *
 * _fors_tree of src/slhdsa/fors.jinc computes, for FORS tree t and the
 * selected leaf tg, the secret of leaf t 2^a + tg (Algorithm 14), its
 * authentication path (Algorithm 16) and the root of the tree
 * (Algorithm 15).
 *
 * Nodes. fnode t z j is the node of tree t at height z with local index
 * j: gnode over the leaves fors_leaf at index t 2^(a - z) + j among all
 * nodes of height z, which is fors_node by FIPS205_TreeForms.fors_nodeE.
 * With base = t 2^a, fnode satisfies the recurrence that the fold of
 * treehash.jinc assumes (fnodeS), so the fold invariant of TreeFold.ec
 * (fs, au) is stated for N = fnode t.
 *
 * End of the tree. After leaf 2^a - 1 the invariant at i = 2^a gives slot
 * a of nodes = node 0 at height a, the root (fs_top), and slot z of auth
 * = the sibling of the target's ancestor at height z for every z < a
 * (au_top); the code copies them out.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_FORS FIPS205_XMSS.
require import MerkleTrees_FIPS205 FIPS205_TreeForms.
require import BArray32.
require import BArray128 SBArray128_32.
require import SetModel CoreExtracted Encoding WotsChain WotsPk WotsLeaf TreeFold.
require ForsPk.
import StdOrder.IntOrder.

(* ------------------------------------------------------------------ *)
(* Nodes of FORS tree t                                               *)

op fnode (pk sk : bytes) (l tr y kp t z j : int) : bytes =
  gnode (fors_leaf P sk pk l tr y kp) (fors_hash P pk l tr y kp) (hts z) (t * 2 ^ (P.`a - z) + j).

lemma fnode0 pk sk l tr y kp t j :
  fnode pk sk l tr y kp t 0 j = fors_leaf P sk pk l tr y kp (t * 2 ^ P.`a + j).
proof. by rewrite /fnode hts0. qed.

(* The parent recurrence, with the ADRS of the fold: height z + 1, index
   base / 2^(z + 1) + j for base = t 2^a. *)
lemma fnodeS pk sk l tr y kp w1 w0 t z j : 0 <= z < P.`a =>
  fnode pk sk l tr y kp t (z + 1) j =
  H P pk (setTreeIndex (setTreeHeight (mk_adrs l tr y kp w1 w0) (z + 1)) (t * 2 ^ P.`a %/ 2 ^ (z + 1) + j))
    (fnode pk sk l tr y kp t z (2 * j) ++ fnode pk sk l tr y kp t z (2 * j + 1)).
proof.
move=> hz; rewrite /fnode htsS 1:/# /= /fors_hash setChainAddressE setHashAddressE.
have e1 : 2 ^ P.`a = 2 ^ (P.`a - (z + 1)) * 2 ^ (z + 1) by apply pow_split => /#.
have e2 : 2 ^ (P.`a - z) = 2 * 2 ^ (P.`a - (z + 1)).
+ by rewrite -exprS 1:/#; congr; ring.
have hp : 2 ^ (z + 1) <> 0 by smt(expr_gt0).
rewrite e1 mulrA mulzK //.
have -> : 2 * (t * 2 ^ (P.`a - (z + 1)) + j) = t * 2 ^ (P.`a - z) + 2 * j by rewrite e2; ring.
by have -> : t * 2 ^ (P.`a - z) + 2 * j + 1 = t * 2 ^ (P.`a - z) + (2 * j + 1) by ring.
qed.

lemma fnode_root pk sk l tr y kp w1 w0 t : 0 <= kp < 2 ^ 32 =>
  fnode pk sk l tr y kp t P.`a 0 = fors_node P sk t P.`a pk (mk_adrs l tr y kp w1 w0).
proof. by move=> hkp; rewrite fors_nodeE // /fnode /= expr0. qed.

lemma fnode_auth pk sk l tr y kp t tg z : 0 <= z < P.`a =>
  fnode pk sk l tr y kp t z (gsibling (tg %/ 2 ^ z)) =
  gnode (fors_leaf P sk pk l tr y kp) (fors_hash P pk l tr y kp) (hts z) (gsibling ((t * 2 ^ P.`a + tg) %/ 2 ^ z)).
proof. by move=> hz; rewrite /fnode -sibling_shift // /sibling /gsibling. qed.

(* ------------------------------------------------------------------ *)
(* The fold invariant at the end of the tree                          *)

lemma fs_top N (b : FoldBuf.t) : fs N b P.`a (2 ^ P.`a) => slot b P.`a = N P.`a 0.
proof.
move=> h; have ha := a_val; have hp : 2 ^ P.`a <> 0 by smt(expr_gt0).
by have := h P.`a _ _; [smt() | rewrite divzz hp /b2i | rewrite divzz hp /b2i].
qed.

lemma au_top N (b : FoldBuf.t) tg : 0 <= tg < 2 ^ P.`a => au N b P.`a (2 ^ P.`a) tg =>
  forall z, 0 <= z < P.`a => slot b z = N z (gsibling (tg %/ 2 ^ z)).
proof.
move=> htg h z hz; apply h; first smt().
have e : 2 ^ P.`a = 2 ^ (P.`a - z) * 2 ^ z by apply pow_split => /#.
have hp : 0 < 2 ^ z by apply expr_gt0.
have hq : 0 < 2 ^ (P.`a - z) by apply expr_gt0.
have hev := pow_even (P.`a - z) _; first smt().
have hlt : tg %/ 2 ^ z < 2 ^ (P.`a - z) by rewrite ltz_divLR // -e; case: htg.
have h0 : 0 <= tg %/ 2 ^ z by apply divz_ge0 => //; case: htg.
rewrite e mulzK 1:/# /gsibling.
move: hlt h0 hev; move: (tg %/ 2 ^ z) (2 ^ (P.`a - z)) => X Q; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Byte views of the copies                                           *)

lemma n8 : 8 * (P.`n %/ 8) = P.`n by rewrite n_val.
lemma an8 : 8 * (P.`a * P.`n %/ 8) = P.`a * P.`n by rewrite a_val n_val.

(* Offsets of the tail copy: word k of auth goes to word n / 8 + k of
   sig (D = n / 8, N = n). *)
lemma ar_lo (q D k : int) (Y : bool) : 0 <= k => q < 8 * D =>
  !(8 * (D + k) <= q < 8 * (D + k) + 8 /\ Y).
proof. by smt(). qed.

lemma ar_lo2 (q D k N : int) (Y : bool) : 8 * D = N => q < 8 * k =>
  !(8 * (D + k) <= N + q < 8 * (D + k) + 8 /\ Y).
proof. by smt(). qed.

lemma ar_hi (q D k N S M : int) : 8 * D = N => 0 <= k => 8 * k <= q < 8 * (k + 1) =>
  8 * k + 8 <= M => S = M + N => 0 <= N =>
  8 * (D + k) <= N + q < 8 * (D + k) + 8 /\ 0 <= N + q < S.
proof. by smt(). qed.

lemma ar_b (q D k N : int) : 8 * D = N => 8 * k <= q < 8 * (k + 1) =>
  0 <= N + q - 8 * (D + k) < 8.
proof. by smt(). qed.

lemma ar_c (q D k N : int) : 8 * D = N => 8 * k + (N + q - 8 * (D + k)) = q.
proof. by smt(). qed.

(* Groups of four leaves: 2^a is a multiple of 4. *)
lemma i4_le (i : int) : 4 %| i => 0 <= i < 2 ^ P.`a => i + 4 <= 2 ^ P.`a.
proof.
move=> h4 hi; have h4a : 4 %| 2 ^ P.`a by rewrite a_val.
by move: h4 h4a hi; move: (2 ^ P.`a) => Q /dvdzP [p ->] /dvdzP [q ->] /#.
qed.

(* Global leaf index g + k of lane k. *)
lemma gkE (g : W32.t) (t i k : int) : 0 <= t < P.`k => 0 <= i => i + 4 <= 2 ^ P.`a => 0 <= k < 4 =>
  to_uint g = t * 2 ^ P.`a + i => to_uint (g + W32.of_int k) = t * 2 ^ P.`a + i + k.
proof.
move=> ht hi hi4 hk hg.
have hb := ForsPk.g_bound t (i + k) ht _.
+ by move: hi hi4 hk; move: (2 ^ P.`a) => Q /#.
have hk' : to_uint (W32.of_int k) = k by rewrite W32.of_uintK pmod_small //; smt().
have hs : to_uint g + to_uint (W32.of_int k) < W32.modulus.
+ by rewrite hk' hg; move: hb; move: (t * 2 ^ P.`a) => T /#.
by rewrite W32.to_uintD_small // hk' hg.
qed.

(* Base plus leaf index, below 2^32. *)
lemma bxE (b x : W32.t) t : 0 <= t < P.`k => to_uint b = t * 2 ^ P.`a => to_uint x < 2 ^ P.`a =>
  to_uint (b + x) = t * 2 ^ P.`a + to_uint x.
proof.
move=> ht hb hx; have h0 := W32.to_uint_cmp x.
have hg := ForsPk.g_bound t (to_uint x) ht _; first smt().
have hs : to_uint b + to_uint x < W32.modulus.
+ by rewrite hb; move: hg; move: (t * 2 ^ P.`a) => T /#.
by rewrite W32.to_uintD_small // hb.
qed.

(* The four address lanes of a leaf group (ADRS4 buffers of lane k). *)
lemma sk_lane_upd (sk : BArray128.t) (r : BArray32.t) K v l tr kp : 0 <= K < 4 =>
  take 28 (lane 32 K (BArray128.to_list sk)) = take 28 (mk_adrs l tr FORS_PRF kp 0 0) =>
  BArray32.to_list r = setTreeIndex (BArray32.to_list (SBArray128_32.get_sub64 sk (4 * K))) v =>
  lane 32 K (BArray128.to_list (SBArray128_32.set_sub64 sk (4 * K) r)) = mk_adrs l tr FORS_PRF kp 0 v.
proof.
by move=> hK h28 hr; rewrite adrs4_set_same // hr adrs4_get // (sha_eq _ _ _ h28) setHashAddressE.
qed.

lemma lf_lane_upd (lf : BArray128.t) (r2 r3 : BArray32.t) K v (A : adrs) l tr y kp w1 w0 :
  0 <= K < 4 => A = mk_adrs l tr y kp w1 w0 =>
  take 24 (lane 32 K (BArray128.to_list lf)) = take 24 A =>
  BArray32.to_list r2 = setTreeHeight (BArray32.to_list (SBArray128_32.get_sub64 lf (4 * K))) 0 =>
  BArray32.to_list r3 =
    setTreeIndex (BArray32.to_list (SBArray128_32.get_sub64 (SBArray128_32.set_sub64 lf (4 * K) r2) (4 * K))) v =>
  lane 32 K (BArray128.to_list (SBArray128_32.set_sub64 (SBArray128_32.set_sub64 lf (4 * K) r2) (4 * K) r3)) =
    mk_adrs l tr y kp 0 v.
proof.
move=> hK hA h24 hr2 hr3.
rewrite adrs4_set_same // hr3 adrs4_get // adrs4_set_same // hr2 adrs4_get //.
by rewrite (tree_adrs_eq _ A) ?adrs4_size // hA setChainAddressE setHashAddressE.
qed.

lemma sk_tpl_upd (sk : BArray128.t) (r : BArray32.t) K v j : 0 <= K < 4 => 0 <= j < 4 =>
  BArray32.to_list r = setTreeIndex (BArray32.to_list (SBArray128_32.get_sub64 sk (4 * K))) v =>
  take 28 (lane 32 j (BArray128.to_list (SBArray128_32.set_sub64 sk (4 * K) r))) =
  take 28 (lane 32 j (BArray128.to_list sk)).
proof.
move=> hK hj hr; rewrite adrs4_set //; case: (j = K) => [->> | //].
rewrite hr adrs4_get //.
have := sha_take (lane 32 K (BArray128.to_list sk)) v _; first by rewrite adrs4_size.
by move=> [_ ->].
qed.

lemma lf_tpl_upd (lf : BArray128.t) (r2 r3 : BArray32.t) K v j : 0 <= K < 4 => 0 <= j < 4 =>
  BArray32.to_list r2 = setTreeHeight (BArray32.to_list (SBArray128_32.get_sub64 lf (4 * K))) 0 =>
  BArray32.to_list r3 =
    setTreeIndex (BArray32.to_list (SBArray128_32.get_sub64 (SBArray128_32.set_sub64 lf (4 * K) r2) (4 * K))) v =>
  take 24 (lane 32 j (BArray128.to_list (SBArray128_32.set_sub64 (SBArray128_32.set_sub64 lf (4 * K) r2) (4 * K) r3))) =
  take 24 (lane 32 j (BArray128.to_list lf)).
proof.
move=> hK hj hr2 hr3; case: (j = K) => [->> | hne].
+ rewrite adrs4_set_same // hr3 adrs4_get // adrs4_set_same // hr2 adrs4_get //.
  by rewrite tree_adrs_take // adrs4_size.
have hne' : K <> j by smt().
by rewrite !(adrs4_set_other _ _ _ _ hK hj hne').
qed.

(* d = target - i, unsigned: below 4 exactly when the target is in the
   group i .. i + 3. *)
lemma dE (t i : W32.t) : to_uint i < 2 ^ P.`a => to_uint t < 2 ^ P.`a =>
  (to_uint i <= to_uint t => to_uint (t - i) = to_uint t - to_uint i) /\
  (to_uint t < to_uint i => 4 <= to_uint (t - i)).
proof.
move=> hi ht; have hA : 2 ^ P.`a <= 65536 by rewrite a_val.
have h0 := W32.to_uint_cmp i; have h1 := W32.to_uint_cmp t.
split => h; first by rewrite W32.to_uintB // W32.uleE.
have e : to_uint (t - i) = (to_uint t - to_uint i) %% W32.modulus.
+ by rewrite W32.to_uintD W32.to_uintN modzDmr.
have hM : W32.modulus = 4294967296 by done.
rewrite e hM; move: hi ht h0 h1 hA h; rewrite hM; move: (to_uint t) (to_uint i) (2 ^ P.`a) => T I Q.
move=> hi ht h0 h1 hA h.
have <- : (T - I + 4294967296) %% 4294967296 = (T - I) %% 4294967296 by rewrite modzDr.
by rewrite modz_small; smt().
qed.

lemma fbl_size (b : FoldBuf.t) : size (FoldBuf.to_list b) = (P.`a + 1) * P.`n.
proof. by rewrite FoldBuf.size_to_list a_val n_val. qed.

(* The first m slots of a fold buffer, concatenated, are its first m n
   bytes. *)
lemma flat_slots (b : FoldBuf.t) m : 0 <= m <= P.`a + 1 =>
  flatten (map (slot b) (range 0 m)) = take (m * P.`n) (FoldBuf.to_list b).
proof.
elim/natind: m => [m hm0 hm | m hm0 ih hm].
+ have -> : m = 0 by smt().
  by rewrite range_geq //= ?flatten_nil take0.
have hn := n_val; have hs := fbuf_size.
have hsl : size (slot b m) = P.`n by rewrite /slot Node.size_to_list hn.
rewrite rangeSr // map_rcons flatten_rcons ih 1:/#.
have -> : (m + 1) * P.`n = m * P.`n + size (slot b m) by rewrite hsl; ring.
rewrite (take_ext W8.zero (FoldBuf.to_list b) (take (m * P.`n) (FoldBuf.to_list b)) (slot b m) (m * P.`n)) //.
+ by apply mulr_ge0 => /#.
+ rewrite hsl fbl_size; move: hm; rewrite a_val hn /=; smt().
move=> q; rewrite hsl => hq.
rewrite FoldBuf.get_to_list /slot Node.get_to_list FoldNode.get8_get_sub ifT; first by move: hq; rewrite hn /= /#.
by congr; ring.
qed.

(* The tree signature: the secret in bytes 0 .. n - 1, then the
   authentication path, slot by slot. *)
lemma sig_cat (s au : FoldBuf.t) (x : Node.t) :
  (forall q, 0 <= q < P.`n => FoldBuf.get8 s q = Node.get8 x q) =>
  (forall q, 0 <= q < P.`a * P.`n => FoldBuf.get8 s (P.`n + q) = FoldBuf.get8 au q) =>
  FoldBuf.to_list s = Node.to_list x ++ flatten (map (slot au) (range 0 P.`a)).
proof.
move=> hx hau; have hn := n_val; have ha := a_val; have hs := fbuf_size.
rewrite flat_slots 1:/#.
have hsx : size (Node.to_list x) = P.`n by rewrite Node.size_to_list hn.
have hta : size (take (P.`a * P.`n) (FoldBuf.to_list au)) = P.`a * P.`n.
+ rewrite size_take; first by rewrite ha hn.
  by rewrite fbl_size ha hn.
apply (eq_from_nth W8.zero).
+ by rewrite size_cat hsx hta fbl_size ha hn.
move=> j; rewrite fbl_size => hj.
rewrite nth_cat hsx FoldBuf.get_to_list.
case: (j < P.`n) => hjn.
+ by rewrite Node.get_to_list hx /#.
rewrite nth_take; 1,2: by move: hj hjn; rewrite ha hn /= => /#.
rewrite FoldBuf.get_to_list -hau; first by move: hj hjn; rewrite ha hn /= => /#.
by congr; ring.
qed.

(* A word copy into a node, byte by byte: after word w, bytes below
   8 (w + 1) are those of the source from offset o. *)
lemma cp_step (dst : Node.t) (src : Node4.t) (o w : int) :
  0 <= w => 8 * (w + 1) <= P.`n => 0 <= o => o + 8 * w + 8 <= 4 * P.`n =>
  (forall b, 0 <= b < 8 * w => Node.get8 dst b = Node4.get8 src (o + b)) =>
  forall b, 0 <= b < 8 * (w + 1) =>
    Node.get8 (Node.set64d dst (8 * w) (Node4.get64d src (o + 8 * w))) b = Node4.get8 src (o + b).
proof.
move=> hw0 hw ho hos h b hb; have hn := n_val.
rewrite Node.get8_set64dE.
case: (8 * w <= b) => hbw.
+ rewrite ifT; first by move: hb hbw hw; rewrite hn /= => /#.
  by rewrite Node4.get64d_byte 1:/#; congr; ring.
by rewrite ifF 1:/#; apply h => /#.
qed.

lemma cp_list (dst : Node.t) (src : Node4.t) k : 0 <= k < 4 =>
  (forall b, 0 <= b < P.`n => Node.get8 dst b = Node4.get8 src (P.`n * k + b)) =>
  Node.to_list dst = lane P.`n k (Node4.to_list src).
proof.
move=> hk h; have hn := n_val.
apply (eq_from_nth W8.zero).
+ rewrite Node.size_to_list lane_size; 1,2: smt().
  + by rewrite Node4.size_to_list hn /= /#.
  by rewrite hn.
move=> j; rewrite Node.size_to_list hn /= => hj.
rewrite ?Node.get_to_list nth_lane 1..3:/#.
by rewrite ?Node4.get_to_list; move: h; rewrite hn => h; apply h.
qed.

(* The word index of lane k, word w, of a four-node buffer, in bytes
   (c is the literal n of the model). *)
lemma cp_idx (c k w : int) : P.`n = c => 8 * (c %/ 8 * k + w) = P.`n * k + 8 * w.
proof. by move=> <-; rewrite mulrDr mulrA n8. qed.

(* Local leaf index i + k, below 2^a. *)
lemma lkE (i : W32.t) (k : int) : 0 <= k => to_uint i + k <= 2 ^ P.`a =>
  to_uint (i + W32.of_int k) = to_uint i + k.
proof.
move=> hk hi; have hA : 2 ^ P.`a <= 65536 by rewrite a_val.
have h0 := W32.to_uint_cmp i.
have hk' : to_uint (W32.of_int k) = k.
+ by rewrite W32.of_uintK pmod_small //; move: hi hA h0; move: (2 ^ P.`a) => Q /#.
by rewrite W32.to_uintD_small hk' //; move: hi hA h0; move: (2 ^ P.`a) => Q /#.
qed.

(* The tree index (bytes 28 .. 31) is outside the first 28 bytes. *)
lemma take28_mk l t y w2 w1 w0 v0 :
  take 28 (mk_adrs l t y w2 w1 w0) = take 28 (mk_adrs l t y w2 w1 v0).
proof. by rewrite /mk_adrs; do ! (rewrite !take_cat !size_cat /=); rewrite !take0 !cats0. qed.

(* ------------------------------------------------------------------ *)
(* _fors_tree (Algorithms 14, 15 and 16 for one tree)                 *)

lemma tc6_h (a0 : BArray32.t) : hoare [M.__adrs_set_type_and_clear : arg = (a0, 6) ==>
  BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) 6].
proof. by conseq (core_set_type_and_clear a0 6 _). qed.

(* The PRF, F and H premises are those of the four-way and scalar thash
   theorems, in hoare form; the fold steps use TreeFold.treehash_fold_h. *)
lemma fors_tree_h (pk_seed : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     hoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk_seed (Node.to_list k0) (lane 32 k (BArray128.to_list a0))]) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     hoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk_seed (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))]) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     hoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)]) =>
  forall (k0 : Node.t) (a0 : BArray32.t) (t0 tg0 : W32.t) (l tr y kp w1 w0 : int),
  BArray32.to_list a0 = mk_adrs l tr y kp w1 w0 => 0 <= kp < 2 ^ 32 =>
  to_uint t0 < P.`k => to_uint tg0 < 2 ^ P.`a =>
  hoare [M._fors_tree :
    sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 ==>
    Node.to_list res.`2 = fnode pk_seed (Node.to_list k0) l tr y kp (to_uint t0) P.`a 0 /\
    FoldBuf.to_list res.`1 =
      fors_sk P (Node.to_list k0) pk_seed l tr kp (to_uint t0 * 2 ^ P.`a + to_uint tg0) ++
      flatten (map (fun z => fnode pk_seed (Node.to_list k0) l tr y kp (to_uint t0) z (gsibling (to_uint tg0 %/ 2 ^ z)))
                   (range 0 P.`a))].
proof.
move=> hprf hf hh k0 a0 t0 tg0 l tr y kp w1 w0 hA hkp ht htg.
have [N hNe] : exists N, N = fnode pk_seed (Node.to_list k0) l tr y kp (to_uint t0)
  by exists (fnode pk_seed (Node.to_list k0) l tr y kp (to_uint t0)).
have [A hAe] : exists A, A = BArray32.to_list a0 by exists (BArray32.to_list a0).
have [B hBe] : exists B, B = to_uint t0 * 2 ^ P.`a by exists (to_uint t0 * 2 ^ P.`a).
have hN0 : forall z j, 0 <= z < P.`a => 0 <= j =>
  N (z + 1) j = H P pk_seed (setTreeIndex (setTreeHeight A (z + 1)) (B %/ 2 ^ (z + 1) + j))
                  (N z (2 * j) ++ N z (2 * j + 1)).
+ by move=> z j hz _; rewrite hNe hAe hA hBe; apply fnodeS.
have hfold := treehash_fold_h pk_seed c0 N A B P.`a hh hN0 _ _.
+ by rewrite a_val.
+ by rewrite hBe; apply dvdz_mull; apply dvdzz.
proc.
(* Tail: the authentication path, word by word, after the secret. *)
while (0 <= k <= inc /\ inc = P.`a * P.`n %/ 8 /\
       (forall q, 0 <= q < P.`n => FoldBuf.get8 sig q = Node.get8 selected q) /\
       (forall q, 0 <= q < 8 * k => FoldBuf.get8 sig (P.`n + q) = FoldBuf.get8 auth q)).
+ wp; skip => &m [#] hk0 hk1 hinc hsel hq hlt.
  have hw : 8 * k{m} + 8 <= P.`a * P.`n.
  + by move: hlt hinc an8; move: (P.`a * P.`n) => X /#.
  have hn0 : 0 <= P.`n by rewrite n_val.
  rewrite -n_val.
  split; first smt().
  split; first done.
  split.
  + move=> q hq'; rewrite FoldBuf.get8_set64dE ifF; last exact hsel.
    by apply ar_lo => //; rewrite n8; case: hq'.
  move=> q hq'; rewrite FoldBuf.get8_set64dE.
  case: (8 * k{m} <= q) => hqk.
  + rewrite ifT.
    + apply (ar_hi _ _ _ _ _ (P.`a * P.`n)).
      + exact n8.
      + exact hk0.
      + by split => //; case: hq'.
      + exact hw.
      + by rewrite a_val n_val.
      exact hn0.
    rewrite FoldBuf.get64d_byte; first by apply ar_b; [exact n8 | split => //; case: hq'].
    by congr; apply ar_c; exact n8.
  rewrite ifF; first by apply ar_lo2; [exact n8 | smt()].
  by apply hq => /#.
wp; ecall (node_copy_h selected); wp; ecall (node_copy_h (FoldNode.get_sub nodes (P.`a * P.`n))); wp.
(* The leaves, four at a time. *)
while (0 <= to_uint i <= 2 ^ P.`a /\ 4 %| to_uint i /\ more = (to_uint i < 2 ^ P.`a) /\
       sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
       take 24 (BArray32.to_list node_adrs) = take 24 A /\
       (forall k, 0 <= k < 4 =>
          take 28 (lane 32 k (BArray128.to_list sk_adrs)) = take 28 (mk_adrs l tr FORS_PRF kp 0 0)) /\
       (forall k, 0 <= k < 4 => take 24 (lane 32 k (BArray128.to_list leaf_adrs)) = take 24 A) /\
       fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\
       (to_uint tg0 < to_uint i =>
          Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0))).
+ seq 6 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
         fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\ (to_uint tg0 < to_uint i =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\
         (forall k, 0 <= k < 4 =>
            take 28 (lane 32 k (BArray128.to_list sk_adrs)) = take 28 (mk_adrs l tr FORS_PRF kp 0 0) /\
            take 24 (lane 32 k (BArray128.to_list leaf_adrs)) = take 24 A) /\
         z = W32.zero /\ k = 0).
  + wp; skip => &m [#] hi0 hi1 h4 hmore hsk hctx had htr hpt hb hna hts htl hfs hau hsel hm /=.
    have hlt : to_uint i{m} < 2 ^ P.`a by rewrite -hmore.
    rewrite ?protect32E.
    do 8!(split; first done).
    split; first by rewrite (bxE _ _ (to_uint t0)) // -?hBe //; split; [smt(W32.to_uint_cmp) | done].
    do 4!(split; first done).
    by move=> j hj; split; [apply hts | apply htl].
  seq 1 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
           fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\ (to_uint tg0 < to_uint i =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\
           (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k))).
  + while (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
           fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\ (to_uint tg0 < to_uint i =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\
           (forall k, 0 <= k < 4 =>
            take 28 (lane 32 k (BArray128.to_list sk_adrs)) = take 28 (mk_adrs l tr FORS_PRF kp 0 0) /\
            take 24 (lane 32 k (BArray128.to_list leaf_adrs)) = take 24 A) /\
           z = W32.zero /\ 0 <= k <= 4 /\
           (forall j, 0 <= j < k =>
              lane 32 j (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + j) /\
              lane 32 j (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + j))).
    + wp; ecall (index_h (SBArray128_32.get_sub64 leaf_adrs (4 * k)) gk); wp.
      ecall (height_h (SBArray128_32.get_sub64 leaf_adrs (4 * k)) z); wp.
      ecall (index_h (SBArray128_32.get_sub64 sk_adrs (4 * k)) gk); wp; skip.
      move=> &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hts -> hk0 hk4 hj hlt /=.
      move=> r1 hr1 r2 hr2 r3 hr3.
      have hK : 0 <= k{m} < 4 by done.
      have hgk : to_uint (g{m} + W32.of_int k{m}) = B + to_uint i{m} + k{m}.
      + rewrite hBe; apply gkE => //.
        + by split; [smt(W32.to_uint_cmp) | done].
        + by apply i4_le.
        by rewrite -hBe.
      move: hr1 hr2 hr3; rewrite hgk ?W32.to_uint0 => hr1 hr2 hr3.
      have hAm : A = mk_adrs l tr y kp w1 w0 by rewrite hAe hA.
      do 13!(split; first done).
      split.
      + move=> j hj4; rewrite (sk_tpl_upd _ _ _ _ _ hK hj4 hr1) (lf_tpl_upd _ _ _ _ _ _ hK hj4 hr2 hr3).
        exact (hts j hj4).
      split; first smt().
      move=> j hj1; case: (j = k{m}) => [->> | hne].
      + have [h28 h24] := hts k{m} hK.
        split; first exact (sk_lane_upd _ _ _ _ _ _ _ hK h28 hr1).
        exact (lf_lane_upd _ _ _ _ _ _ _ _ _ _ _ _ hK hAm h24 hr2 hr3).
      have hjk : 0 <= j < k{m} by smt().
      have hj4 : 0 <= j < 4 by smt().
      have hne' : k{m} <> j by smt().
      rewrite !(adrs4_set_other _ _ _ _ hK hj4 hne'); exact (hj j hjk).
    skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hts hz hk /=.
    split; first by do 15!(split; first done); rewrite hk; split => //; move=> j /#.
    move=> k1 la sa hk1 [#] _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hk10 hk14 hj.
    do 13!(split; first done).
    by move=> j hj4; apply hj => /#.
  seq 3 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
           fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\ (to_uint tg0 < to_uint i =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\
           (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\
           (forall k, 0 <= k < 4 =>
            lane P.`n k (Node4.to_list leaves) = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint i + k))).
  + ecall (hprf k0 sk_adrs); wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hla /=.
    rewrite ?protectpE.
    split; first by rewrite hsk hctx.
    move=> _ r hr.
    do 14!(split; first done).
    move=> k hk; have [h1 _] := hla k hk.
    by rewrite hr // h1 /fors_sk.
  seq 6 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
           fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\ (to_uint tg0 < to_uint i + 4 =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\
           (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\
           (forall k, 0 <= k < 4 =>
            lane P.`n k (Node4.to_list leaves) = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint i + k))).
  + seq 5 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
             fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\ (to_uint tg0 < to_uint i =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\
             (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\
             (forall k, 0 <= k < 4 =>
            lane P.`n k (Node4.to_list leaves) = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint i + k)) /\
             d = tg0 - i /\ found = (d \ult W32.of_int 4)).
    + wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hla hsk4 /=.
      rewrite ?protect32E.
      do 15!(split; first done).
      by rewrite hpt.
    have hda := dE tg0.
    if.
    + inline M.__offset64; wp.
      while (0 <= w <= inc /\ inc = P.`n %/ 8 /\ lp = leaves /\
             sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
             fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\
             (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\
             (forall k, 0 <= k < 4 =>
            lane P.`n k (Node4.to_list leaves) = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint i + k)) /\
             to_uint i <= to_uint tg0 < to_uint i + 4 /\ to_uint d = to_uint tg0 - to_uint i /\
             to_uint src = to_uint d * P.`n + 8 * w /\
             (forall b, 0 <= b < 8 * w => Node.get8 selected b = Node4.get8 leaves (to_uint d * P.`n + b))).
      + wp; skip => &m [#] hw0 hw1 hinc hlp hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hla hsk4.
        move=> hd0 hd1 hd hsrc hby hlt /=.
        have hn8 := n8.
        have hw8 : 8 * (w{m} + 1) <= P.`n.
        + by move: hlt hinc hn8; move: (P.`n) (P.`n %/ 8) => Nn D /#.
        have hd4 : to_uint d{m} < 4 by rewrite hd; move: hd1 => /#.
        split; first by move: hw0 hlt => /#.
        do 18!(split; first done).
        split.
        + rewrite W64.to_uintD_small W64.of_uintK /= hsrc.
          + by move: hd4 hw8; rewrite n_val => /#.
          by ring.
        move=> b hbb; rewrite hsrc hlp.
        apply (cp_step _ _ _ _ hw0 hw8 _ _ hby b hbb).
        + by apply mulr_ge0; [smt(W32.to_uint_cmp) | rewrite n_val].
        by move: hd4 hw8; rewrite n_val => /#.
      wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hla hsk4 hd hfd hfound /=.
      have [hdi hdo] := hda i{m} hi1 htg.
      have hle : to_uint i{m} <= to_uint tg0.
      + case: (to_uint i{m} <= to_uint tg0) => // hgt.
        have := hdo _; first smt().
        by move: hfound; rewrite hfd hd W32.ultE /= => /#.
      have hdv := hdi hle.
      have hd4 : to_uint d{m} < 4 by move: hfound; rewrite hfd W32.ultE.
      have hdt : to_uint d{m} = to_uint tg0 - to_uint i{m} by rewrite hd.
      split.
      + split; first by rewrite n_val.
        do 14!(split; first done).
        split; first by split; [done | move: hd4; rewrite hdt => /#].
        split; first done.
        split; last by move=> b /#.
        by rewrite (offE64 _ _ _ n_val) zext64E.
      move=> s1 se1 ww hw [#] hw0 hw1 hinc _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hsrc hby.
      have hwn : 8 * ww = P.`n.
      + by move: hw hw1 hinc n8; move: (P.`n) (P.`n %/ 8) => Nn D /#.
      do 12!(split; first done).
      split.
      + move=> _; rewrite (cp_list s1 leaves{m} (to_uint d{m})).
        + by split; [smt(W32.to_uint_cmp) | done].
        + by move=> b hbb; rewrite hby; [rewrite hwn | congr; ring].
        rewrite hsk4; first by split; [smt(W32.to_uint_cmp) | done].
        by congr; rewrite hdt; ring.
      by split.
    wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hla hsk4 hd hfd hnf /=.
    have [hdi hdo] := hda i{m} hi1 htg.
    do 12!(split; first done).
    split; last by split.
    move=> hlt4; apply hsel.
    case: (to_uint tg0 < to_uint i{m}) => // hge.
    have hdv := hdi _; first smt().
    by move: hnf; rewrite hfd hd W32.ultE hdv /= => /#.
  seq 2 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\
           fs N nodes P.`a (to_uint i) /\ au N auth P.`a (to_uint i) (to_uint tg0) /\ (to_uint tg0 < to_uint i + 4 =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\
           (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\ (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list leaves) = N 0 (to_uint i + k))).
  + ecall (hf leaves leaf_adrs); wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hla hsk4 /=.
    rewrite ?protectpE.
    split; first by rewrite hctx.
    move=> _ r hr.
    do 14!(split; first done).
    move=> k hk; have [_ h2] := hla k hk.
    have e : to_uint t0 * 2 ^ P.`a + (to_uint i{m} + k) = B + to_uint i{m} + k by rewrite hBe; ring.
    by rewrite hr // h2 (hsk4 k hk) hNe fnode0 e /fors_leaf.
  (* The fold of leaves i .. i + 3, then i += 4. *)
  seq 2 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\ (to_uint tg0 < to_uint i + 4 =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\ (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\
           fs N nodes P.`a (to_uint i + 4) /\ au N auth P.`a (to_uint i + 4) (to_uint tg0)).
  + while (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\ (to_uint tg0 < to_uint i + 4 =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\ (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\ (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list leaves) = N 0 (to_uint i + k)) /\ 0 <= k <= 4 /\
           fs N nodes P.`a (to_uint i + k) /\ au N auth P.`a (to_uint i + k) (to_uint tg0)).
    + seq 3 : (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\ (to_uint tg0 < to_uint i + 4 =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\ (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\ (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list leaves) = N 0 (to_uint i + k)) /\ 0 <= k < 4 /\
             fs N nodes P.`a (to_uint i + k) /\ au N auth P.`a (to_uint i + k) (to_uint tg0) /\
             Node.to_list node = N 0 (to_uint i + k)).
      + while (sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 /\ to_uint base = B /\
         0 <= to_uint i < 2 ^ P.`a /\ 4 %| to_uint i /\ to_uint g = B + to_uint i /\
         take 24 (BArray32.to_list node_adrs) = take 24 A /\ (to_uint tg0 < to_uint i + 4 =>
            Node.to_list selected = fors_sk P (Node.to_list k0) pk_seed l tr kp (B + to_uint tg0)) /\ (forall k, 0 <= k < 4 =>
            lane 32 k (BArray128.to_list sk_adrs) = mk_adrs l tr FORS_PRF kp 0 (B + to_uint i + k) /\
            lane 32 k (BArray128.to_list leaf_adrs) = mk_adrs l tr y kp 0 (B + to_uint i + k)) /\ (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list leaves) = N 0 (to_uint i + k)) /\ 0 <= k < 4 /\
             fs N nodes P.`a (to_uint i + k) /\ au N auth P.`a (to_uint i + k) (to_uint tg0) /\
             0 <= w <= inc /\ inc = P.`n %/ 8 /\
             (forall b, 0 <= b < 8 * w => Node.get8 node b = Node4.get8 leaves (P.`n * k + b))).
        + wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hsel hla hlf hk0 hk1 hfs hau.
          move=> hw0 hw1 hinc hby hlt.
          rewrite (cp_idx _ k{m} w{m} n_val).
          have hw8 : 8 * (w{m} + 1) <= P.`n.
          + by move: hlt hinc n8; move: (P.`n) (P.`n %/ 8) => Nn D /#.
          do 16!(split; first done).
          split; first by move: hw0 hlt => /#.
          split; first done.
          move=> b hbb; apply (cp_step _ _ _ _ hw0 hw8 _ _ hby b hbb).
          + by apply mulr_ge0; [rewrite n_val | smt()].
          by move: hk1 hw8; rewrite n_val => /#.
        wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hsel hla hlf hk0 hk4 hfs hau hk /=.
        split.
        + do 16!(split; first done).
          split; first by rewrite n_val.
          by move=> b /#.
        move=> nd w2 hw [#] _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hw0 hw1 hinc hby.
        have hwn : 8 * w2 = P.`n.
        + by move: hw hw1 hinc n8; move: (P.`n) (P.`n %/ 8) => Nn D /#.
        do 16!(split; first done).
        rewrite (cp_list nd leaves{m} k{m}); first by split.
        + by move=> b hbb; apply hby; rewrite hwn.
        by apply hlf; split.
      wp; ecall (hfold nodes auth node li gi tg node_adrs); wp; skip.
      move=> &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hsel hla hlf hk0 hk1 hfs hau hnd.
      rewrite ?protect32E ?protectpE.
      have hi4 := i4_le (to_uint i{m}) h4 _; first by split.
      have hli : to_uint (i{m} + W32.of_int k{m}) = to_uint i{m} + k{m}.
      + by apply lkE => //; move: hi4 hk1; move: (2 ^ P.`a) => Q /#.
      have hgi : to_uint (g{m} + W32.of_int k{m}) = B + to_uint i{m} + k{m}.
      + rewrite hBe; apply gkE; [by split; [smt(W32.to_uint_cmp) | done] | done | done | done | by rewrite -hBe].
      simplify; rewrite hli hgi hpt.
      split.
      + split; first done.
        split; first by move: hi4 hk1; move: (2 ^ P.`a) => Q /#.
        split; first by ring.
        by do 3!(split; first done).
      move=> _ r [#] hfs' hau' hna'.
      have e : to_uint i{m} + (k{m} + 1) = to_uint i{m} + k{m} + 1 by ring.
      rewrite e.
      do 13!(split; first done).
      split; first by move: hk0 hk1 => /#.
      by split.
    wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hfs hau hsel hla hlf /=.
    split; first by do !(split; first done).
    move=> au1 c1 g1 i1 k1 na1 nd1 tg1 hk.
    move=> [#] j1 j2 j3 j4 j5 j6 j7 j8 j9 j10 j11 j12 j13 _ hk0 hk1 hfs1 hau1.
    have hk4 : k1 = 4 by move: hk hk1 => /#.
    move: hfs1 hau1; rewrite hk4 => hfs1 hau1.
    by do !(split; first done).
  wp; skip => &m [#] hsk hctx had htr hpt hb hi0 hi1 h4 hg hna hsel hla hfs hau.
  rewrite ?protect32E; simplify.
  have hi4 := i4_le (to_uint i{m}) h4 _; first by split.
  have hiE : to_uint (i{m} + W32.of_int 4) = to_uint i{m} + 4 by apply lkE.
  rewrite hiE.
  split; first by move: hi0 hi4; move: (2 ^ P.`a) => Q /#.
  split; first by apply dvdzD => //; apply dvdzz.
  split; first by rewrite (ForsPk.ultP _ (2 ^ P.`a)) ?hiE //= ?a_val /(`<<`).
  do 7!(split; first done).
  split; first by move=> j hj; have [-> _] := hla j hj; apply take28_mk.
  split; first by move=> j hj; have [_ ->] := hla j hj; rewrite hAe hA; apply ForsPk.take24_mk.
  by do 2!(split; first done).
(* The buffer fills: dead stores, every slot read later is written first. *)
wp; while true; first by auto.
wp; while true; first by auto.
wp; ecall (copy_hh node_adrs adrs).
(* The address templates. *)
while (0 <= k <= 4 /\ adrs = a0 /\ sk_seed = k0 /\ ctx = c0 /\ tree = t0 /\ target = tg0 /\
       (forall j, 0 <= j < k =>
          lane 32 j (BArray128.to_list sk_adrs) = setKeyPairAddress (setTypeAndClear A 6) (getKeyPairAddress A) /\
          lane 32 j (BArray128.to_list leaf_adrs) = A)).
+ wp; ecall (copy_hh (SBArray128_32.get_sub64 leaf_adrs (4 * k)) adrs); wp.
  ecall (ForsPk.ckp_h (SBArray128_32.get_sub64 sk_adrs (4 * k)) adrs); wp.
  ecall (tc6_h (SBArray128_32.get_sub64 sk_adrs (4 * k))); wp.
  ecall (copy_hh (SBArray128_32.get_sub64 sk_adrs (4 * k)) adrs); wp; skip.
  move=> &hr [#] hk0 hk1 -> -> -> -> -> hj hk4 /= r1 hr1 r2 hr2 r3 hr3 r4 hr4.
  split; first smt().
  move=> j hj'; case: (j = k{hr}) => [-> | hne].
  + have hk : 0 <= k{hr} < 4 by done.
    rewrite (adrs4_set_same _ _ _ hk) (adrs4_set_same _ _ _ hk) hr4 hr3.
    rewrite (adrs4_get _ _ hk) (adrs4_set_same _ _ _ hk) hr2.
    by rewrite (adrs4_get _ _ hk) (adrs4_set_same _ _ _ hk) hr1 hAe.
  have hk : 0 <= k{hr} < 4 by done.
  have hj4 : 0 <= j < 4 by smt().
  have hjk : 0 <= j < k{hr} by smt().
  have hne' : k{hr} <> j by smt().
  rewrite !(adrs4_set_other _ _ _ _ hk hj4 hne'); exact (hj j hjk).
wp; skip.
move=> &m /= [#] -> -> -> -> ->.
have hkpA : getKeyPairAddress A = kp by rewrite hAe hA getKeyPairAddressE pmod_small.
have hskA : setKeyPairAddress (setTypeAndClear A 6) (getKeyPairAddress A) = mk_adrs l tr FORS_PRF kp 0 0.
+ by rewrite hkpA hAe hA setTypeAndClearE setKeyPairAddressE.
have hp : 0 < 2 ^ P.`a by apply expr_gt0.
have htg0 := W32.to_uint_cmp tg0.
split; first by move=> j /#.
move=> k1 la sa hk1 [#] hk10 hk14 _ _ _ _ _ hj.
move=> r hr /=.
move=> au0 kf1 nd0 _ kf2 se0 _.
split.
(* The loop invariant at i = 0. *)
+ rewrite ?W32.to_uint0 /=.
  split; first smt().
  split; first exact dvdz0.
  split.
  + by rewrite (ForsPk.ultP _ (2 ^ P.`a)) ?W32.to_uint0 //= ?a_val /(`<<`).
  split; first by rewrite hBe (ForsPk.shlE _ _ _ ht) // a_val.
  split; first by rewrite hr hAe.
  split; first by move=> j hj4; have [-> _] := hj j _; [smt() | rewrite hskA].
  split; first by move=> j hj4; have [_ ->] := hj j _; [smt() | done].
  split; first by move=> z _; rewrite div0z mod0z.
  split; last smt().
  move=> z hz; rewrite div0z /gsibling.
  have hX : 0 <= to_uint tg0 %/ 2 ^ z by apply divz_ge0; [apply expr_gt0; smt() | smt()].
  clear hz; move: hX; move: (to_uint tg0 %/ 2 ^ z) => X hX.
  case: (X = 0) => [h0 | hX0]; first by rewrite h0 mod0z /=.
  by case: (X %% 2 = 0) => h; smt().
(* The loop exit at i = 2^a, then the copies out. *)
move=> au1 b1 c1 i1 la1 m1 na1 nd1 se1 sa1 sk1 tg1 hm [#] hi0 hi1 _ hmore _ _ _ _ _ _ _ hfs hau hsel /=.
have hi2 : to_uint i1 = 2 ^ P.`a.
+ by move: hm hmore hi1; move: (2 ^ P.`a) => Q /#.
split; first by rewrite a_val n_val.
move=> _ r0 hr0 r1 hr1.
split.
+ split; first by rewrite a_val n_val.
  split; last by move=> q /#.
  move=> q hq; rewrite FoldNode.get8_set_sub ifT; first by move: hq; rewrite n_val /= /#.
  by rewrite hr1.
move=> k2 sig2 hk2 [#] hk20 hk21 hinc2 hs2 ha2.
have h8 : 8 * k2 = P.`a * P.`n.
+ by move: hk2 hk21 hinc2 an8; move: (P.`a * P.`n) (P.`a * P.`n %/ 8) => X D /#.
split.
+ have := fs_top N nd1 _; first by rewrite -hi2.
  by rewrite /slot hr0 hNe => <-.
rewrite (sig_cat sig2 au1 se1 hs2 _).
+ by move=> q hq; apply ha2; rewrite h8.
rewrite (hsel _); first by rewrite hi2.
rewrite hBe; congr.
congr; apply/eq_in_map => z /mem_range hz /=.
have hau2 : au N au1 P.`a (2 ^ P.`a) (to_uint tg0) by rewrite -hi2.
by rewrite (au_top N au1 (to_uint tg0) _ hau2 z) ?hNe //; smt().
qed.

(* ------------------------------------------------------------------ *)
(* _fors_tree: termination                                            *)

lemma fors_tree_ll c0 :
  phoare [M._thash_prf_x4 : ctx = c0 ==> true] = 1%r =>
  phoare [M._thash_f_x4 : ctx = c0 ==> true] = 1%r =>
  phoare [M._thash_h : ctx = c0 ==> true] = 1%r =>
  phoare [M._fors_tree : ctx = c0 ==> true] = 1%r.
proof.
move=> hprfl hfl hhl.
have hfoldl := treehash_fold_ll c0 hhl.
have hA : 2 ^ P.`a <= 65536 by rewrite a_val.
proc.
while (true) (inc - k); first by move=> v; auto => /#.
wp; call node_copy_ll; wp; call node_copy_ll; wp.
while (0 <= to_uint i <= 2 ^ P.`a /\ 4 %| to_uint i /\ more = (to_uint i < 2 ^ P.`a) /\ ctx = c0)
      (2 ^ P.`a - to_uint i).
+ move=> v; exlim i => i0.
  seq 15 : (ctx = c0 /\ i = i0 /\ 0 <= to_uint i0 < 2 ^ P.`a /\ 4 %| to_uint i0 /\
            2 ^ P.`a - to_uint i0 = v) 1%r 1%r 0%r _.
  + done.
  + wp; call hprfl; wp.
    while (true) (4 - k).
    + move=> u; wp; call set_tree_index_ll; wp; call set_tree_height_ll; wp.
      by call set_tree_index_ll; auto => /#.
    wp; skip => &hr [#] <- hi0 hi1 h4 hmore hctx hm hv.
    have hlt : to_uint i0 < 2 ^ P.`a by rewrite -hmore.
    move=> k1 sa; split; first smt().
    by move=> _ /=; rewrite ?protectpE hctx /=; split => // _ r; rewrite ?protect32E /=.
  + seq 1 : (ctx = c0 /\ i = i0 /\ 0 <= to_uint i0 < 2 ^ P.`a /\ 4 %| to_uint i0 /\
             2 ^ P.`a - to_uint i0 = v) 1%r 1%r 0%r _.
    + done.
    + if.
      + inline M.__offset64; wp; while (true) (inc - w); first by move=> ?; auto => /#.
        by auto => /#.
      by auto.
    + wp; while (ctx = c0 /\ i = i0 /\ 0 <= k <= 4) (4 - k).
      + move=> u; wp; call hfoldl; wp.
        while (true) (inc - w); first by move=> ?; auto => /#.
        wp; skip => &hr [#] hc hi hk0 hk1 hk hu.
        move=> /= *; split; first smt().
        by move=> _; rewrite ?protectpE ?protect32E hc hi /= /#.
      wp; call hfl; wp; skip => &hr [#] hc hi hi0 hi1 h4 hv.
      rewrite ?protectpE hc hi /=.
      move=> c1 i1 k1; split; first smt().
      move=> hk [#] -> -> hk0 hk1; rewrite ?protect32E /=.
      have hi4 := i4_le (to_uint i0) h4 _; first by split.
      have hiE : to_uint (i0 + W32.of_int 4) = to_uint i0 + 4 by apply lkE.
      have hd : 4 %| (to_uint i0 + 4) by apply dvdzD => //; apply dvdzz.
      rewrite (ForsPk.ultP _ (2 ^ P.`a)); try (by rewrite ?a_val).
      rewrite hiE hd /=.
      by move: hi0 hi4 hv; move: (2 ^ P.`a) => Q /#.
    + hoare; if.
      + inline M.__offset64; wp; while (true); first by auto.
        by auto.
      by auto.
    by [].
  + hoare; wp; call (_ : ctx = c0 ==> true); first by conseq hprfl.
    wp; while (true).
    + wp; call (_ : true ==> true); first by conseq set_tree_index_ll.
      wp; call (_ : true ==> true); first by conseq set_tree_height_ll.
      wp; call (_ : true ==> true); first by conseq set_tree_index_ll.
      by auto.
    wp; skip => &hr [#] <- hi0 hi1 h4 hmore hctx hm hv.
    have hlt : to_uint i0 < 2 ^ P.`a by rewrite -hmore.
    by move=> k1 sa _ /=; rewrite ?protectpE hctx /= => _; rewrite hi0 hlt h4 hv.
  by [].
wp; while (true) (inc - k); first by move=> v; auto => /#.
wp; while (true) (inc - k); first by move=> v; auto => /#.
wp; call copy_ll; wp.
while (true) (4 - k).
+ move=> u; wp; call copy_ll; wp; call ForsPk.copy_kp_ll; wp; call set_tc_ll; wp.
  by call copy_ll; auto => /#.
wp; skip => &hr /= hc k1; split; first smt().
move=> _ /=.
move=> kf1; split; first smt().
move=> _ kf2; split; first smt().
move=> _.
have h2 : 0 < 2 ^ P.`a by apply expr_gt0.
rewrite (ForsPk.ultP _ (2 ^ P.`a)); try (by rewrite ?a_val).
rewrite W32.to_uint0 dvdz0 h2 hc /=.
split; first exact (ltzW _ _ h2).
move=> c1 i1 m1; split.
+ move=> [#] h0 h1 _ -> _ hle; move: h1 hle; move: (2 ^ P.`a) => Q /#.
by move=> _ _ /= k2; smt().
qed.

(* Total correctness: the hoare part under the premises read as hoare
   statements, and termination. *)
lemma fors_tree_correct (pk_seed : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk_seed (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk_seed (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  forall (k0 : Node.t) (a0 : BArray32.t) (t0 tg0 : W32.t) (l tr y kp w1 w0 : int),
  BArray32.to_list a0 = mk_adrs l tr y kp w1 w0 => 0 <= kp < 2 ^ 32 =>
  to_uint t0 < P.`k => to_uint tg0 < 2 ^ P.`a =>
  phoare [M._fors_tree :
    sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ tree = t0 /\ target = tg0 ==>
    Node.to_list res.`2 = fnode pk_seed (Node.to_list k0) l tr y kp (to_uint t0) P.`a 0 /\
    FoldBuf.to_list res.`1 =
      fors_sk P (Node.to_list k0) pk_seed l tr kp (to_uint t0 * 2 ^ P.`a + to_uint tg0) ++
      flatten (map (fun z => fnode pk_seed (Node.to_list k0) l tr y kp (to_uint t0) z (gsibling (to_uint tg0 %/ 2 ^ z)))
                   (range 0 P.`a))] = 1%r.
proof.
move=> hprf hf hh k0 a0 t0 tg0 l tr y kp w1 w0 hA hkp ht htg.
have hprfl : phoare [M._thash_prf_x4 : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim sk_seed, adrs => k1 a1; call (hprf k1 a1); auto.
have hfl : phoare [M._thash_f_x4 : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim x, adrs => x1 a1; call (hf x1 a1); auto.
have hhl : phoare [M._thash_h : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (hh x1 a1); auto.
conseq (fors_tree_ll c0 hprfl hfl hhl)
       (fors_tree_h pk_seed c0 _ _ _ k0 a0 t0 tg0 l tr y kp w1 w0 hA hkp ht htg) => //.
+ by move=> k1 a1; conseq (hprf k1 a1).
+ by move=> x1 a1; conseq (hf x1 a1).
by move=> x1 a1; conseq (hh x1 a1).
qed.
