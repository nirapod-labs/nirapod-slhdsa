(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hypertree.ec
 * ============
 *
 * The hypertree of src/slhdsa/hypertree.jinc: _ht_sign computes
 * ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf) of FIPS 205
 * Algorithm 12 and _ht_verify computes ht_verify(M, SIG_HT, PK.seed,
 * idx_tree, idx_leaf, PK.root) of Algorithm 13.
 *
 * Layers. TreeForms writes both algorithms layer by layer (ht_signE,
 * ht_verifyE): layer j uses the tree index ht_tree j = idx_tree >> j h',
 * the leaf index ht_leaf j (idx_leaf on layer 0, the low h' bits of
 * ht_tree (j - 1) above it) and the address mk_adrs j (ht_tree j) 0 0 0 0.
 * The code runs the same loop over j = 0 .. d - 1 with the indices in two
 * words: it shifts idx_tree right by h' and masks its low 32 bits to
 * h' bits, which keeps exactly those values. Its address starts as zero
 * and only ever has its layer and tree words set, so on layer j it is
 * the spec's address.
 *
 * Signing. Algorithm 12 signs layer j's message and recomputes the root
 * of that tree from the signature with xmss_pkFromSig. The code takes the
 * root from the same treehash pass that produced the signature
 * (_xmss_treehash, Xmss.ec), so its message for layer j + 1 is
 * xmss_node(SK.seed, 0, h', PK.seed, ADRS_j). That is the spec's root by
 * xmss_correct, the equation ht_signE already applies: ht_msg j is that
 * node for j > 0. Each layer's signature is copied into the signature
 * buffer after the FORS signature, at (1 + k (1 + a)) n + j (h' + len) n,
 * the layout of Algorithm 19 line 18 and Figure 13.
 *
 * Verification. Each layer's slice of SIG_HT goes to _xmss_pk_from_sig
 * (XmssPk.ec) with the node of the layer below; the last node is compared
 * with PK.root word by word, and the result is 0 exactly when they are
 * equal.
 *
 * Hash premises. Those of xmss_sign_correct for signing (PRF, F and T_l
 * four-way, and H) and of xmss_pk_from_sig_correct for verification (F,
 * T_l and H), for one fixed PK.seed pk and ctx c0.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorems:
 *     ht_sign_correct     _ht_sign writes ht_sign(M, SK.seed, PK.seed,
 *                         idx_tree, idx_leaf) after the first
 *                         (1 + k (1 + a)) n bytes of the signature, which
 *                         it leaves unchanged, and returns the root of the
 *                         top tree; total correctness.
 *     ht_verify_correct   _ht_verify returns 0 when ht_verify(M, SIG_HT,
 *                         PK.seed, idx_tree, idx_leaf, PK.root) holds and
 *                         all ones otherwise; total correctness.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_WOTS FIPS205_XMSS FIPS205_Hypertree.
require import MerkleTrees_FIPS205 FIPS205_TreeForms.
require import BArray32 BArray128.
require import SetModel CoreExtracted Wots Encoding WotsChain WotsPk WotsLeaf TreeFold XmssPk Xmss.
require ADRS AddressExtracted.

(* ------------------------------------------------------------------ *)
(* The layer and tree setters and the zero address, in this model     *)

lemma core_adrs_zero (a0 : BArray32.t) :
  phoare [M.__adrs_zero : arg = a0 ==> BArray32.to_list res = toByte 0 32] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_zero(adrs{m}) @ &m : BArray32.to_list res = toByte 0 32] =
          Pr[AddressExtracted.M.__adrs_zero(a0) @ &m : BArray32.to_list res = toByte 0 32].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (ADRS.adrs_zero_correct a0).
qed.

lemma core_set_layer (a0 : BArray32.t) (l0 : W32.t) :
  phoare [M.__adrs_set_layer : arg = (a0, l0) ==>
          BArray32.to_list res = setLayerAddress (BArray32.to_list a0) (to_uint l0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_set_layer(adrs{m}, layer{m}) @ &m :
               BArray32.to_list res = setLayerAddress (BArray32.to_list a0) (to_uint l0)] =
          Pr[AddressExtracted.M.__adrs_set_layer(a0, l0) @ &m :
               BArray32.to_list res = setLayerAddress (BArray32.to_list a0) (to_uint l0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_layer_correct a0 l0).
qed.

lemma core_set_tree (a0 : BArray32.t) (t0 : W64.t) :
  phoare [M.__adrs_set_tree : arg = (a0, t0) ==>
          BArray32.to_list res = setTreeAddress (BArray32.to_list a0) (to_uint t0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_set_tree(adrs{m}, tree{m}) @ &m :
               BArray32.to_list res = setTreeAddress (BArray32.to_list a0) (to_uint t0)] =
          Pr[AddressExtracted.M.__adrs_set_tree(a0, t0) @ &m :
               BArray32.to_list res = setTreeAddress (BArray32.to_list a0) (to_uint t0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_tree_correct a0 t0).
qed.

lemma zero_h (a0 : BArray32.t) :
  hoare [M.__adrs_zero : arg = a0 ==> BArray32.to_list res = toByte 0 32].
proof. by conseq (core_adrs_zero a0). qed.

lemma layer_h (a0 : BArray32.t) (l0 : W32.t) : hoare [M.__adrs_set_layer : arg = (a0, l0) ==>
  BArray32.to_list res = setLayerAddress (BArray32.to_list a0) (to_uint l0)].
proof. by conseq (core_set_layer a0 l0). qed.

lemma tree_h (a0 : BArray32.t) (t0 : W64.t) : hoare [M.__adrs_set_tree : arg = (a0, t0) ==>
  BArray32.to_list res = setTreeAddress (BArray32.to_list a0) (to_uint t0)].
proof. by conseq (core_set_tree a0 t0). qed.

lemma adrs_zero_ll : islossless M.__adrs_zero.
proof. proc*; exlim adrs => a; call (core_adrs_zero a); auto. qed.

lemma set_layer_ll : islossless M.__adrs_set_layer.
proof. proc*; exlim adrs, layer => a l; call (core_set_layer a l); auto. qed.

lemma set_tree_ll : islossless M.__adrs_set_tree.
proof. proc*; exlim adrs, tree => a t; call (core_set_tree a t); auto. qed.

(* ------------------------------------------------------------------ *)
(* Sizes and offsets                                                  *)

lemma P_in : P \in parameter_sets by rewrite /P /parameter_sets.

(* The signature buffer: R and SIG_FORS, then SIG_HT (Algorithm 19). *)
op ht_off : int = (1 + P.`k * (1 + P.`a)) * P.`n.

lemma xsl_size : xmss_sig_length P = XmssSig.size.
proof. by rewrite xsig_size /xmss_sig_length; ring. qed.

lemma sig_size : Sig.size = ht_off + P.`d * xmss_sig_length P.
proof. by rewrite /ht_off /xmss_sig_length /len len1_val len2_val n_val k_val a_val d_val hp_val. qed.

lemma htsig_size : HtSig.size = P.`d * xmss_sig_length P.
proof. by rewrite /xmss_sig_length /len len1_val len2_val n_val d_val hp_val. qed.

lemma d_ge1 : 1 <= P.`d by rewrite d_val.
lemma d_lt : P.`d <= 22 by rewrite d_val.
lemma xsl_b : 0 < xmss_sig_length P <= 2400.
proof. by rewrite /xmss_sig_length /len len1_val len2_val n_val hp_val. qed.
lemma xsl_8 : 8 %| xmss_sig_length P.
proof. by rewrite /xmss_sig_length /len len1_val len2_val n_val hp_val. qed.
lemma off_b : 0 <= ht_off /\ ht_off + P.`d * xmss_sig_length P <= 49856.
proof. by rewrite /ht_off /xmss_sig_length /len len1_val len2_val n_val k_val a_val d_val hp_val. qed.

lemma d_ult (x : W32.t) c : P.`d = c => (x \ult W32.of_int c) = (to_uint x < P.`d).
proof. by move=> hc; rewrite (ult_c x c P.`d) //; smt(d_val). qed.

(* The byte offset of layer j: j (h' + len) n, after ht_off in a whole
   signature. *)
lemma layer_off (j : W32.t) c : c = xmss_sig_length P => to_uint j < P.`d =>
  to_uint (zeroextu64 j * W64.of_int c) = to_uint j * xmss_sig_length P.
proof.
move=> -> hj; have hb := xsl_b; have hd := d_lt; have h0 := W32.to_uint_cmp j.
have hM : W64.modulus = 18446744073709551616 by done.
have hj' : to_uint j * xmss_sig_length P <= 22 * 2400 by apply IntOrder.ler_pmul; smt().
rewrite W64.to_uintM_small zext64E W64.of_uintK hM modz_small //; smt().
qed.

lemma sig_off (j : W32.t) c e : c = xmss_sig_length P => e = ht_off => to_uint j < P.`d =>
  to_uint (zeroextu64 j * W64.of_int c + W64.of_int e) = ht_off + to_uint j * xmss_sig_length P.
proof.
move=> hc he hj; have hb := xsl_b; have hd := d_lt; have [ho0 ho1] := off_b.
have h0 := W32.to_uint_cmp j.
have hM : W64.modulus = 18446744073709551616 by done.
have hj' : to_uint j * xmss_sig_length P <= 22 * 2400 by apply IntOrder.ler_pmul; smt().
rewrite W64.to_uintD_small (layer_off j c) // W64.of_uintK he hM modz_small //; smt().
qed.

(* One layer up: idx_leaf <- idx_tree mod 2^h', idx_tree <- idx_tree >> h'
   (Algorithm 12, lines 7 and 8). *)
lemma leaf_up (x : W64.t) c : P.`hp = c =>
  to_uint (truncateu32 x `&` W32.of_int ((1 `<<` c) - 1)) = to_uint x %% 2 ^ P.`hp.
proof.
move=> hc; have hh := hp_lt; rewrite -hc /(`<<`) ifT 1:/# /= W32.to_uint_and_mod 1:/#.
by rewrite /truncateu32 W32.of_uintK modz_dvd.
qed.

lemma tree_up (x : W64.t) c : P.`hp = c => to_uint (x `>>` W8.of_int c) = to_uint x %/ 2 ^ P.`hp.
proof.
move=> hc; have hh := hp_lt; rewrite -hc W64.shr_div W8.of_uintK modz_small //; smt().
qed.

(* ------------------------------------------------------------------ *)
(* The signature buffer, layer by layer                               *)

lemma take_set64d (s : Sig.t) o p (w : W64.t) : 0 <= o <= p =>
  take o (Sig.to_list (Sig.set64d s p w)) = take o (Sig.to_list s).
proof.
move=> ho; apply (eq_from_nth W8.zero); first by rewrite !size_take ?Sig.size_to_list /#.
move=> q; rewrite size_take 1:/# Sig.size_to_list => hq.
rewrite !nth_take 1..4:/# !Sig.get_to_list Sig.get8_set64dE ifF //; smt().
qed.

lemma take_block (s : Sig.t) (x : XmssSig.t) o : 0 <= o => o + XmssSig.size <= Sig.size =>
  (forall q, 0 <= q < XmssSig.size => Sig.get8 s (o + q) = XmssSig.get8 x q) =>
  take XmssSig.size (drop o (Sig.to_list s)) = XmssSig.to_list x.
proof.
move=> ho hs hq; apply (eq_from_nth W8.zero).
+ by rewrite size_take ?size_drop ?Sig.size_to_list ?XmssSig.size_to_list; smt(xsl_b xsl_size).
move=> q hq'; have hq0 : 0 <= q < XmssSig.size.
+ by move: hq'; rewrite size_take ?size_drop ?Sig.size_to_list; smt(xsl_b xsl_size).
rewrite nth_take 1,2:/# nth_drop 1,2:/# Sig.get_to_list XmssSig.get_to_list.
by rewrite ?(addzC q) hq.
qed.

lemma x_ult (x : W64.t) c : c = xmss_sig_length P =>
  (x \ult W64.of_int c) = (to_uint x < xmss_sig_length P).
proof.
move=> ->; have hb := xsl_b; have hM : W64.modulus = 18446744073709551616 by done.
by rewrite W64.ultE W64.of_uintK hM modz_small //; smt().
qed.

lemma add8 (x : W64.t) : to_uint x < 49856 => to_uint (x + W64.of_int 8) = to_uint x + 8.
proof.
move=> h; have h0 := W64.to_uint_cmp x; have hM : W64.modulus = 18446744073709551616 by done.
by rewrite W64.to_uintD_small W64.of_uintK hM (modz_small 8) //; smt().
qed.

lemma lt8 x y : 8 %| x => 8 %| y => x < y => x + 8 <= y.
proof. by move=> /dvdzP [a ->] /dvdzP [b ->]; smt(). qed.

(* The signature of layer j (ht_signE). *)
op hsg (pk m sk : bytes) (it il : int) (j : int) : bytes =
  xmss_sign P (ht_msg P m sk pk it j) sk (ht_leaf P it il j) pk (mk_adrs j (ht_tree P it j) 0 0 0 0).

lemma flat_step (f : int -> bytes) j : 0 <= j =>
  flatten (map f (range 0 (j + 1))) = flatten (map f (range 0 j)) ++ f j.
proof. by move=> hj; rewrite rangeSr 1:/# map_rcons -cats1 flatten_cat flatten_seq1. qed.

(* ------------------------------------------------------------------ *)
(* _ht_sign (Algorithm 12)                                            *)

(* On entry to layer j the indices, the message and the address are those
   of layer j, and the signature holds its first ht_off bytes unchanged
   followed by the signatures of layers 0 .. j - 1. The copy loop moves
   layer j's signature in 8-byte words to ht_off + j (h' + len) n. *)
lemma ht_sign_h (pk : bytes) c0 :
  (forall (r0 : Node.t) (s0 : XmssSig.t) (k0 : Node.t) (a0 : BArray32.t) (tg0 : W32.t)
          (st0 : WotsDigits.t) (m0 : Node.t),
   hoare [M._xmss_treehash :
     root = r0 /\ sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
     steps = st0 /\ to_uint tg0 < 2 ^ P.`hp /\
     map W8.to_uint (WotsDigits.to_list st0) = wots_digits P (Node.to_list m0) ==>
     Node.to_list res.`1 = xmss_node P (Node.to_list k0) 0 P.`hp pk (BArray32.to_list a0) /\
     XmssSig.to_list res.`2 =
       xmss_sign P (Node.to_list m0) (Node.to_list k0) (to_uint tg0) pk (BArray32.to_list a0)]) =>
  forall (s0 : Sig.t) (m0 k0 : Node.t) (it0 : W64.t) (il0 : W32.t),
  to_uint il0 < 2 ^ P.`hp =>
  hoare [M._ht_sign :
    sig = s0 /\ msg = m0 /\ sk_seed = k0 /\ ctx = c0 /\ idx_tree = it0 /\ idx_leaf = il0 ==>
    take (ht_off + P.`d * xmss_sig_length P) (Sig.to_list res.`1) =
      take ht_off (Sig.to_list s0) ++
      flatten (map (hsg pk (Node.to_list m0) (Node.to_list k0) (to_uint it0) (to_uint il0))
                   (range 0 P.`d)) /\
    Node.to_list res.`2 = ht_msg P (Node.to_list m0) (Node.to_list k0) pk (to_uint it0) P.`d].
proof.
move=> hx s0 m0 k0 it0 il0 hil.
have hb := xsl_b; have h8 := xsl_8; have hd1 := d_ge1; have hd2 := d_lt; have [ho0 ho1] := off_b.
have hss := sig_size; have hxs := xsl_size.
proc.
wp.
while (sk_seed = k0 /\ ctx = c0 /\ 0 <= to_uint j <= P.`d /\ more = (to_uint j < P.`d) /\
       to_uint idx_tree = ht_tree P (to_uint it0) (to_uint j) /\
       to_uint idx_leaf = ht_leaf P (to_uint it0) (to_uint il0) (to_uint j) /\
       Node.to_list msg = ht_msg P (Node.to_list m0) (Node.to_list k0) pk (to_uint it0) (to_uint j) /\
       (forall x y, setTreeAddress (setLayerAddress (BArray32.to_list adrs) x) y = mk_adrs x y 0 0 0 0) /\
       take (ht_off + to_uint j * xmss_sig_length P) (Sig.to_list sig) =
         take ht_off (Sig.to_list s0) ++ flatten (map (hsg pk (Node.to_list m0) (Node.to_list k0) (to_uint it0) (to_uint il0)) (range 0 (to_uint j)))).
+ inline M.__hook_ht_root M.__offset; wp.
  while (sk_seed = k0 /\ ctx = c0 /\ 0 <= to_uint j < P.`d /\
         to_uint idx_tree = ht_tree P (to_uint it0) (to_uint j) /\
         Node.to_list msg =
           ht_msg P (Node.to_list m0) (Node.to_list k0) pk (to_uint it0) (to_uint j + 1) /\
         BArray32.to_list adrs = mk_adrs (to_uint j) (ht_tree P (to_uint it0) (to_uint j)) 0 0 0 0 /\
         XmssSig.to_list src =
           hsg pk (Node.to_list m0) (Node.to_list k0) (to_uint it0) (to_uint il0) (to_uint j) /\
         0 <= to_uint k <= xmss_sig_length P /\ 8 %| to_uint k /\
         to_uint off = ht_off + to_uint j * xmss_sig_length P /\
         copy = (to_uint k < xmss_sig_length P) /\
         take (ht_off + to_uint j * xmss_sig_length P) (Sig.to_list sig) =
           take ht_off (Sig.to_list s0) ++
           flatten (map (hsg pk (Node.to_list m0) (Node.to_list k0) (to_uint it0) (to_uint il0))
                        (range 0 (to_uint j))) /\
         forall q, 0 <= q < to_uint k =>
           Sig.get8 sig (ht_off + to_uint j * xmss_sig_length P + q) = XmssSig.get8 src q).
  + wp; skip => &m [#] 2!-> hj0 hj1 hit hmsg hadr hsrc hk0 hk1 hk8 hoff -> hpre hq hlt /=.
    have hJX : to_uint j{m} * xmss_sig_length P + xmss_sig_length P <= P.`d * xmss_sig_length P.
    + by have := StdOrder.IntOrder.ler_wpmul2r (xmss_sig_length P) _ (to_uint j{m} + 1) P.`d _; smt().
    have ek := add8 k{m} _; first smt().
    have eo : to_uint (off{m} + k{m}) = to_uint off{m} + to_uint k{m}.
    + by rewrite W64.to_uintD_small //; smt().
    have hk8' := lt8 _ _ hk8 h8 hlt.
    rewrite (x_ult _ _ _); first by rewrite /xmss_sig_length /len len1_val len2_val n_val hp_val.
    rewrite ek eo hit hmsg hadr hsrc /=.
    do 4!(split; first smt(dvdzD dvdzz)).
    split; first by rewrite take_set64d 1:/# hpre.
    move=> q hq0; rewrite Sig.get8_set64dE.
    case: (to_uint k{m} <= q) => hqk.
    + have hjX0 : 0 <= to_uint j{m} * xmss_sig_length P.
      + by apply StdOrder.IntOrder.mulr_ge0; smt().
      have hc : (to_uint off{m} + to_uint k{m} <= ht_off + to_uint j{m} * xmss_sig_length P + q <
                 to_uint off{m} + to_uint k{m} + 8) /\
                0 <= ht_off + to_uint j{m} * xmss_sig_length P + q < Sig.size.
      + by rewrite hoff hss; smt().
      rewrite ifT 1:hc.
      by rewrite XmssSig.get64d_byte 1:/#; congr; smt().
    by rewrite ifF; [smt() | apply hq; smt()].
  wp; ecall (hx msg layer sk_seed adrs leaf digits msg); wp.
  ecall (wots_digits_h msg); ecall (tree_h adrs idx_tree); ecall (layer_h adrs j); wp; skip.
  move=> &m [#] 2!-> hj0 hj1 hmore hit hlf hmsg hadr hpre hm ms1 a1 ha1 a2 ha2 dg hdg.
  have hjd : to_uint j{m} < P.`d by rewrite -hmore.
  have hA : BArray32.to_list a2 =
            mk_adrs (to_uint j{m}) (ht_tree P (to_uint it0) (to_uint j{m})) 0 0 0 0.
  + by rewrite ha2 ha1 hit hadr.
  have hhp0 : 0 <= P.`hp by rewrite hp_val.
  have hj1' : to_uint j{m} + 1 - 1 = to_uint j{m} by ring.
  have hnext : xmss_node P (Node.to_list k0) 0 P.`hp pk (BArray32.to_list a2) =
               ht_msg P (Node.to_list m0) (Node.to_list k0) pk (to_uint it0) (to_uint j{m} + 1).
  + by rewrite hA /ht_msg ifF 1:/# hj1'.
  split.
  + rewrite hlf; have := ht_leaf_range P (to_uint it0) (to_uint il0) (to_uint j{m}) _.
    + by have := W32.to_uint_cmp il0; smt().
    smt().
  move=> _ [r sx ms2] /= [hr hs].
  have hsx : XmssSig.to_list sx =
             hsg pk (Node.to_list m0) (Node.to_list k0) (to_uint it0) (to_uint il0) (to_uint j{m}).
  + by rewrite hs /hsg hmsg hlf hA.
  split.
  + split; first smt().
    split; first exact hit.
    split; first by rewrite hr hnext.
    split; first exact hA.
    split; first exact hsx.
    split; first smt().
    split; first exact dvdz0.
    split; last first.
    + by split; [smt() | split; [exact hpre | smt()]].
    rewrite (sig_off j{m} _ _ _ _ hjd) //.
    by rewrite /xmss_sig_length /len len1_val len2_val n_val hp_val.
  move=> copy0 k1 sig0 hc [#] _ _ _ _ _ _ hk0 hk1 _ _ hcp hpre' hq'.
  have hkX : to_uint k1 = xmss_sig_length P by smt().
  have hj32 := inc32 j{m} P.`d _ _; 1,2: smt(d_lt).
  rewrite (d_ult _ _ _); first by rewrite d_val.
  rewrite hj32.
  rewrite (tree_up _ _ _); first by rewrite hp_val.
  rewrite (leaf_up _ _ _); first by rewrite hp_val.
  rewrite hit ht_treeS // /ht_leaf ifF 1:/# hj1' hr hnext /=.
  split; first smt().
  split.
  + by move=> x y; rewrite hA setLayerAddressE setTreeAddressE.
  have -> : ht_off + (to_uint j{m} + 1) * xmss_sig_length P =
            (ht_off + to_uint j{m} * xmss_sig_length P) + xmss_sig_length P by ring.
  have hjX0 : 0 <= to_uint j{m} * xmss_sig_length P by apply StdOrder.IntOrder.mulr_ge0; smt().
  rewrite take_add 1,2:/# hpre' flat_step // -catA; congr; congr.
  have hJX : to_uint j{m} * xmss_sig_length P + xmss_sig_length P <= P.`d * xmss_sig_length P.
  + by have := StdOrder.IntOrder.ler_wpmul2r (xmss_sig_length P) _ (to_uint j{m} + 1) P.`d _; smt().
  have := take_block sig0 sx (ht_off + to_uint j{m} * xmss_sig_length P) _ _ _.
  + smt().
  + by rewrite -hxs; smt().
  + by move=> q hq0; apply hq'; smt().
  by rewrite -hxs hsx.
wp; ecall (zero_h adrs); wp; skip => &m /> r hr.
split.
+ split; first by move=> x y; rewrite hr mk_adrs0 setLayerAddressE setTreeAddressE.
  by rewrite range_geq // flatten_nil cats0.
move=> a1 l1 t1 j1 m1 mg1 sg1 _ hj0 hj1 hjd _ _ hmg _ hpre.
have hjD : to_uint j1 = P.`d by smt().
by move: hpre hmg; rewrite hjD.
qed.

lemma ht_sign_ll c0 :
  phoare [M._xmss_treehash : ctx = c0 ==> true] = 1%r =>
  phoare [M._ht_sign : ctx = c0 ==> true] = 1%r.
proof.
move=> hxl; have hb := xsl_b; have h8 := xsl_8; have hd1 := d_ge1; have hd2 := d_lt.
proc; wp.
while (ctx = c0 /\ 0 <= to_uint j <= P.`d /\ more = (to_uint j < P.`d)) (P.`d - to_uint j).
+ move=> v; inline M.__hook_ht_root M.__offset; wp.
  while (ctx = c0 /\ 0 <= to_uint j < P.`d /\ P.`d - to_uint j = v /\
         0 <= to_uint k <= xmss_sig_length P /\ 8 %| to_uint k /\
         copy = (to_uint k < xmss_sig_length P)) (xmss_sig_length P - to_uint k).
  + move=> v2; wp; skip => &m [#] -> hj0 hj1 hv hk0 hk1 hk8 -> hlt hv2 /=.
    have ek := add8 k{m} _; first smt().
    have hk8' := lt8 _ _ hk8 h8 hlt.
    rewrite (x_ult _ _ _); first by rewrite /xmss_sig_length /len len1_val len2_val n_val hp_val.
    rewrite ek; smt(dvdzD dvdzz).
  wp; call hxl; wp; call wots_digits_ll; call set_tree_ll; call set_layer_ll; wp; skip.
  move=> &m [#] -> hj0 hj1 -> hjd hv /=.
  split; first smt(dvdz0).
  move=> c1 k1; split; first smt().
  move=> hc _.
  have hj32 := inc32 j{m} P.`d _ _; 1,2: smt().
  rewrite (d_ult _ _ _); first by rewrite d_val.
  rewrite hj32; smt().
wp; call adrs_zero_ll; wp; skip => &m -> /=.
split; first smt(d_ult d_val).
move=> j1 m1; smt().
qed.

lemma ht_sign_correct (pk : bytes) c0 :
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
  forall (s0 : Sig.t) (m0 k0 : Node.t) (it0 : W64.t) (il0 : W32.t),
  to_uint il0 < 2 ^ P.`hp =>
  phoare [M._ht_sign :
    sig = s0 /\ msg = m0 /\ sk_seed = k0 /\ ctx = c0 /\ idx_tree = it0 /\ idx_leaf = il0 ==>
    Sig.to_list res.`1 =
      take ht_off (Sig.to_list s0) ++
      ht_sign P (Node.to_list m0) (Node.to_list k0) pk (to_uint it0) (to_uint il0) /\
    Node.to_list res.`2 =
      xmss_node P (Node.to_list k0) 0 P.`hp pk
        (mk_adrs (P.`d - 1) (ht_tree P (to_uint it0) (P.`d - 1)) 0 0 0 0)] = 1%r.
proof.
move=> hprf hf htl hh s0 m0 k0 it0 il0 hil.
have hxl := xmss_treehash_ll pk c0 hprf hf htl hh.
have hx : forall (r0 : Node.t) (s1 : XmssSig.t) (k1 : Node.t) (a0 : BArray32.t) (tg0 : W32.t)
                 (st0 : WotsDigits.t) (m1 : Node.t),
  hoare [M._xmss_treehash :
    root = r0 /\ sig = s1 /\ sk_seed = k1 /\ ctx = c0 /\ adrs = a0 /\ target = tg0 /\
    steps = st0 /\ to_uint tg0 < 2 ^ P.`hp /\
    map W8.to_uint (WotsDigits.to_list st0) = wots_digits P (Node.to_list m1) ==>
    Node.to_list res.`1 = xmss_node P (Node.to_list k1) 0 P.`hp pk (BArray32.to_list a0) /\
    XmssSig.to_list res.`2 =
      xmss_sign P (Node.to_list m1) (Node.to_list k1) (to_uint tg0) pk (BArray32.to_list a0)].
+ by move=> r0 s1 k1 a0 tg0 st0 m1; conseq (xmss_sign_correct pk c0 hprf hf htl hh r0 s1 k1 a0 tg0 st0 m1).
conseq (ht_sign_ll c0 hxl) (ht_sign_h pk c0 hx s0 m0 k0 it0 il0 hil) => //.
move=> &m _ r; split; first by move=> [_ h].
move=> [_ [hs hm]]; split; last by split.
have hd1 := d_ge1; have hss := sig_size.
split.
+ rewrite -(take_oversize (ht_off + P.`d * xmss_sig_length P) (Sig.to_list r.`1)).
  + by rewrite Sig.size_to_list -hss.
  rewrite hs ht_signE 1:P_in; first by have := W32.to_uint_cmp il0; smt().
  by congr.
by rewrite hm /ht_msg ifF 1:/#.
qed.
