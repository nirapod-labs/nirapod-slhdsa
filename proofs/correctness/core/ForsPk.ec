(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ForsPk.ec
 * =========
 *
 * _fors_pk_from_sig of src/slhdsa/fors.jinc computes fors_pkFromSig of
 * FIPS 205 Algorithm 17.
 *
 * The code takes the k indices already decoded from the digest (they are
 * base_2b(md, a, k), DigestIndices.fors_indices_correct) and the caller's
 * ADRS, whose tree height and tree index it overwrites. Write the ADRS as
 * mk_adrs l t y kp w1 w0 (adrs_split); then FIPS205_TreeForms.
 * fors_pkFromSigE gives Algorithm 17 as T_k of the k roots fors_root i,
 * each a gfold over the a heights of tree i.
 *
 * Tree i. The leaf is F of the secret at bytes i (a + 1) n, under ADRS
 * index g = i 2^a + idx_i. The climb keeps three counters in step with
 * the height z: idx = idx_i >> z, g = (i 2^a + idx_i) >> z, and the ADRS
 * mk_adrs l t y kp z g. Bit z of idx_i decides the order of the pair, as
 * bit z of g does in gfold (bit_shift: the bits of i 2^a are above a).
 * The loop invariant is that node is gfold of the first z heights.
 *
 * Roots. Root i is written at bytes i n of roots; the outer invariant is
 * that the first i n bytes are roots 0 .. i - 1, concatenated. The T_k
 * address is built from the caller's ADRS, which the climb never changes
 * outside the tree height and index words.
 *
 * Hash premises. F, H and T_k enter as hypotheses for one fixed PK.seed
 * and ctx, in the shape of the per-family thash theorems, as in
 * WotsPk.ec. The theorem is the hoare part (fors_pk_from_sig_h) and the
 * termination (fors_pk_from_sig_ll) combined.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorem:
 *     fors_pk_from_sig_correct   given the F, H and T_k premises,
 *                                _fors_pk_from_sig returns
 *                                fors_pkFromSig(sig, md, PK.seed, ADRS)
 *                                when the indices are base_2b(md, a, k);
 *                                total correctness.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Params FIPS205_Encoding FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_FORS.
require import MerkleTrees_FIPS205 FIPS205_TreeForms.
require import BArray32.
require import SetModel CoreExtracted Encoding WotsChain WotsPk TreeFold.
require ADRS AddressExtracted Validate_Encoding.
import StdOrder.IntOrder.

(* ------------------------------------------------------------------ *)
(* ADRS setters of the FORS code, moved to this set's model           *)

lemma core_copy_keypair (d0 s0 : BArray32.t) :
  phoare [M.__adrs_copy_keypair : arg = (d0, s0) ==>
          BArray32.to_list res =
            setKeyPairAddress (BArray32.to_list d0) (getKeyPairAddress (BArray32.to_list s0))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_copy_keypair(dst{m}, src{m}) @ &m :
               BArray32.to_list res =
                 setKeyPairAddress (BArray32.to_list d0) (getKeyPairAddress (BArray32.to_list s0))] =
          Pr[AddressExtracted.M.__adrs_copy_keypair(d0, s0) @ &m :
               BArray32.to_list res =
                 setKeyPairAddress (BArray32.to_list d0) (getKeyPairAddress (BArray32.to_list s0))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_copy_keypair_correct d0 s0).
qed.

(* Hoare and lossless forms. *)
lemma th_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_tree_height : arg = (a0, i0) ==>
  BArray32.to_list res = setTreeHeight (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_tree_height a0 i0). qed.

lemma ti_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_tree_index : arg = (a0, i0) ==>
  BArray32.to_list res = setTreeIndex (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_tree_index a0 i0). qed.

lemma ckp_h (d0 s0 : BArray32.t) : hoare [M.__adrs_copy_keypair : arg = (d0, s0) ==>
  BArray32.to_list res = setKeyPairAddress (BArray32.to_list d0) (getKeyPairAddress (BArray32.to_list s0))].
proof. by conseq (core_copy_keypair d0 s0). qed.

lemma cp_h (d0 s0 : BArray32.t) :
  hoare [M.__adrs_copy : arg = (d0, s0) ==> BArray32.to_list res = BArray32.to_list s0].
proof. by conseq (core_copy d0 s0). qed.

lemma tc4_h (a0 : BArray32.t) : hoare [M.__adrs_set_type_and_clear : arg = (a0, 4) ==>
  BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) 4].
proof. by conseq (core_set_type_and_clear a0 4 _). qed.

lemma set_th_ll : islossless M.__adrs_set_tree_height.
proof. proc*; exlim adrs, height => a i; call (core_set_tree_height a i); auto. qed.

lemma set_ti_ll : islossless M.__adrs_set_tree_index.
proof. proc*; exlim adrs, index => a i; call (core_set_tree_index a i); auto. qed.

lemma copy_kp_ll : islossless M.__adrs_copy_keypair.
proof. proc*; exlim dst, src => a b; call (core_copy_keypair a b); auto. qed.

(* The SLH operations are the identity on values. *)
lemma fprot32E (x : W32.t) (m : W64.t) : SLH64.protect_32 x m = x by done.
lemma fprot64E (x : W64.t) (m : W64.t) : SLH64.protect_64 x m = x by done.
lemma fprotpE (x : 'a) (m : W64.t) : SLH64.protect_ptr x m = x by done.
hint simplify fprot32E, fprot64E, fprotpE.

(* ------------------------------------------------------------------ *)
(* Addresses as mk_adrs                                               *)

lemma slice_cat2 (x : bytes) i j k : 0 <= i <= j => j <= k =>
  slice x i j ++ slice x j k = slice x i k.
proof.
move=> hij hjk; rewrite /slice.
have -> : drop j x = drop (j - i) (drop i x) by rewrite drop_drop /#.
by rewrite -takeD 1,2:/#; congr; ring.
qed.

(* Every 32-byte address is mk_adrs of its six fields. *)
op fld (a : adrs) (i j : int) : int = toInt (slice a i j) (j - i).

lemma adrs_split (a : adrs) : size a = 32 =>
  a = mk_adrs (fld a 0 4) (fld a 4 16) (fld a 16 20) (fld a 20 24) (fld a 24 28) (fld a 28 32).
proof.
move=> ha; rewrite /mk_adrs /fld /= !ADRS.toByte_toInt; 1..6: by rewrite size_slice // ha.
by rewrite !slice_cat2 // /slice drop0 take_oversize // ha.
qed.

lemma fld_range (a : adrs) i : size a = 32 => 0 <= i <= 28 => 0 <= fld a i (i + 4) < 2 ^ 32.
proof.
move=> ha hi; have hs : size (slice a i (i + 4)) = 4 by rewrite size_slice // /#.
have h1 := ADRS.toByte_toInt (slice a i (i + 4)) 4 hs.
have hf : fld a i (i + 4) = toInt (slice a i (i + 4)) 4 by rewrite /fld (_ : i + 4 - i = 4) 1:/#.
have h2 := toInt_toByte (toInt (slice a i (i + 4)) 4) 4 _ => //.
move: h2; rewrite h1 => h2; rewrite hf h2.
have h256 : 256 ^ 4 = W32.modulus by done.
by rewrite h256; smt(modz_ge0 ltz_pmod).
qed.

lemma take24_mk l t y w2 w1 w0 v1 v0 :
  take 24 (mk_adrs l t y w2 w1 w0) = take 24 (mk_adrs l t y w2 v1 v0).
proof. by rewrite /mk_adrs; do ! (rewrite !take_cat !size_cat /=); rewrite !take0 !cats0. qed.

lemma shsc_take (x y : adrs) v1 v0 : 24 <= size x => take 24 x = take 24 y =>
  setHashAddress (setChainAddress x v1) v0 = setHashAddress (setChainAddress y v1) v0.
proof. by move=> hx h; apply sha_eq; apply take28_sca. qed.

(* ------------------------------------------------------------------ *)
(* Byte-array views                                                   *)

lemma slice_slice (x : bytes) b e i j : 0 <= b => 0 <= i <= j => j <= e - b =>
  slice (slice x b e) i j = slice x (b + i) (b + j).
proof.
move=> hb hij hj; rewrite /slice drop_take 1,2:/# take_take drop_drop 1,2:/#.
by rewrite (_ : j - i <= e - b - i) 1:/# /= (_ : b + j - (b + i) = j - i) 1:/# (addzC i b).
qed.

lemma fsig_size : ForsSig.size = P.`k * (P.`a + 1) * P.`n.
proof. by rewrite k_val a_val n_val. qed.

lemma tk_size : TKIn.size = P.`k * P.`n.
proof. by rewrite k_val n_val. qed.

lemma fsig_sub (s : ForsSig.t) o : 0 <= o => o + P.`n <= ForsSig.size =>
  Node.to_list (ForsSigNode.get_sub s o) = slice (ForsSig.to_list s) o (o + P.`n).
proof.
move=> ho hs; have hn := n_val; apply (eq_from_nth W8.zero).
+ rewrite Node.size_to_list /slice size_take; first smt().
  by rewrite size_drop; [smt() | rewrite ForsSig.size_to_list; smt()].
rewrite Node.size_to_list => q hq; rewrite Node.get_to_list ForsSigNode.get8_get_sub.
rewrite /slice nth_take; 1,2:smt(). rewrite nth_drop; 1,2:smt().
by rewrite ForsSig.get_to_list; smt().
qed.

lemma tk_take_set_sub (r : TKIn.t) (c : Node.t) j : 0 <= j < P.`k =>
  take ((j + 1) * P.`n) (TKIn.to_list (TKNode.set_sub r (j * P.`n) c)) =
  take (j * P.`n) (TKIn.to_list r) ++ Node.to_list c.
proof.
move=> hj; have hn := n_val; have hk := k_val; have hts := tk_size.
apply (eq_from_nth W8.zero).
+ rewrite size_cat Node.size_to_list !size_take; 1,2:smt().
  by rewrite !TKIn.size_to_list; move: hj hn hk hts; move: (P.`k) (P.`n) => K N /#.
rewrite size_take; 1:smt(); rewrite TKIn.size_to_list => q hq.
rewrite nth_take; 1,2:smt(); rewrite TKIn.get_to_list TKNode.get8_set_sub.
rewrite nth_cat size_take; 1:smt(); rewrite TKIn.size_to_list.
have hjn : (if j * P.`n < max 0 TKIn.size then j * P.`n else max 0 TKIn.size) = j * P.`n.
+ by move: hj hn hk hts; move: (P.`k) (P.`n) => K N /#.
rewrite hjn; case: (q < j * P.`n) => hq2 /=.
+ have -> /= : !(j * P.`n <= q) by smt().
  by rewrite nth_take 1,2:/# TKIn.get_to_list.
have -> /= : (j * P.`n <= q < j * P.`n + Node.size) /\ (0 <= q < TKIn.size).
+ by move: hj hn hk hts hq hq2; move: (P.`k) (P.`n) => K N /#.
done.
qed.

(* ------------------------------------------------------------------ *)
(* Word arithmetic of the climb                                       *)

lemma ka_bound : P.`k * 2 ^ P.`a <= 2 ^ 32.
proof. by rewrite k_val a_val. qed.

lemma a_lt32 : 0 < P.`a < 32 by rewrite a_val.

lemma shlE (x : W32.t) c : c = P.`a => to_uint x < P.`k =>
  to_uint (x `<<` W8.of_int c) = to_uint x * 2 ^ P.`a.
proof.
move=> -> hx; have ha : 0 <= P.`a < W32.size by rewrite a_val.
have ha0 : 0 <= P.`a by rewrite a_val.
have h0 := W32.to_uint_cmp x; have hk : P.`k * 2 ^ P.`a <= 4294967296 by rewrite k_val a_val.
have hp : 0 < 2 ^ P.`a by apply expr_gt0.
have hm : to_uint x * 2 ^ P.`a < P.`k * 2 ^ P.`a by apply ltr_pmul2r.
have hb : 0 <= to_uint x * 2 ^ P.`a < `|W32.modulus| by smt().
by rewrite W32.shl_shlw // W32.to_uint_shl // (modz_small _ _ hb).
qed.

lemma shr1E (x : W32.t) : to_uint (x `>>` W8.of_int 1) = to_uint x %/ 2.
proof. by rewrite W32.shr_div_le // expr1. qed.

lemma bit1E (x : W32.t) : (x `&` W32.of_int 1 = W32.of_int 1) = (to_uint x %% 2 <> 0).
proof.
have h := W32.to_uint_and_mod 1 x _ => //; move: h; rewrite expr1 /= => h.
apply eq_iff; split => [he|hne].
+ by have := congr1 W32.to_uint _ _ he; rewrite h W32.of_uintK => ->.
apply W32.to_uint_eq; rewrite h W32.of_uintK /=; smt(modz_ge0 ltz_pmod).
qed.

lemma offG (x : W32.t) c : 0 <= c < W32.modulus => to_uint x * c < W32.modulus =>
  to_uint (zeroextu64 x * W64.of_int c) = to_uint x * c.
proof.
move=> hc hx; have h0 := W32.to_uint_cmp x; have hm : W32.modulus < `|W64.modulus| by done.
have hm2 : W32.modulus * W32.modulus <= W64.modulus by done.
have hc64 : to_uint (W64.of_int c) = c.
+ rewrite W64.of_uintK; apply modz_small.
  by move: hc hm => [h1 h2] h3; split => // _; exact (ltz_trans _ _ _ h2 h3).
have hm3 : W32.modulus < W64.modulus by done.
rewrite W64.to_uintM_small zext64E hc64 //.
exact (ltz_trans _ _ _ hx hm3).
qed.

lemma add64 (x y : W64.t) : to_uint x + to_uint y < 2 ^ 64 => to_uint (x + y) = to_uint x + to_uint y.
proof. by move=> h; rewrite W64.to_uintD_small. qed.

(* ------------------------------------------------------------------ *)
(* The FORS tree root of Algorithm 17, one height at a time           *)

lemma gfold0 (T : int -> int -> bytes -> bytes -> bytes) au g leaf : gfold T au g leaf 0 = leaf.
proof. by rewrite /gfold range_geq. qed.

lemma ultP (x : W32.t) v c : v = c => 0 <= c < W32.modulus => (x \ult W32.of_int c) = (to_uint x < v).
proof. by move=> -> hc; rewrite W32.ultE W32.of_uintK (pmod_small _ _ hc). qed.

lemma inc32o (x : W32.t) : to_uint x + 1 < W32.modulus => to_uint (x + W32.one) = to_uint x + 1.
proof. by move=> hx; rewrite W32.to_uintD_small; rewrite W32.to_uint1. qed.

lemma gfold_step (T : int -> int -> bytes -> bytes -> bytes) au g leaf z :
  0 <= z =>
  gfold T au g leaf (z + 1) =
  if (g %/ 2 ^ z) %% 2 = 0 then T (z + 1) (g %/ 2 ^ (z + 1)) (gfold T au g leaf z) (au z)
  else T (z + 1) (g %/ 2 ^ (z + 1)) (au z) (gfold T au g leaf z).
proof. by move=> hz; rewrite gfoldS. qed.

(* ------------------------------------------------------------------ *)
(* Offsets of the climb, at the literal sizes of the set              *)

lemma g_bound i x : 0 <= i < P.`k => 0 <= x < 2 ^ P.`a => 0 <= i * 2 ^ P.`a + x < W32.modulus.
proof.
move=> hi hx; have hp : 0 < 2 ^ P.`a by apply expr_gt0.
have h1 : (i + 1) * 2 ^ P.`a <= P.`k * 2 ^ P.`a by apply ler_pmul2r => /#.
have hk : P.`k * 2 ^ P.`a <= W32.modulus by rewrite k_val a_val.
have h2 : 0 <= i * 2 ^ P.`a by apply mulr_ge0 => /#.
have he : (i + 1) * 2 ^ P.`a = i * 2 ^ P.`a + 2 ^ P.`a by ring.
move: hi hx hp h1 hk h2 he; move: (P.`k) (2 ^ P.`a) (i * 2 ^ P.`a) => K Q I; smt().
qed.

lemma gE (t x : W32.t) c : P.`a = c => to_uint t < P.`k => to_uint x < 2 ^ P.`a =>
  to_uint ((t `<<` W8.of_int c) + x) = to_uint t * 2 ^ P.`a + to_uint x.
proof.
move=> hc ht hx; have h0 := W32.to_uint_cmp t; have h1 := W32.to_uint_cmp x.
have hx0 : 0 <= to_uint x < 2 ^ P.`a by smt().
have ht0 : 0 <= to_uint t < P.`k by smt().
have hb := g_bound (to_uint t) (to_uint x) ht0 hx0.
have hc' : c = P.`a by rewrite hc.
rewrite W32.to_uintD_small (shlE t c hc' ht) //.
by move: hb; move: (to_uint t * 2 ^ P.`a) => I /#.
qed.

lemma fsig_small : P.`k * (P.`a + 1) * P.`n < W32.modulus by rewrite k_val a_val n_val.

lemma soffE (t : W32.t) c1 c2 : P.`a = c1 => P.`n = c2 => to_uint t < P.`k =>
  to_uint (zeroextu64 t * W64.of_int ((c1 + 1) * c2)) = to_uint t * (P.`a + 1) * P.`n.
proof.
move=> <- <- ht; have h0 := W32.to_uint_cmp t; have hs := fsig_small.
have hp : 0 < (P.`a + 1) * P.`n by rewrite a_val n_val.
have hm : to_uint t * ((P.`a + 1) * P.`n) <= P.`k * ((P.`a + 1) * P.`n) by apply ler_pmul2r => /#.
have e : P.`k * ((P.`a + 1) * P.`n) = P.`k * (P.`a + 1) * P.`n by ring.
rewrite offG; last by ring.
+ by move: hp hs e; move: (P.`k * (P.`a + 1) * P.`n) ((P.`a + 1) * P.`n) => F Q /#.
by move: hm hp hs e; move: (P.`k * (P.`a + 1) * P.`n) (to_uint t * ((P.`a + 1) * P.`n)) (P.`k * ((P.`a + 1) * P.`n)) => F T G /#.
qed.

lemma roffE (t : W32.t) c : P.`n = c => to_uint t < P.`k =>
  to_uint (zeroextu64 t * W64.of_int c) = to_uint t * P.`n.
proof.
move=> <- ht; have h0 := W32.to_uint_cmp t; have hs := fsig_small.
have hp : 0 < P.`n by rewrite n_val.
have hm : to_uint t * P.`n <= P.`k * P.`n by apply ler_pmul2r => /#.
have hm2 : P.`k * P.`n <= P.`k * (P.`a + 1) * P.`n by rewrite k_val a_val n_val.
rewrite offG //.
by move: hp hs hm hm2; move: (P.`n) (P.`k * (P.`a + 1) * P.`n) (P.`k * P.`n) (to_uint t * P.`n) => N F G T /#.
qed.

lemma aoffE (z : W32.t) (so : W64.t) i c : P.`n = c => to_uint z < P.`a => 0 <= i < P.`k =>
  to_uint so = i * (P.`a + 1) * P.`n =>
  to_uint (zeroextu64 z * W64.of_int c + so + W64.of_int c) = to_uint z * P.`n + i * (P.`a + 1) * P.`n + P.`n.
proof.
move=> <- hz hi hso; have h0 := W32.to_uint_cmp z; have hn := n_val.
have hM : W32.modulus = 4294967296 by done.
have hM64 : W64.modulus = 18446744073709551616 by done.
have hm : to_uint z * P.`n <= P.`a * P.`n by apply ler_pmul2r => /#.
have hm1 : i * (P.`a + 1) * P.`n <= P.`k * (P.`a + 1) * P.`n.
+ by rewrite -!mulrA; apply ler_pmul2r; [rewrite a_val n_val | smt()].
have hs : P.`a * P.`n + P.`k * (P.`a + 1) * P.`n + P.`n < 4294967296 by rewrite a_val k_val n_val.
have hi0 : 0 <= i * (P.`a + 1) * P.`n by apply mulr_ge0; [apply mulr_ge0 | ] => /#.
have hF : 0 <= P.`k * (P.`a + 1) * P.`n /\ 0 < P.`n by rewrite k_val a_val n_val.
have hc : to_uint (W64.of_int P.`n) = P.`n by rewrite W64.of_uintK n_val.
have h1 : to_uint (zeroextu64 z * W64.of_int P.`n) = to_uint z * P.`n.
+ apply offG; rewrite hM; first by rewrite n_val.
  by move: hm hs hi0 hF; move: (P.`n) (to_uint z * P.`n) (P.`a * P.`n) (i * (P.`a + 1) * P.`n) (P.`k * (P.`a + 1) * P.`n) => N Z A I F /#.
have h2 : to_uint (zeroextu64 z * W64.of_int P.`n + so) = to_uint z * P.`n + i * (P.`a + 1) * P.`n.
+ rewrite add64 h1 hso // hM64.
  by move: hm hm1 hs hi0 hF; move: (P.`n) (to_uint z * P.`n) (P.`a * P.`n) (i * (P.`a + 1) * P.`n) (P.`k * (P.`a + 1) * P.`n) => N Z A I F /#.
rewrite add64 h2 hc // hM64.
by move: hm hm1 hs hi0 hF; move: (P.`n) (to_uint z * P.`n) (P.`a * P.`n) (i * (P.`a + 1) * P.`n) (P.`k * (P.`a + 1) * P.`n) => N Z A I F /#.
qed.

(* The authentication path node z of tree i, and the offsets it lies at. *)
op fau (s : bytes) (i : int) : int -> bytes = fun j =>
  slice (slice s ((i * (P.`a + 1) + 1) * P.`n) ((i + 1) * (P.`a + 1) * P.`n)) (j * P.`n) ((j + 1) * P.`n).

op flf (pk : bytes) (l t y kp : int) (s : bytes) (i g : int) : bytes =
  F P pk (mk_adrs l t y kp 0 g) (slice s (i * (P.`a + 1) * P.`n) ((i * (P.`a + 1) + 1) * P.`n)).

lemma fors_rootE pk l t y kp s i idx :
  fors_root P pk l t y kp s i idx =
  gfold (fors_hash P pk l t y kp) (fau s i) (i * 2 ^ P.`a + idx) (flf pk l t y kp s i (i * 2 ^ P.`a + idx)) P.`a.
proof. by rewrite /fors_root /fau /flf. qed.

lemma au_in i z : 0 <= i < P.`k => 0 <= z < P.`a =>
  0 <= z * P.`n + i * (P.`a + 1) * P.`n + P.`n /\
  z * P.`n + i * (P.`a + 1) * P.`n + P.`n + P.`n <= ForsSig.size.
proof.
move=> hi hz; rewrite fsig_size; have hn := n_val.
have h1 : (i + 1) * ((P.`a + 1) * P.`n) <= P.`k * ((P.`a + 1) * P.`n).
+ by apply ler_pmul2r; [rewrite a_val n_val | smt()].
have h2 : (z + 2) * P.`n <= (P.`a + 1) * P.`n by apply ler_pmul2r => /#.
have e1 : (i + 1) * ((P.`a + 1) * P.`n) = i * (P.`a + 1) * P.`n + (P.`a + 1) * P.`n by ring.
have e2 : (z + 2) * P.`n = z * P.`n + P.`n + P.`n by ring.
have e3 : P.`k * ((P.`a + 1) * P.`n) = P.`k * (P.`a + 1) * P.`n by ring.
have h3 : 0 <= z * P.`n by apply mulr_ge0 => /#.
have h4 : 0 <= i * (P.`a + 1) * P.`n by apply mulr_ge0; [apply mulr_ge0 | ] => /#.
smt().
qed.

lemma fauE (s : bytes) i z : 0 <= i < P.`k => 0 <= z < P.`a =>
  fau s i z = slice s (z * P.`n + i * (P.`a + 1) * P.`n + P.`n) (z * P.`n + i * (P.`a + 1) * P.`n + P.`n + P.`n).
proof.
move=> hi hz; have hn := n_val; rewrite /fau slice_slice.
+ by apply mulr_ge0; [ | rewrite n_val]; smt().
+ split; [by apply mulr_ge0 => /# | by move=> _; apply ler_pmul2r => /#].
+ have h1 : (z + 1) * P.`n <= P.`a * P.`n by apply ler_pmul2r => /#.
  have e : (i + 1) * (P.`a + 1) * P.`n - (i * (P.`a + 1) + 1) * P.`n = P.`a * P.`n by ring.
  smt().
by congr; ring.
qed.

lemma leaf_in i : 0 <= i < P.`k =>
  0 <= i * (P.`a + 1) * P.`n /\ i * (P.`a + 1) * P.`n + P.`n <= ForsSig.size.
proof.
move=> hi; have := au_in i 0 hi _; first by rewrite a_val.
by have hn := n_val; smt().
qed.

(* ------------------------------------------------------------------ *)
(* _fors_pk_from_sig (Algorithm 17)                                   *)

lemma fors_pk_from_sig_h (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     hoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)]) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     hoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)]) =>
  (forall (m0 : TKIn.t) (a0 : BArray32.t),
     hoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TKIn.to_list m0)]) =>
  forall (s0 : ForsSig.t) (i0 : ForsIdx.t) (a0 : BArray32.t) (md : bytes),
  hoare [M._fors_pk_from_sig :
    sig = s0 /\ indices = i0 /\ ctx = c0 /\ adrs = a0 /\
    (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = nth 0 (base_2b md P.`a P.`k) j) ==>
    Node.to_list res.`1 = fors_pkFromSig P (ForsSig.to_list s0) md pk_seed (BArray32.to_list a0)].
proof.
move=> hf hh htk s0 i0 a0 md.
have [A hAe] : exists A, A = BArray32.to_list a0 by exists (BArray32.to_list a0).
have hA : size A = 32 by rewrite hAe BArray32.size_to_list.
have [l tr y kp w1 w0 [hAs hkp]] : exists l tr y kp w1 w0,
  A = mk_adrs l tr y kp w1 w0 /\ 0 <= kp < 2 ^ 32.
+ exists (fld A 0 4) (fld A 4 16) (fld A 16 20) (fld A 20 24) (fld A 24 28) (fld A 28 32).
  by split; [exact adrs_split | exact (fld_range A 20)].
have [S hSe] : exists S, S = ForsSig.to_list s0 by exists (ForsSig.to_list s0).
have [ix hix] : exists (ix : int -> int), ix = fun i => nth 0 (base_2b md P.`a P.`k) i.
+ by exists (fun i => nth 0 (base_2b md P.`a P.`k) i).
have hixr : forall i, 0 <= i < P.`k => 0 <= ix i < 2 ^ P.`a.
+ move=> i hi; have := List.allP (fun v => 0 <= v < 2 ^ P.`a) (base_2b md P.`a P.`k).
  rewrite Validate_Encoding.base_2b_range /= hix /= => h; apply h; apply mem_nth.
  by rewrite Validate_Encoding.size_base_2b; smt(k_val).
have [R hR] : exists (R : int -> bytes), R = fun i => fors_root P pk_seed l tr y kp S i (ix i).
+ by exists (fun i => fors_root P pk_seed l tr y kp S i (ix i)).
have hspec : fors_pkFromSig P S md pk_seed A =
             T_l P pk_seed (mk_adrs l tr FORS_ROOTS kp 0 0) (flatten (map R (range 0 P.`k))).
+ by rewrite hAs fors_pkFromSigE // ?ka_bound ?hR ?hix; smt(a_val k_val).
have ha := a_val; have hn := n_val; have hk := k_val.
proc.
ecall (htk roots roots_adrs).
ecall (ckp_h roots_adrs adrs).
ecall (tc4_h roots_adrs).
ecall (cp_h roots_adrs adrs).
inline M.__offset; wp.
while (0 <= to_uint t <= P.`k /\ more = (to_uint t < P.`k) /\ sig = s0 /\ indices = i0 /\
       ctx = c0 /\ adrs = a0 /\
       take 24 (BArray32.to_list node_adrs) = take 24 A /\
       take (to_uint t * P.`n) (TKIn.to_list roots) = flatten (map R (range 0 (to_uint t))) /\
       (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = ix j)).
+ exlim t => t0.
  wp; ecall (node_copy_h node); wp.
  while (0 <= to_uint z <= P.`a /\ climb = (to_uint z < P.`a) /\ t = t0 /\ 0 <= to_uint t0 < P.`k /\
         sig = s0 /\ indices = i0 /\ ctx = c0 /\ adrs = a0 /\
         to_uint sig_off = to_uint t0 * (P.`a + 1) * P.`n /\
         to_uint idx = ix (to_uint t0) %/ 2 ^ to_uint z /\
         to_uint g = (to_uint t0 * 2 ^ P.`a + ix (to_uint t0)) %/ 2 ^ to_uint z /\
         BArray32.to_list node_adrs =
           mk_adrs l tr y kp (to_uint z) ((to_uint t0 * 2 ^ P.`a + ix (to_uint t0)) %/ 2 ^ to_uint z) /\
         Node.to_list node =
           gfold (fors_hash P pk_seed l tr y kp) (fau S (to_uint t0)) (to_uint t0 * 2 ^ P.`a + ix (to_uint t0))
             (flf pk_seed l tr y kp S (to_uint t0) (to_uint t0 * 2 ^ P.`a + ix (to_uint t0))) (to_uint z) /\
         take (to_uint t0 * P.`n) (TKIn.to_list roots) = flatten (map R (range 0 (to_uint t0))) /\
         (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = ix j)).
  + seq 14 : (0 <= to_uint z < P.`a /\ t = t0 /\ 0 <= to_uint t0 < P.`k /\
         sig = s0 /\ indices = i0 /\ ctx = c0 /\ adrs = a0 /\
         to_uint sig_off = to_uint t0 * (P.`a + 1) * P.`n /\
         to_uint idx = ix (to_uint t0) %/ 2 ^ to_uint z /\
         to_uint g = (to_uint t0 * 2 ^ P.`a + ix (to_uint t0)) %/ 2 ^ to_uint z /\
         BArray32.to_list node_adrs =
           mk_adrs l tr y kp (to_uint z) ((to_uint t0 * 2 ^ P.`a + ix (to_uint t0)) %/ 2 ^ to_uint z) /\
         Node.to_list node =
           gfold (fors_hash P pk_seed l tr y kp) (fau S (to_uint t0)) (to_uint t0 * 2 ^ P.`a + ix (to_uint t0))
             (flf pk_seed l tr y kp S (to_uint t0) (to_uint t0 * 2 ^ P.`a + ix (to_uint t0))) (to_uint z) /\
         Node2.to_list pair =
           (if (ix (to_uint t0) %/ 2 ^ to_uint z) %% 2 <> 0
            then fau S (to_uint t0) (to_uint z) ++ Node.to_list node
            else Node.to_list node ++ fau S (to_uint t0) (to_uint z)) /\
         take (to_uint t0 * P.`n) (TKIn.to_list roots) = flatten (map R (range 0 (to_uint t0))) /\
         (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = ix j)).
    + (* The pair: AUTH[z] on the side bit z of the index says. *)
      sp; if.
      + wp; ecall (node_copy_h node); wp; ecall (node_copy_h (ForsSigNode.get_sub sig (W64.to_uint auth_off))).
        wp; skip.
        move=> &hr [[sg0 ms0 H] hod]; move: H.
        move=> [#] hms hsg hi hst hc hoff hau hbit hodd hz0 hz1 hcl ht ht0 ht1 hsg0 hind hctx had hso hid hg hna hnd hrt hidF hclimb.
        move=> /= r -> r0 -> /=.
        have hzl : to_uint z{hr} < P.`a by rewrite -hcl.
        have hzk : 0 <= to_uint z{hr} < P.`a by done.
        have ht0k : 0 <= to_uint t0 < P.`k by done.
        have hao : to_uint auth_off{hr} = to_uint z{hr} * P.`n + to_uint t0 * (P.`a + 1) * P.`n + P.`n.
        + by rewrite hau hoff hc hst hi; exact (aoffE z{hr} sig_off{hr} (to_uint t0) _ n_val hzl ht0k hso).
        have [hb0 hb1] := au_in _ _ ht0k hzk.
        have hsub : Node.to_list (ForsSigNode.get_sub s0 (to_uint auth_off{hr})) = fau S (to_uint t0) (to_uint z{hr}).
        + by rewrite hao (fsig_sub _ _ hb0 hb1) -hSe -fauE.
        have hb : (ix (to_uint t0) %/ 2 ^ to_uint z{hr}) %% 2 <> 0.
        + by move: hod; rewrite hodd hbit bit1E hid.
        rewrite hsg /= hsg0 hb /= (pair_cat _ _ _ _ n_val) hsub.
        by do ! split => //.
      wp; ecall (node_copy_h (ForsSigNode.get_sub sig (W64.to_uint auth_off))); wp; ecall (node_copy_h node).
      wp; skip.
      move=> &hr [[sg0 ms0 H] hod]; move: H.
      move=> [#] hms hsg hi hst hc hoff hau hbit hodd hz0 hz1 hcl ht ht0 ht1 hsg0 hind hctx had hso hid hg hna hnd hrt hidF hclimb.
      move=> /= r -> r0 -> /=.
      have hzl : to_uint z{hr} < P.`a by rewrite -hcl.
      have hzk : 0 <= to_uint z{hr} < P.`a by done.
      have ht0k : 0 <= to_uint t0 < P.`k by done.
      have hao : to_uint auth_off{hr} = to_uint z{hr} * P.`n + to_uint t0 * (P.`a + 1) * P.`n + P.`n.
      + by rewrite hau hoff hc hst hi; exact (aoffE z{hr} sig_off{hr} (to_uint t0) _ n_val hzl ht0k hso).
      have [hb0 hb1] := au_in _ _ ht0k hzk.
      have hsub : Node.to_list (ForsSigNode.get_sub s0 (to_uint auth_off{hr})) = fau S (to_uint t0) (to_uint z{hr}).
      + by rewrite hao (fsig_sub _ _ hb0 hb1) -hSe -fauE.
      have hb : (ix (to_uint t0) %/ 2 ^ to_uint z{hr}) %% 2 = 0.
      + by move: hod; rewrite hodd hbit bit1E hid.
      rewrite hsg /= hsg0 hb /= (pair_cat _ _ _ _ n_val) hsub.
      by do ! split => //.
    (* The parent: H at height z + 1, index g >> 1. *)
    wp; ecall (hh pair node_adrs); wp; ecall (ti_h node_adrs g); ecall (th_h node_adrs z); wp; skip.
    move=> &hr [#] hz0 hzl -> ht0 ht1 -> -> -> -> hso hid hg hna hnd hpr hrt hidF /=.
    move=> r1 hr1 r2 hr2 r3 hr3 /=.
    have hzk : 0 <= to_uint z{hr} < P.`a by done.
    have hM : W32.modulus = 4294967296 by done.
    have hzo : to_uint (z{hr} + W32.one) = to_uint z{hr} + 1.
    + by apply inc32o; rewrite hM; move: hzl; rewrite ha => /#.
    have hid1 : to_uint (idx{hr} `>>` W8.of_int 1) = ix (to_uint t0) %/ 2 ^ (to_uint z{hr} + 1).
    + by rewrite shr1E hid (div2S _ _ hz0).
    have hg1 : to_uint (g{hr} `>>` W8.of_int 1) =
               (to_uint t0 * 2 ^ P.`a + ix (to_uint t0)) %/ 2 ^ (to_uint z{hr} + 1).
    + by rewrite shr1E hg (div2S _ _ hz0).
    have hm : BArray32.to_list r2 =
              mk_adrs l tr y kp (to_uint z{hr} + 1) ((to_uint t0 * 2 ^ P.`a + ix (to_uint t0)) %/ 2 ^ (to_uint z{hr} + 1)).
    + by rewrite hr2 hr1 hna setChainAddressE setHashAddressE hzo hg1.
    have hnode : Node.to_list r3.`1 =
           gfold (fors_hash P pk_seed l tr y kp) (fau S (to_uint t0)) (to_uint t0 * 2 ^ P.`a + ix (to_uint t0))
             (flf pk_seed l tr y kp S (to_uint t0) (to_uint t0 * 2 ^ P.`a + ix (to_uint t0))) (to_uint z{hr} + 1).
    + rewrite hr3 hm hpr hnd (gfold_step _ _ _ _ _ hz0) (bit_shift _ _ _ _ hzk) /fors_hash.
      by case: ((ix (to_uint t0) %/ 2 ^ to_uint z{hr}) %% 2 = 0) => hb.
    rewrite (ultP _ _ _ a_val) // hzo hid1 hg1 hm hnode /=.
    by do ! split => //; move: hz0 hzl; move: (P.`a) => Av /#.
  wp; ecall (hf node node_adrs); ecall (ti_h node_adrs g); ecall (th_h node_adrs z); wp.
  ecall (node_copy_h (ForsSigNode.get_sub sig (W64.to_uint sig_off))); wp; skip.
  move=> &hr /= [#] <- ht0 ht1 hmo hsg hind hctx had h24 hrt hidF hmore.
have hlt : to_uint t0 < P.`k by rewrite -hmo.
have ht0k : 0 <= to_uint t0 < P.`k by done.
have hidx : to_uint (ForsIdx.get32 i0 (to_uint t0)) = ix (to_uint t0) by rewrite hidF.
have hix0 := hixr (to_uint t0) ht0k.
have hidl : to_uint (ForsIdx.get32 i0 (to_uint t0)) < 2 ^ P.`a by rewrite hidx; case: hix0.
have hg := gE t0 (ForsIdx.get32 i0 (to_uint t0)) _ a_val hlt hidl.
have hso := soffE t0 _ _ a_val n_val hlt.
have [hl0 hl1] := leaf_in (to_uint t0) ht0k.
rewrite zext64E hsg hind hctx had hso /=.
move=> r hr0 r0 hr1 r1 hr2 r2 hr3.
split.
+ have hm : BArray32.to_list r1 = mk_adrs l tr y kp 0 (to_uint t0 * 2 ^ P.`a + ix (to_uint t0)).
  + rewrite hr2 hr1 hg hidx ?W32.to_uint0 (shsc_take _ (mk_adrs l tr y kp w1 w0)) ?ADRS.size_bytes_of //.
    + by rewrite h24 hAs.
    by rewrite setChainAddressE setHashAddressE.
  rewrite hidx hg hm hr3 hm hr0 fsig_sub // gfold0 /flf -hSe /=.
  do ! split => //; try by rewrite a_val.
  + by rewrite hidx.
  by congr; congr; ring.
move=> cl1 cx1 g1 id1 nd1 na1 sg1 so1 t1 z2 hcl [#] hz0 hz1 hcl' -> _ _ hsg1 hcx1 hso1 hid1 hg1 hna1 hnd1 htk1 _.
rewrite ?hsg1 ?hcx1 /= => r4 -> /=.
have hz : to_uint z2 = P.`a by smt().
have hro := roffE t0 _ n_val hlt.
have ht2 : to_uint (t0 + W32.one) = to_uint t0 + 1.
+ by apply inc32o; move: hlt; rewrite hk; smt(W32.to_uint_cmp).
rewrite hro (ultP _ _ _ k_val) // ht2 tk_take_set_sub // htk1 hnd1 hz /=.
split; first smt().
split; first by rewrite hna1 hAs; apply take24_mk.
split; last done.
rewrite rangeSr 1:/# map_rcons flatten_rcons; congr.
by rewrite hR /= fors_rootE.

wp; while (true); first by wp.
wp; ecall (cp_h node_adrs adrs); wp; skip.
move=> &hr /= [#] -> -> -> -> hid na hna k0 r0 _ /=.
split.
+ rewrite hna -hAe take0 range_geq // flatten_nil /= hk /=.
  by move=> j hj; rewrite hid // hix.
move=> ctx1 ind1 mo na1 r1 sg1 t1 hmo [#] ht0 ht1 hmo' hsg hid2 hcx h24 htake _ /=; rewrite ?hcx /=.
move=> ra hra rb hrb rc hrc r hr.
have ht : to_uint t1 = P.`k by smt().
have hroots : TKIn.to_list r1 = flatten (map R (range 0 P.`k)).
+ by rewrite -ht -htake take_oversize // TKIn.size_to_list ht hk hn.
rewrite hr hrc hrb hra -hAe hAs setTypeAndClearE getKeyPairAddressE mod32 // setKeyPairAddressE hroots.
by rewrite -hSe -hAs hspec /FORS_ROOTS.

qed.

(* _fors_pk_from_sig terminates: the fill loop counts to its bound, the
   outer loop runs t up to k and the climb runs z up to a. *)
lemma fors_pk_from_sig_ll (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  phoare [M._fors_pk_from_sig : ctx = c0 ==> true] = 1%r.
proof.
move=> hf hh htk.
have hfl : phoare [M._thash_f : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim x, adrs => x1 a1; call (hf x1 a1); auto.
have hhl : phoare [M._thash_h : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (hh x1 a1); auto.
have htkl : phoare [M._thash_t_k : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (htk x1 a1); auto.
have ha := a_val; have hk := k_val; have hM : W32.modulus = 4294967296 by done.
proc; inline M.__offset.
call htkl; call copy_kp_ll; call set_tc_ll; call copy_ll; wp.
while (0 <= to_uint t <= P.`k /\ more = (to_uint t < P.`k) /\ ctx = c0) (P.`k - to_uint t).
+ move=> v; exlim t => t0.
  wp; call node_copy_ll; wp.
  while (0 <= to_uint z <= P.`a /\ climb = (to_uint z < P.`a) /\ t = t0 /\ ctx = c0) (P.`a - to_uint z).
  + move=> w; wp; call hhl; wp; call set_ti_ll; call set_th_ll; wp; sp; if.
    + wp; call node_copy_ll; wp; call node_copy_ll; wp; skip.
      move=> &hr [[sg0 ms0 [#] _ _ _ _ _ _ _ _ _ hz0 hz1 hcl ht hctx hclimb hw] _] /=.
      rewrite hctx /=.
      have hzl : to_uint z{hr} < P.`a by rewrite -hcl.
      have hzo : to_uint (z{hr} + W32.one) = to_uint z{hr} + 1.
      + by apply inc32o; rewrite hM; move: hzl; rewrite ha => /#.
      rewrite (ultP _ _ _ a_val) // hzo ht /=.
      by move: hz0 hzl hw; move: (P.`a) => Av /#.
    wp; call node_copy_ll; wp; call node_copy_ll; wp; skip.
    move=> &hr [[sg0 ms0 [#] _ _ _ _ _ _ _ _ _ hz0 hz1 hcl ht hctx hclimb hw] _] /=.
    rewrite hctx /=.
    have hzl : to_uint z{hr} < P.`a by rewrite -hcl.
    have hzo : to_uint (z{hr} + W32.one) = to_uint z{hr} + 1.
    + by apply inc32o; rewrite hM; move: hzl; rewrite ha => /#.
    rewrite (ultP _ _ _ a_val) // hzo ht /=.
    by move: hz0 hzl hw; move: (P.`a) => Av /#.
  wp; call hfl; call set_ti_ll; call set_th_ll; wp; call node_copy_ll; wp; skip.
  move=> &hr [#] <- ht0 ht1 hmo hctx hmore hv /=.
  have hlt : to_uint t0 < P.`k by rewrite -hmo.
  rewrite hctx /= a_val /=.
  move=> cl c1 t1 z0; split.
  + move=> [#] hz0 hz1 -> _ _ hle; move: hz1 hle; move: (P.`a) => Av /#.
  move=> _ [#] hz0 hz1 _ -> -> /=.
  have ht2 : to_uint (t0 + W32.one) = to_uint t0 + 1.
  + by apply inc32o; rewrite hM; move: hlt; rewrite hk => /#.
  rewrite (ultP _ _ _ k_val) // ht2 /=.
  by move: ht0 hlt hv; move: (P.`k) => Kv /#.
wp; while true (inc - k); first by move=> z; wp; skip => /#.
wp; call copy_ll; wp; skip.
move=> &hr hc /= k0; split; first smt().
move=> _; rewrite hc k_val /=; move=> c1 m1 t1; split; last by move=> _ [#].
by move=> [#] _ h1 -> _ h2; move: h1 h2 => /#.
qed.

(* Total correctness: the hoare part under the premises read as hoare
   statements, and termination. *)
lemma fors_pk_from_sig_correct (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  forall (s0 : ForsSig.t) (i0 : ForsIdx.t) (a0 : BArray32.t) (md : bytes),
  phoare [M._fors_pk_from_sig :
    sig = s0 /\ indices = i0 /\ ctx = c0 /\ adrs = a0 /\
    (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = nth 0 (base_2b md P.`a P.`k) j) ==>
    Node.to_list res.`1 = fors_pkFromSig P (ForsSig.to_list s0) md pk_seed (BArray32.to_list a0)] = 1%r.
proof.
move=> hf hh htk s0 i0 a0 md.
conseq (fors_pk_from_sig_ll pk_seed c0 hf hh htk)
       (fors_pk_from_sig_h pk_seed c0 _ _ _ s0 i0 a0 md) => //.
+ by move=> x1 a1; conseq (hf x1 a1).
+ by move=> x1 a1; conseq (hh x1 a1).
by move=> m1 a1; conseq (htk m1 a1).
qed.
