(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_TreeForms.ec
 * ====================
 *
 * Closed forms of the FIPS 205 WOTS+, XMSS, FORS and hypertree algorithms
 * (sections 5 to 8) in terms of the generic tree operators of
 * MerkleTrees_FIPS205.ec, and the correctness of WOTS+ and XMSS
 * verification on honestly produced signatures.
 *
 *     chainE               Algorithm 5 hashes under the hash addresses
 *                          i .. i + s - 1 of an otherwise fixed ADRS
 *     wots_correct         wots_pkFromSig(wots_sign(M)) = wots_pkGen
 *     xmss_nodeE           Algorithm 9 is gnode with WOTS+ public keys as
 *                          leaves and H under TREE addresses as node hash
 *     xmss_pkFromSigE      Algorithm 11 is gfold from the WOTS+ public key
 *     xmss_correct         xmss_pkFromSig(xmss_sign(M)) is the XMSS root
 *     fors_nodeE           Algorithm 15 is gnode over FORS leaves
 *     fors_pkFromSigE      Algorithm 17 is T_l of k gfold roots
 *     ht_signE, ht_verifyE Algorithms 12 and 13 layer by layer
 *
 * Addresses are written with mk_adrs (FIPS205_Address_Props). Every
 * statement holds for every parameter set of Table 2.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Hash.
require import FIPS205_WOTS FIPS205_XMSS FIPS205_Hypertree FIPS205_FORS.
require import FIPS205_Address_Props FIPS205_Hash_Props Validate_Params.
require Validate_Encoding.
require import MerkleTrees_FIPS205.

(* ------------------------------------------------------------------ *)
(* Parameter sets                                                     *)

lemma ps_facts p : p \in parameter_sets =>
     n_ok p /\ p.`lgw = 4 /\ w p = 16 /\ len1 p = 2 * p.`n /\ len2 p = 3
  /\ len p = 2 * p.`n + 3 /\ p.`h = p.`d * p.`hp
  /\ 1 <= p.`hp <= 9 /\ 1 <= p.`a <= 14 /\ 1 <= p.`k <= 35 /\ 1 <= p.`d <= 22.
proof.
move=> hin; have := List.allP table2_consistent parameter_sets.
rewrite table2_ok /= => /(_ p hin); rewrite /table2_consistent => [#] h1 h2 h3 h4 _ h5 *.
rewrite /len h3 h4 h1 h2 /n_ok /=.
move: hin; rewrite /parameter_sets /slh_dsa_sha2_128s /slh_dsa_shake_128s /slh_dsa_sha2_128f.
rewrite /slh_dsa_shake_128f /slh_dsa_sha2_192s /slh_dsa_shake_192s /slh_dsa_sha2_192f.
rewrite /slh_dsa_shake_192f /slh_dsa_sha2_256s /slh_dsa_shake_256s /slh_dsa_sha2_256f.
by rewrite /slh_dsa_shake_256f /=; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Byte strings made of n-byte blocks                                 *)

lemma slice_flatten (bs : bytes list) (n i : int) :
  0 <= n => (forall b, b \in bs => size b = n) => 0 <= i < size bs =>
  slice (flatten bs) (i * n) ((i + 1) * n) = nth [] bs i.
proof.
move=> hn; elim: bs i => [|b bs ih] i hs hi.
+ by move: hi => /= /#.
rewrite flatten_cons /=.
have hb : size b = n by apply hs.
case: (i = 0) => [-> /= | hi0].
+ by rewrite slice_cat_l 1:/# -hb slice_whole.
rewrite slice_cat_r 1:/# hb.
have -> : i * n - n = (i - 1) * n by ring.
have -> : (i + 1) * n - n = (i - 1 + 1) * n by ring.
by apply ih => [x hx|]; [apply hs; right | smt()].
qed.

lemma range_size (i n : int) : 0 <= i < n => 0 <= i < size (range 0 n).
proof. by rewrite size_range /#. qed.

lemma map_range_size ['a] (f : int -> 'a) (i n : int) : 0 <= i < n => 0 <= i < size (map f (range 0 n)).
proof. by rewrite size_map size_range /#. qed.

lemma size_flatten_n (bs : bytes list) (n : int) :
  (forall b, b \in bs => size b = n) => size (flatten bs) = n * size bs.
proof. exact size_flatten_ctt. qed.

(* ------------------------------------------------------------------ *)
(* Chains (Algorithm 5)                                               *)

op chain_from (p : params) (pk_seed : bytes) (l t y w2 w1 : int) (x : bytes) (js : int list) : bytes =
  foldl (fun (x : bytes) (j : int) => F p pk_seed (mk_adrs l t y w2 w1 j) x) x js.

lemma chainE p x i s pk_seed l t y w2 w1 w0 :
  chain p x i s pk_seed (mk_adrs l t y w2 w1 w0)
  = chain_from p pk_seed l t y w2 w1 x (range i (i + s)).
proof.
rewrite /chain /chain_from.
have h : forall (js : int list) (x : bytes) (v : int),
  (foldl (fun (st : bytes * adrs) (j : int) =>
            let a' = setHashAddress st.`2 j in (F p pk_seed a' st.`1, a'))
         (x, mk_adrs l t y w2 w1 v) js).`1
  = foldl (fun (x : bytes) (j : int) => F p pk_seed (mk_adrs l t y w2 w1 j) x) x js.
+ by elim => [//|j js ih] x' v /=; rewrite setHashAddressE ih.
by apply h.
qed.

lemma chain_from_cat p pk_seed l t y w2 w1 x js1 js2 :
  chain_from p pk_seed l t y w2 w1 x (js1 ++ js2)
  = chain_from p pk_seed l t y w2 w1 (chain_from p pk_seed l t y w2 w1 x js1) js2.
proof. by rewrite /chain_from foldl_cat. qed.

lemma size_chain_from p pk_seed l t y w2 w1 x js :
  n_ok p => size x = p.`n => size (chain_from p pk_seed l t y w2 w1 x js) = p.`n.
proof.
move=> hn; rewrite /chain_from; elim: js x => [//|j js ih] x hx /=.
by apply ih; rewrite size_F.
qed.

(* Chaining s1 steps from i, then s2 more, is chaining s1 + s2 steps. *)
lemma chain_chain p x i s1 s2 pk_seed l t y w2 w1 w0 w0' :
  0 <= s1 => 0 <= s2 =>
  chain p (chain p x i s1 pk_seed (mk_adrs l t y w2 w1 w0)) (i + s1) s2 pk_seed (mk_adrs l t y w2 w1 w0')
  = chain p x i (s1 + s2) pk_seed (mk_adrs l t y w2 w1 w0).
proof.
move=> h1 h2; rewrite !chainE -chain_from_cat; congr.
by rewrite addrA -range_cat /#.
qed.

(* ------------------------------------------------------------------ *)
(* WOTS+ (Algorithms 6 to 8)                                          *)

lemma wots_digits_range p (m : bytes) :
  p \in parameter_sets =>
  size (wots_digits p m) = len p /\ all (fun v => 0 <= v < w p) (wots_digits p m).
proof.
move=> hin; have [#] hn h4 hw h1 h2 hl *:= ps_facts p hin.
rewrite /wots_digits /= size_cat all_cat !Validate_Encoding.size_base_2b 1,2:/#.
have hr : forall x o, all (fun v => 0 <= v < 16) (base_2b x 4 o).
+ by move=> x o; have := Validate_Encoding.base_2b_range x 4 o.
by rewrite /len hw h4 !hr.
qed.

op wots_sk (p : params) (sk_seed pk_seed : bytes) (l t kp : int) (i : int) : bytes =
  PRF p pk_seed sk_seed (mk_adrs l t WOTS_PRF kp i 0).

lemma wots_signE p m sk_seed pk_seed l t y kp w1 w0 :
  0 <= kp < 2 ^ 32 =>
  wots_sign p m sk_seed pk_seed (mk_adrs l t y kp w1 w0)
  = flatten (map (fun i => chain_from p pk_seed l t y kp i (wots_sk p sk_seed pk_seed l t kp i)
                                      (range 0 (nth 0 (wots_digits p m) i)))
                 (range 0 (len p))).
proof.
move=> hkp; rewrite /wots_sign /= setTypeAndClearE getKeyPairAddressE setKeyPairAddressE.
rewrite mod32 //; congr; apply eq_in_map => i hi /=.
by rewrite !setChainAddressE chainE /wots_sk.
qed.

lemma wots_pkGenE p sk_seed pk_seed l t y kp w1 w0 :
  0 <= kp < 2 ^ 32 =>
  wots_pkGen p sk_seed pk_seed (mk_adrs l t y kp w1 w0)
  = T_l p pk_seed (mk_adrs l t WOTS_PK kp 0 0)
      (flatten (map (fun i => chain_from p pk_seed l t y kp i (wots_sk p sk_seed pk_seed l t kp i)
                                         (range 0 (w p - 1)))
                    (range 0 (len p)))).
proof.
move=> hkp; rewrite /wots_pkGen /= !setTypeAndClearE getKeyPairAddressE !setKeyPairAddressE.
rewrite mod32 //; congr; congr; apply eq_in_map => i hi /=.
by rewrite !setChainAddressE chainE /wots_sk.
qed.

lemma wots_pkFromSigE p sig m pk_seed l t y kp w1 w0 :
  0 <= kp < 2 ^ 32 =>
  wots_pkFromSig p sig m pk_seed (mk_adrs l t y kp w1 w0)
  = T_l p pk_seed (mk_adrs l t WOTS_PK kp 0 0)
      (flatten (map (fun i => chain_from p pk_seed l t y kp i (slice sig (i * p.`n) ((i + 1) * p.`n))
                                         (range (nth 0 (wots_digits p m) i) (w p - 1)))
                    (range 0 (len p)))).
proof.
move=> hkp; rewrite /wots_pkFromSig /= setTypeAndClearE getKeyPairAddressE setKeyPairAddressE.
rewrite mod32 //; congr; congr; apply eq_in_map => i hi /=.
by rewrite setChainAddressE chainE /#.
qed.

lemma size_wots_sign p m sk_seed pk_seed l t y kp w1 w0 :
  p \in parameter_sets => 0 <= kp < 2 ^ 32 =>
  size (wots_sign p m sk_seed pk_seed (mk_adrs l t y kp w1 w0)) = len p * p.`n.
proof.
move=> hin hkp; have [#] hn *:= ps_facts p hin.
rewrite wots_signE // (size_flatten_n _ p.`n).
+ by move=> b /mapP [i [_ ->]] /=; rewrite size_chain_from // /wots_sk size_PRF.
by rewrite size_map size_range; smt(ps_facts).
qed.

lemma wots_correct p m sk_seed pk_seed l t y kp w1 w0 :
  p \in parameter_sets => 0 <= kp < 2 ^ 32 =>
  wots_pkFromSig p (wots_sign p m sk_seed pk_seed (mk_adrs l t y kp w1 w0)) m pk_seed
                 (mk_adrs l t y kp w1 w0)
  = wots_pkGen p sk_seed pk_seed (mk_adrs l t y kp w1 w0).
proof.
move=> hin hkp; have [#] hn h4 hw *:= ps_facts p hin.
have [hsd hrd] := wots_digits_range p m hin.
rewrite wots_pkFromSigE // wots_pkGenE //; congr; congr.
apply eq_in_map => i /mem_range hi /=.
rewrite wots_signE // (slice_flatten _ p.`n) 1:/#.
+ by move=> b /mapP [j [_ ->]] /=; rewrite size_chain_from // /wots_sk size_PRF.
+ exact map_range_size.
rewrite (nth_map 0 []) 1:range_size // nth_range //=.
have hdi : 0 <= nth 0 (wots_digits p m) i < w p.
+ by have := List.allP (fun v => 0 <= v < w p) (wots_digits p m); rewrite hrd /= => h;
     apply h; apply mem_nth; rewrite hsd.
rewrite -chain_from_cat -(range_cat (nth 0 (wots_digits p m) i)) //#.
qed.

(* ------------------------------------------------------------------ *)
(* Root computation loops (Algorithms 11 and 17)                      *)

lemma odd_div2 (x : int) : x %% 2 <> 0 => (x - 1) %/ 2 = x %/ 2.
proof. by move=> h; smt(divz_eq modz_ge0 ltz_pmod). qed.

(* Both loops keep the node and an ADRS whose tree height is the current
   height and whose tree index is that of the current node. *)
lemma fold_track (f : bytes * adrs -> int -> bytes * adrs)
                 (T : int -> int -> bytes -> bytes -> bytes) (auth : int -> bytes)
                 (g : int) (node0 : bytes) (l t y kp m : int) (s : bytes * adrs) :
  s = (node0, mk_adrs l t y kp 0 g) => 0 <= m =>
  (forall node k, 0 <= k < m =>
     f (node, mk_adrs l t y kp k (g %/ 2 ^ k)) k
     = ((if (g %/ 2 ^ k) %% 2 = 0
         then T (k + 1) (g %/ 2 ^ (k + 1)) node (auth k)
         else T (k + 1) (g %/ 2 ^ (k + 1)) (auth k) node),
        mk_adrs l t y kp (k + 1) (g %/ 2 ^ (k + 1)))) =>
  foldl f s (range 0 m)
  = (gfold T auth g node0 m, mk_adrs l t y kp m (g %/ 2 ^ m)).
proof.
move=> -> hm hf; elim: m hm hf => [|m hm ih] hf.
+ by rewrite range_geq // /gfold range_geq // expr0 divz1.
rewrite rangeSr // -cats1 foldl_cat /= ih => [node k hk|].
+ by apply hf => /#.
by rewrite hf 1:/# gfoldS.
qed.

(* The step of Algorithms 11 and 17 on an ADRS in the tracked form. The
   loop tests bit k of c, the index of the leaf within its tree; g is the
   index of the leaf among all leaves at its height, with the same low
   bits. *)
lemma fips_step_track p pk_seed (node auth_k : bytes) (c g l t y kp k : int) :
  0 <= k => 0 <= g < 2 ^ 32 => (c %/ 2 ^ k) %% 2 = (g %/ 2 ^ k) %% 2 =>
  (if (c %/ 2 ^ k) %% 2 = 0
   then (H p pk_seed
           (setTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1))
              (getTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1)) %/ 2))
           (node ++ auth_k),
         setTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1))
           (getTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1)) %/ 2))
   else (H p pk_seed
           (setTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1))
              ((getTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1)) - 1) %/ 2))
           (auth_k ++ node),
         setTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1))
           ((getTreeIndex (setTreeHeight (mk_adrs l t y kp k (g %/ 2 ^ k)) (k + 1)) - 1) %/ 2)))
  = ((if (g %/ 2 ^ k) %% 2 = 0
      then H p pk_seed (mk_adrs l t y kp (k + 1) (g %/ 2 ^ (k + 1))) (node ++ auth_k)
      else H p pk_seed (mk_adrs l t y kp (k + 1) (g %/ 2 ^ (k + 1))) (auth_k ++ node)),
     mk_adrs l t y kp (k + 1) (g %/ 2 ^ (k + 1))).
proof.
move=> hk hg ->; rewrite setChainAddressE getTreeIndexE mod32.
+ split; [by apply divz_ge0; [apply expr_gt0 | smt()] | move=> _].
  apply (ler_lt_trans g); last by case: hg.
  by apply leq_div; [case: hg | apply expr_ge0].
rewrite div2S //.
case: ((g %/ 2 ^ k) %% 2 = 0) => hb /=; first by rewrite !setHashAddressE.
by rewrite odd_div2 // !setHashAddressE.
qed.

(* ------------------------------------------------------------------ *)
(* XMSS (Algorithms 9 to 11)                                          *)

op xmss_leaf (p : params) (sk_seed pk_seed : bytes) (l t : int) (i : int) : bytes =
  wots_pkGen p sk_seed pk_seed (mk_adrs l t WOTS_HASH i 0 0).

op xmss_hash (p : params) (pk_seed : bytes) (l t : int) (z i : int) (x y : bytes) : bytes =
  H p pk_seed (mk_adrs l t TREE 0 z i) (x ++ y).

lemma xmss_nodeE p sk_seed i z pk_seed l t y w2 w1 w0 :
  xmss_node p sk_seed i z pk_seed (mk_adrs l t y w2 w1 w0)
  = gnode (xmss_leaf p sk_seed pk_seed l t) (xmss_hash p pk_seed l t) (hts z) i.
proof.
rewrite /xmss_node -/(hts z); elim: (hts z) i => [|z' zs ih] i /=.
+ by rewrite setTypeAndClearE setKeyPairAddressE.
by rewrite !ih setTypeAndClearE setChainAddressE setHashAddressE.
qed.

lemma xmss_pkFromSigE p idx sig_xmss msg pk_seed l t y w2 w1 w0 :
  0 <= idx < 2 ^ 32 => 0 <= p.`hp =>
  xmss_pkFromSig p idx sig_xmss msg pk_seed (mk_adrs l t y w2 w1 w0)
  = gfold (xmss_hash p pk_seed l t)
          (fun k => slice (slice sig_xmss (len p * p.`n) ((len p + p.`hp) * p.`n)) (k * p.`n) ((k + 1) * p.`n))
          idx
          (wots_pkFromSig p (slice sig_xmss 0 (len p * p.`n)) msg pk_seed (mk_adrs l t WOTS_HASH idx 0 0))
          p.`hp.
proof.
move=> hidx hh; rewrite /xmss_pkFromSig /= setTypeAndClearE setKeyPairAddressE.
rewrite setTypeAndClearE setHashAddressE.
rewrite (fold_track _ (xmss_hash p pk_seed l t)
           (fun k => slice (slice sig_xmss (len p * p.`n) ((len p + p.`hp) * p.`n)) (k * p.`n) ((k + 1) * p.`n))
           idx (wots_pkFromSig p (slice sig_xmss 0 (len p * p.`n)) msg pk_seed (mk_adrs l t WOTS_HASH idx 0 0))
           l t TREE 0 p.`hp) //=.
move=> node k hk; rewrite (fips_step_track p pk_seed node _ idx idx l t TREE 0 k _ hidx) 1:/# //.
qed.

lemma gfold_eq_auth (T : int -> int -> bytes -> bytes -> bytes) (auth auth' : int -> bytes) g leaf m :
  0 <= m => (forall k, 0 <= k < m => auth k = auth' k) =>
  gfold T auth g leaf m = gfold T auth' g leaf m.
proof.
move=> hm; elim: m hm => [|m hm ih] h; first by rewrite /gfold range_geq.
by rewrite !gfoldS //= ih => [k hk|]; [apply h => /# | rewrite h /#].
qed.

lemma size_gnode (L : int -> bytes) (T : int -> int -> bytes -> bytes -> bytes) n zs i :
  (forall i, size (L i) = n) => (forall z i x y, size (T z i x y) = n) =>
  size (gnode L T zs i) = n.
proof. by move=> hL hT; case: zs => [|z zs] /=; [apply hL | apply hT]. qed.

lemma size_xmss_leaf p sk_seed pk_seed l t i :
  n_ok p => size (xmss_leaf p sk_seed pk_seed l t i) = p.`n.
proof. by move=> hn; rewrite /xmss_leaf /wots_pkGen /= size_T_l. qed.

lemma size_xmss_hash p pk_seed l t z i x y :
  n_ok p => size (xmss_hash p pk_seed l t z i x y) = p.`n.
proof. by move=> hn; rewrite /xmss_hash size_H. qed.

lemma xmss_signE p msg sk_seed idx pk_seed l t y w2 w1 w0 :
  0 <= idx < 2 ^ 32 =>
  xmss_sign p msg sk_seed idx pk_seed (mk_adrs l t y w2 w1 w0)
  = wots_sign p msg sk_seed pk_seed (mk_adrs l t WOTS_HASH idx 0 0)
    ++ flatten (map (fun j => gnode (xmss_leaf p sk_seed pk_seed l t) (xmss_hash p pk_seed l t)
                                    (hts j) (gsibling (idx %/ 2 ^ j)))
                    (range 0 p.`hp)).
proof.
move=> hidx; rewrite /xmss_sign /= setTypeAndClearE setKeyPairAddressE; congr; congr.
by apply eq_in_map => j hj /=; rewrite xmss_nodeE.
qed.

lemma size_xmss_sign p msg sk_seed idx pk_seed l t y w2 w1 w0 :
  p \in parameter_sets => 0 <= idx < 2 ^ 32 =>
  size (xmss_sign p msg sk_seed idx pk_seed (mk_adrs l t y w2 w1 w0)) = (len p + p.`hp) * p.`n.
proof.
move=> hin hidx; have [#] hn *:= ps_facts p hin.
rewrite xmss_signE // size_cat size_wots_sign // (size_flatten_n _ p.`n).
+ move=> b /mapP [j [_ ->]] /=; apply size_gnode => *.
  + exact size_xmss_leaf.
  exact size_xmss_hash.
by rewrite size_map size_range ler_maxr /#.
qed.

lemma xmss_correct p msg sk_seed idx pk_seed l t y w2 w1 w0 :
  p \in parameter_sets => 0 <= idx < 2 ^ p.`hp =>
  xmss_pkFromSig p idx (xmss_sign p msg sk_seed idx pk_seed (mk_adrs l t y w2 w1 w0)) msg pk_seed
                 (mk_adrs l t y w2 w1 w0)
  = xmss_node p sk_seed 0 p.`hp pk_seed (mk_adrs l t y w2 w1 w0).
proof.
move=> hin hidx; have [#] hn h4 hw h1 h2 hl hh hhp1 hhp2 *:= ps_facts p hin.
have h32 : 0 <= idx < 2 ^ 32.
+ split; first by case: hidx.
  move=> _; apply (ltr_le_trans (2 ^ p.`hp)); first by case: hidx.
  by apply ler_weexpn2l => /#.
have hsw := size_wots_sign p msg sk_seed pk_seed l t WOTS_HASH idx 0 0 hin h32.
have hn0 : 0 <= p.`n by move: hn; rewrite /n_ok /#.
have hln : 0 <= len p * p.`n by apply mulr_ge0 => /#.
pose auth := map (fun j => gnode (xmss_leaf p sk_seed pk_seed l t) (xmss_hash p pk_seed l t)
                                 (hts j) (gsibling (idx %/ 2 ^ j))) (range 0 p.`hp).
have hauth : forall b, b \in auth => size b = p.`n.
+ move=> b /mapP [j [_ ->]] /=; apply size_gnode => *.
  + exact size_xmss_leaf.
  exact size_xmss_hash.
have hsa : size (flatten auth) = p.`hp * p.`n.
+ by rewrite (size_flatten_n _ p.`n) // size_map size_range ler_maxr /#.
rewrite xmss_pkFromSigE // 1:/# xmss_nodeE xmss_signE // -/auth.
rewrite (slice_cat_l _ _ 0 (len p * p.`n)); first by rewrite hsw /#.
rewrite -hsw slice_whole.
rewrite (slice_cat_r _ _ (size (wots_sign p msg sk_seed pk_seed (mk_adrs l t WOTS_HASH idx 0 0)))) //.
rewrite hsw (_: len p * p.`n - len p * p.`n = 0) 1:/#.
rewrite (_: (len p + p.`hp) * p.`n - len p * p.`n = size (flatten auth)); first by rewrite hsa; ring.
rewrite slice_whole (wots_correct p msg sk_seed pk_seed l t WOTS_HASH idx 0 0 hin h32).
rewrite (gfold_eq_auth _ _ (fun j => gnode (xmss_leaf p sk_seed pk_seed l t) (xmss_hash p pk_seed l t)
                                          (hts j) (gsibling (idx %/ 2 ^ j)))) 1:/#.
+ move=> k hk /=; rewrite (slice_flatten _ p.`n) //.
  + by rewrite /auth; apply map_range_size.
  by rewrite /auth (nth_map 0) 1:range_size // nth_range.
rewrite (_: wots_pkGen p sk_seed pk_seed (mk_adrs l t WOTS_HASH idx 0 0)
            = xmss_leaf p sk_seed pk_seed l t idx) 1:/xmss_leaf //.
rewrite gfold_gnode 1:/#; congr.
by rewrite divz_small // ger0_norm 1:expr_ge0.
qed.

(* ------------------------------------------------------------------ *)
(* FORS (Algorithms 14 to 17)                                         *)

op fors_sk (p : params) (sk_seed pk_seed : bytes) (l t kp : int) (i : int) : bytes =
  PRF p pk_seed sk_seed (mk_adrs l t FORS_PRF kp 0 i).

op fors_leaf (p : params) (sk_seed pk_seed : bytes) (l t y kp : int) (i : int) : bytes =
  F p pk_seed (mk_adrs l t y kp 0 i) (fors_sk p sk_seed pk_seed l t kp i).

op fors_hash (p : params) (pk_seed : bytes) (l t y kp : int) (z i : int) (x x' : bytes) : bytes =
  H p pk_seed (mk_adrs l t y kp z i) (x ++ x').

lemma fors_skGenE p sk_seed pk_seed l t y kp w1 w0 i :
  0 <= kp < 2 ^ 32 =>
  fors_skGen p sk_seed pk_seed (mk_adrs l t y kp w1 w0) i = fors_sk p sk_seed pk_seed l t kp i.
proof.
move=> hkp; rewrite /fors_skGen /= setTypeAndClearE getKeyPairAddressE mod32 //.
by rewrite setKeyPairAddressE setHashAddressE.
qed.

lemma fors_nodeE p sk_seed i z pk_seed l t y kp w1 w0 :
  0 <= kp < 2 ^ 32 =>
  fors_node p sk_seed i z pk_seed (mk_adrs l t y kp w1 w0)
  = gnode (fors_leaf p sk_seed pk_seed l t y kp) (fors_hash p pk_seed l t y kp) (hts z) i.
proof.
move=> hkp; rewrite /fors_node -/(hts z); elim: (hts z) i => [|z' zs ih] i /=.
+ by rewrite fors_skGenE // setChainAddressE setHashAddressE.
by rewrite !ih setChainAddressE setHashAddressE.
qed.

(* Bits below position a of i 2^a + idx are those of idx. *)
lemma div_shift (i idx a j : int) :
  0 <= j <= a => (i * 2 ^ a + idx) %/ 2 ^ j = i * 2 ^ (a - j) + idx %/ 2 ^ j.
proof.
move=> hj; rewrite (_: 2 ^ a = 2 ^ (a - j) * 2 ^ j).
+ by rewrite -exprD_nneg 1,2:/# /#.
rewrite mulrA divzMDl //; smt(expr_gt0).
qed.

lemma bit_shift (i idx a j : int) :
  0 <= j < a => ((i * 2 ^ a + idx) %/ 2 ^ j) %% 2 = (idx %/ 2 ^ j) %% 2.
proof.
move=> hj; rewrite div_shift 1:/# (_: a - j = (a - j - 1) + 1) 1:/# exprS 1:/#.
by rewrite (_: i * (2 * 2 ^ (a - j - 1)) = (i * 2 ^ (a - j - 1)) * 2) 1:/# modzMDl.
qed.

lemma sibling_shift (i idx a j : int) :
  0 <= j < a =>
  i * 2 ^ (a - j) + sibling (idx %/ 2 ^ j) = gsibling ((i * 2 ^ a + idx) %/ 2 ^ j).
proof.
move=> hj; rewrite /sibling /gsibling bit_shift // div_shift 1:/#.
by case: ((idx %/ 2 ^ j) %% 2 = 0) => _; ring.
qed.

lemma fors_signE p md sk_seed pk_seed l t y kp w1 w0 :
  0 <= kp < 2 ^ 32 => 0 <= p.`a =>
  fors_sign p md sk_seed pk_seed (mk_adrs l t y kp w1 w0)
  = flatten (map (fun i =>
      let g = i * 2 ^ p.`a + nth 0 (base_2b md p.`a p.`k) i in
      fors_sk p sk_seed pk_seed l t kp g
      ++ flatten (map (fun j => gnode (fors_leaf p sk_seed pk_seed l t y kp) (fors_hash p pk_seed l t y kp)
                                      (hts j) (gsibling (g %/ 2 ^ j)))
                      (range 0 p.`a)))
      (range 0 p.`k)).
proof.
move=> hkp ha; rewrite /fors_sign /=; congr; apply eq_in_map => i hi /=.
rewrite fors_skGenE //; congr; congr; apply eq_in_map => j /mem_range hj /=.
by rewrite fors_nodeE // sibling_shift.
qed.

lemma size_gfold (T : int -> int -> bytes -> bytes -> bytes) auth g leaf m n :
  0 <= m => (forall z i x y, size (T z i x y) = n) => size leaf = n =>
  size (gfold T auth g leaf m) = n.
proof.
move=> hm hT hl; case: (m = 0) => [-> | hm0]; first by rewrite /gfold range_geq.
rewrite (_: m = (m - 1) + 1) 1:/# gfoldS 1:/# /=.
by case: (g %/ 2 ^ (m - 1) %% 2 = 0) => _; apply hT.
qed.

(* The root of FORS tree i (Algorithm 17, lines 3 to 18), for the leaf
   index idx selected by the message. *)
op fors_root (p : params) (pk_seed : bytes) (l t y kp : int) (sig_fors : bytes) (i idx : int) : bytes =
  let n = p.`n in
  gfold (fors_hash p pk_seed l t y kp)
        (fun j => slice (slice sig_fors ((i * (p.`a + 1) + 1) * n) ((i + 1) * (p.`a + 1) * n))
                        (j * n) ((j + 1) * n))
        (i * 2 ^ p.`a + idx)
        (F p pk_seed (mk_adrs l t y kp 0 (i * 2 ^ p.`a + idx))
           (slice sig_fors (i * (p.`a + 1) * n) ((i * (p.`a + 1) + 1) * n)))
        p.`a.

(* The outer loop of Algorithm 17: each tree appends its root and leaves
   the ADRS at height a and tree index i. *)
lemma fold_roots (f : bytes list * adrs -> int -> bytes list * adrs) (R : int -> bytes)
                 (l t y kp w1 w0 a m : int) (s : bytes list * adrs) :
  s = ([], mk_adrs l t y kp w1 w0) => 1 <= m =>
  (forall roots v1 v0 i, 0 <= i < m =>
     f (roots, mk_adrs l t y kp v1 v0) i = (rcons roots (R i), mk_adrs l t y kp a i)) =>
  foldl f s (range 0 m) = (map R (range 0 m), mk_adrs l t y kp a (m - 1)).
proof.
move=> -> hm1 hf; have hm : 0 <= m by smt().
elim: m hm hm1 hf => [|m hm ih] hm1 hf; first smt().
case: (m = 0) => [-> /= | hm0].
+ have -> : range 0 1 = [0] by rewrite -(rangeS 0).
  by rewrite /= hf /#.
rewrite rangeSr // -cats1 foldl_cat ih 1:/#.
+ by move=> roots v1 v0 i hi; apply hf => /#.
by rewrite /= hf 1:/# map_cat /= cats1.
qed.

lemma fors_pkFromSigE p sig_fors md pk_seed l t y kp w1 w0 :
  0 <= kp < 2 ^ 32 => 0 <= p.`a => 1 <= p.`k => p.`k * 2 ^ p.`a <= 2 ^ 32 =>
  fors_pkFromSig p sig_fors md pk_seed (mk_adrs l t y kp w1 w0)
  = T_l p pk_seed (mk_adrs l t FORS_ROOTS kp 0 0)
      (flatten (map (fun i => fors_root p pk_seed l t y kp sig_fors i (nth 0 (base_2b md p.`a p.`k) i))
                    (range 0 p.`k))).
proof.
move=> hkp ha hk hka; rewrite /fors_pkFromSig /=.
pose idxs := base_2b md p.`a p.`k.
have hidx : forall i, 0 <= i < p.`k => 0 <= nth 0 idxs i < 2 ^ p.`a.
+ move=> i hi; have := List.allP (fun v => 0 <= v < 2 ^ p.`a) idxs.
  rewrite Validate_Encoding.base_2b_range /= => h; apply h; apply mem_nth.
  by rewrite Validate_Encoding.size_base_2b /#.
have hg : forall i, 0 <= i < p.`k => 0 <= i * 2 ^ p.`a + nth 0 idxs i < 2 ^ 32.
+ move=> i hi; have [h0 h1] := hidx i hi.
  have h2a : 0 <= 2 ^ p.`a by apply expr_ge0.
  have hk1 : 0 <= (p.`k - i - 1) * 2 ^ p.`a by apply mulr_ge0 => /#.
  have hi0 : 0 <= i * 2 ^ p.`a by apply mulr_ge0 => /#.
  split; first by apply addr_ge0.
  move=> _; apply (ltr_le_trans (p.`k * 2 ^ p.`a)) => //.
  have -> : p.`k * 2 ^ p.`a = i * 2 ^ p.`a + ((p.`k - i - 1) * 2 ^ p.`a + 2 ^ p.`a) by ring.
  rewrite ltr_add2l; apply (ltr_le_trans (2 ^ p.`a)) => //.
  by rewrite ler_addr.
rewrite (fold_roots _ (fun i => fors_root p pk_seed l t y kp sig_fors i (nth 0 idxs i))
                   l t y kp w1 w0 p.`a p.`k) //=.
+ move=> roots v1 v0 m hm /=.
  rewrite setChainAddressE setHashAddressE.
  rewrite (fold_track _ (fors_hash p pk_seed l t y kp)
             (fun j => slice (slice sig_fors ((m * (p.`a + 1) + 1) * p.`n) ((m + 1) * (p.`a + 1) * p.`n))
                             (j * p.`n) ((j + 1) * p.`n))
             (m * 2 ^ p.`a + nth 0 idxs m)
             (F p pk_seed (mk_adrs l t y kp 0 (m * 2 ^ p.`a + nth 0 idxs m))
                (slice sig_fors (m * (p.`a + 1) * p.`n) ((m * (p.`a + 1) + 1) * p.`n)))
             l t y kp p.`a) //=.
  + move=> node j hj /=.
    rewrite (fips_step_track p pk_seed node _ (nth 0 idxs m)
               (m * 2 ^ p.`a + nth 0 idxs m) l t y kp j _ (hg m _)) 1,2:/#.
    + by rewrite bit_shift.
    by rewrite /fors_hash; case: ((m * 2 ^ p.`a + nth 0 idxs m) %/ 2 ^ j %% 2 = 0).
  rewrite /fors_root /=; congr.
  rewrite divzMDl; first by apply/gtr_eqF/expr_gt0.
  rewrite divz_small //; rewrite ger0_norm 1:expr_ge0 //; exact hidx.
by rewrite setTypeAndClearE getKeyPairAddressE mod32 // setKeyPairAddressE.
qed.

(* ------------------------------------------------------------------ *)
(* Hypertree (Algorithms 12 and 13)                                   *)

(* The tree and leaf indices used on layer j (Algorithm 12, lines 7 and
   8, applied j times), and the message signed on layer j: M on layer 0,
   and the root of the layer below otherwise. *)
op ht_tree (p : params) (idx_tree j : int) : int = idx_tree %/ 2 ^ (p.`hp * j).

op ht_leaf (p : params) (idx_tree idx_leaf j : int) : int =
  if j = 0 then idx_leaf else ht_tree p idx_tree (j - 1) %% 2 ^ p.`hp.

op ht_msg (p : params) (msg sk_seed pk_seed : bytes) (idx_tree j : int) : bytes =
  if j = 0 then msg
  else xmss_node p sk_seed 0 p.`hp pk_seed (mk_adrs (j - 1) (ht_tree p idx_tree (j - 1)) 0 0 0 0).

lemma ht_treeS p idx_tree j :
  0 <= p.`hp => 0 <= j => ht_tree p idx_tree j %/ 2 ^ p.`hp = ht_tree p idx_tree (j + 1).
proof.
move=> hh hj; rewrite /ht_tree -divzMr 1,2:expr_ge0 //.
have -> : p.`hp * (j + 1) = p.`hp * j + p.`hp by ring.
by rewrite exprD_nneg // mulr_ge0.
qed.

lemma ht_leaf_range p idx_tree idx_leaf j :
  0 <= idx_leaf < 2 ^ p.`hp => 0 <= ht_leaf p idx_tree idx_leaf j < 2 ^ p.`hp.
proof.
move=> h; rewrite /ht_leaf; case: (j = 0) => // _.
by rewrite modz_ge0 /= 1:gtr_eqF 1:expr_gt0 // ltz_pmod expr_gt0.
qed.

lemma ht_signE p msg sk_seed pk_seed idx_tree idx_leaf :
  p \in parameter_sets => 0 <= idx_leaf < 2 ^ p.`hp =>
  ht_sign p msg sk_seed pk_seed idx_tree idx_leaf
  = flatten (map (fun j => xmss_sign p (ht_msg p msg sk_seed pk_seed idx_tree j) sk_seed
                                     (ht_leaf p idx_tree idx_leaf j) pk_seed
                                     (mk_adrs j (ht_tree p idx_tree j) 0 0 0 0))
                 (range 0 p.`d)).
proof.
move=> hin hleaf; have [#] hn h4 hw h1 h2 hl hh hhp1 hhp2 _ _ _ _ hd1 hd2 := ps_facts p hin.
pose sigj := fun j => xmss_sign p (ht_msg p msg sk_seed pk_seed idx_tree j) sk_seed
                                  (ht_leaf p idx_tree idx_leaf j) pk_seed
                                  (mk_adrs j (ht_tree p idx_tree j) 0 0 0 0).
rewrite /ht_sign /= mk_adrs0 setTreeAddressE.
pose f := fun (st : bytes * bytes * int * adrs) (j : int) =>
  let (sig_ht, root, idx_tree, a) = st in
  let idx_leaf = idx_tree %% 2 ^ p.`hp in
  let idx_tree = idx_tree %/ 2 ^ p.`hp in
  let a = setTreeAddress (setLayerAddress a j) idx_tree in
  let sig_tmp = xmss_sign p root sk_seed idx_leaf pk_seed a in
  let root = if j < p.`d - 1 then xmss_pkFromSig p idx_leaf sig_tmp root pk_seed a else root in
  (sig_ht ++ sig_tmp, root, idx_tree, a).
have inv : forall m, 0 <= m => m + 1 <= p.`d =>
  let st = foldl f (sigj 0, ht_msg p msg sk_seed pk_seed idx_tree 1, idx_tree,
                    mk_adrs 0 idx_tree 0 0 0 0) (range 1 (m + 1)) in
     st.`1 = flatten (map sigj (range 0 (m + 1)))
  /\ st.`3 = ht_tree p idx_tree m
  /\ st.`4 = mk_adrs m (ht_tree p idx_tree m) 0 0 0 0
  /\ (m + 1 < p.`d => st.`2 = ht_msg p msg sk_seed pk_seed idx_tree (m + 1)).
+ elim => [|m hm ih] hmd.
  + rewrite /= range_geq //= (_: range 0 1 = [0]) 1:-(rangeS 0) //= flatten_seq1.
    by rewrite /ht_tree /= ?expr0 ?divz1.
  have [i1 [i3 [i4 i2]]] := ih _; first smt().
  rewrite (rangeSr 1 (m + 1)) 1:/# -cats1 foldl_cat /=.
  move: i1 i3 i4 i2; case: (foldl f _ _) => s1 s2 s3 s4 /= -> -> -> i2.
  rewrite /f /= setLayerAddressE setTreeAddressE ht_treeS 1,2:/#.
  have hlf : ht_tree p idx_tree m %% 2 ^ p.`hp = ht_leaf p idx_tree idx_leaf (m + 1).
  + by rewrite /ht_leaf ifF 1:/#.
  rewrite hlf i2 1:/#.
  split; first by rewrite (rangeSr 0 (m + 1)) 1:/# map_rcons -cats1 flatten_cat flatten_seq1.
  move=> hlt; rewrite ifT 1:/# xmss_correct //; first by apply ht_leaf_range.
  by rewrite /ht_msg /= ifF 1:/#.
have [i1 _] := inv (p.`d - 1) _ _; 1,2: smt().
have hd : p.`d - 1 + 1 = p.`d by ring.
have e0 : sigj 0 = xmss_sign p msg sk_seed idx_leaf pk_seed (mk_adrs 0 idx_tree 0 0 0 0).
+ by rewrite /sigj /ht_msg /ht_leaf /ht_tree /= ?expr0 ?divz1.
have e1 : ht_msg p msg sk_seed pk_seed idx_tree 1
          = xmss_node p sk_seed 0 p.`hp pk_seed (mk_adrs 0 idx_tree 0 0 0 0).
+ by rewrite /ht_msg /ht_tree /= ?expr0 ?divz1.
move: i1; rewrite hd e0 e1 /f /= => i1.
by rewrite xmss_correct.
qed.

lemma ht_verifyE p msg sig_ht pk_seed idx_tree idx_leaf pk_root :
  p \in parameter_sets =>
  ht_verify p msg sig_ht pk_seed idx_tree idx_leaf pk_root
  = (foldl (fun (node : bytes) (j : int) =>
              xmss_pkFromSig p (ht_leaf p idx_tree idx_leaf j)
                (slice sig_ht (j * xmss_sig_length p) ((j + 1) * xmss_sig_length p))
                node pk_seed (mk_adrs j (ht_tree p idx_tree j) 0 0 0 0))
           msg (range 0 p.`d)
     = pk_root).
proof.
move=> hin; have [#] hn h4 hw h1 h2 hl hh hhp1 hhp2 _ _ _ _ hd1 hd2 := ps_facts p hin.
pose g := fun (node : bytes) (j : int) =>
  xmss_pkFromSig p (ht_leaf p idx_tree idx_leaf j)
    (slice sig_ht (j * xmss_sig_length p) ((j + 1) * xmss_sig_length p))
    node pk_seed (mk_adrs j (ht_tree p idx_tree j) 0 0 0 0).
rewrite /ht_verify /= mk_adrs0 setTreeAddressE.
pose f := fun (st : bytes * int * adrs) (j : int) =>
  let (node, idx_tree, a) = st in
  let idx_leaf = idx_tree %% 2 ^ p.`hp in
  let idx_tree = idx_tree %/ 2 ^ p.`hp in
  let a = setTreeAddress (setLayerAddress a j) idx_tree in
  let sig_tmp = slice sig_ht (j * xmss_sig_length p) ((j + 1) * xmss_sig_length p) in
  (xmss_pkFromSig p idx_leaf sig_tmp node pk_seed a, idx_tree, a).
have inv : forall m, 0 <= m => m + 1 <= p.`d =>
  foldl f (g msg 0, idx_tree, mk_adrs 0 idx_tree 0 0 0 0) (range 1 (m + 1))
  = (foldl g msg (range 0 (m + 1)), ht_tree p idx_tree m,
     mk_adrs m (ht_tree p idx_tree m) 0 0 0 0).
+ elim => [|m hm ih] hmd.
  + by rewrite /= range_geq //= (_: range 0 1 = [0]) 1:-(rangeS 0) //= /ht_tree /= ?expr0 ?divz1.
  rewrite (rangeSr 1 (m + 1)) 1:/# -cats1 foldl_cat ih 1:/# /= (rangeSr 0 (m + 1)) 1:/# -cats1 foldl_cat /=.
  rewrite /f /= setLayerAddressE setTreeAddressE ht_treeS 1,2:/#.
  by rewrite /g /ht_leaf ifF 1:/#.
have := inv (p.`d - 1) _ _; 1,2: smt().
have hd : p.`d - 1 + 1 = p.`d by ring.
have e0 : g msg 0 = xmss_pkFromSig p idx_leaf (slice sig_ht 0 (xmss_sig_length p)) msg pk_seed
                      (mk_adrs 0 idx_tree 0 0 0 0).
+ by rewrite /g /ht_leaf /ht_tree /= ?expr0 ?divz1.
by rewrite hd e0 /f /= => ->.
qed.
