(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ForsSign.ec
 * ===========
 *
 * _fors_sign of src/slhdsa/fors.jinc writes SIG_FORS (Algorithm 16) into
 * sig[n : n + k (a + 1) n], after the randomizer R, and returns PK_FORS,
 * T_k of the k tree roots.
 *
 * Blocks. Tree t is signed by _fors_tree (ForsTree.fors_tree_h) into a
 * block ftsig t (ix t) of (a + 1) n bytes, the leaf secret then the
 * authentication path; fors_sign_blocks rewrites Algorithm 16 as the
 * concatenation of these blocks, so block t starts at byte n + t (a + 1) n
 * of the signature.
 *
 * Signature bytes. The invariant of the tree loop and of the copy loop is
 * stated per byte against the target list X = sig[0 : n] ++ SIG_FORS ++
 * sig[n + k (a + 1) n :]: the bytes from n up to the write position are
 * those of X, the others those of the input. sig_step is the copy step;
 * it names the store address as block start plus counter, which is what
 * both forms of the copy loop (offset advanced with the counter, or fixed
 * per tree) compute.
 *
 * PK_FORS. fors_correct: on a signature of Algorithm 16, Algorithm 17
 * recomputes the roots fors_node t a, so T_k of the roots is
 * fors_pkFromSig of the signature, the value Algorithm 19 uses.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_Hash_Props FIPS205_FORS FIPS205_XMSS.
require import MerkleTrees_FIPS205 FIPS205_TreeForms.
require import BArray32.
require import SetModel CoreExtracted Encoding WotsChain WotsPk WotsLeaf TreeFold ForsTree.
require ForsPk.
import StdOrder.IntOrder.

lemma nok : n_ok P by rewrite /n_ok n_val.

(* ------------------------------------------------------------------ *)
(* Algorithm 16 as k blocks                                           *)

op ftsig (pk sk : bytes) (l tr y kp t tg : int) : bytes =
  fors_sk P sk pk l tr kp (t * 2 ^ P.`a + tg) ++
  flatten (map (fun z => fnode pk sk l tr y kp t z (gsibling (tg %/ 2 ^ z))) (range 0 P.`a)).

lemma size_fnode pk sk l tr y kp t z j : size (fnode pk sk l tr y kp t z j) = P.`n.
proof.
rewrite /fnode; apply size_gnode => *.
+ by rewrite /fors_leaf (size_F P _ _ _ nok).
by rewrite /fors_hash (size_H P _ _ _ nok).
qed.

lemma size_ftsig pk sk l tr y kp t tg : size (ftsig pk sk l tr y kp t tg) = (P.`a + 1) * P.`n.
proof.
rewrite /ftsig size_cat /fors_sk (size_PRF P _ _ _ nok) (size_flatten_n _ P.`n).
+ by move=> b /mapP [z [_ ->]]; apply size_fnode.
by rewrite size_map size_range a_val n_val.
qed.

lemma fors_sign_blocks md pk sk l tr y kp w1 w0 :
  0 <= kp < 2 ^ 32 =>
  fors_sign P md sk pk (mk_adrs l tr y kp w1 w0) =
  flatten (map (fun t => ftsig pk sk l tr y kp t (nth 0 (base_2b md P.`a P.`k) t)) (range 0 P.`k)).
proof.
move=> hkp; have ha0 : 0 <= P.`a by rewrite a_val.
rewrite (fors_signE P md sk pk l tr y kp w1 w0 hkp ha0) /=.
apply (congr1 flatten); apply eq_in_map => t ht /=.
rewrite /ftsig; congr; apply (congr1 flatten); apply eq_in_map => z /mem_range hz /=.
by rewrite (fnode_auth pk sk l tr y kp t _ z hz).
qed.

lemma nth_blocks (f : int -> bytes) (K S t r : int) :
  (forall i, 0 <= i < K => size (f i) = S) => 0 <= t < K => 0 <= r < S =>
  nth W8.zero (flatten (map f (range 0 K))) (t * S + r) = nth W8.zero (f t) r.
proof.
elim/natind: K t => [K hK | K hK ih] t hs ht hr; first smt().
have hsz : size (flatten (map f (range 0 K))) = S * K.
+ rewrite (size_flatten_n _ S); first by move=> b /mapP [i [/mem_range hi ->]]; apply hs => /#.
  by rewrite size_map size_range /#.
rewrite rangeSr // map_rcons flatten_rcons nth_cat hsz.
case: (t < K) => htK.
+ have h1 : (t + 1) * S <= K * S by apply ler_wpmul2r => /#.
  rewrite ifT 1:/#; apply ih; [by move=> i hi; apply hs => /# | smt() | done].
have -> : t = K by smt().
by rewrite ifF 1:/#; congr; ring.
qed.

(* ------------------------------------------------------------------ *)
(* The signature bytes                                                *)

(* One word of block b, at counter kk: bytes from lo up to b + kk + 8 are
   then those of X. *)
lemma sig_step (sig s0 : Sig.t) (src : FoldBuf.t) (X : W8.t list) (lo b kk : int) :
  0 <= lo <= b => 0 <= kk => kk + 8 <= (P.`a + 1) * P.`n =>
  (forall r, 0 <= r < (P.`a + 1) * P.`n => FoldBuf.get8 src r = nth W8.zero X (b + r)) =>
  (forall q, 0 <= q < Sig.size => Sig.get8 sig q = if lo <= q < b + kk then nth W8.zero X q else Sig.get8 s0 q) =>
  forall q, 0 <= q < Sig.size =>
    Sig.get8 (Sig.set64d sig (b + kk) (FoldBuf.get64d src kk)) q =
    if lo <= q < b + kk + 8 then nth W8.zero X q else Sig.get8 s0 q.
proof.
move=> hlo hk hkM hsrc hinv q hq.
rewrite Sig.get8_set64dE.
case: (b + kk <= q < b + kk + 8) => hw.
+ rewrite ifT 1:/# FoldBuf.get64d_byte 1:/# ifT 1:/#.
  by rewrite (_ : kk + (q - (b + kk)) = q - b) 1:/# hsrc 1:/#; congr; ring.
rewrite ifF 1:/# hinv //.
by case: (lo <= q < b + kk) => h; [rewrite ifT 1:/# | rewrite ifF 1:/#].
qed.

lemma ult64P (x : W64.t) v c : v = c => 0 <= c < W64.modulus => (x \ult W64.of_int c) = (to_uint x < v).
proof. by move=> -> hc; rewrite W64.ultE W64.of_uintK (pmod_small _ _ hc). qed.

lemma size_fsig md pk sk l tr y kp w1 w0 : 0 <= kp < 2 ^ 32 =>
  size (fors_sign P md sk pk (mk_adrs l tr y kp w1 w0)) = P.`k * ((P.`a + 1) * P.`n).
proof.
move=> hkp; rewrite fors_sign_blocks // (size_flatten_n _ ((P.`a + 1) * P.`n)).
+ by move=> b /mapP [z [_ ->]]; apply size_ftsig.
by rewrite size_map size_range; smt(k_val).
qed.

(* The block t of the target list: bytes n + t (a + 1) n onwards of X. *)
lemma blk_byte (src : FoldBuf.t) (S0 : W8.t list) md pk sk l tr y kp w1 w0 t r :
  0 <= kp < 2 ^ 32 => P.`n <= size S0 => 0 <= t < P.`k => 0 <= r < (P.`a + 1) * P.`n =>
  FoldBuf.to_list src = ftsig pk sk l tr y kp t (nth 0 (base_2b md P.`a P.`k) t) =>
  FoldBuf.get8 src r =
  nth W8.zero (take P.`n S0 ++ fors_sign P md sk pk (mk_adrs l tr y kp w1 w0) ++
               drop (P.`n + P.`k * ((P.`a + 1) * P.`n)) S0)
      (P.`n + t * ((P.`a + 1) * P.`n) + r).
proof.
move=> hkp hS ht hr hsrc.
have htM : (t + 1) * ((P.`a + 1) * P.`n) <= P.`k * ((P.`a + 1) * P.`n).
+ by apply ler_wpmul2r; smt(a_val n_val).
have hsz := size_fsig md pk sk l tr y kp w1 w0 hkp.
have hM0 : 0 <= t * ((P.`a + 1) * P.`n) by apply mulr_ge0; smt(a_val n_val).
(* Past the first n bytes, and inside SIG_FORS. *)
rewrite nth_cat size_cat size_takel; first smt(n_val).
rewrite hsz ifT.
+ have e : (t + 1) * ((P.`a + 1) * P.`n) = t * ((P.`a + 1) * P.`n) + (P.`a + 1) * P.`n by ring.
  rewrite -addrA ltr_add2l (ltr_le_trans ((t + 1) * ((P.`a + 1) * P.`n))) // e ltr_add2l; by case: hr.
rewrite nth_cat size_takel; first smt(n_val).
rewrite ifF; first by move: hM0 hr; move: (P.`n) (t * ((P.`a + 1) * P.`n)) => N T /#.
(* Byte r of block t. *)
rewrite (_ : P.`n + t * ((P.`a + 1) * P.`n) + r - P.`n = t * ((P.`a + 1) * P.`n) + r) 1:/#.
rewrite fors_sign_blocks // nth_blocks //; first by move=> i _; apply size_ftsig.
by rewrite /= -hsrc FoldBuf.get_to_list.
qed.

(* The target list keeps the size of the signature and its bytes outside
   [n, D). *)
lemma size_X (S0 FS : W8.t list) n D : 0 <= n => n + size FS = D => D <= size S0 =>
  size (take n S0 ++ FS ++ drop D S0) = size S0.
proof.
move=> h0 h1 h2; have hs := size_ge0 FS; rewrite !size_cat size_takel 1:/# size_drop 1:/#; smt().
qed.

lemma nth_X (S0 FS : W8.t list) n D q : 0 <= n => n + size FS = D => D <= size S0 =>
  0 <= q => !(n <= q < D) =>
  nth W8.zero (take n S0 ++ FS ++ drop D S0) q = nth W8.zero S0 q.
proof.
move=> h0 h1 h2 hq hout; have hs := size_ge0 FS.
rewrite nth_cat size_cat size_takel 1:/#.
case: (q < n + size FS) => h3.
+ by rewrite nth_cat size_takel 1:/# ifT 1:/# nth_take //; smt().
by rewrite nth_drop 1,2:/#; congr; smt().
qed.

(* Word arithmetic of the copy loop: the counter test against (a + 1) n,
   the 8-byte step and the start of block t, all far below 2^64. *)
lemma ultM (x : W64.t) c1 c2 : P.`a = c1 => P.`n = c2 =>
  (x \ult W64.of_int ((c1 + 1) * c2)) = (to_uint x < (P.`a + 1) * P.`n).
proof. by move=> <- <-; apply ult64P => //; rewrite a_val n_val. qed.

lemma add8 (x : W64.t) : to_uint x + 8 < W64.modulus => to_uint (x + W64.of_int 8) = to_uint x + 8.
proof.
move=> h; have h8 : to_uint (W64.of_int 8) = 8 by rewrite W64.of_uintK pmod_small.
by rewrite W64.to_uintD_small h8 //; smt(W64.to_uint_cmp).
qed.

(* The start of block t in the signature, n + t (a + 1) n. *)
lemma soff_n (t : W32.t) c1 c2 c3 : P.`a = c1 => P.`n = c2 => P.`n = c3 => to_uint t < P.`k =>
  to_uint (zeroextu64 t * W64.of_int ((c1 + 1) * c2) + W64.of_int c3) =
  P.`n + to_uint t * ((P.`a + 1) * P.`n).
proof.
move=> ha hn hn3 ht; have hs := ForsPk.soffE t c1 c2 ha hn ht.
have h0 := W32.to_uint_cmp t; have hfs := ForsPk.fsig_small.
have hm : to_uint t * (P.`a + 1) * P.`n <= P.`k * (P.`a + 1) * P.`n.
+ by rewrite -!mulrA; apply ler_wpmul2r; smt(a_val n_val).
have hc : to_uint (W64.of_int c3) = P.`n by rewrite -hn3 W64.of_uintK pmod_small // n_val.
have hnb : P.`n < W32.modulus by rewrite n_val.
have hmm : W32.modulus < 2 ^ 64 by done.
have e := ForsPk.add64 (zeroextu64 t * W64.of_int ((c1 + 1) * c2)) (W64.of_int c3) _.
+ by rewrite hs hc; smt().
by rewrite e hs hc; ring.
qed.

lemma sig_bound : P.`n + P.`k * ((P.`a + 1) * P.`n) <= Sig.size by rewrite n_val k_val a_val.
lemma sig_small : P.`n + P.`k * ((P.`a + 1) * P.`n) < 2 ^ 32 by rewrite n_val k_val a_val.

(* ------------------------------------------------------------------ *)
(* _fors_sign (Algorithm 16 and the roots of Algorithm 19)            *)

(* The PRF, F and H premises are those of ForsTree.fors_tree_h, the T_k
   premise that of ForsPk.fors_pk_from_sig_h, all in hoare form. *)
lemma fors_sign_h (pk_seed : bytes) c0 :
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
  (forall (m0 : TKIn.t) (a0 : BArray32.t),
     hoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TKIn.to_list m0)]) =>
  forall (s0 : Sig.t) (i0 : ForsIdx.t) (k0 : Node.t) (a0 : BArray32.t) (md : bytes)
         (l tr y kp w1 w0 : int),
  BArray32.to_list a0 = mk_adrs l tr y kp w1 w0 => 0 <= kp < 2 ^ 32 =>
  hoare [M._fors_sign :
    sig = s0 /\ indices = i0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\
    (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = nth 0 (base_2b md P.`a P.`k) j) ==>
    Sig.to_list res.`1 =
      take P.`n (Sig.to_list s0) ++ fors_sign P md (Node.to_list k0) pk_seed (BArray32.to_list a0) ++
      drop (P.`n + P.`k * ((P.`a + 1) * P.`n)) (Sig.to_list s0) /\
    Node.to_list res.`2 =
      T_l P pk_seed (mk_adrs l tr FORS_ROOTS kp 0 0)
          (flatten (map (fun t => fnode pk_seed (Node.to_list k0) l tr y kp t P.`a 0) (range 0 P.`k)))].
proof.
move=> hprf hf hh htk s0 i0 k0 a0 md l tr y kp w1 w0 hA hkp.
have htree := fors_tree_h pk_seed c0 hprf hf hh.
have [ix hix] : exists (ix : int -> int), ix = fun i => nth 0 (base_2b md P.`a P.`k) i.
+ by exists (fun i => nth 0 (base_2b md P.`a P.`k) i).
have hixr : forall i, 0 <= i < P.`k => 0 <= ix i < 2 ^ P.`a.
+ move=> i hi; have := List.allP (fun v => 0 <= v < 2 ^ P.`a) (base_2b md P.`a P.`k).
  rewrite Validate_Encoding.base_2b_range /= hix /= => h; apply h; apply mem_nth.
  by rewrite Validate_Encoding.size_base_2b; smt(k_val).
have [X hX] : exists X, X =
  take P.`n (Sig.to_list s0) ++ fors_sign P md (Node.to_list k0) pk_seed (BArray32.to_list a0) ++
  drop (P.`n + P.`k * ((P.`a + 1) * P.`n)) (Sig.to_list s0).
+ by exists (take P.`n (Sig.to_list s0) ++ fors_sign P md (Node.to_list k0) pk_seed (BArray32.to_list a0) ++
             drop (P.`n + P.`k * ((P.`a + 1) * P.`n)) (Sig.to_list s0)).
have [RT hRT] : exists (RT : int -> bytes), RT = fun t => fnode pk_seed (Node.to_list k0) l tr y kp t P.`a 0.
+ by exists (fun t => fnode pk_seed (Node.to_list k0) l tr y kp t P.`a 0).
proc; inline M.__offset.
wp; ecall (htk roots roots_adrs).
ecall (ForsPk.ckp_h roots_adrs adrs).
ecall (ForsPk.tc4_h roots_adrs).
ecall (ForsPk.cp_h roots_adrs adrs).
wp.
(* Tree loop: trees below t are in sig and roots. *)
while (0 <= to_uint t <= P.`k /\ more = (to_uint t < P.`k) /\
       indices = i0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\
       take (to_uint t * P.`n) (TKIn.to_list roots) = flatten (map RT (range 0 (to_uint t))) /\
       (forall q, 0 <= q < Sig.size => Sig.get8 sig q =
          if P.`n <= q < P.`n + to_uint t * ((P.`a + 1) * P.`n) then nth W8.zero X q else Sig.get8 s0 q) /\
       (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = ix j)).
+ exlim t => t0.
  have hem : (to_uint t0 < P.`k /\ to_uint (ForsIdx.get32 i0 (to_uint t0)) < 2 ^ P.`a) \/ !(to_uint t0 < P.`k /\ to_uint (ForsIdx.get32 i0 (to_uint t0)) < 2 ^ P.`a) by rewrite orbN.
  move: hem => [hm | hm]; last first.
  + conseq (_ : false ==> _) => //.
    move=> &hr [#] <- _ _ hmo _ _ _ _ _ _ hidx hmore; apply hm.
    have ht : to_uint t0 < P.`k by rewrite -hmo.
    have h0 := W32.to_uint_cmp t0.
    have hj := hidx (to_uint t0) _; first by split; [case: h0 | done].
    have := hixr (to_uint t0) _; first by split; [case: h0 | done].
    by move=> [_ h2]; split; [exact ht | rewrite hj].
  move: hm => [ht0 htg0].
  wp; ecall (node_copy_h root); wp.
  (* Copy loop: bytes of block t0 below k are in sig. *)
  while (0 <= to_uint k <= (P.`a + 1) * P.`n /\ 8 %| to_uint k /\
         copy = (to_uint k < (P.`a + 1) * P.`n) /\
         to_uint off = P.`n + to_uint t0 * ((P.`a + 1) * P.`n) /\
         t = t0 /\ indices = i0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\
         FoldBuf.to_list src = ftsig pk_seed (Node.to_list k0) l tr y kp (to_uint t0) (ix (to_uint t0)) /\
         Node.to_list root = RT (to_uint t0) /\
         take (to_uint t0 * P.`n) (TKIn.to_list roots) = flatten (map RT (range 0 (to_uint t0))) /\
         (forall q, 0 <= q < Sig.size => Sig.get8 sig q =
            if P.`n <= q < P.`n + to_uint t0 * ((P.`a + 1) * P.`n) + to_uint k
            then nth W8.zero X q else Sig.get8 s0 q) /\
         (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = ix j)).
  + wp; skip => &m [#] hk0 hk1 h8 hcopy hoff -> -> -> -> -> hsrc hroot hroots hsig hidx hc.
    have hkM : to_uint k{m} < (P.`a + 1) * P.`n by rewrite -hcopy.
    have h8M : 8 %| (P.`a + 1) * P.`n by rewrite a_val n_val.
    have hk8 : to_uint k{m} + 8 <= (P.`a + 1) * P.`n.
    + by move: h8 h8M hkM => /dvdzP [u ->] /dvdzP [v ->] /#.
    have h0t := W32.to_uint_cmp t0.
    have htM1 : (to_uint t0 + 1) * ((P.`a + 1) * P.`n) <= P.`k * ((P.`a + 1) * P.`n).
    + by apply ler_wpmul2r; smt(a_val n_val).
    have htM : to_uint t0 * ((P.`a + 1) * P.`n) + (P.`a + 1) * P.`n <= P.`k * ((P.`a + 1) * P.`n).
    + by move: htM1; move: ((P.`a + 1) * P.`n) => M0; rewrite mulrDl mul1r.
    have hM0 : 0 <= to_uint t0 * ((P.`a + 1) * P.`n) by apply mulr_ge0; smt(a_val n_val).
    have hB := sig_small.
    have hmm : 2 ^ 32 < W64.modulus by done.
    have hsig' := sig_step sig{m} s0 src{m} X P.`n (P.`n + to_uint t0 * ((P.`a + 1) * P.`n)) (to_uint k{m}) _ _ hk8 _ hsig.
    + by split; smt(n_val).
    + done.
    + move=> r hr; rewrite hX hA.
      apply (blk_byte src{m} (Sig.to_list s0) md pk_seed (Node.to_list k0) l tr y kp w1 w0 (to_uint t0) r) => //.
      + split.
        + by case: h0t.
        by move: ht0; rewrite k_val.
      by rewrite hsrc hix.
    have hok : to_uint (off{m} + k{m}) = P.`n + to_uint t0 * ((P.`a + 1) * P.`n) + to_uint k{m}.
    + by rewrite -hoff; apply ForsPk.add64; rewrite hoff; smt().
    rewrite /= (ultM _ _ _ a_val n_val) add8 1:/# hok hoff.
    rewrite (_ : P.`n + to_uint t0 * ((P.`a + 1) * P.`n) + (to_uint k{m} + 8) =
                 P.`n + to_uint t0 * ((P.`a + 1) * P.`n) + to_uint k{m} + 8); first by ring.
    do ! split => //; first smt().
    by apply dvdzD; [exact h8 | exact dvdzz].
  wp.
  ecall (htree k0 a0 t0 (ForsIdx.get32 i0 (to_uint t0)) l tr y kp w1 w0 hA hkp ht0 htg0).
  wp; skip => &m [#] <- ht1 ht2 hmo -> -> -> -> hrts hsig hidx hmore.
  have h0t := W32.to_uint_cmp t0.
  have ht0' : 0 <= to_uint t0 < P.`k by split; [case: h0t | move: ht0; rewrite k_val].
  have hid0 : to_uint (ForsIdx.get32 i0 (to_uint t0)) = ix (to_uint t0) by apply hidx.
  rewrite /= ?ForsPk.fprotpE ?ForsPk.fprot32E WotsPk.zext64E /=.
  move=> [tsig rt ms1] /= [hrt hts].
  have hfs : FoldBuf.to_list tsig = ftsig pk_seed (Node.to_list k0) l tr y kp (to_uint t0) (ix (to_uint t0)).
  + by rewrite hts /ftsig hid0.
  have hrt' : Node.to_list rt = RT (to_uint t0) by rewrite hrt hRT.
  have hM0 : 0 < (P.`a + 1) * P.`n by rewrite a_val n_val.
  rewrite (soff_n t0 _ _ _ a_val n_val n_val ht0) hM0 /=.
  split.
  + do ! split => //.
  move=> c2 k2 sg2 hc2 [#] hk20 hk21 h82 hc2' _ _ _ hsg2 _ r0 ->.
  have hk2 : to_uint k2 = (P.`a + 1) * P.`n by move: hc2; rewrite hc2' => /#.
  have htS : to_uint (t0 + W32.one) = to_uint t0 + 1.
  + by apply ForsPk.inc32o; move: ht0; rewrite k_val => /#.
  rewrite (ForsPk.ultP _ _ _ k_val) // htS (ForsPk.roffE t0 _ n_val ht0) ForsPk.tk_take_set_sub //.
  rewrite hrts hrt' rangeSr; first by case: h0t.
  rewrite map_rcons flatten_rcons.
  do ! split => //.
  + by case: h0t => /#.
  + by move: ht0; rewrite k_val => /#.
  move=> q hq; rewrite hsg2 // hk2.
  have -> // : P.`n + (to_uint t0 + 1) * ((P.`a + 1) * P.`n) =
               P.`n + to_uint t0 * ((P.`a + 1) * P.`n) + (P.`a + 1) * P.`n by ring.
(* The roots fill: a dead store, root t is written before it is read. *)
wp; while true; first by auto.
wp; skip => &m /= [#] -> -> -> -> -> hid.
have hfz := size_fsig md pk_seed (Node.to_list k0) l tr y kp w1 w0 hkp.
have hsb := sig_bound.
move=> jf rf _; split.
+ rewrite take0 range_geq // flatten_nil k_val /=.
  split; first by move=> q hq; rewrite ifF 1:/#.
  by move=> j hj; rewrite hid 1:k_val // hix.
move=> ad1 cx1 ind1 mo1 rts1 sg1 sk1 t1 hmo [#] ht10 ht11 hmo' _ _ -> -> hrts1 hsg1 _.
move=> ra hra rb hrb rc hrc /= [pk ms2] /= hpk; rewrite ?ForsPk.fprotpE /=.
have ht : to_uint t1 = P.`k by move: hmo ht11; rewrite hmo' k_val => /#.
have hroots : TKIn.to_list rts1 = flatten (map RT (range 0 P.`k)).
+ by rewrite -ht -hrts1 take_oversize // TKIn.size_to_list ht k_val n_val.
have hsg : Sig.to_list sg1 = X.
+ apply (eq_from_nth W8.zero).
  + rewrite Sig.size_to_list hX hA size_X //; (try by rewrite hfz); (try by rewrite Sig.size_to_list).
  move=> q; rewrite Sig.size_to_list => hq; rewrite Sig.get_to_list hsg1 // ht.
  case: (P.`n <= q < P.`n + P.`k * ((P.`a + 1) * P.`n)) => hc //.
  rewrite hX hA nth_X //; (try by rewrite hfz); (try by rewrite Sig.size_to_list); (try by case: hq).
split; first by rewrite hsg hX.
rewrite hpk hrc hrb hra hA setTypeAndClearE getKeyPairAddressE mod32 // setKeyPairAddressE hroots.
by rewrite hRT /FORS_ROOTS.
qed.

(* _fors_sign terminates: the tree loop runs t up to k, the copy loop
   runs its counter up to (a + 1) n in steps of 8. *)
lemma fors_sign_ll c0 :
  phoare [M._thash_prf_x4 : ctx = c0 ==> true] = 1%r =>
  phoare [M._thash_f_x4 : ctx = c0 ==> true] = 1%r =>
  phoare [M._thash_h : ctx = c0 ==> true] = 1%r =>
  phoare [M._thash_t_k : ctx = c0 ==> true] = 1%r =>
  phoare [M._fors_sign : ctx = c0 ==> true] = 1%r.
proof.
move=> hprfl hfl hhl htkl.
have htl := fors_tree_ll c0 hprfl hfl hhl.
have hMb : (P.`a + 1) * P.`n <= 1024 by rewrite a_val n_val.
proc; inline M.__offset.
wp; call htkl; call ForsPk.copy_kp_ll; call set_tc_ll; call copy_ll; wp.
while (0 <= to_uint t <= P.`k /\ more = (to_uint t < P.`k) /\ ctx = c0) (P.`k - to_uint t).
+ move=> v; exlim t => t0.
  wp; call node_copy_ll; wp.
  while (0 <= to_uint k < (P.`a + 1) * P.`n + 8 /\ copy = (to_uint k < (P.`a + 1) * P.`n) /\
         t = t0 /\ ctx = c0 /\ 0 <= to_uint t0 < P.`k /\ P.`k - to_uint t0 = v)
        ((P.`a + 1) * P.`n - to_uint k).
  + move=> u; wp; skip => &hr /> hk0 hk1 ht0 ht1 hkl.
    have hk8 : to_uint (k{hr} + W64.of_int 8) = to_uint k{hr} + 8.
    + by apply add8; move: hkl hMb; move: ((P.`a + 1) * P.`n) => M0 /#.
    by rewrite (ultM _ _ _ a_val n_val) hk8 /=; move: hk0 hkl; move: ((P.`a + 1) * P.`n) => M0 /#.
  wp; call htl; wp; skip.
  move=> &hr [#] <- ht0 ht1 hmo hctx hmore hv.
  have hlt : to_uint t0 < P.`k by rewrite -hmo.
  rewrite /= ?ForsPk.fprotpE ?ForsPk.fprot32E hctx /=.
  split.
  + have hM0 : 0 < (P.`a + 1) * P.`n by rewrite a_val n_val.
    rewrite hM0 /=; move: hM0; move: ((P.`a + 1) * P.`n) => M0 hM0.
    by do ! split => //; smt().
  move=> c1 k1; split.
  + by move=> [[hk0 hk1] [-> _]] hle; move: hk1 hle; move: ((P.`a + 1) * P.`n) => M0 /#.
  move=> hc _.
  have htS : to_uint (t0 + W32.one) = to_uint t0 + 1.
  + by apply ForsPk.inc32o; move: hlt; rewrite k_val => /#.
  by rewrite /= (ForsPk.ultP _ _ _ k_val) // htS /=; move: ht0 hlt hv; rewrite k_val => /#.
wp; while (true) (inc - j); first by move=> v; auto => /#.
wp; skip => &hr /= ->; rewrite k_val /=.
move=> jf; split; first smt().
move=> _.
move=> cx1 mo1 t1; split; first by move=> [#] _ h1 -> _ h2; move: h1 h2 => /#.
by move=> _ [#].
qed.

(* ------------------------------------------------------------------ *)
(* Algorithm 17 on a signature of Algorithm 16                        *)

(* Tree t of the signature holds the leaf secret of g = t 2^a + idx_t and
   the authentication path of g, so the fold of Algorithm 17 climbs to
   the root of tree t (gfold_gnode). *)
lemma fors_correct md sk pk l tr y kp w1 w0 :
  0 <= kp < 2 ^ 32 =>
  fors_pkFromSig P (fors_sign P md sk pk (mk_adrs l tr y kp w1 w0)) md pk (mk_adrs l tr y kp w1 w0) =
  T_l P pk (mk_adrs l tr FORS_ROOTS kp 0 0)
      (flatten (map (fun t => fnode pk sk l tr y kp t P.`a 0) (range 0 P.`k))).
proof.
move=> hkp; have ha := a_val; have hn := n_val; have hk := k_val.
have h0a : 0 <= P.`a by rewrite a_val.
have h1k : 1 <= P.`k by rewrite k_val.
have h0n : 0 <= P.`n by rewrite n_val.
have h0M : 0 <= (P.`a + 1) * P.`n by rewrite a_val n_val.
have [FS hFS] : exists FS, FS = fors_sign P md sk pk (mk_adrs l tr y kp w1 w0).
+ by exists (fors_sign P md sk pk (mk_adrs l tr y kp w1 w0)).
have hblk : forall t, 0 <= t < P.`k =>
  slice FS (t * ((P.`a + 1) * P.`n)) ((t + 1) * ((P.`a + 1) * P.`n)) =
  ftsig pk sk l tr y kp t (nth 0 (base_2b md P.`a P.`k) t).
+ move=> t ht; rewrite hFS fors_sign_blocks // (slice_flatten _ ((P.`a + 1) * P.`n)) //.
  + by move=> b /mapP [z [_ ->]]; apply size_ftsig.
  + by apply map_range_size.
  by rewrite (nth_map 0) 1:range_size // nth_range 1:/#.
rewrite -hFS fors_pkFromSigE // ?ForsPk.ka_bound.
congr; congr; apply eq_in_map => t /mem_range ht /=.
have [g hg] : exists g, g = t * 2 ^ P.`a + nth 0 (base_2b md P.`a P.`k) t.
+ by exists (t * 2 ^ P.`a + nth 0 (base_2b md P.`a P.`k) t).
have hix : 0 <= nth 0 (base_2b md P.`a P.`k) t < 2 ^ P.`a.
+ have := List.allP (fun v => 0 <= v < 2 ^ P.`a) (base_2b md P.`a P.`k).
  rewrite Validate_Encoding.base_2b_range /= => h; apply h; apply mem_nth.
  by rewrite Validate_Encoding.size_base_2b; smt(k_val).
have hsk : size (fors_sk P sk pk l tr kp g) = P.`n by rewrite /fors_sk (size_PRF P _ _ _ nok).
have [AU hAU] : exists AU,
  AU = map (fun z => fnode pk sk l tr y kp t z (gsibling (nth 0 (base_2b md P.`a P.`k) t %/ 2 ^ z))) (range 0 P.`a).
+ by exists (map (fun z => fnode pk sk l tr y kp t z (gsibling (nth 0 (base_2b md P.`a P.`k) t %/ 2 ^ z))) (range 0 P.`a)).
have hAUs : forall b, b \in AU => size b = P.`n.
+ by move=> b; rewrite hAU => /mapP [z [_ ->]]; apply size_fnode.
have hfa : size (flatten AU) = P.`a * P.`n.
+ by rewrite (size_flatten_n _ P.`n) // hAU size_map size_range /#.
have hB := hblk t ht; rewrite /ftsig -hg -hAU in hB.
have hleaf : slice FS (t * (P.`a + 1) * P.`n) ((t * (P.`a + 1) + 1) * P.`n) = fors_sk P sk pk l tr kp g.
+ have -> : t * (P.`a + 1) * P.`n = t * ((P.`a + 1) * P.`n) + 0 by ring.
  have -> : (t * (P.`a + 1) + 1) * P.`n = t * ((P.`a + 1) * P.`n) + P.`n by ring.
  rewrite -(ForsPk.slice_slice FS (t * ((P.`a + 1) * P.`n)) ((t + 1) * ((P.`a + 1) * P.`n)) 0 P.`n).
  + smt(). + smt(). + smt().
  rewrite hB slice_cat_l; first smt().
  by rewrite -hsk slice_whole.
have hauth : forall j, 0 <= j < P.`a =>
  slice (slice FS ((t * (P.`a + 1) + 1) * P.`n) ((t + 1) * (P.`a + 1) * P.`n)) (j * P.`n) ((j + 1) * P.`n) =
  gnode (fors_leaf P sk pk l tr y kp) (fors_hash P pk l tr y kp) (hts j) (gsibling (g %/ 2 ^ j)).
+ move=> j hj.
  have -> : (t * (P.`a + 1) + 1) * P.`n = t * ((P.`a + 1) * P.`n) + P.`n by ring.
  have -> : (t + 1) * (P.`a + 1) * P.`n = t * ((P.`a + 1) * P.`n) + (P.`a + 1) * P.`n by ring.
  rewrite -(ForsPk.slice_slice FS (t * ((P.`a + 1) * P.`n)) ((t + 1) * ((P.`a + 1) * P.`n)) P.`n ((P.`a + 1) * P.`n)).
  + smt(). + smt(). + smt().
  rewrite hB slice_cat_r; first smt().
  rewrite hsk subrr (_ : (P.`a + 1) * P.`n - P.`n = size (flatten AU)); first by rewrite hfa; ring.
  rewrite slice_whole (slice_flatten _ P.`n) //; first by rewrite hAU; apply map_range_size.
  rewrite hAU (nth_map 0) 1:range_size // nth_range; first by rewrite subr0.
  rewrite /=.
  by rewrite fnode_auth // -hg.
rewrite /fors_root /= -hg hleaf.
rewrite (gfold_eq_auth _ _ (fun j => gnode (fors_leaf P sk pk l tr y kp) (fors_hash P pk l tr y kp)
                                           (hts j) (gsibling (g %/ 2 ^ j)))) //.
have -> : F P pk (mk_adrs l tr y kp 0 g) (fors_sk P sk pk l tr kp g) = fors_leaf P sk pk l tr y kp g.
+ by rewrite /fors_leaf.
rewrite gfold_gnode // /fnode; congr.
rewrite hg divzMDl; first by apply/gtr_eqF/expr_gt0.
rewrite divz_small; first by rewrite ger0_norm 1:expr_ge0 //; exact hix.
by rewrite subrr expr0.
qed.

(* ------------------------------------------------------------------ *)
(* Total correctness                                                   *)

(* Under the hash premises in phoare form, _fors_sign writes SIG_FORS of
   Algorithm 16 after the randomizer and returns PK_FORS, the value that
   Algorithm 17 recomputes from that signature. *)
lemma fors_sign_correct (pk_seed : bytes) c0 :
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
  (forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  forall (s0 : Sig.t) (i0 : ForsIdx.t) (k0 : Node.t) (a0 : BArray32.t) (md : bytes)
         (l tr y kp w1 w0 : int),
  BArray32.to_list a0 = mk_adrs l tr y kp w1 w0 => 0 <= kp < 2 ^ 32 =>
  phoare [M._fors_sign :
    sig = s0 /\ indices = i0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\
    (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = nth 0 (base_2b md P.`a P.`k) j) ==>
    Sig.to_list res.`1 =
      take P.`n (Sig.to_list s0) ++ fors_sign P md (Node.to_list k0) pk_seed (BArray32.to_list a0) ++
      drop (P.`n + P.`k * ((P.`a + 1) * P.`n)) (Sig.to_list s0) /\
    Node.to_list res.`2 =
      fors_pkFromSig P (fors_sign P md (Node.to_list k0) pk_seed (BArray32.to_list a0)) md pk_seed
                     (BArray32.to_list a0)] = 1%r.
proof.
move=> hprf hf hh htk s0 i0 k0 a0 md l tr y kp w1 w0 hA hkp.
have hprfl : phoare [M._thash_prf_x4 : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim sk_seed, adrs => k1 a1; call (hprf k1 a1); auto.
have hfl : phoare [M._thash_f_x4 : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim x, adrs => x1 a1; call (hf x1 a1); auto.
have hhl : phoare [M._thash_h : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (hh x1 a1); auto.
have htkl : phoare [M._thash_t_k : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => x1 a1; call (htk x1 a1); auto.
have hpk := fors_correct md (Node.to_list k0) pk_seed l tr y kp w1 w0 hkp.
conseq (fors_sign_ll c0 hprfl hfl hhl htkl)
       (fors_sign_h pk_seed c0 _ _ _ _ s0 i0 k0 a0 md l tr y kp w1 w0 hA hkp).
+ by move=> &hr [#] -> -> -> -> -> h; do ! split => //.
+ move=> &hr _ r; rewrite hA hpk.
  by split => [[_ h] | [_ h]].
+ by move=> k1 a1; conseq (hprf k1 a1).
+ by move=> x1 a1; conseq (hf x1 a1).
+ by move=> x1 a1; conseq (hh x1 a1).
by move=> m1 a1; conseq (htk m1 a1).
qed.
