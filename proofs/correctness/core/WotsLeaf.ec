(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * WotsLeaf.ec
 * ===========
 *
 * The four-way WOTS+ key generation of src/slhdsa/wots.jinc:
 * _wots_leaf_x4 computes the public keys of key pairs kp0 .. kp0 + 3
 * (FIPS 205 Algorithm 6) and, for lane < 4, the signature of key pair
 * kp0 + lane (Algorithm 7) from the caller's digits.
 *
 * Lanes. The four-way buffers hold lane k at bytes m k .. m (k + 1) - 1,
 * where m is the size of one lane: 32 for the ADRS4 buffer, n for a
 * node, len n for the T_l input. lane m k l is that slice of l.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_WOTS.
require import BArray32 BArray128 SBArray128_32.
require import SetModel CoreExtracted Wots WotsChain WotsPk.

op lane (m k : int) (l : 'a list) : 'a list = take m (drop (m * k) l).

(* ------------------------------------------------------------------ *)
(* Lane k of the ADRS4 buffer is bytes 32 k .. 32 k + 31.             *)

lemma adrs4_get (a : BArray128.t) k : 0 <= k < 4 =>
  BArray32.to_list (SBArray128_32.get_sub64 a (4 * k)) = lane 32 k (BArray128.to_list a).
proof.
move=> hk; apply (eq_from_nth W8.zero).
+ by rewrite BArray32.size_to_list /lane size_take // size_drop 1:/# BArray128.size_to_list /#.
move=> j; rewrite BArray32.size_to_list => hj.
rewrite BArray32.get_to_list SBArray128_32.get8_get_sub /lane nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite BArray128.get_to_list /#.
qed.

lemma adrs4_set_same (a : BArray128.t) (x : BArray32.t) k : 0 <= k < 4 =>
  lane 32 k (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k) x)) = BArray32.to_list x.
proof.
move=> hk; apply (eq_from_nth W8.zero).
+ by rewrite BArray32.size_to_list /lane size_take // size_drop 1:/# BArray128.size_to_list /#.
move=> j; rewrite /lane size_take // size_drop 1:/# BArray128.size_to_list => hj.
rewrite nth_take 1,2:/# nth_drop 1,2:/# BArray128.get_to_list SBArray128_32.get8_set_sub.
by rewrite BArray32.get_to_list /#.
qed.

lemma adrs4_set_other (a : BArray128.t) (x : BArray32.t) k k' :
  0 <= k < 4 => 0 <= k' < 4 => k <> k' =>
  lane 32 k' (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k) x)) =
  lane 32 k' (BArray128.to_list a).
proof.
move=> hk hk' hne; apply (eq_from_nth W8.zero).
+ by rewrite /lane !size_take // !size_drop 1,2:/# !BArray128.size_to_list.
move=> j; rewrite /lane size_take // size_drop 1:/# BArray128.size_to_list => hj.
rewrite !nth_take 1..4:/# !nth_drop 1..4:/# !BArray128.get_to_list SBArray128_32.get8_set_sub.
by rewrite /#.
qed.

lemma lane_size (m k : int) (l : 'a list) : 0 <= m => 0 <= k => m * (k + 1) <= size l =>
  size (lane m k l) = m.
proof. by move=> hm hk hl; rewrite /lane size_take // size_drop; smt(). qed.

lemma nth_lane (d : 'a) (m k j : int) (l : 'a list) : 0 <= m => 0 <= k => 0 <= j < m =>
  nth d (lane m k l) j = nth d l (m * k + j).
proof. by move=> hm hk hj; rewrite /lane nth_take 1,2:/# nth_drop /#. qed.

lemma adrs4_size (a : BArray128.t) k : 0 <= k < 4 => size (lane 32 k (BArray128.to_list a)) = 32.
proof. by move=> hk; rewrite lane_size // 1:/# BArray128.size_to_list /#. qed.

(* Lane k of an ADRS4 buffer after a write to lane k'. *)
lemma adrs4_set (a : BArray128.t) (x : BArray32.t) k k' : 0 <= k < 4 => 0 <= k' < 4 =>
  lane 32 k' (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k) x)) =
  if k' = k then BArray32.to_list x else lane 32 k' (BArray128.to_list a).
proof.
move=> hk hk'; case: (k' = k) => h.
+ by rewrite h adrs4_set_same.
by rewrite adrs4_set_other // eq_sym.
qed.

(* Two offsets k L + x and k' L + y inside blocks of size L agree only
   when k = k' and x = y. *)
lemma blk_eq (L k k' x y : int) : 0 <= x < L => 0 <= y < L => k * L + x = k' * L + y =>
  k = k' /\ x = y.
proof.
move=> hx hy h; have hL : L <> 0 by smt().
have h1 := divzMDl k x L hL; have h2 := divzMDl k' y L hL.
have hx0 : x %/ L = 0 by rewrite divz_small; smt().
have hy0 : y %/ L = 0 by rewrite divz_small; smt().
by move: h1 h2; rewrite h hx0 hy0 /= => -> /#.
qed.

lemma take_ext (d : 'a) (l pre x : 'a list) o : 0 <= o => take o l = pre =>
  o + size x <= size l => (forall b, 0 <= b < size x => nth d l (o + b) = nth d x b) =>
  take (o + size x) l = pre ++ x.
proof.
move=> ho hp hs hx; have hsp : size pre = o by rewrite -hp size_take //; smt(size_ge0).
apply (eq_from_nth d); first by rewrite size_cat size_take; smt(size_ge0).
move=> j; rewrite size_take; 1: smt(size_ge0).
have -> : (if o + size x < size l then o + size x else size l) = o + size x by smt().
move=> hj; rewrite nth_take 1,2:/# nth_cat hsp.
case: (j < o) => h; first by rewrite -hp nth_take /#.
by have := hx (j - o) _; [smt() | rewrite (_ : o + (j - o) = j) 1:/#].
qed.

lemma take_lane_eq (d : 'a) (l1 l2 : 'a list) L k c : 0 <= c <= L => 0 <= k =>
  size l1 = size l2 =>
  (forall b, 0 <= b < c => nth d l1 (L * k + b) = nth d l2 (L * k + b)) =>
  take c (lane L k l1) = take c (lane L k l2).
proof.
move=> hc hk hs h; rewrite /lane !take_take (_ : c <= L) 1:/# /=.
apply (eq_from_nth d); first by rewrite !size_take 1,2:/# !size_drop 1,2:/# hs.
move=> j; rewrite size_take 1:/# size_drop 1:/# => hj.
by rewrite !nth_take 1..4:/# !nth_drop 1..4:/# h /#.
qed.

lemma sca_sca (x : adrs) i c : 24 <= size x =>
  setChainAddress (setChainAddress x i) c = setChainAddress x c.
proof.
move=> h; have hs : size (take 24 x) = 24 by rewrite size_take //; smt().
rewrite /setChainAddress /slice !drop0 /= -!catA take_cat hs /= take0 cats0.
by rewrite drop_cat hs /= drop_cat size_toByte4 /= drop0 take_take.
qed.

lemma size_sca (x : adrs) i : size x = 32 => size (setChainAddress x i) = 32.
proof.
by move=> h; rewrite /setChainAddress /slice drop0 !size_cat size_toByte4 size_take // size_take // size_drop; smt().
qed.

(* The lane view under a name that program variables do not shadow. *)
abbrev lanev ['a] (m k : int) (l : 'a list) : 'a list = lane m k l.

(* Hoare forms of the ADRS setters, for the loops below. *)
lemma copy_h (d0 s0 : BArray32.t) :
  hoare [M.__adrs_copy : arg = (d0, s0) ==> BArray32.to_list res = BArray32.to_list s0].
proof. by conseq (core_copy d0 s0). qed.

lemma tc0_h (a0 : BArray32.t) : hoare [M.__adrs_set_type_and_clear : arg = (a0, 0) ==>
  BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) 0].
proof. by conseq (core_set_type_and_clear a0 0 _). qed.

lemma tc1_h (a0 : BArray32.t) : hoare [M.__adrs_set_type_and_clear : arg = (a0, 1) ==>
  BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) 1].
proof. by conseq (core_set_type_and_clear a0 1 _). qed.

lemma tc5_h (a0 : BArray32.t) : hoare [M.__adrs_set_type_and_clear : arg = (a0, 5) ==>
  BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) 5].
proof. by conseq (core_set_type_and_clear a0 5 _). qed.

lemma kp_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_keypair : arg = (a0, i0) ==>
  BArray32.to_list res = setKeyPairAddress (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_keypair a0 i0). qed.

lemma chain_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_chain : arg = (a0, i0) ==>
  BArray32.to_list res = setChainAddress (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_chain a0 i0). qed.

lemma hash_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_hash : arg = (a0, i0) ==>
  BArray32.to_list res = setHashAddress (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_hash a0 i0). qed.

lemma prot32E (x : W32.t) (m : W64.t) : SLH64.protect_32 x m = x by done.
lemma prot64E (x : W64.t) (m : W64.t) : SLH64.protect_64 x m = x by done.
lemma protpE (x : 'a) (m : W64.t) : SLH64.protect_ptr x m = x by done.
hint simplify prot32E, prot64E, protpE.

(* ------------------------------------------------------------------ *)
(* The addresses and chain values of key pair kp                      *)

(* The address of type y of key pair kp, from the caller's ADRS a. *)
op adA (a : adrs) (y kp : int) : adrs = setKeyPairAddress (setTypeAndClear a y) kp.

(* Chain i of key pair kp after s steps (Algorithm 6, lines 5 to 8;
   Algorithm 7, lines 12 to 15). *)
op cend (pk sk : bytes) (a : adrs) (kp s i : int) : bytes =
  chain P (PRF P pk sk (setChainAddress (adA a WOTS_PRF kp) i)) 0 s pk
        (setChainAddress (adA a WOTS_HASH kp) i).

lemma size_adA (a : adrs) y kp : size a = 32 => size (adA a y kp) = 32.
proof. by move=> h; rewrite /adA size_skp // size_tc /#. qed.

lemma wots_pkGenE (sk pk : bytes) (a : adrs) kp : size a = 32 => 0 <= kp < 2 ^ 32 =>
  wots_pkGen P sk pk (adA a WOTS_HASH kp) =
  T_l P pk (adA a WOTS_PK kp) (flatten (map (cend pk sk a kp (w P - 1)) (range 0 (len P)))).
proof.
by move=> ha hk; rewrite /wots_pkGen /= /adA !pk_adrsE //.
qed.

(* Byte arrays that agree below o have the same first o bytes. *)
lemma take_tlen_eq (t1 t2 : TLenIn.t) o : 0 <= o =>
  (forall j, 0 <= j < o => TLenIn.get8 t1 j = TLenIn.get8 t2 j) =>
  take o (TLenIn.to_list t1) = take o (TLenIn.to_list t2).
proof.
move=> ho h; apply (eq_from_nth W8.zero); first by rewrite !size_take // !TLenIn.size_to_list.
move=> j; rewrite size_take // TLenIn.size_to_list => hj.
by rewrite !nth_take // 1,2:/# !TLenIn.get_to_list h /#.
qed.

(* The byte offset lane n of the signing lane in a four-way node. *)
lemma offE64 (x : W64.t) c : to_uint x < 4 => P.`n = c =>
  to_uint (x * W64.of_int c) = to_uint x * P.`n.
proof.
move=> hx hc; have hn := n_val; have h0 := W64.to_uint_cmp x.
have hc' : to_uint (W64.of_int c) = P.`n by rewrite W64.of_uintK -hc hn.
rewrite W64.to_uintM_small; rewrite hc' //.
by move: hx h0 hn; move: (to_uint x) (P.`n) => X N /#.
qed.

(* Offset arithmetic of the copy loops, at the literal sizes of the set. *)
lemma ar_w (w : int) : w < P.`n %/ 8 => 8 * (w + 1) <= P.`n.
proof. by rewrite n_val /=; smt(). qed.

lemma ar_blk (x : int) : 0 <= x < len P => 0 <= x * P.`n /\ x * P.`n + P.`n <= len P * P.`n.
proof. have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val). by rewrite hl n_val /=; smt(). qed.

lemma ar_off (x w : int) : 0 <= x < len P => 0 <= w => 8 * (w + 1) <= P.`n =>
  x * P.`n + 8 * w + 8 < W64.modulus.
proof. have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val). by rewrite hl n_val /=; smt(). qed.

lemma ar_in (x b : int) : 0 <= x < len P => 0 <= b < P.`n => 0 <= x * P.`n + b < len P * P.`n.
proof. have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val). by rewrite hl n_val /=; smt(). qed.

lemma len_ge4 : 4 <= len P.
proof. have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val). by rewrite hl n_val. qed.

lemma ar_pk (k x b : int) : 0 <= k < 4 => 0 <= x < len P => 0 <= b < P.`n =>
  0 <= k * (len P * P.`n) + x * P.`n + b < 4 * (len P * P.`n).
proof. have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val). by rewrite hl n_val /=; smt(). qed.

lemma ar_L4 : 4 * (len P * P.`n) < 18446744073709551616.
proof. have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val). by rewrite hl n_val. qed.

(* An index b of block k' lies outside the eight bytes at y of block k
   when the blocks differ or b < y. *)
lemma blk_out (L k k' b y : int) : 0 <= b < L => 0 <= y => y + 8 <= L =>
  (k' <> k \/ b < y) => !(k * L + y <= k' * L + b < k * L + y + 8).
proof.
move=> hb hy hyL hor; apply/negP => -[h1 h2].
have [hkk hxy] := blk_eq L k' k b (k' * L + b - k * L) hb _ _; 1,2: smt().
by move: hor h1; rewrite hkk => /#.
qed.

(* The eight bytes written at X + 8 w of block k miss byte X + b of an
   earlier block k'. *)
lemma blk_prev (L k k' X N b w : int) (Q : bool) : 0 <= b < N => 0 <= X => X + N <= L =>
  0 <= w => 8 * (w + 1) <= N => 0 <= k' < k =>
  !(k * L + X + 8 * w <= k' * L + X + b < k * L + X + 8 * w + 8 /\ Q).
proof.
move=> hb hX hXL hw hw8 hk; have h := blk_out L k k' (X + b) (X + 8 * w) _ _ _ _; 1..4: smt().
by apply/negP => -[hr _]; apply h; move: hr => /#.
qed.

lemma wots_leaf_x4_h (pk_seed : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     hoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk_seed (Node.to_list k0) (lane 32 k (BArray128.to_list a0))]) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     hoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk_seed (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))]) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     hoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk_seed (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))]) =>
  forall (s0 : TLenIn.t) (k0 : Node.t) (a0 : BArray32.t) (q0 : W32.t) (st0 : WotsDigits.t)
         (ln0 : W64.t),
  to_uint q0 + 3 < 2 ^ 32 =>
  hoare [M._wots_leaf_x4 :
    sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ kp0 = q0 /\ steps = st0 /\
    lane = ln0 /\
    (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) ==>
    (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
       wots_pkGen P (Node.to_list k0) pk_seed (adA (BArray32.to_list a0) WOTS_HASH (to_uint q0 + k))) /\
    (to_uint ln0 < 4 => TLenIn.to_list res.`2 =
       flatten (map (fun i => cend pk_seed (Node.to_list k0) (BArray32.to_list a0) (to_uint q0 + to_uint ln0)
                    (nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i) i) (range 0 (len P)))) /\
    (4 <= to_uint ln0 => res.`2 = s0)].
proof.
move=> hprf hf htl s0 k0 a0 q0 st0 ln0 hq.
have hb4 : forall k, 0 <= k < 4 => 0 <= to_uint q0 + k < W32.modulus.
+ move=> k hk; have := W32.to_uint_cmp q0; move: hq hk; clear hprf hf htl; smt().
have [A hA] : exists A, A = BArray32.to_list a0 by exists (BArray32.to_list a0).
have [K hK] : exists K, K = to_uint q0 by exists (to_uint q0).
have [sk hsk] : exists sk, sk = Node.to_list k0 by exists (Node.to_list k0).
have [D hD] : exists D, D = map W8.to_uint (WotsDigits.to_list st0) by exists (map W8.to_uint (WotsDigits.to_list st0)).
have [L hL] : exists L, L = len P * P.`n by exists (len P * P.`n).
pose sg := fun i => cend pk_seed sk A (K + to_uint ln0) (nth 0 D i) i.
pose pc := fun k => cend pk_seed sk A (K + k) (w P - 1).
pose SP := fun i => if to_uint ln0 < 4 then nth 0 D i else 16.
have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have hn := n_val.
have hAs : size A = 32 by rewrite hA BArray32.size_to_list.
have hL0 : 0 < L by rewrite hL hl hn.
have hL4 : forall (t : TLenIn4.t), size (TLenIn4.to_list t) = L * 4.
+ by move=> t; rewrite TLenIn4.size_to_list hL hl hn.
have hlane4 : forall (t : TLenIn4.t) k, 0 <= k < 4 => size (lanev L k (TLenIn4.to_list t)) = L.
+ move=> t k hk; have h := StdOrder.IntOrder.ler_wpmul2l L _ (k + 1) 4 _; 1,2: smt().
  rewrite lane_size; 1,2,4: smt().
  by rewrite hL4.
proc.
wp; ecall (htl pk pk_adrs); wp.
while (0 <= to_uint i <= len P /\ more = (to_uint i < len P) /\ sk_seed = k0 /\ ctx = c0 /\
       steps = st0 /\ lane = ln0 /\ (forall j, 0 <= j < len P => nth 0 D j < 16) /\
       (to_uint ln0 < 4 => take (to_uint i * P.`n) (TLenIn.to_list sig) =
          flatten (map sg (range 0 (to_uint i)))) /\
       (4 <= to_uint ln0 => sig = s0) /\
       forall k, 0 <= k < 4 =>
         (forall c, setChainAddress (lanev 32 k (BArray128.to_list sk_adrs)) c =
                    setChainAddress (adA A WOTS_PRF (K + k)) c) /\
         take 24 (lanev 32 k (BArray128.to_list chain_adrs)) = take 24 (adA A WOTS_HASH (K + k)) /\
         take (to_uint i * P.`n) (lanev L k (TLenIn4.to_list pk)) =
           flatten (map (pc k) (range 0 (to_uint i)))).
+ exlim i => i0.
  seq 15 : ((0 <= to_uint j <= 16 /\ step = (to_uint j < 16) /\ i = i0 /\ lane = ln0 /\ ctx = c0 /\
         0 <= to_uint i0 < len P /\ to_uint split_0 = SP (to_uint i0) /\
         (to_uint ln0 < 4 => 0 <= SP (to_uint i0) < 16) /\
         (forall k, 0 <= k < 4 =>
            lanev P.`n k (Node4.to_list cur) =
              cend pk_seed sk A (K + k) (min (to_uint j) (w P - 1)) (to_uint i0) /\
            take 28 (lanev 32 k (BArray128.to_list chain_adrs)) =
              take 28 (setChainAddress (adA A WOTS_HASH (K + k)) (to_uint i0))) /\
         (to_uint ln0 < 4 =>
            take (to_uint i0 * P.`n) (TLenIn.to_list sig) = flatten (map sg (range 0 (to_uint i0))) /\
            (SP (to_uint i0) < to_uint j =>
               take ((to_uint i0 + 1) * P.`n) (TLenIn.to_list sig) =
                 flatten (map sg (range 0 (to_uint i0 + 1))))) /\
         (4 <= to_uint ln0 => sig = s0)) /\
           !step /\ sk_seed = k0 /\ steps = st0 /\ (forall j, 0 <= j < len P => nth 0 D j < 16) /\
           forall k, 0 <= k < 4 =>
             lanev 32 k (BArray128.to_list sk_adrs) = setChainAddress (adA A WOTS_PRF (K + k)) (to_uint i0) /\
             take (to_uint i0 * P.`n) (lanev L k (TLenIn4.to_list pk)) = flatten (map (pc k) (range 0 (to_uint i0)))).
    while (0 <= to_uint j <= 16 /\ step = (to_uint j < 16) /\ i = i0 /\ lane = ln0 /\ ctx = c0 /\
           0 <= to_uint i0 < len P /\ to_uint split_0 = SP (to_uint i0) /\
           (to_uint ln0 < 4 => 0 <= SP (to_uint i0) < 16) /\
           (forall k, 0 <= k < 4 =>
              lanev P.`n k (Node4.to_list cur) =
                cend pk_seed sk A (K + k) (min (to_uint j) (w P - 1)) (to_uint i0) /\
              take 28 (lanev 32 k (BArray128.to_list chain_adrs)) =
                take 28 (setChainAddress (adA A WOTS_HASH (K + k)) (to_uint i0))) /\
           (to_uint ln0 < 4 =>
              take (to_uint i0 * P.`n) (TLenIn.to_list sig) = flatten (map sg (range 0 (to_uint i0))) /\
              (SP (to_uint i0) < to_uint j =>
                 take ((to_uint i0 + 1) * P.`n) (TLenIn.to_list sig) =
                   flatten (map sg (range 0 (to_uint i0 + 1))))) /\
           (4 <= to_uint ln0 => sig = s0)).
    + seq 4 : (0 <= to_uint j < 16 /\ i = i0 /\ lane = ln0 /\ ctx = c0 /\
               0 <= to_uint i0 < len P /\ to_uint split_0 = SP (to_uint i0) /\
               (to_uint ln0 < 4 => 0 <= SP (to_uint i0) < 16) /\
               (forall k, 0 <= k < 4 =>
                  lanev P.`n k (Node4.to_list cur) =
                    cend pk_seed sk A (K + k) (to_uint j) (to_uint i0) /\
                  take 28 (lanev 32 k (BArray128.to_list chain_adrs)) =
                    take 28 (setChainAddress (adA A WOTS_HASH (K + k)) (to_uint i0))) /\
               (to_uint ln0 < 4 =>
                  take (to_uint i0 * P.`n) (TLenIn.to_list sig) = flatten (map sg (range 0 (to_uint i0))) /\
                  (SP (to_uint i0) <= to_uint j =>
                     take ((to_uint i0 + 1) * P.`n) (TLenIn.to_list sig) =
                       flatten (map sg (range 0 (to_uint i0 + 1))))) /\
               (4 <= to_uint ln0 => sig = s0)).
      + sp; if.
        + inline M.__offset M.__offset64; wp.
          while (0 <= w <= inc /\ inc = P.`n %/ 8 /\ cp = cur /\ i = i0 /\ lane = ln0 /\
                 0 <= to_uint i0 < len P /\ to_uint ln0 < 4 /\
                 to_uint off = to_uint i0 * P.`n + 8 * w /\ to_uint src = to_uint ln0 * P.`n + 8 * w /\
                 take (to_uint i0 * P.`n) (TLenIn.to_list sig) = flatten (map sg (range 0 (to_uint i0))) /\
                 (forall b, 0 <= b < 8 * w =>
                    TLenIn.get8 sig (to_uint i0 * P.`n + b) = Node4.get8 cur (to_uint ln0 * P.`n + b))).
          + wp; skip => &m [#] hw0 hw1 hinc hcp hi hln hi0 hi1 hl4 hoff hsrc hsig hb hlt /=.
            have hts := tlen_size.
            have hw8 : 8 * (w{m} + 1) <= P.`n by apply ar_w; rewrite -hinc.
            have hl4' : 0 <= to_uint ln0 < len P by have := len_ge4; smt(W64.to_uint_cmp).
            split; first by move: hw0 hlt => /#.
            split; first by move: hw0 hlt => /#.
            do 3!(split; first done); split; first by split. split; first done.
            split.
            + rewrite W64.to_uintD_small W64.of_uintK /=; rewrite hoff.
              + by apply ar_off => //; split.
              by ring.
            split.
            + rewrite W64.to_uintD_small W64.of_uintK /=; rewrite hsrc.
              + by apply ar_off.
              by ring.
            split.
            + rewrite -hsig; apply take_tlen_eq; first smt(W32.to_uint_cmp).
              move=> b hb'; rewrite TLenIn.get8_set64dE ifF //; rewrite hoff.
              by move: hb' hw0; move: (to_uint i0 * P.`n) => X /#.
            move=> b hb'; rewrite TLenIn.get8_set64dE hoff.
            case: (8 * w{m} <= b) => hbw.
            + rewrite ifT.
              + have hin : 0 <= to_uint i0 * P.`n + b < len P * P.`n.
                + by apply ar_in; [split | move: hb' hw8 => /#].
                by move: hin hb' hbw; rewrite hl hn /= => /#.
              have -> : to_uint i0 * P.`n + b - (to_uint i0 * P.`n + 8 * w{m}) = b - 8 * w{m} by ring.
              rewrite hcp Node4.get64d_byte 1:/# hsrc; congr; ring.
            rewrite ifF; first by move: hbw; move: (to_uint i0 * P.`n) => X /#.
            by apply hb; move: hb' hbw => /#.
          wp; skip => &m /= [[sp0 ms0] [#] hms hsp hhit hj0 hj1 hst hi hln hctx hi0 hi1 hspE hsp16 hC
            hsig hsig4 hstep] hh.
          have hjs : to_uint j{m} = SP (to_uint i0) by move: hh; rewrite hhit hsp => ->; exact hspE.
          have hl4 : to_uint ln0 < 4.
          + case: (to_uint ln0 < 4) => // h4; move: hjs hst hstep; rewrite /SP h4 /= => -> /#.
          have hSP : SP (to_uint i0) = nth 0 D (to_uint i0) by rewrite /SP hl4.
          rewrite hi hln (offE i0 _ _ hn) 1:/# (offE64 ln0 _ _ hn) 1:hl4.
          have hts := tlen_size.
          have hn8 : 8 * (P.`n %/ 8) = P.`n by rewrite hn.
          split.
          + do 7!(split; first by rewrite ?hn).
            split; first by have [-> _] := hsig hl4.
            by move=> b /#.
          move=> off2 sig0 src0 w0 hw [#] g0 g1 ginc gi gln gi0 gi1 gl4 goff gsrc gsig gb.
          have hw0 : 8 * w0 = P.`n by rewrite -hn8; congr; move: hw g1 ginc => /#.
          have hmin : min (to_uint j{m}) (w P - 1) = to_uint j{m} by rewrite w_val; move: hj1 hst hstep => /#.
          split; first by move: hj0 hst hstep => /#.
          do 3!(split; first done).
          split; first by split.
          split; first by rewrite hsp.
          split; first exact hsp16.
          split; first by move=> k hk; rewrite -hmin; apply hC.
          split; last by move: hl4 => /#.
          move=> _; split; first exact gsig.
          move=> _.
          have hx : size (lanev P.`n (to_uint ln0) (Node4.to_list cur{m})) = P.`n.
          + rewrite lane_size; 1,2: smt(W64.to_uint_cmp).
            + by rewrite Node4.size_to_list; move: hl4 hn; move: (to_uint ln0) (P.`n) => X N /#.
            done.
          have := take_ext W8.zero (TLenIn.to_list sig0) (flatten (map sg (range 0 (to_uint i0))))
                    (lanev P.`n (to_uint ln0) (Node4.to_list cur{m})) (to_uint i0 * P.`n) _ gsig _ _.
          + smt(W32.to_uint_cmp).
          + rewrite hx TLenIn.size_to_list; have := ar_blk (to_uint i0) _; first by split.
            by rewrite hl hn /= => /#.
          + move=> b; rewrite hx => hb; rewrite TLenIn.get_to_list gb 1:/#.
            by have hl0 := W64.to_uint_cmp ln0; rewrite nth_lane 1,2:/# // Node4.get_to_list mulzC.
          rewrite hx (_ : to_uint i0 * P.`n + P.`n = (to_uint i0 + 1) * P.`n) 1:/# => ->.
          rewrite rangeSr 1:/# map_rcons flatten_rcons.
          have [-> _] := hC (to_uint ln0) _; first smt(W64.to_uint_cmp).
          by rewrite hmin hjs hSP /sg.
        wp; skip => &m /= [[sp0 ms0] [#] hms hsp hhit hj0 hj1 hst hi hln hctx hi0 hi1 hspE hsp16 hC
          hsig hsig4 hstep] hh.
        have hjs : to_uint j{m} <> SP (to_uint i0).
        + by rewrite -hspE -hsp; move: hh; rewrite hhit W32.to_uint_eq.
        have hmin : min (to_uint j{m}) (w P - 1) = to_uint j{m} by rewrite w_val; move: hj1 hst hstep => /#.
        split; first by move: hj0 hst hstep => /#.
        do 3!(split; first done).
        split; first by split.
        split; first by rewrite hsp.
        split; first exact hsp16.
        split; first by move=> k hk; rewrite -hmin; apply hC.
        split; last exact hsig4.
        move=> h4; have [g1 g2] := hsig h4; split; first exact g1.
        by move=> hle; apply g2; move: hle hjs => /#.
      sp; if.
      + wp; ecall (hf cur chain_adrs); wp.
        while (0 <= k <= 4 /\ 0 <= to_uint j < 15 /\
               forall k', 0 <= k' < 4 =>
                 (k' < k => lanev 32 k' (BArray128.to_list chain_adrs) =
                    setHashAddress (setChainAddress (adA A WOTS_HASH (K + k')) (to_uint i0)) (to_uint j)) /\
                 (k <= k' => take 28 (lanev 32 k' (BArray128.to_list chain_adrs)) =
                    take 28 (setChainAddress (adA A WOTS_HASH (K + k')) (to_uint i0)))).
        + wp; ecall (hash_h (SBArray128_32.get_sub64 chain_adrs (4 * k)) j).
          skip => &m [#] hk0 hk1 hj0 hj1 hI hk /= r hr.
          have hg : forall a, BArray32.to_list (SBArray128_32.get_sub64 a (4 * k{m})) =
                              lane 32 k{m} (BArray128.to_list a) by move=> a; apply adrs4_get; smt().
          have hs : forall a x, lane 32 k{m} (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k{m}) x)) =
                                BArray32.to_list x by move=> a x; apply adrs4_set_same; smt().
          move: hr; rewrite hg => hr.
          split; first smt().
          split; first by split.
          move=> k' hk'; case: (k' = k{m}) => [->|hne].
          + rewrite hs /=; split; last by move=> /#.
            move=> _; have := hI k{m} _; first smt().
            move=> [_ /(_ _)]; first smt().
            by move=> h28; rewrite hr; apply sha_eq.
          have ho : forall a x, lane 32 k' (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k{m}) x)) =
                                lane 32 k' (BArray128.to_list a) by move=> a x; apply adrs4_set_other; smt().
          rewrite !ho; have [hIa hIb] := hI k' hk'; case: (k' < k{m}) => h.
          + by split => [_|/#]; apply hIa.
          by split => [/#|_]; apply hIb => /#.
        wp; skip => &m [#] hfwd hj0 hj1 hi hln hctx hi0 hi1 hspE hsp16 hC hsig hsig4 hf' /=.
        have hj15 : to_uint j{m} < 15 by move: hf'; rewrite hfwd W32.ultE W32.of_uintK /=.
        split.
        + split; first by split.
          by move=> k' hk'; split => [/#|_]; have [_ ->] := hC k' hk'.
        move=> ca k1 hk4 [#] g0 g1 gj0 gj1 gI.
        have hk : k1 = 4 by move: hk4 g1 => /#.
        rewrite hctx /= => r hr.
        have hjj : to_uint (j{m} + W32.one) = to_uint j{m} + 1.
        + by rewrite W32.to_uintD_small W32.to_uint1 //; move: hj15 => /#.
        have hmin : min (to_uint j{m} + 1) (w P - 1) = to_uint j{m} + 1 by rewrite w_val; move: hj15 => /#.
        rewrite hjj hmin.
        split; first by move: hj0 hj15 => /#.
        split; first by rewrite W32.ultE W32.of_uintK hjj /=.
        do 2!(split; first done).
        split; first by split.
        split; first done.
        split; first exact hsp16.
        split.
        + move=> k hk'; have [hc h28] := hC k hk'; have [gl _] := gI k hk'.
          have hla := gl _; first by rewrite hk; move: hk' => /#.
          have hsz : 28 <= size (setChainAddress (adA A WOTS_HASH (K + k)) (to_uint i0)).
          + by rewrite size_sca //; apply size_adA.
          split.
          + by rewrite hr // hla hc /cend (chainS _ _ _ _ _ hj0 hsz) /=.
          by rewrite hla; have [_ ->] := sha_take _ (to_uint j{m}) hsz.
        split; last exact hsig4.
        move=> h4; have [s1 s2] := hsig h4; split; first exact s1.
        by move=> hlt; apply s2; move: hlt => /#.
      wp; skip => &m [#] hfwd hj0 hj1 hi hln hctx hi0 hi1 hspE hsp16 hC hsig hsig4 hf' /=.
      have hj15 : to_uint j{m} = 15 by move: hf'; rewrite hfwd W32.ultE W32.of_uintK /=; move: hj1 => /#.
      have hjj : to_uint (j{m} + W32.one) = 16 by rewrite W32.to_uintD_small W32.to_uint1 hj15.
      have hmin : min 16 (w P - 1) = to_uint j{m} by rewrite w_val hj15.
      rewrite hjj hmin W32.ultE W32.of_uintK hjj /=.
      do 3!(split; first done).
      split; first by split.
      split; first done.
      split; first exact hsp16.
      split; first exact hC.
      split; last exact hsig4.
      move=> h4; have [s1 s2] := hsig h4; split; first exact s1.
      by move=> hlt; apply s2; move: hlt; rewrite hj15 => /#.
    wp; ecall (hprf sk_seed sk_adrs); wp.
    while (0 <= k <= 4 /\
           forall k', 0 <= k' < 4 =>
             (k' < k => lanev 32 k' (BArray128.to_list sk_adrs) =
                          setChainAddress (adA A WOTS_PRF (K + k')) (to_uint i) /\
                        take 28 (lanev 32 k' (BArray128.to_list chain_adrs)) =
                          take 28 (setChainAddress (adA A WOTS_HASH (K + k')) (to_uint i))) /\
             (k <= k' => (forall c, setChainAddress (lanev 32 k' (BArray128.to_list sk_adrs)) c =
                                    setChainAddress (adA A WOTS_PRF (K + k')) c) /\
                         take 24 (lanev 32 k' (BArray128.to_list chain_adrs)) =
                           take 24 (adA A WOTS_HASH (K + k')))).
    + wp; ecall (chain_h (SBArray128_32.get_sub64 chain_adrs (4 * k)) i); wp.
      ecall (chain_h (SBArray128_32.get_sub64 sk_adrs (4 * k)) i); skip => &m [#] hk0 hk1 hI hk /=.
      move=> r1 hr1 r2 hr2.
      have hg : forall a, BArray32.to_list (SBArray128_32.get_sub64 a (4 * k{m})) =
                          lane 32 k{m} (BArray128.to_list a) by move=> a; apply adrs4_get; smt().
      have hs : forall a x, lane 32 k{m} (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k{m}) x)) =
                            BArray32.to_list x by move=> a x; apply adrs4_set_same; smt().
      move: hr1 hr2; rewrite !hg => hr1 hr2.
      split; first smt().
      move=> k' hk'; case: (k' = k{m}) => [->|hne].
      + rewrite !hs /=; split; last by move: hk1 => /#.
        move=> _; have := hI k{m} _; first smt().
        move=> [_ /(_ _)]; first smt().
        move=> [hsc hc24]; rewrite hr1 hsc hr2; split; first done.
        by apply take28_sca; [rewrite adrs4_size; smt() | exact hc24].
      have ho : forall a x, lane 32 k' (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k{m}) x)) =
                            lane 32 k' (BArray128.to_list a) by move=> a x; apply adrs4_set_other; smt().
      rewrite !ho; have [hIa hIb] := hI k' hk'; case: (k' < k{m}) => h.
      + by have h1 := hIa h; split => // /#.
      have h2 := hIb _; first smt().
      by split; [move=> /# | move=> _; exact h2].
    wp; skip => &m [#] -> hi0 hi1 hmo hsks hctx hst hln hdd hsig1 hsig2 hI hmore /=.
    have hlt : to_uint i{m} < len P by move: hmo hmore => /#.
    split.
    + move=> k' hk'; split; first by move=> /#.
      by move=> _; have [#] h1 h2 _ := hI k' hk'; split; [exact h1 | exact h2].
    move=> ca k1 sa hk4 [#] hk0 hk1 hC; rewrite hctx /= => r hr.
    have hcur : forall k, 0 <= k < 4 =>
      lanev P.`n k (Node4.to_list r.`1) = cend pk_seed sk A (K + k) 0 (to_uint i{m}).
    + move=> k hk'; rewrite hr // hsks -hsk.
      have [hCa _] := hC k hk'; have [-> _] := hCa _; first by move: hk4 hk1 hk' => /#.
      by rewrite /cend chain0.
    have hch : forall k, 0 <= k < 4 =>
      take 28 (lanev 32 k (BArray128.to_list ca)) =
      take 28 (setChainAddress (adA A WOTS_HASH (K + k)) (to_uint i{m})).
    + move=> k hk'; have [hCa _] := hC k hk'; have [_ ->] := hCa _; first by move: hk4 hk1 hk' => /#.
      done.
    have hsa : forall k, 0 <= k < 4 =>
      lanev 32 k (BArray128.to_list sa) = setChainAddress (adA A WOTS_PRF (K + k)) (to_uint i{m}).
    + move=> k hk'; have [hCa _] := hC k hk'; have [-> _] := hCa _; first by move: hk4 hk1 hk' => /#.
      done.
    have hm0 : min 0 (w P - 1) = 0 by rewrite w_val.
    have htk : (ln0 \ult W64.of_int 4) = (to_uint ln0 < 4) by rewrite W64.ultE W64.of_uintK modz_small.
    have hz : to_uint W32.zero = 0 by done.
    have hz16 : (W32.zero \ult W32.of_int 16) = true by rewrite W32.ultE W32.of_uintK modz_small.
    have hSP0 : to_uint ln0 < 4 => 0 <= nth 0 D (to_uint i{m}) < 16.
    + move=> _; have h16 := hdd (to_uint i{m}) _; first by move: hi0 hlt => /#.
      have h0 : 0 <= nth 0 D (to_uint i{m}).
      + rewrite hD (nth_map W8.zero) ?WotsDigits.size_to_list; first by move: hi0 hlt hl hn => /#.
        by have := W8.to_uint_cmp (nth W8.zero (WotsDigits.to_list st0) (to_uint i{m})); move=> /#.
      by move: h0 h16 => /#.
    rewrite hln htk; case: (to_uint ln0 < 4) => hl4 /=.
    + split.
      + split; first by move: hi0 hlt => /#.
        split.
        + rewrite /SP hl4 /= zext64E zext32E W32.of_uintK pmod_small.
          + by have := W8.to_uint_cmp (WotsDigits.get8 steps{m} (to_uint i{m})); smt().
          rewrite hst hD (nth_map W8.zero) ?WotsDigits.size_to_list; first by move: hi0 hlt hl hn => /#.
          by rewrite WotsDigits.get_to_list.
        split; first by rewrite /SP hl4 /=; apply hSP0.
        split; first by move=> k hk'; rewrite hm0 hcur // hch.
        split; last by move: hl4 => /#.
        split; first by apply hsig1.
        by rewrite /SP hl4 /=; have := hSP0 hl4; move=> /#.
      move=> ca2 ctx2 cur2 i2 j2 ln2 sg2 sp2 st2 hns hIj.
      split; first exact hIj.
      split; first done.
      split; first exact hsks.
      split; first exact hst.
      split; first exact hdd.
      move=> k hk'; split; first by apply hsa.
      by have [#] _ _ -> := hI k hk'.
    split.
    + split; first by move: hi0 hlt => /#.
      split; first by rewrite /SP hl4.
      split; first by move=> k hk'; rewrite hm0 hcur // hch.
      by move=> h4; apply hsig2.
    move=> ca2 ctx2 cur2 i2 j2 ln2 sg2 sp2 st2 hns hIj.
    split; first exact hIj.
    split; first done.
    split; first exact hsks.
    split; first exact hst.
    split; first exact hdd.
    move=> k hk'; split; first by apply hsa.
    by have [#] _ _ -> := hI k hk'.
  wp; while (0 <= k <= 4 /\ 0 <= to_uint i0 < len P /\
             to_uint off = k * L + to_uint i0 * P.`n /\
             (forall k', 0 <= k' < 4 => take (to_uint i0 * P.`n) (lanev L k' (TLenIn4.to_list dst)) =
                                     flatten (map (pc k') (range 0 (to_uint i0)))) /\
             (forall k' b, 0 <= k' < k => 0 <= b < P.`n =>
                TLenIn4.get8 dst (k' * L + to_uint i0 * P.`n + b) = Node4.get8 cur (k' * P.`n + b))).
  + wp; while (0 <= k < 4 /\ 0 <= w <= inc /\ inc = P.`n %/ 8 /\ 0 <= to_uint i0 < len P /\
               to_uint off = k * L + to_uint i0 * P.`n + 8 * w /\
               (forall k', 0 <= k' < 4 => take (to_uint i0 * P.`n) (lanev L k' (TLenIn4.to_list dst)) =
                                       flatten (map (pc k') (range 0 (to_uint i0)))) /\
               (forall k' b, 0 <= k' < k => 0 <= b < P.`n =>
                  TLenIn4.get8 dst (k' * L + to_uint i0 * P.`n + b) = Node4.get8 cur (k' * P.`n + b)) /\
               (forall b, 0 <= b < 8 * w =>
                  TLenIn4.get8 dst (k * L + to_uint i0 * P.`n + b) = Node4.get8 cur (k * P.`n + b))).
    + wp; skip => &m [#] hk0 hk1 hw0 hw1 hinc hi0 hi1 hoff hpre hprev hcur hlt /=.
      have hw8 : 8 * (w{m} + 1) <= P.`n by apply ar_w; rewrite -hinc.
      have [hb0 hbl] : 0 <= to_uint i0 * P.`n /\ to_uint i0 * P.`n + P.`n <= L.
      + by rewrite hL; apply ar_blk; split.
      split; first by split.
      split; first by move: hw0 hlt => /#.
      split; first done.
      split; first by split.
      split.
      + rewrite W64.to_uintD_small W64.of_uintK /= hoff.
        + have h := ar_pk k{m} (to_uint i0) (8 * w{m} + 7).
          have := ar_L4; rewrite -hL; move: h; rewrite -hL; move: hk0 hk1 hi0 hi1 hw0 hw8 => /#.
        by ring.
      split.
      + move=> k' hk'; rewrite -(hpre k' hk'); apply (take_lane_eq W8.zero).
        + by move: hb0 hbl hn; move: (to_uint i0 * P.`n) => X /#.
        + smt().
        + by rewrite !hL4.
        move=> b hb; rewrite !TLenIn4.get_to_list TLenIn4.get8_set64dE hoff ifF //.
        have := blk_out L k{m} k' b (to_uint i0 * P.`n + 8 * w{m}).
        by rewrite (mulzC L k'); move: hb hb0 hbl hw0 hw8 hk' hk0; move: (to_uint i0 * P.`n) => X /#.
      split.
      + move=> k' b hk' hb; rewrite TLenIn4.get8_set64dE hoff ifF; last by apply hprev.
        exact (blk_prev L k{m} k' (to_uint i0 * P.`n) P.`n b w{m}).
      move=> b hb; rewrite TLenIn4.get8_set64dE hoff.
      case: (8 * w{m} <= b) => hbw.
      + rewrite ifT.
        + by move: hk0 hk1 hi0 hi1 hb hbw hw8; rewrite hL hl hn /= => /#.
        have -> : k{m} * L + to_uint i0 * P.`n + b - (k{m} * L + to_uint i0 * P.`n + 8 * w{m}) =
                  b - 8 * w{m} by ring.
        rewrite Node4.get64d_byte 1:/#; congr.
        by rewrite hn /=; ring.
      rewrite ifF; first by move: hbw; move: (k{m} * L + to_uint i0 * P.`n) => X /#.
      by apply hcur; move: hb hbw => /#.
    wp; skip => &m [#] hk0 hk1 hi0 hi1 hoff hpre hprev hlt /=.
    split.
    + split; first by split.
      split; first by rewrite hn.
      split; first by split.
      split; first done.
      split; first exact hpre.
      split; first exact hprev.
      by move=> b /#.
    move=> dst0 off0 w0 hw [#] g0 g1 g2 g3 ginc gi0 gi1 goff gpre gprev gcur.
    have hw0 : 8 * w0 = P.`n.
    + have -> : w0 = P.`n %/ 8 by move: hw g3 ginc; move: (P.`n %/ 8) => M /#.
      by rewrite hn.
    split; first by move: hk0 hlt => /#.
    split; first by split.
    split.
    + rewrite W64.to_uintD_small W64.of_uintK /= goff hw0.
      + by move: hk0 hlt hi0 hi1; rewrite hL hl hn /= => /#.
      by move: hk0 hlt hi0 hi1; rewrite hL hl hn /= => /#.
    split; first exact gpre.
    move=> k' b hk' hb; case: (k' < k{m}) => h; first by apply gprev => //; move: hk' h => /#.
    have -> : k' = k{m} by move: hk' h => /#.
    by apply gcur; rewrite hw0.
  inline M.__offset; wp; skip => &m /= [#] hj0 hj1 hst hi hln hctx hi0 hi1 hspE hsp16 hC hsig hsig4
    hns hsks hstp hdd hP.
  have hj16 : to_uint j{m} = 16 by move: hst hns hj1 => /#.
  have hmin : min (to_uint j{m}) (w P - 1) = w P - 1 by rewrite hj16 w_val.
  have hts := tlen_size.
  have [hb0 hbl] : 0 <= to_uint i0 * P.`n /\ to_uint i0 * P.`n + P.`n <= L.
  + by rewrite hL; apply ar_blk; split.
  rewrite hi (offE i0 _ _ hn) 1:hi1.
  split.
  + split; first by split.
    split; first done.
    split; first by move=> k' hk'; have [_ ->] := hP k' hk'.
    by move=> k' b /#.
  move=> dst0 k1 off0 hk [#] g0 g1 gi0 gi1 goff gpre gprev.
  have hk4 : k1 = 4 by move: hk g1 => /#.
  have hii : to_uint (i0 + W32.one) = to_uint i0 + 1.
  + rewrite W32.to_uintD_small W32.to_uint1 //.
    by move: hi1; rewrite hl hn /= => /#.
  rewrite hii.
  split; first by move: hi0 hi1 => /#.
  split; first by rewrite W32.ultE W32.of_uintK hii hl hn /=.
  do 5!(split; first done).
  split.
  + move=> h4; have [_ h] := hsig h4; apply h.
    by have := hsp16 h4; rewrite hj16 => /#.
  split; first exact hsig4.
  move=> k2 hk2; split.
  + by move=> c; have [-> _] := hP k2 hk2; rewrite sca_sca ?size_adA.
  split.
  + have [_ h28] := hC k2 hk2.
    have h24 : take 24 (take 28 (lanev 32 k2 (BArray128.to_list chain_adrs{m}))) =
               take 24 (take 28 (setChainAddress (adA A WOTS_HASH (K + k2)) (to_uint i0))).
    + by rewrite h28.
    by move: h24; rewrite !take_take /= take24_sca ?size_adA.
  have hx : size (lanev P.`n k2 (Node4.to_list cur{m})) = P.`n.
  + rewrite lane_size; 1,2: smt().
    + rewrite Node4.size_to_list hn /max /=.
      by move: hk2 => /#.
    done.
  have hl2 : size (lanev L k2 (TLenIn4.to_list dst0)) = L by apply hlane4.
  have := take_ext W8.zero (lanev L k2 (TLenIn4.to_list dst0)) (flatten (map (pc k2) (range 0 (to_uint i0))))
            (lanev P.`n k2 (Node4.to_list cur{m})) (to_uint i0 * P.`n) _ (gpre k2 hk2) _ _.
  + done.
  + by rewrite hx hl2.
  + move=> b; rewrite hx => hb.
    have hL0' : 0 <= L by move: hL0 => /#.
    have e1 : nth W8.zero (lanev L k2 (TLenIn4.to_list dst0)) (to_uint i0 * P.`n + b) =
              nth W8.zero (TLenIn4.to_list dst0) (L * k2 + (to_uint i0 * P.`n + b)).
    + apply nth_lane; [done | smt() | move: hb hb0 hbl; move: (to_uint i0 * P.`n) => X; move: (P.`n) => N /#].
    have e2 : nth W8.zero (lanev P.`n k2 (Node4.to_list cur{m})) b =
              nth W8.zero (Node4.to_list cur{m}) (P.`n * k2 + b).
    + by apply nth_lane; [rewrite hn | smt() | done].
    rewrite e1 e2 TLenIn4.get_to_list Node4.get_to_list (mulzC L k2) addzA (mulzC P.`n k2).
    by apply gprev; [rewrite hk4 | done].
  rewrite hx (_ : to_uint i0 * P.`n + P.`n = (to_uint i0 + 1) * P.`n) 1:/# => ->.
  rewrite rangeSr 1:/# map_rcons flatten_rcons.
  have [-> _] := hC k2 hk2.
  by rewrite hmin /pc.
wp; while (true); first by wp.
wp; while (0 <= k <= 4 /\ adrs = a0 /\ kp0 = q0 /\
           forall k', 0 <= k' < k =>
             lanev 32 k' (BArray128.to_list sk_adrs) = adA A WOTS_PRF (K + k') /\
             lanev 32 k' (BArray128.to_list chain_adrs) = adA A WOTS_HASH (K + k') /\
             lanev 32 k' (BArray128.to_list pk_adrs) = adA A WOTS_PK (K + k')).
+ wp.
  ecall (kp_h (SBArray128_32.get_sub64 pk_adrs (4 * k)) kp); wp.
  ecall (tc1_h (SBArray128_32.get_sub64 pk_adrs (4 * k))); wp.
  ecall (copy_h (SBArray128_32.get_sub64 pk_adrs (4 * k)) adrs); wp.
  ecall (kp_h (SBArray128_32.get_sub64 chain_adrs (4 * k)) kp); wp.
  ecall (tc0_h (SBArray128_32.get_sub64 chain_adrs (4 * k))); wp.
  ecall (copy_h (SBArray128_32.get_sub64 chain_adrs (4 * k)) adrs); wp.
  ecall (kp_h (SBArray128_32.get_sub64 sk_adrs (4 * k)) kp); wp.
  ecall (tc5_h (SBArray128_32.get_sub64 sk_adrs (4 * k))); wp.
  ecall (copy_h (SBArray128_32.get_sub64 sk_adrs (4 * k)) adrs); wp.
  skip => &m [#] hk0 hk1 -> -> hI hk /=.
  move=> r1 hr1 r2 hr2 r3 hr3 r4 hr4 r5 hr5 r6 hr6 r7 hr7 r8 hr8 r9 hr9.
  have hg : forall a, BArray32.to_list (SBArray128_32.get_sub64 a (4 * k{m})) =
                      lane 32 k{m} (BArray128.to_list a) by move=> a; apply adrs4_get; smt().
  have hs : forall a x, lane 32 k{m} (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k{m}) x)) =
                        BArray32.to_list x by move=> a x; apply adrs4_set_same; smt().
  have hkp : to_uint (q0 + W32.of_int k{m}) = K + k{m}.
  + have hk' : to_uint (W32.of_int k{m}) = k{m} by rewrite W32.of_uintK modz_small /#.
    by rewrite W32.to_uintD_small; rewrite hk'; move: hq hk hK hk0 => /#.
  move: hr2 hr3 hr5 hr6 hr8 hr9; rewrite !hg !hs => hr2 hr3 hr5 hr6 hr8 hr9.
  split; first smt().
  move=> k' hk'; case: (k' = k{m}) => [->|hne].
  + by rewrite !hs hr3 hr2 hr6 hr5 hr9 hr8 hr1 hr4 hr7 hkp /adA hA.
  have ho : forall a x, lane 32 k' (BArray128.to_list (SBArray128_32.set_sub64 a (4 * k{m}) x)) =
                        lane 32 k' (BArray128.to_list a) by move=> a x; apply adrs4_set_other; smt().
  by rewrite !ho; apply hI; smt().
wp; skip => &m [#] -> -> -> -> -> -> -> hdd /=.
split; first smt().
move=> ca k1 pa sa hk4 [#] hk0 hk1 hS k2 pk0 _.
have hk : k1 = 4 by move: hk4 hk1 => /#.
split.
+ split; first smt(n_val len1_val len2_val).
  split; first smt(n_val len1_val len2_val).
  split; first by rewrite hD.
  split; first by rewrite take0 range_geq.
  move=> k hk'; have := hS k _; first smt().
  by move=> [#] -> -> _ /=; rewrite take0 range_geq.
move=> ca2 ctx2 i2 ln2 mo2 pk2 sg2 sa2 sks2 st2 hmo [#] hi0 hi1 hmo' hsks hctx hst hln hd2.
move=> hsig1 hsig2 hI; have hi : to_uint i2 = len P by move: hmo hmo' hi1 => /#.
rewrite hctx /= => r hr.
have hts := tlen_size.
split.
+ move=> k hk'; have hb := hb4 k hk'.
  rewrite hr // (wots_pkGenE _ _ _ _ (ADRS.size_bytes_of a0) hb).
  have := hS k _; first smt().
  move=> [#] _ _ ->; rewrite -hA -hK -hsk.
  have := hI k hk'; rewrite hi => [#] _ _ <-.
  by rewrite -hL take_oversize // hlane4.
split => hlt.
+ have := hsig1 hlt; rewrite hi -hts take_oversize ?TLenIn.size_to_list //.
  by move=> ->; rewrite /sg hsk hA hK hD.
by apply hsig2.
qed.

(* The step of a 32-bit loop counter below its bound. *)
lemma cnt_step (j : W32.t) c : 0 <= to_uint j < c => c < W32.modulus =>
  to_uint (j + W32.one) = to_uint j + 1 /\
  ((j + W32.one) \ult W32.of_int c) = (to_uint j + 1 < c).
proof.
move=> hj hc; have e : to_uint (j + W32.one) = to_uint j + 1.
+ by rewrite W32.to_uintD_small W32.to_uint1 //; move: hj hc => /#.
by rewrite W32.ultE e W32.of_uintK modz_small //; move: hj hc => /#.
qed.

(* _wots_leaf_x4 terminates for every input; the x4 premises give the
   termination of the hash calls with the caller's ctx. *)
lemma wots_leaf_x4_ll (pk_seed : bytes) cx :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = cx /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk_seed (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = cx /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk_seed (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = cx /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk_seed (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  phoare [M._wots_leaf_x4 : ctx = cx ==> true] = 1%r.
proof.
move=> hprf hf htl.
have hprfl : phoare [M._thash_prf_x4 : ctx = cx ==> true] = 1%r.
+ by proc*; exlim sk_seed, adrs => k1 a1; call (hprf k1 a1); auto.
have hfl : phoare [M._thash_f_x4 : ctx = cx ==> true] = 1%r.
+ by proc*; exlim x, adrs => x1 a1; call (hf x1 a1); auto.
have htll : phoare [M._thash_t_len_x4 : ctx = cx ==> true] = 1%r.
+ by proc*; exlim in_0, adrs => m1 a1; call (htl m1 a1); auto.
have off_ll : islossless M.__offset by islossless.
have off64_ll : islossless M.__offset64 by islossless.
have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have hn := n_val.
have hlm : len P < W32.modulus by rewrite hl hn.
proc.
wp; call htll; wp.
while (ctx = cx /\ more = (to_uint i < len P) /\ 0 <= to_uint i <= len P) (len P - to_uint i).
+ move=> z.
  wp; while true (4 - k).
  + move=> ?; wp; while true (inc - w); first by auto => /#.
    by auto => /#.
  wp; call off_ll; wp.
  while (ctx = cx /\ step = (to_uint j < 16) /\ 0 <= to_uint j <= 16 /\
         0 <= to_uint i < len P /\ len P - to_uint i = z) (16 - to_uint j).
  + move=> z2.
    seq 4 : (ctx = cx /\ 0 <= to_uint j < 16 /\ 0 <= to_uint i < len P /\
             len P - to_uint i = z /\ 16 - to_uint j = z2) 1%r 1%r 0%r _.
    + sp; if; last by auto.
      by inline *; wp; while (true); auto.
    + sp; if.
      + wp; while true (inc - w); first by auto => /#.
        by wp; call off64_ll; call off_ll; auto => /#.
      by auto => /#.
    + sp; if.
      + wp; call hfl; wp; while true (4 - k).
        + by move=> ?; wp; call set_hash_ll; auto => /#.
        auto => &m [#] hfw hc hj0 hj1 hi0 hi1 hz hz2 hfw2 k0 /=.
        split; first smt().
        move=> _; rewrite hc /=.
        by have [-> ->] := cnt_step j{m} 16 _ _; [split | done | smt()].
      auto => &m [#] hfw hc hj0 hj1 hi0 hi1 hz hz2 hfw2 /=; rewrite hc /=.
      by have [-> ->] := cnt_step j{m} 16 _ _; [split | done | smt()].
    + hoare; sp; if.
      + inline *; wp; while (true); first by auto.
        by auto => /#.
      by auto => /#.
    by move=> &hr.
  wp; call hprfl; wp; while true (4 - k).
  + by move=> ?; wp; call set_chain_ll; wp; call set_chain_ll; auto => /#.
  auto => &m [#] hc hmo hi0 hi1 hmore hz /= k0.
  split; first smt().
  move=> _; rewrite hc /=.
  have hil : to_uint i{m} < len P by move: hmo hmore => /#.
  case: (lane{m} \ult W64.of_int 4) => _ /=.
  + split; first by move: hi0 hil hz => /#.
    move=> ctx0 i0 j0 step0; split; first smt().
    move=> hs [#] gc gst gj0 gj1 gi0 gi1 gz k1; split; first smt().
    move=> _; have hp1 : 0 <= to_uint i0 < len P by split.
    have [e1 e2] := cnt_step i0 (len P) hp1 hlm.
    rewrite e1 gc /=; move: e2 gi0 gi1 gz; rewrite hl hn /= => -> /#.
  split; first by move: hi0 hil hz => /#.
  move=> ctx0 i0 j0 step0; split; first smt().
  move=> hs [#] gc gst gj0 gj1 gi0 gi1 gz k1; split; first smt().
  move=> _; have hp1 : 0 <= to_uint i0 < len P by split.
  have [e1 e2] := cnt_step i0 (len P) hp1 hlm.
  rewrite e1 gc /=; move: e2 gi0 gi1 gz; rewrite hl hn /= => -> /#.
wp; while true (inc - k); first by auto => /#.
wp; while true (4 - k).
+ move=> ?; wp; call set_keypair_ll; wp; call set_tc_ll; wp; call copy_ll; wp.
  call set_keypair_ll; wp; call set_tc_ll; wp; call copy_ll; wp.
  by call set_keypair_ll; wp; call set_tc_ll; wp; call copy_ll; auto => /#.
auto => &m hc /= k0; split; first smt().
move=> _ k1; split; first smt().
move=> _; split; first by rewrite hc /= hl hn.
move=> ctx0 i1 more0; split; first smt().
by move=> _ [].
qed.

(* FIPS 205 Algorithm 6 for key pairs q0 .. q0 + 3 and, when lane < 4,
   the chains of Algorithm 7 (lines 8 to 15) for key pair q0 + lane, each
   advanced by the caller's digit: _wots_leaf_x4 returns the four public
   keys lane by lane and the signature of the signing lane, and leaves
   sig untouched for lane >= 4. The digits are below w = 16, as
   wots_digits produces them. *)
lemma wots_leaf_x4_correct (pk_seed : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk_seed (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk_seed (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk_seed (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  forall (s0 : TLenIn.t) (k0 : Node.t) (a0 : BArray32.t) (q0 : W32.t) (st0 : WotsDigits.t)
         (ln0 : W64.t),
  to_uint q0 + 3 < 2 ^ 32 =>
  phoare [M._wots_leaf_x4 :
    sig = s0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\ kp0 = q0 /\ steps = st0 /\
    lane = ln0 /\
    (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i < 16) ==>
    (forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
       wots_pkGen P (Node.to_list k0) pk_seed (adA (BArray32.to_list a0) WOTS_HASH (to_uint q0 + k))) /\
    (to_uint ln0 < 4 => TLenIn.to_list res.`2 =
       flatten (map (fun i => cend pk_seed (Node.to_list k0) (BArray32.to_list a0) (to_uint q0 + to_uint ln0)
                    (nth 0 (map W8.to_uint (WotsDigits.to_list st0)) i) i) (range 0 (len P)))) /\
    (4 <= to_uint ln0 => res.`2 = s0)] = 1%r.
proof.
move=> hprf hf htl s0 k0 a0 q0 st0 ln0 hq.
have hprf' : forall (k1 : Node.t) (a1 : BArray128.t),
  hoare [M._thash_prf_x4 : sk_seed = k1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      PRF P pk_seed (Node.to_list k1) (lane 32 k (BArray128.to_list a1))].
+ by move=> k1 a1; conseq (hprf k1 a1).
have hf' : forall (x1 : Node4.t) (a1 : BArray128.t),
  hoare [M._thash_f_x4 : x = x1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      F P pk_seed (lane 32 k (BArray128.to_list a1)) (lane P.`n k (Node4.to_list x1))].
+ by move=> x1 a1; conseq (hf x1 a1).
have htl' : forall (m1 : TLenIn4.t) (a1 : BArray128.t),
  hoare [M._thash_t_len_x4 : in_0 = m1 /\ ctx = c0 /\ adrs = a1 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      T_l P pk_seed (lane 32 k (BArray128.to_list a1))
          (lane (len P * P.`n) k (TLenIn4.to_list m1))].
+ by move=> m1 a1; conseq (htl m1 a1).
conseq (wots_leaf_x4_ll pk_seed c0 hprf hf htl)
       (wots_leaf_x4_h pk_seed c0 hprf' hf' htl' s0 k0 a0 q0 st0 ln0 hq) => //.
qed.
