(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * DigestIndices.ec
 * ================
 *
 * The digest decoding of src/slhdsa/encoding.jinc: __digest_tree_leaf
 * returns idx_tree and idx_leaf of FIPS 205 Algorithm 19, lines 6 to 10,
 * and __fors_indices returns base_2b(md, a, k) (Algorithm 4), each index
 * read from the three digest bytes that hold its a bits. Both accumulate
 * big-endian bytes with shifts and ors on disjoint bits; or_lo32 and
 * or_lo64 turn those into additions, and digit_window equates the
 * three-byte window with the closed form of base_2b (nth_base_2b).
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel (P, the
 * lemmas n_val, a_val, ..., the array theories Digest and ForsIdx). A
 * proof step that needs a parameter's value cites its lemma, so no value
 * is written in the proof text.
 *
 * Theorems:
 *     digest_tree_leaf_correct   __digest_tree_leaf returns idx_tree and
 *                                idx_leaf of split_digest;
 *     fors_indices_correct       index j of __fors_indices is digit j of
 *                                base_2b(md, a, k), md the first field of
 *                                split_digest;
 * each a total-correctness statement.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Params FIPS205_Encoding FIPS205_Encoding_Props FIPS205_Internal.
require import SetModel CoreExtracted.

(* ------------------------------------------------------------------ *)
(* Words and big-endian integers                                      *)

lemma m8 : W8.modulus = 256 by done.
lemma m64 : W64.modulus = 2 ^ 64 by done.
lemma m32 : W32.modulus = 2 ^ 32 by done.

lemma be_int_lt (l : bytes) : be_int l < 256 ^ size l.
proof.
elim/last_ind: l => [|l c ih]; first by rewrite /be_int expr0.
rewrite be_int_rcons size_rcons exprS 1:size_ge0; smt(W8.to_uint_cmp m8).
qed.

lemma toInt_be (x : bytes) (n : int) : 0 <= n <= size x => toInt x n = be_int (take n x).
proof.
elim/natind: n => [n hn0 hn | n hn ih hs].
+ have -> : n = 0 by smt().
  by rewrite /toInt range_geq //= take0 /be_int.
rewrite /toInt rangeSr // -cats1 foldl_cat /= -/(toInt x n) ih 1:/# be_int_take_succ /#.
qed.

lemma or_lo64 (x y : W64.t) (k : int) : 0 <= k =>
  to_uint x %% 2 ^ k = 0 => to_uint y < 2 ^ k => to_uint (x `|` y) = to_uint x + to_uint y.
proof.
move=> hk hx hy; apply W64.to_uint_orw_disjoint; apply/W64.wordP => i hi.
rewrite W64.andwE W64.zerowE !W64.get_to_uint /=; case: (i < k) => hik.
+ have e : 2 ^ k = 2 ^ i * (2 * 2 ^ (k - i - 1)).
  + by rewrite -exprS 1:/# -exprD_nneg 1,2:/#; congr; ring.
  have -> : to_uint x = 2 ^ i * (2 * (2 ^ (k - i - 1) * (to_uint x %/ 2 ^ k))).
  + by rewrite {1}(divz_eq (to_uint x) (2 ^ k)) hx /= e; ring.
  rewrite mulKz; [smt(StdOrder.IntOrder.expr_gt0) | smt(modzMr)].
rewrite (divz_small (to_uint y)) 2:/#; smt(W64.to_uint_cmp StdOrder.IntOrder.ler_weexpn2l).
qed.

lemma or_lo32 (x y : W32.t) (k : int) : 0 <= k =>
  to_uint x %% 2 ^ k = 0 => to_uint y < 2 ^ k => to_uint (x `|` y) = to_uint x + to_uint y.
proof.
move=> hk hx hy; apply W32.to_uint_orw_disjoint; apply/W32.wordP => i hi.
rewrite W32.andwE W32.zerowE !W32.get_to_uint /=; case: (i < k) => hik.
+ have e : 2 ^ k = 2 ^ i * (2 * 2 ^ (k - i - 1)).
  + by rewrite -exprS 1:/# -exprD_nneg 1,2:/#; congr; ring.
  have -> : to_uint x = 2 ^ i * (2 * (2 ^ (k - i - 1) * (to_uint x %/ 2 ^ k))).
  + by rewrite {1}(divz_eq (to_uint x) (2 ^ k)) hx /= e; ring.
  rewrite mulKz; [smt(StdOrder.IntOrder.expr_gt0) | smt(modzMr)].
rewrite (divz_small (to_uint y)) 2:/#; smt(W32.to_uint_cmp StdOrder.IntOrder.ler_weexpn2l).
qed.

lemma zext64 (b : W8.t) : to_uint (zeroextu64 b) = to_uint b.
proof. rewrite /zeroextu64 W64.of_uintK modz_small //; smt(W8.to_uint_cmp pow2_64 pow2_8). qed.

lemma zext32 (b : W8.t) : to_uint (zeroextu32 b) = to_uint b.
proof. rewrite /zeroextu32 W32.of_uintK modz_small //; smt(W8.to_uint_cmp pow2_32 pow2_8). qed.

(* One step of a big-endian accumulation: acc << 8 | b, while it fits. *)
lemma acc64 (acc : W64.t) (b : W8.t) : to_uint acc < 256 ^ 7 =>
  to_uint ((acc `<<` W8.of_int 8) `|` zeroextu64 b) = 256 * to_uint acc + to_uint b.
proof.
move=> ha; have h0 := W64.to_uint_cmp acc.
have e : 2 ^ 64 = 256 ^ 7 * 2 ^ 8 by done.
have hs : to_uint (acc `<<` W8.of_int 8) = 256 * to_uint acc.
+ rewrite W64.shl_shlw // W64.to_uint_shl // modz_small.
  + rewrite m8 m64 e pow2_8 StdOrder.IntOrder.ger0_norm; first smt(StdOrder.IntOrder.expr_gt0).
    split; [smt() | move=> _; apply StdOrder.IntOrder.ltr_pmul2r => //].
  by rewrite m8; ring.
rewrite (or_lo64 _ _ 8) // ?hs ?zext64 //; smt(W8.to_uint_cmp m8).
qed.

lemma acc32 (acc : W32.t) (b : W8.t) : to_uint acc < 256 ^ 3 =>
  to_uint ((acc `<<` W8.of_int 8) `|` zeroextu32 b) = 256 * to_uint acc + to_uint b.
proof.
move=> ha; have h0 := W32.to_uint_cmp acc.
have e : 2 ^ 32 = 256 ^ 3 * 2 ^ 8 by done.
have hs : to_uint (acc `<<` W8.of_int 8) = 256 * to_uint acc.
+ rewrite W32.shl_shlw // W32.to_uint_shl // modz_small.
  + rewrite m8 m32 e pow2_8 StdOrder.IntOrder.ger0_norm; first smt(StdOrder.IntOrder.expr_gt0).
    split; [smt() | move=> _; apply StdOrder.IntOrder.ltr_pmul2r => //].
  by rewrite m8; ring.
rewrite (or_lo32 _ _ 8) // ?hs ?zext32 //; smt(W8.to_uint_cmp m8).
qed.

lemma shl1 (k : int) : 0 <= k => 1 `<<` k = 2 ^ k.
proof. by move=> hk; rewrite /(`<<`) hk. qed.

(* ------------------------------------------------------------------ *)
(* __digest_tree_leaf                                                 *)

lemma hp_def : P.`h %/ P.`d = P.`hp by rewrite h_val d_val hp_val.
lemma tree_bytes_val : tree_bytes P = (P.`h - P.`hp + 7) %/ 8 by rewrite /tree_bytes /cdiv hp_def.
lemma leaf_bytes_val : leaf_bytes P = (P.`hp + 7) %/ 8.
proof. by rewrite /leaf_bytes /cdiv h_val d_val hp_val. qed.
lemma md_bytes_val : md_bytes P = (P.`k * P.`a + 7) %/ 8 by rewrite /md_bytes /cdiv.
(* The three fields fit in the digest, the tree index in a 64-bit word and
   the leaf index in a 32-bit word. *)
lemma digest_fields : 0 <= md_bytes P /\ 0 <= tree_bytes P <= 8 /\ 0 <= leaf_bytes P <= 3 /\
  md_bytes P + tree_bytes P + leaf_bytes P <= P.`m /\ 0 <= P.`hp /\ 0 <= P.`h - P.`hp.
proof. by rewrite md_bytes_val tree_bytes_val leaf_bytes_val k_val a_val h_val hp_val m_val. qed.

lemma be_take_le (l : bytes) (j e : int) : 0 <= j <= e => be_int (take j l) < 256 ^ e.
proof.
move=> hj; have := be_int_lt (take j l).
have : 256 ^ size (take j l) <= 256 ^ e by apply StdOrder.IntOrder.ler_weexpn2l; smt(size_take size_ge0).
smt().
qed.

(* With the reduction mod 2^(h - h'), for h - h' < 64. *)
lemma tree_mask (t : W64.t) (x : bytes) (e : int) : e = P.`h - P.`hp => size x = P.`m =>
  to_uint t = be_int (take (tree_bytes P) (drop (md_bytes P) x)) =>
  to_uint (t `&` W64.of_int ((1 `<<` e) - 1)) =
  toInt (slice x (md_bytes P) (md_bytes P + tree_bytes P)) (tree_bytes P) %% 2 ^ (P.`h - P.`h %/ P.`d).
proof.
have [#] hmb htb0 htb1 hlb0 hlb1 hsz hhp hth := digest_fields.
move=> -> hx ht; rewrite shl1 1:/# W64.to_uint_and_mod 1:/# ht /slice toInt_be.
+ smt(size_take size_drop).
by rewrite take_take ifT 1:/# hp_def.
qed.

(* Without the reduction: for h - h' = 64 the tree index is the whole word. *)
lemma tree_nomask (t : W64.t) (x : bytes) : 64 <= P.`h - P.`hp => size x = P.`m =>
  to_uint t = be_int (take (tree_bytes P) (drop (md_bytes P) x)) =>
  to_uint t = toInt (slice x (md_bytes P) (md_bytes P + tree_bytes P)) (tree_bytes P)
              %% 2 ^ (P.`h - P.`h %/ P.`d).
proof.
have [#] hmb htb0 htb1 hlb0 hlb1 hsz hhp hth := digest_fields.
move=> h64 hx ht.
rewrite ht /slice toInt_be; first smt(size_take size_drop).
rewrite take_take ifT 1:/#.
apply/eq_sym/modz_small; split; first by apply be_int_ge0.
move=> _; have hb : be_int (take (tree_bytes P) (drop (md_bytes P) x)) < 256 ^ 8.
+ by apply be_take_le => /#.
have : 256 ^ 8 <= 2 ^ (P.`h - P.`h %/ P.`d).
+ rewrite hp_def (_ : 256 ^ 8 = 2 ^ 64) 1:// StdOrder.IntOrder.ler_weexpn2l /#.
move=> hle; have h0 : 0 < 2 ^ (P.`h - P.`h %/ P.`d) by apply StdOrder.IntOrder.expr_gt0.
rewrite StdOrder.IntOrder.ger0_norm 1:/#; exact (StdOrder.IntOrder.ltr_le_trans _ _ _ hb hle).
qed.

lemma digest_tree_leaf_h (d0 : Digest.t) :
  hoare [M.__digest_tree_leaf : digest = d0 ==>
    to_uint res.`1 = (split_digest P (Digest.to_list d0)).`2 /\
         to_uint res.`2 = (split_digest P (Digest.to_list d0)).`3].
proof.
have [#] hmb htb0 htb1 hlb0 hlb1 hsz hhp hth := digest_fields.
have hx : size (Digest.to_list d0) = P.`m by rewrite Digest.size_to_list m_val.
proc.
seq 4 : (digest = d0 /\ to_uint tree =
           be_int (take (tree_bytes P) (drop (md_bytes P) (Digest.to_list d0)))).
+ while (0 <= j <= inc /\ inc = tree_bytes P /\ digest = d0 /\
         to_uint tree = be_int (take j (drop (md_bytes P) (Digest.to_list d0)))).
  + wp; skip => &m [#] h0 hj hinc hd ht hlt /=.
    rewrite acc64; first by rewrite ht; apply be_take_le => /#.
    rewrite ht (be_int_take_succ _ j{m}); first by rewrite size_drop // /#.
    (* The model's offset is md_bytes P as a literal. *)
    by rewrite nth_drop // 1:/# Digest.get_to_list hd md_bytes_val k_val a_val.
  wp; skip => &m -> /=; split.
  + by rewrite take0 /be_int tree_bytes_val h_val hp_val.
  move=> j0 t0 hn [#] h1 h2 h3 h5; rewrite h5 (_ : j0 = tree_bytes P) 1:/# //.
seq 1 : (digest = d0 /\ to_uint tree =
           toInt (slice (Digest.to_list d0) (md_bytes P) (md_bytes P + tree_bytes P)) (tree_bytes P)
           %% 2 ^ (P.`h - P.`h %/ P.`d)).
+ if.
  (* The condition and the mask width are h - h' as literals: h_val and hp_val
     relate them to P and refute the condition of the branch a set does not take. *)
  + wp; skip => &m [#] hd ht hc; split => //; apply (tree_mask _ _ _ _ hx ht); smt(h_val hp_val).
  skip => &m [#] hd ht hc; split => //; apply (tree_nomask _ _ _ hx ht); smt(h_val hp_val).
wp; while (0 <= j <= inc /\ inc = leaf_bytes P /\ digest = d0 /\
         to_uint leaf = be_int (take j (drop (md_bytes P + tree_bytes P) (Digest.to_list d0)))).
+ wp; skip => &m [#] h0 hj hinc hd hl hlt /=.
  rewrite acc32; first by rewrite hl; apply be_take_le => /#.
  rewrite hl (be_int_take_succ _ j{m}); first by rewrite size_drop // /#.
  by rewrite nth_drop // 1:/# Digest.get_to_list hd.
wp; skip => &m [#] hd ht /=; split.
+ by rewrite take0 /be_int leaf_bytes_val hp_val.
move=> j0 l0 hn [#] h1 h2 h3 h4 h5; have hj0 : j0 = leaf_bytes P by smt().
rewrite /split_digest /=; split; first by rewrite ht.
rewrite shl1 // W32.to_uint_and_mod // h5 hj0 /slice toInt_be; first smt(size_take size_drop).
by rewrite take_take ifT 1:/# hp_def hp_val.
qed.

lemma digest_tree_leaf_ll : islossless M.__digest_tree_leaf.
proof.
proc; wp; while true (inc - j); 1: by auto => /#.
wp; while true (inc - j); 1: by auto => /#.
by auto => /#.
qed.

lemma digest_tree_leaf_correct (d0 : Digest.t) :
  phoare [M.__digest_tree_leaf : digest = d0 ==>
    to_uint res.`1 = (split_digest P (Digest.to_list d0)).`2 /\
         to_uint res.`2 = (split_digest P (Digest.to_list d0)).`3] = 1%r.
proof. by conseq digest_tree_leaf_ll (digest_tree_leaf_h d0). qed.

(* ------------------------------------------------------------------ *)
(* __fors_indices                                                     *)

lemma be_int_cat (l1 l2 : bytes) : be_int (l1 ++ l2) = be_int l1 * 256 ^ size l2 + be_int l2.
proof.
elim/last_ind: l2 => [|l c ih]; first by rewrite cats0 /be_int expr0.
by rewrite -rcons_cat !be_int_rcons ih size_rcons exprS 1:size_ge0; ring.
qed.

lemma be_int_takeD (x : bytes) (c q : int) : 0 <= c <= q <= size x =>
  be_int (take q x) = be_int (take c x) * 256 ^ (q - c) + be_int (take (q - c) (drop c x)).
proof.
move=> h; have := takeD x c (q - c) _ _; 1,2: smt().
rewrite (_ : c + (q - c) = q) 1:/# => ->; rewrite be_int_cat; congr; congr.
smt(size_take size_drop).
qed.

lemma be_int3 (x : bytes) (b0 : int) : 0 <= b0 => b0 + 3 <= size x =>
  be_int (take 3 (drop b0 x)) = 65536 * to_uint (nth W8.zero x b0) +
    256 * to_uint (nth W8.zero x (b0 + 1)) + to_uint (nth W8.zero x (b0 + 2)).
proof.
move=> h0 h3.
have -> : take 3 (drop b0 x) = [nth W8.zero x b0; nth W8.zero x (b0 + 1); nth W8.zero x (b0 + 2)].
+ apply (eq_from_nth W8.zero); first by rewrite size_take // size_drop // /#.
  move=> j; rewrite size_take // size_drop // => hj.
  rewrite nth_take 1,2:/# nth_drop 1,2:/#.
  have : j = 0 \/ j = 1 \/ j = 2 by smt().
  by case=> [-> | [-> | ->]].
by rewrite /be_int /=; ring.
qed.

(* Digit i of base_2b(X, a, _) lies in the three bytes from b0 = i a / 8:
   the bits below it in those bytes are shifted out, the bits above it are
   reduced away. *)
lemma digit_window (x : bytes) (a i : int) :
  0 < a => 0 <= i => (i * a) %% 8 + a <= 24 => (i * a) %/ 8 + 3 <= size x =>
  digit x a i =
  ((65536 * to_uint (nth W8.zero x ((i * a) %/ 8)) + 256 * to_uint (nth W8.zero x ((i * a) %/ 8 + 1))
    + to_uint (nth W8.zero x ((i * a) %/ 8 + 2))) %/ 2 ^ (24 - (i * a) %% 8 - a)) %% 2 ^ a.
proof.
move=> ha hi hsa hx.
have hia0 : 0 <= i * a by smt().
have hs0 : 0 <= (i * a) %% 8 < 8 by smt(modz_ge0 ltz_pmod).
have hb0 : 0 <= (i * a) %/ 8 by smt(divz_ge0).
have hia : (i + 1) * a = 8 * ((i * a) %/ 8) + (i * a) %% 8 + a by smt(divz_eq).
have hc : cdiv ((i + 1) * a) 8 = (i * a) %/ 8 + ((i * a) %% 8 + a + 7) %/ 8.
+ rewrite /cdiv hia (_ : 8 * ((i * a) %/ 8) + (i * a) %% 8 + a + 8 - 1
                       = (i * a) %/ 8 * 8 + ((i * a) %% 8 + a + 7)) 1:/# divzMDl //.
rewrite /digit /= hc.
pose b0 := (i * a) %/ 8; pose s := (i * a) %% 8; pose q := (s + a + 7) %/ 8.
have hxw : b0 + 3 <= size x by rewrite /b0.
have hb0w : 0 <= b0 by rewrite /b0.
have hsw : 0 <= s < 8 by rewrite /s.
have hsaw : s + a <= 24 by rewrite /s.
have hiaw : (i + 1) * a = 8 * b0 + s + a by rewrite /b0 /s.
have hq : 1 <= q <= 3 by rewrite /q; smt().
have hqw : 8 * q - 7 <= s + a <= 8 * q by rewrite /q; smt().
pose e := 8 * (b0 + q) - (i + 1) * a.
have he : 0 <= e < 8 by rewrite /e; smt().
have hew : e = 8 * q - s - a by rewrite /e; smt().
have hT1 := be_int_takeD x (b0 + q) (b0 + 3) _; 1: smt().
have hT2 := be_int_takeD x b0 (b0 + 3) _; 1: smt().
rewrite (_ : b0 + 3 - b0 = 3) 1:/# (be_int3 x b0 hb0w hxw) in hT2.
pose B := 65536 * to_uint (nth W8.zero x b0) + 256 * to_uint (nth W8.zero x (b0 + 1))
          + to_uint (nth W8.zero x (b0 + 2)).
pose R := be_int (take (b0 + 3 - (b0 + q)) (drop (b0 + q) x)).
have hR : 0 <= R < 256 ^ (3 - q).
+ split; first by apply be_int_ge0.
  by move=> _; rewrite /R (_ : b0 + 3 - (b0 + q) = 3 - q) 1:/#; apply be_take_le => /#.
have h2e : 2 ^ (24 - s - a) = 256 ^ (3 - q) * 2 ^ e.
+ have -> : 256 ^ (3 - q) = 2 ^ (8 * (3 - q)).
  + by rewrite exprM.
  by rewrite -exprD_nneg 1,2:/#; congr; smt().
have h24 : 256 ^ 3 = 2 ^ (24 - s - a) * 2 ^ (s + a).
+ by rewrite -exprD_nneg 1,2:/# (_ : 24 - s - a + (s + a) = 24) 1:/#.
(* digit from the c-byte prefix equals the window value through T. *)
have hA : be_int (take (b0 + q) x) %/ 2 ^ e = be_int (take (b0 + 3) x) %/ 2 ^ (24 - s - a).
+ rewrite h2e divzMr 1,2:StdOrder.IntOrder.expr_ge0 // hT1 -/R.
  rewrite (_ : b0 + 3 - (b0 + q) = 3 - q) 1:/# divzMDl; first smt(StdOrder.IntOrder.expr_gt0).
  (* R, the bytes after the prefix, is below 256^(3 - q), so its quotient is 0. *)
  have hRn : 0 <= R < `|256 ^ (3 - q)|.
  + by rewrite StdOrder.IntOrder.ger0_norm; [apply StdOrder.IntOrder.expr_ge0 | exact hR].
  by rewrite (divz_small R _ hRn) addz0.
rewrite hA hT2 -/B h24 mulrA mulrAC divzMDl; first smt(StdOrder.IntOrder.expr_gt0).
have -> : 2 ^ (s + a) = 2 ^ s * 2 ^ a by rewrite exprD_nneg /#.
by rewrite mulrA modzMDl.
qed.

(* The window of digit i, as the code computes it in a 32-bit word. *)
lemma fors_word (d : Digest.t) (a i : int) :
  0 < a => 0 <= i => (i * a) %% 8 + a <= 24 => (i * a) %/ 8 + 3 <= P.`m =>
  to_uint (((((zeroextu32 (Digest.get8 d ((i * a) %/ 8)) `<<` W8.of_int 16) `|`
              (zeroextu32 (Digest.get8 d ((i * a) %/ 8 + 1)) `<<` W8.of_int 8)) `|`
              zeroextu32 (Digest.get8 d ((i * a) %/ 8 + 2))) `>>` W8.of_int (24 - (i * a) %% 8 - a)) `&`
           W32.of_int ((1 `<<` a) - 1))
  = digit (Digest.to_list d) a i.
proof.
move=> ha hi hs hb.
have hsz : (i * a) %/ 8 + 3 <= size (Digest.to_list d) by rewrite Digest.size_to_list; smt(m_val).
rewrite (digit_window _ a i ha hi hs hsz) !Digest.get_to_list.
have hs0 : 0 <= (i * a) %% 8 < 8 by smt(modz_ge0 ltz_pmod).
pose x0 := (Digest.get8 d ((i * a) %/ 8)); pose x1 := (Digest.get8 d ((i * a) %/ 8 + 1)); pose x2 := (Digest.get8 d ((i * a) %/ 8 + 2)).
have [h00 h01] := W8.to_uint_cmp x0; have [h10 h11] := W8.to_uint_cmp x1.
have [h20 h21] := W8.to_uint_cmp x2.
rewrite m8 in h01; rewrite m8 in h11; rewrite m8 in h21.
have e0 : to_uint (zeroextu32 x0 `<<` W8.of_int 16) = 65536 * to_uint x0.
+ rewrite W32.shl_shlw // W32.to_uint_shl // zext32 modz_small; last by ring.
  by rewrite m32 StdOrder.IntOrder.ger0_norm //; smt().
have e1 : to_uint (zeroextu32 x1 `<<` W8.of_int 8) = 256 * to_uint x1.
+ rewrite W32.shl_shlw // W32.to_uint_shl // zext32 modz_small; last by rewrite m8; ring.
  by rewrite m8 m32 StdOrder.IntOrder.ger0_norm //; smt().
have e2 : to_uint ((zeroextu32 x0 `<<` W8.of_int 16) `|` (zeroextu32 x1 `<<` W8.of_int 8))
          = 65536 * to_uint x0 + 256 * to_uint x1.
+ rewrite -e0 -e1; apply (or_lo32 _ _ 16) => //; first by rewrite e0 pow2_16 modzMr.
  by rewrite e1 pow2_16; smt().
have e3 : to_uint (((zeroextu32 x0 `<<` W8.of_int 16) `|` (zeroextu32 x1 `<<` W8.of_int 8)) `|`
                   zeroextu32 x2) = 65536 * to_uint x0 + 256 * to_uint x1 + to_uint x2.
+ rewrite -e2 -(zext32 x2); apply (or_lo32 _ _ 8) => //; last by rewrite zext32 pow2_8.
  rewrite e2 pow2_8 (_ : 65536 * to_uint x0 + 256 * to_uint x1 = (256 * to_uint x0 + to_uint x1) * 256) 1:/#.
  by rewrite modzMl.
rewrite shl1 1:/# W32.to_uint_and_mod 1:/# W32.shr_shrw 1:/# W32.to_uint_shr 1:/# e3.
by rewrite /x0 /x1 /x2.
qed.

(* FORS needs a <= 14, so digit i lies in three bytes; the last window
   ends inside the digest, and the k indices fill ForsIdx. *)
lemma fors_fields : 0 < P.`a <= 14 /\ 0 < P.`k /\ ((P.`k - 1) * P.`a) %/ 8 + 3 <= P.`m /\
  4 * P.`k = ForsIdx.size.
proof. by rewrite a_val k_val m_val. qed.

lemma digit_take (x : bytes) (a j l : int) : cdiv ((j + 1) * a) 8 <= l =>
  digit (take l x) a j = digit x a j.
proof. by move=> h; rewrite /digit /= take_take ifT. qed.

lemma fors_indices_h (d0 : Digest.t) :
  hoare [M.__fors_indices : digest = d0 ==>
    forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 res j) =
      nth 0 (base_2b (split_digest P (Digest.to_list d0)).`1 P.`a P.`k) j].
proof.
have [#] ha0 ha1 hk hfit hsz := fors_fields.
proc.
while (0 <= i <= P.`k /\ digest = d0 /\
       forall j, 0 <= j < i => to_uint (ForsIdx.get32 idx j) = digit (Digest.to_list d0) P.`a j).
+ wp; skip => &m [#] h0 hi hd hj hlt /=.
  do 2!(split; first smt(k_val)).
  move=> j [hj0 hj1]; rewrite ForsIdx.get_set32E 1:/#; first smt(k_val).
  case: (i{m} = j) => [hij | hne]; last by rewrite hj /#.
  rewrite -hij hd a_val fors_word //; 1,2: smt(k_val).
wp; skip => &m hd /=; split; first smt(k_val).
move=> idx0 i0 hn [#] h1 h2 h3 h4 j hj.
rewrite (h4 j _); first smt(k_val).
have hsz2 : cdiv (P.`k * P.`a) 8 <= size (take (md_bytes P) (Digest.to_list d0)).
+ rewrite size_take; first smt(md_bytes_val k_val a_val).
  rewrite Digest.size_to_list /md_bytes; smt(md_bytes_val k_val a_val m_val).
rewrite /split_digest /= /slice drop0 (nth_base_2b _ _ _ _ _ _ hsz2) 1,2:/#.
rewrite digit_take // /md_bytes /cdiv; apply leq_div2r => //; smt().
qed.

lemma fors_indices_ll : islossless M.__fors_indices.
proof. by proc; while true (P.`k - i); auto; smt(k_val). qed.

lemma fors_indices_correct (d0 : Digest.t) :
  phoare [M.__fors_indices : digest = d0 ==>
    forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 res j) =
      nth 0 (base_2b (split_digest P (Digest.to_list d0)).`1 P.`a P.`k) j] = 1%r.
proof. by conseq fors_indices_ll (fors_indices_h d0). qed.
