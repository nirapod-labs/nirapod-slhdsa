(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wots.ec
 * =======
 *
 * The digit encoding of src/slhdsa/wots.jinc: __wots_digits returns the
 * len base-w digits of FIPS 205 Algorithm 7, lines 1 to 7 (wots_digits of
 * FIPS205_WOTS): the len1 = 2n digits of the message, then the len2 = 3
 * digits of its checksum.
 *
 * lg_w = 4 in every parameter set, so digit 2t of the message is the high
 * nibble of byte t and digit 2t + 1 its low nibble (digit_hi, digit_lo).
 * The code sums the checksum in a 32-bit word; the sum is at most
 * 2n * 15 <= 960 (csum_bound), so the word holds it exactly and its shifts
 * and masks are integer divisions and remainders (shr32, and15). The
 * standard shifts the checksum left by 4 bits, writes it as two bytes and
 * reads three digits from them; those are the three low nibbles of the
 * unshifted sum, most significant first (csum_digits).
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel (P, n_val,
 * lgw_val, the array theories Node and WotsDigits).
 *
 * Theorem:
 *     wots_digits_correct   __wots_digits returns wots_digits(P, msg), as
 *                           the list of its digit values; total correctness.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Params FIPS205_Encoding FIPS205_Encoding_Props.
require import FIPS205_Address_Props FIPS205_WOTS.
require import SetModel CoreExtracted.

(* ------------------------------------------------------------------ *)
(* Section 5 for lg_w = 4                                             *)

lemma w_val : w P = 16 by rewrite /w lgw_val.
lemma len1_val : len1 P = 2 * P.`n by rewrite /len1 /cdiv lgw_val n_val.

(* Algorithm 1: capacities 16 and 256 are at most max_checksum = 2n * 15,
   4096 is not, so the loop stops with len2 = 3. *)
lemma len2_val : len2 P = 3.
proof.
rewrite /len2 /gen_len2 lgw_val n_val /=.
rewrite bounded_while_unfold // /= bounded_while_unfold // /=.
by rewrite bounded_while_stop.
qed.

(* ------------------------------------------------------------------ *)
(* Base-16 digits                                                     *)

lemma m8 : W8.modulus = 256 by done.
lemma m32 : W32.modulus = 2 ^ 32 by done.

(* Algorithm 4 in closed form (base_2b_state). *)
lemma base_2bE (x : bytes) (b o : int) : 0 < b => 0 <= o => cdiv (o * b) 8 <= size x =>
  base_2b x b o = mkseq (digit x b) o.
proof. by move=> hb ho hs; rewrite /base_2b base_2b_state. qed.

(* The bytes before c do not reach its nibbles. *)
lemma nib_split (b c : int) : 256 * b + c = b * 16 * 16 + c by ring.

lemma digit_hi (x : bytes) (t : int) : 0 <= t < size x =>
  digit x 4 (2 * t) = to_uint (nth W8.zero x t) %/ 16.
proof.
move=> ht; have [c0 c1] := W8.to_uint_cmp (nth W8.zero x t).
have hc : cdiv ((2 * t + 1) * 4) 8 = t + 1.
+ by rewrite /cdiv (_ : (2 * t + 1) * 4 + 8 - 1 = (t + 1) * 8 + 3) 1:/# divzMDl.
rewrite /digit /= hc (_ : 8 * (t + 1) - (2 * t + 1) * 4 = 4) 1:/# ?pow2_4.
rewrite be_int_take_succ // nib_split divzMDl // modzMDl modz_small //.
rewrite m8 in c1; split; first by apply divz_ge0.
by move=> _; apply ltz_divLR.
qed.

lemma digit_lo (x : bytes) (t : int) : 0 <= t < size x =>
  digit x 4 (2 * t + 1) = to_uint (nth W8.zero x t) %% 16.
proof.
move=> ht.
have hc : cdiv ((2 * t + 1 + 1) * 4) 8 = t + 1.
+ by rewrite /cdiv (_ : (2 * t + 1 + 1) * 4 + 8 - 1 = (t + 1) * 8 + 7) 1:/# divzMDl.
rewrite /digit /= hc (_ : 8 * (t + 1) - (2 * t + 1 + 1) * 4 = 0) 1:/# ?pow2_0 divz1 ?pow2_4.
by rewrite be_int_take_succ // nib_split modzMDl.
qed.

lemma digit_bound (x : bytes) (j : int) : 0 <= digit x 4 j < 16.
proof. by rewrite /digit /= ?pow2_4 modz_ge0 //= ltz_pmod. qed.

(* ------------------------------------------------------------------ *)
(* The checksum                                                       *)

(* Lines 1 and 3 to 5 of Algorithm 7, over the first k digits. *)
op csum (x : bytes) (k : int) : int =
  foldl (fun (c t : int) => c + 15 - digit x 4 t) 0 (range 0 k).

lemma csum0 (x : bytes) : csum x 0 = 0 by rewrite /csum range_geq.

lemma csumS (x : bytes) (k : int) : 0 <= k => csum x (k + 1) = csum x k + (15 - digit x 4 k).
proof. by move=> hk; rewrite /csum rangeSr // -cats1 foldl_cat /=; ring. qed.

lemma csum_bound (x : bytes) (k : int) : 0 <= k => 0 <= csum x k <= 15 * k.
proof.
elim/natind: k => [k hk0 hk | k hk ih _].
+ by rewrite (_ : k = 0) 1:/# csum0.
have [d0 d1] := digit_bound x k.
by rewrite csumS //; smt().
qed.

(* The code's 32-bit words, on values below 2^32. *)
lemma small32 (z : int) : 0 <= z < 2 ^ 32 => z %% W32.modulus = z.
proof. by move=> hz; apply modz_small; rewrite StdOrder.IntOrder.ger0_norm. qed.

lemma small8 (z : int) : 0 <= z < 256 => z %% W8.modulus = z.
proof. by move=> hz; apply modz_small; rewrite StdOrder.IntOrder.ger0_norm. qed.

lemma zext32E (b : W8.t) : zeroextu32 b = W32.of_int (to_uint b) by rewrite /zeroextu32.

lemma shr32 (c k : int) : 0 <= c < 2 ^ 32 => 0 <= k < 32 =>
  W32.of_int c `>>` W8.of_int k = W32.of_int (c %/ 2 ^ k).
proof.
move=> hc hk; have hp : 0 < 2 ^ k by apply StdOrder.IntOrder.expr_gt0.
have hq : 0 <= c %/ 2 ^ k < 2 ^ 32.
+ case: hc => c0 c1; split; first by rewrite divz_ge0.
  by move=> _; apply (StdOrder.IntOrder.ler_lt_trans c) => //; apply leq_div => //; apply ltzW.
apply/W32.to_uint_eq; rewrite W32.shr_shrw 1:/# W32.to_uint_shr 1:/# !W32.of_uintK m32.
by rewrite (small32 c hc) (small32 _ hq).
qed.

lemma and15 (c : int) : 0 <= c < 2 ^ 32 => W32.of_int c `&` W32.of_int 15 = W32.of_int (c %% 16).
proof.
move=> hc; have hr : 0 <= c %% 16 < 2 ^ 32.
+ by rewrite modz_ge0 //=; apply (StdOrder.IntOrder.ltr_le_trans 16) => //; apply ltz_pmod.
apply/W32.to_uint_eq; rewrite (_ : 15 = 2 ^ 4 - 1) // W32.to_uint_and_mod // ?pow2_4.
by rewrite !W32.of_uintK (small32 c hc) (small32 _ hr).
qed.

lemma trunc8 (v : int) : 0 <= v < 256 => to_uint (truncateu8 (W32.of_int v)) = v.
proof.
move=> hv; have hv32 : 0 <= v < 2 ^ 32.
+ by case: hv => v0 v1; split => // _; apply (StdOrder.IntOrder.ltr_le_trans 256).
by rewrite /truncateu8 W8.of_uintK W32.of_uintK (small32 v hv32) (small8 v hv).
qed.

(* The nibbles of byte b, as the code extracts them. *)
lemma nibbles (b : W8.t) :
  zeroextu32 b `>>` W8.of_int 4 = W32.of_int (to_uint b %/ 16) /\
  zeroextu32 b `&` W32.of_int 15 = W32.of_int (to_uint b %% 16) /\
  0 <= to_uint b %/ 16 < 16 /\ 0 <= to_uint b %% 16 < 16.
proof.
have [b0 b1] := W8.to_uint_cmp b; rewrite m8 in b1.
have hb : 0 <= to_uint b < 2 ^ 32 by split => // _; apply (StdOrder.IntOrder.ltr_le_trans 256).
rewrite zext32E (shr32 _ 4 hb) // (and15 _ hb) ?pow2_4 /=; split.
+ by split; [apply divz_ge0 | move=> _; apply ltz_divLR].
by rewrite modz_ge0 //= ltz_pmod.
qed.

(* Lines 6 and 7: the three digits of toByte(c 2^4, 2), for c < 2^12. *)
lemma csum_digits (c : int) : 0 <= c < 4096 =>
  base_2b (toByte (c * 16) 2) 4 3 = [c %/ 256; c %/ 16 %% 16; c %% 16].
proof.
move=> hc; pose y := toByte (c * 16) 2.
have hy : size y = 2 by rewrite /y size_toByte.
have e0 : c * 16 %/ 256 = c %/ 16.
+ by rewrite (_ : 256 = 16 * 16) // divzMr // mulzK.
have y0 : to_uint (nth W8.zero y 0) = c %/ 16.
+ rewrite /y toByteE // /be_bytes nth_mkseq //= ?W8.of_uintK ?m8 e0 modz_small //.
  by split; [apply divz_ge0 | move=> _; apply ltz_divLR] => /#.
have y1 : to_uint (nth W8.zero y 1) = c %% 16 * 16.
+ rewrite /y toByteE // /be_bytes nth_mkseq //= ?W8.of_uintK ?m8.
  by rewrite (_ : 256 = 16 * 16) // mulz_modl.
rewrite base_2bE // 1:hy //.
apply (eq_from_nth 0); first by rewrite size_mkseq.
move=> j; rewrite size_mkseq => hj; rewrite nth_mkseq 1:/#.
have : j = 0 \/ j = 1 \/ j = 2 by smt().
case=> [-> | [-> | ->]] /=.
+ have := digit_hi y 0 _; first by rewrite hy.
  by rewrite /= y0 => ->; rewrite -divzMr.
+ have := digit_lo y 0 _; first by rewrite hy.
  by rewrite /= y0.
have := digit_hi y 1 _; first by rewrite hy.
by rewrite /= y1 => ->; rewrite mulzK.
qed.

(* The three checksum digits fit in a byte (csum <= 2n * 15 <= 960). *)
lemma csum_nibbles (c : int) : 0 <= c <= 960 =>
  0 <= c %/ 256 < 256 /\ 0 <= c %/ 16 %% 16 < 256 /\ 0 <= c %% 16 < 256.
proof. by move=> hc; smt(divz_ge0 modz_ge0 ltz_pmod ltz_divLR). qed.

(* ------------------------------------------------------------------ *)
(* Algorithm 7, lines 1 to 7, in closed form                          *)

(* The 2n message digits, then the three low nibbles of the checksum. *)
lemma wots_digits_closed (x : bytes) : size x = P.`n =>
  wots_digits P x = mkseq (digit x 4) (2 * P.`n) ++
    [csum x (2 * P.`n) %/ 256; csum x (2 * P.`n) %/ 16 %% 16; csum x (2 * P.`n) %% 16].
proof.
have hn : 0 < P.`n <= 32 by rewrite n_val.
move=> hx; rewrite /wots_digits /= lgw_val len1_val len2_val w_val /=.
have hd : base_2b x 4 (2 * P.`n) = mkseq (digit x 4) (2 * P.`n).
+ by rewrite base_2bE // 1:/# /cdiv hx; smt().
rewrite hd; congr.
have -> : foldl (fun (c i : int) => c + 16 - 1 - nth 0 (mkseq (digit x 4) (2 * P.`n)) i) 0
            (range 0 (2 * P.`n)) = csum x (2 * P.`n).
+ rewrite /csum; apply eq_in_foldl => // c t /mem_range ht /=.
  by rewrite nth_mkseq //; ring.
have [c0 c1] := csum_bound x (2 * P.`n) _; first smt().
by rewrite /cdiv /= csum_digits //; smt().
qed.

(* ------------------------------------------------------------------ *)
(* __wots_digits                                                      *)

lemma wots_sizes : Node.size = P.`n /\ WotsDigits.size = 2 * P.`n + 3 by rewrite n_val.

lemma wots_digits_h (m0 : Node.t) :
  hoare [M.__wots_digits : msg = m0 ==>
         map W8.to_uint (WotsDigits.to_list res) = wots_digits P (Node.to_list m0)].
proof.
have [hns hds] := wots_sizes.
have hx : size (Node.to_list m0) = P.`n by rewrite Node.size_to_list n_val.
proc; wp.
(* Invariant: digits 0 .. 2 i - 1 are written, csum is their checksum. *)
while (0 <= i <= P.`n /\ msg = m0 /\
       (forall j, 0 <= j < 2 * i => to_uint (WotsDigits.get8 d j) = digit (Node.to_list m0) 4 j) /\
       csum = W32.of_int (csum (Node.to_list m0) (2 * i))).
+ wp; skip => &m [#] h0 hi hm hd hc hlt /=.
  have hin : i{m} < P.`n by smt(n_val).
  have [hh [hl [hhb hlb]]] := nibbles (Node.get8 msg{m} i{m}).
  have [s0 s1] := csum_bound (Node.to_list m0) (2 * i{m}) _; first smt().
  rewrite hh hl hc hm; do 2!(split; first smt()); split.
  + move=> j [hj0 hj1]; rewrite !WotsDigits.get_setE 1,2:/#.
    case: (j = 2 * i{m} + 1) => [-> /= | hj1n].
    + by rewrite trunc8 1:/# (digit_lo _ i{m}) 1:/# Node.get_to_list.
    case: (j = 2 * i{m}) => [-> /= | hj0n].
    + by rewrite trunc8 1:/# (digit_hi _ i{m}) 1:/# Node.get_to_list.
    by rewrite /= hd /#.
  rewrite W32.of_intD' !W32.of_intS' (_ : 2 * (i{m} + 1) = 2 * i{m} + 1 + 1) 1:/# !csumS 1,2:/#.
  rewrite (digit_hi _ i{m}) 1:/# (digit_lo _ i{m}) 1:/# Node.get_to_list; congr; ring.
wp; skip => &m hm /=; split.
+ by rewrite csum0; smt(n_val).
move=> d0 c0 i0 hn [#] h1 h2 h3 h4 h5.
have hi0 : i0 = P.`n by smt(n_val).
rewrite h5 hi0 (wots_digits_closed _ hx).
have [s0 s1] := csum_bound (Node.to_list m0) (2 * P.`n) _; first smt().
pose C := csum (Node.to_list m0) (2 * P.`n).
have hCb : 0 <= C <= 960 by rewrite /C; smt(n_val).
have hC : 0 <= C < 2 ^ 32 by smt().
have [t0 [t1 t2]] := csum_nibbles C hCb.
have hC4 : 0 <= C %/ 2 ^ 4 < 2 ^ 32.
+ case: hC => hc0 hc1; split; first by rewrite divz_ge0.
  by move=> _; apply (StdOrder.IntOrder.ler_lt_trans C) => //; apply leq_div.
rewrite (shr32 C 8 hC) // (shr32 C 4 hC) // (and15 _ hC4) (and15 _ hC) ?pow2_4 ?pow2_8.
apply (eq_from_nth 0).
+ by rewrite size_map WotsDigits.size_to_list size_cat size_mkseq /=; smt(n_val).
move=> j; rewrite size_map WotsDigits.size_to_list => hj.
rewrite (nth_map W8.zero) 1:WotsDigits.size_to_list 1:/# WotsDigits.get_to_list nth_cat size_mkseq.
rewrite (_ : max 0 (2 * P.`n) = 2 * P.`n) 1:n_val // !WotsDigits.get_setE; first 3 smt(n_val).
case: (j < 2 * P.`n) => hjn.
+ rewrite nth_mkseq 1:/# !ifF; first 3 smt(n_val).
  by rewrite h4 /#.
have : j = 2 * P.`n \/ j = 2 * P.`n + 1 \/ j = 2 * P.`n + 2 by smt(n_val).
case=> [-> | [-> | ->]]; rewrite n_val /=.
+ by rewrite trunc8.
+ by rewrite trunc8.
by rewrite trunc8.
qed.

lemma wots_digits_ll : islossless M.__wots_digits.
proof. by proc; wp; while true (P.`n - i); auto; smt(n_val). qed.

lemma wots_digits_correct (m0 : Node.t) :
  phoare [M.__wots_digits : msg = m0 ==>
          map W8.to_uint (WotsDigits.to_list res) = wots_digits P (Node.to_list m0)] = 1%r.
proof. by conseq wots_digits_ll (wots_digits_h m0). qed.
