(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * WOTS_Encoding.ec
 * ================
 *
 * The WOTS+ message encoding of FIPS 205 (Algorithms 7 and 8, lines 1 to
 * 7: base-16 digits of the message followed by the base-16 digits of the
 * checksum) satisfies the property the SPHINCS+ security proof assumes of
 * its abstract encoding (two_encodings in WOTS_TW_ES of formosa-slhdsa):
 *
 *     for messages m <> m' of n bytes, some digit of the encoding of m is
 *     smaller than the same digit of the encoding of m'.
 *
 * Argument. If a message digit of m is smaller than the one of m', done.
 * Otherwise every message digit of m is at least that of m', and since
 * m <> m' one is larger, so the checksum sum(15 - d_i) of m is smaller
 * than that of m'. Both checksums are below 16^3, and the three checksum
 * digits are their base-16 digits, most significant first; at the first
 * position where the two checksums' digits differ, m's digit is smaller.
 *
 * Scope: lg_w = 4, len1 = 2n, len2 = 3 and n <= 32, which hold for every
 * parameter set of FIPS 205 Table 2 (Validate_Params.table2_ok).
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Encoding FIPS205_Encoding_Props FIPS205_Params FIPS205_WOTS.
require import Validate_Encoding Validate_Params.

(* ------------------------------------------------------------------ *)
(* Base-16 digits of bytes                                            *)

lemma digit4_hi (m : bytes) j : 0 <= j < size m =>
  digit m 4 (2 * j) = W8.to_uint (nth W8.zero m j) %/ 16.
proof.
move=> hj; rewrite /digit /cdiv /=.
have -> : (2 * j + 1) * 4 + 8 - 1 = 3 + (j + 1) * 8 by ring.
rewrite divzMDr //= (_: 8 * (j + 1) - (2 * j + 1) * 4 = 4) 1:/# /=.
rewrite be_int_take_succ 1:/#.
have hc : 0 <= W8.to_uint (nth W8.zero m j) < 256 by have := W8.to_uint_cmp (nth W8.zero m j).
have -> : 256 * be_int (take j m) + W8.to_uint (nth W8.zero m j)
        = W8.to_uint (nth W8.zero m j) + (16 * be_int (take j m)) * 16 by ring.
rewrite (divzMDr (16 * be_int (take j m)) (W8.to_uint (nth W8.zero m j)) 16) //.
rewrite (mulzC 16) modzMDl pmod_small //; smt(divz_ge0 ltz_divLR).
qed.

lemma digit4_lo (m : bytes) j : 0 <= j < size m =>
  digit m 4 (2 * j + 1) = W8.to_uint (nth W8.zero m j) %% 16.
proof.
move=> hj; rewrite /digit /cdiv /=.
have -> : (2 * j + 1 + 1) * 4 + 8 - 1 = 7 + (j + 1) * 8 by ring.
rewrite divzMDr //= (_: 8 * (j + 1) - (2 * j + 1 + 1) * 4 = 0) 1:/# /=.
rewrite be_int_take_succ 1:/#.
have -> : 256 * be_int (take j m) + W8.to_uint (nth W8.zero m j)
        = W8.to_uint (nth W8.zero m j) + (16 * be_int (take j m)) * 16 by ring.
by rewrite modzMDr.
qed.

(* Two bytes strings of equal length that differ have a differing digit. *)
lemma digits4_differ (m m' : bytes) :
  size m = size m' => m <> m' =>
  exists i, 0 <= i < 2 * size m /\ digit m 4 i <> digit m' 4 i.
proof.
move=> hs hne.
have [j [hj hdj]] : exists j, 0 <= j < size m /\ nth W8.zero m j <> nth W8.zero m' j.
+ move: hne; apply contraLR => /= hn.
  apply (eq_from_nth W8.zero) => // j hj.
  by move: hn; apply contraR => hneq; exists j.
case: (W8.to_uint (nth W8.zero m j) %/ 16 = W8.to_uint (nth W8.zero m' j) %/ 16) => hhi.
+ exists (2 * j + 1); split; first smt().
  rewrite digit4_lo // digit4_lo 1:/#.
  apply/negP => hlo; apply hdj; rewrite W8.to_uint_eq.
  by rewrite (divz_eq (W8.to_uint (nth W8.zero m j)) 16) (divz_eq (W8.to_uint (nth W8.zero m' j)) 16) hhi hlo.
exists (2 * j); split; first smt().
by rewrite digit4_hi // digit4_hi 1:/#.
qed.

(* ------------------------------------------------------------------ *)
(* The checksum                                                       *)

lemma foldl_addE (f : int -> int) (a : int) (l : int list) :
  foldl (fun (c i : int) => c + f i) a l = a + sumz (map f l).
proof.
elim: l a => [|x l ih] a /=; first by rewrite /sumz.
by rewrite ih /sumz /=; ring.
qed.

lemma sumz_map_le (f g : int -> int) (l : int list) :
  (forall i, i \in l => f i <= g i) => sumz (map f l) <= sumz (map g l).
proof.
elim: l => [|x l ih] h; first by rewrite /sumz.
rewrite /sumz /= -/(sumz _) -/(sumz _).
have := h x _; first by left.
have := ih _; first by move=> i hi; apply h; right.
smt().
qed.

lemma sumz_map_lt (f g : int -> int) (l : int list) :
  (forall i, i \in l => f i <= g i) => (exists i, i \in l /\ f i < g i) =>
  sumz (map f l) < sumz (map g l).
proof.
elim: l => [|x l ih] h [i [hi hlt]]; first by move: hi.
rewrite /sumz /= -/(sumz _) -/(sumz _).
have hx := h x _; first by left.
have hle := sumz_map_le f g l _; first by move=> k hk; apply h; right.
case: (i = x) => [->> | ne]; first smt().
have := ih _ _; first by move=> k hk; apply h; right.
+ by exists i; split => //; move: hi => /= [/#|].
smt().
qed.

(* Algorithms 7/8 lines 1 to 7 for lg_w = 4 and len2 = 3: the checksum is
   shifted left by 4 bits and written as two bytes. *)
lemma wots_digitsE p m :
  p.`lgw = 4 => len1 p = 2 * p.`n => len2 p = 3 =>
  wots_digits p m =
    base_2b m 4 (2 * p.`n)
    ++ base_2b (toByte (sumz (map (fun i => 15 - nth 0 (base_2b m 4 (2 * p.`n)) i)
                                  (range 0 (2 * p.`n))) * 16) 2) 4 3.
proof.
move=> hl hl1 hl2; rewrite /wots_digits /w hl hl1 hl2 /=.
have -> : (fun (c i : int) => c + 16 - 1 - nth 0 (base_2b m 4 (2 * p.`n)) i)
        = (fun (c i : int) => c + (15 - nth 0 (base_2b m 4 (2 * p.`n)) i)).
+ by apply/fun_ext => c; apply/fun_ext => i; ring.
by rewrite foldl_addE /cdiv.
qed.

lemma toByte2 v : toByte v 2 = [W8.of_int (v %/ 256); W8.of_int v].
proof.
rewrite /toByte /zeros /range -mkseq_nseq /mkseq -iotaredE /= /put /=.
by rewrite -(W8.of_int_mod (v %/ 256)) -(W8.of_int_mod v).
qed.

(* The three checksum digits are the base-16 digits of the checksum. *)
lemma csum_digits cs : 0 <= cs < 4096 =>
  base_2b (toByte (cs * 16) 2) 4 3 = [cs %/ 256; (cs %/ 16) %% 16; cs %% 16].
proof.
move=> hcs; apply (eq_from_nth 0).
+ by rewrite size_base_2b.
move=> i; rewrite size_base_2b // => hi.
rewrite nth_base_2b // 1:toByte2 1:/cdiv //.
have : i = 0 \/ i = 1 \/ i = 2 by smt().
case=> [->|[->|->]] /=.
+ by rewrite (digit4_hi _ 0) ?toByte2 //= W8.of_uintK /=; smt(divz_eq modz_ge0 ltz_pmod).
+ by rewrite (digit4_lo _ 0) ?toByte2 //= W8.of_uintK /=; smt(divz_eq modz_ge0 ltz_pmod).
by rewrite (digit4_hi _ 1) ?toByte2 //= W8.of_uintK /=; smt(divz_eq modz_ge0 ltz_pmod).
qed.

(* Of two numbers below 16^3, the smaller has the smaller base-16 digit at
   the first position where their digits differ. *)
lemma digits16_lt (cs cs' : int) : 0 <= cs => cs < cs' => cs' < 4096 =>
  exists i, 0 <= i < 3 /\
    nth 0 [cs %/ 256; (cs %/ 16) %% 16; cs %% 16] i
    < nth 0 [cs' %/ 256; (cs' %/ 16) %% 16; cs' %% 16] i.
proof.
move=> h0 hlt h1.
case: (cs %/ 256 < cs' %/ 256) => ha; first by exists 0.
have ea : cs %/ 256 = cs' %/ 256 by smt(leq_div2r).
case: ((cs %/ 16) %% 16 < (cs' %/ 16) %% 16) => hb; first by exists 1.
have eb : cs %/ 16 = cs' %/ 16.
+ have e16 : forall x, 0 <= x => x %/ 16 = 16 * (x %/ 256) + (x %/ 16) %% 16.
  + move=> x hx; rewrite {1}(divz_eq (x %/ 16) 16) (_: 256 = 16 * 16) // (divz_mulp x 16 16) //; ring.
  have : cs %/ 16 <= cs' %/ 16 by smt(leq_div2r).
  smt().
exists 2 => /=; smt(divz_eq).
qed.

lemma sumz_const (c : int) (l : int list) : sumz (map (fun _ => c) l) = c * size l.
proof. by elim: l => [|x l ih]; rewrite /sumz //= -/(sumz _) ih; ring. qed.

(* The checksum of one message, as wots_digitsE writes it. *)
op csum (ds : int list) (l : int) : int = sumz (map (fun i => 15 - nth 0 ds i) (range 0 l)).

lemma csum_bounds (ds : int list) (l : int) :
  0 <= l => (forall i, 0 <= i < l => 0 <= nth 0 ds i < 16) =>
  0 <= csum ds l <= 15 * l.
proof.
move=> hl hd; rewrite /csum; split.
+ have := sumz_map_le (fun _ => 0) (fun i => 15 - nth 0 ds i) (range 0 l) _.
  + by move=> i /mem_range hi /=; smt().
  by rewrite sumz_const.
have := sumz_map_le (fun i => 15 - nth 0 ds i) (fun _ => 15) (range 0 l) _.
+ by move=> i /mem_range hi /=; smt().
by rewrite sumz_const size_range /#.
qed.

(* ------------------------------------------------------------------ *)
(* two_encodings                                                      *)

lemma wots_two_encodings p (m m' : bytes) :
  p.`lgw = 4 => len1 p = 2 * p.`n => len2 p = 3 => 0 < p.`n <= 32 =>
  size m = p.`n => size m' = p.`n => m <> m' =>
  exists i, 0 <= i < len p /\ nth 0 (wots_digits p m) i < nth 0 (wots_digits p m') i.
proof.
move=> hl hl1 hl2 hn hs hs' hne.
rewrite !wots_digitsE // -/(csum _ _) -/(csum _ _).
pose L := 2 * p.`n.
have hlen : len p = L + 3 by rewrite /len hl1 hl2.
have hL : 0 <= L by rewrite /L /#.
have hsz : forall x, size (base_2b x 4 L) = L by move=> x; rewrite size_base_2b /#.
have hdig : forall x j, size x = p.`n => 0 <= j < L =>
            nth 0 (base_2b x 4 L) j = digit x 4 j.
+ by move=> x j hx hj; rewrite nth_base_2b // /cdiv /#.
have hrng : forall x j, 0 <= j < L => 0 <= nth 0 (base_2b x 4 L) j < 16.
+ move=> x j hj; have := base_2b_range x 4 L; rewrite allP => /(_ (nth 0 (base_2b x 4 L) j)).
  by rewrite mem_nth 1:hsz //.
case: (exists i, 0 <= i < L /\ nth 0 (base_2b m 4 L) i < nth 0 (base_2b m' 4 L) i).
+ move=> [i [hi hlt]]; exists i; split; first by rewrite hlen /#.
  by rewrite !nth_cat !hsz ifT 1:/# ifT 1:/#.
move=> /negb_exists /= hno.
have hge : forall i, 0 <= i < L => nth 0 (base_2b m' 4 L) i <= nth 0 (base_2b m 4 L) i.
+ by move=> i hi; have := hno i; rewrite hi /= lezNgt.
have [i0 [hi0 hne0]] : exists i, 0 <= i < L /\ nth 0 (base_2b m 4 L) i <> nth 0 (base_2b m' 4 L) i.
+ have [i [hi hd]] := digits4_differ m m' _ hne; first by rewrite hs hs'.
  by exists i; rewrite hdig // 1:/# hdig // 1:/# /#.
have hcs : csum (base_2b m 4 L) L < csum (base_2b m' 4 L) L.
+ apply sumz_map_lt.
  + by move=> i /mem_range hi /=; have := hge i hi; smt().
  exists i0; rewrite mem_range hi0 /=; have := hge i0 hi0; smt().
have [c0 c1] := csum_bounds (base_2b m 4 L) L _ _; 1: smt(); 1: by move=> j hj; apply hrng.
have [c0' c1'] := csum_bounds (base_2b m' 4 L) L _ _; 1: smt(); 1: by move=> j hj; apply hrng.
have [i [hi hlt]] := digits16_lt (csum (base_2b m 4 L) L) (csum (base_2b m' 4 L) L) c0 hcs _.
+ smt().
case: hi => hil hi3.
exists (L + i); split.
+ by rewrite hlen; split; [apply addz_ge0 | rewrite ltz_add2l].
have hnl : !(L + i < L) by rewrite -lezNgt ler_addl.
rewrite !nth_cat !hsz hnl /= (_: L + i - L = i); first by ring.
have hb : 0 <= csum (base_2b m 4 L) L < 4096 by move: c0 c1 hn; rewrite /L; clear hrng hdig hno hge; smt().
have hb' : 0 <= csum (base_2b m' 4 L) L < 4096 by move: c0' c1' hn; rewrite /L; clear hrng hdig hno hge; smt().
by rewrite (csum_digits _ hb) (csum_digits _ hb').
qed.

(* The Table 2 parameter sets meet the hypotheses. *)
lemma wots_two_encodings_sets p (m m' : bytes) :
  p \in parameter_sets =>
  size m = p.`n => size m' = p.`n => m <> m' =>
  exists i, 0 <= i < len p /\ nth 0 (wots_digits p m) i < nth 0 (wots_digits p m') i.
proof.
move=> hp.
have := List.allP table2_consistent parameter_sets; rewrite Validate_Params.table2_ok /= => /(_ p hp).
rewrite /table2_consistent => [#] hl _ hl1 hl2 *.
have hn : 0 < p.`n <= 32.
+ move: hp; rewrite /parameter_sets /slh_dsa_sha2_128s /slh_dsa_shake_128s /slh_dsa_sha2_128f.
  rewrite /slh_dsa_shake_128f /slh_dsa_sha2_192s /slh_dsa_shake_192s /slh_dsa_sha2_192f.
  rewrite /slh_dsa_shake_192f /slh_dsa_sha2_256s /slh_dsa_shake_256s /slh_dsa_sha2_256f.
  by rewrite /slh_dsa_shake_256f /=; smt().
by apply wots_two_encodings.
qed.
