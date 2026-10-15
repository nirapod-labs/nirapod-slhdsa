(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ADRSc.ec
 * ========
 *
 * The compressed address of FIPS 205 section 11.2 (SHA2 parameter sets):
 * __adrs_compress_into64 and __adrs_compress_into128 of
 * src/slhdsa/thash_sha2.jinc write ADRS^c = compress(ADRS) into the first
 * 22 bytes of a hash block and leave the rest of the block unchanged.
 *
 * Model. The procedures are the same for every SHA2 set and use no
 * parameter, but they exist only in the SHA2 sets' models, so this file is
 * checked against each of them (correctness/core/sha2/). The address is
 * the 32-byte array of the model (BArray32), viewed as bytes by to_list,
 * as in correctness/slhdsa/ADRS.ec.
 *
 * Both procedures write the 22 bytes in increasing order: byte 0, bytes 1
 * to 8, byte 9, bytes 10 to 21. Each loop invariant says that the bytes
 * below the next one to be written are those of compress(ADRS) and that
 * every other byte is still the input block's.
 *
 * Theorems:
 *     adrs_compress_into64_correct    the 64-byte block, total correctness;
 *     adrs_compress_into128_correct   the 128-byte block, total correctness.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import BArray32 BArray64 BArray128 SetModel CoreExtracted.
require import Bytes FIPS205_Address.

(* ------------------------------------------------------------------ *)
(* compress, byte by byte                                             *)

(* The address byte that lands at byte j of ADRS^c (FIPS 205 section
   11.2: bytes 3, 8 to 15, 19 and 20 to 31 of ADRS). *)
op adrsc_src (j : int) : int =
  if j = 0 then 3 else if j < 9 then j + 7 else if j = 9 then 19 else j + 10.

lemma slice32 (a : BArray32.t) (i j : int) : 0 <= i <= j <= 32 =>
  slice (BArray32.to_list a) i j = mkseq (fun k => a.[i + k]) (j - i).
proof.
move=> hij; apply (eq_from_nth W8.zero).
+ by rewrite /slice size_take 1:/# size_drop 1:/# BArray32.size_to_list size_mkseq /#.
move=> k; rewrite /slice size_take 1:/# size_drop 1:/# BArray32.size_to_list => hk.
by rewrite nth_take 1,2:/# nth_drop 1,2:/# BArray32.get_to_list nth_mkseq /#.
qed.

lemma compress_nth (a : BArray32.t) (j : int) : 0 <= j < 22 =>
  nth W8.zero (FIPS205_Address.compress (BArray32.to_list a)) j = a.[adrsc_src j].
proof.
move=> hj; rewrite /FIPS205_Address.compress !slice32 // /adrsc_src /=.
rewrite !nth_cat /= !size_mkseq /=.
case: (j = 0) => h0 //=.
rewrite size_cat size_mkseq /=.
case: (j < 9) => h9; first smt(nth_mkseq).
case: (j = 9) => h10; first smt().
smt(nth_mkseq).
qed.

lemma size_compress (a : BArray32.t) : size (FIPS205_Address.compress (BArray32.to_list a)) = 22.
proof. by rewrite /FIPS205_Address.compress !slice32 // /= !size_cat !size_mkseq. qed.

lemma trunc_zext8 (x : W8.t) : truncateu8 (zeroextu64 x) = x.
proof.
rewrite /truncateu8 /zeroextu64 W64.of_uintK modz_small; first smt(W8.to_uint_cmp pow2_64 pow2_8).
by rewrite W8.to_uintK.
qed.

(* ------------------------------------------------------------------ *)
(* __adrs_compress_into64                                             *)

(* The bytes below w are those of ADRS^c, the others those of d0. *)
op written64 (a : BArray32.t) (d0 d : BArray64.t) (w : int) =
  forall j, 0 <= j < 64 =>
    d.[j] = if j < w then nth W8.zero (FIPS205_Address.compress (BArray32.to_list a)) j else d0.[j].

lemma adrs_compress_into64_h (d0 : BArray64.t) (a0 : BArray32.t) :
  hoare [M.__adrs_compress_into64 : dst = d0 /\ adrs = a0 ==>
         take 22 (BArray64.to_list res) = FIPS205_Address.compress (BArray32.to_list a0) /\
         drop 22 (BArray64.to_list res) = drop 22 (BArray64.to_list d0)].
proof.
proc.
while (0 <= i <= 12 /\ adrs = a0 /\ written64 a0 d0 dst (10 + i)).
+ wp; skip => &m [#] h0 hi ha hw hlt /=; do 2!(split; first smt()).
  move=> j hj; rewrite BArray64.get_setE 1:/# trunc_zext8 ha.
  case: (j = 10 + i{m}) => [-> | hne]; first by rewrite ifT 1:/# compress_nth 1:/# /adrsc_src /#.
  by rewrite hw // /#.
wp; while (0 <= i <= 8 /\ adrs = a0 /\ written64 a0 d0 dst (1 + i)).
+ wp; skip => &m [#] h0 hi ha hw hlt /=; do 2!(split; first smt()).
  move=> j hj; rewrite BArray64.get_setE 1:/# trunc_zext8 ha.
  case: (j = 1 + i{m}) => [-> | hne]; first by rewrite ifT 1:/# compress_nth 1:/# /adrsc_src /#.
  by rewrite hw // /#.
wp; skip => &m [-> ->] /=; split.
+ move=> j hj; rewrite BArray64.get_setE 1:/# trunc_zext8.
  case: (j = 0) => [-> /= | hne]; first by rewrite compress_nth.
  by rewrite ifF /#.
move=> d1 i1 hn1 [#] g0 g1 g3; split.
+ move=> j hj; rewrite BArray64.get_setE 1:/# trunc_zext8.
  case: (j = 9) => [-> /= | hne]; first by rewrite compress_nth.
  by rewrite (g3 j hj); smt().
move=> d2 i2 hn2 [#] k0 k1 k3; have hi2 : i2 = 12 by smt().
split; apply (eq_from_nth W8.zero).
+ by rewrite size_take // BArray64.size_to_list size_compress.
+ move=> j; rewrite size_take // BArray64.size_to_list /= => hj.
  by rewrite nth_take 1,2:/# BArray64.get_to_list k3 1:/# ifT /#.
+ by rewrite !size_drop // !BArray64.size_to_list.
move=> j; rewrite size_drop // BArray64.size_to_list /= => hj.
by rewrite !nth_drop 1..4:/# !BArray64.get_to_list k3 1:/# ifF /#.
qed.

lemma adrs_compress_into64_ll : islossless M.__adrs_compress_into64.
proof.
proc; while true (12 - i); 1: by auto => /#.
wp; while true (8 - i); 1: by auto => /#.
by auto => /#.
qed.

lemma adrs_compress_into64_correct (d0 : BArray64.t) (a0 : BArray32.t) :
  phoare [M.__adrs_compress_into64 : dst = d0 /\ adrs = a0 ==>
          take 22 (BArray64.to_list res) = FIPS205_Address.compress (BArray32.to_list a0) /\
          drop 22 (BArray64.to_list res) = drop 22 (BArray64.to_list d0)] = 1%r.
proof. by conseq adrs_compress_into64_ll (adrs_compress_into64_h d0 a0). qed.

(* ------------------------------------------------------------------ *)
(* __adrs_compress_into128                                            *)

(* The bytes below w are those of ADRS^c, the others those of d0. *)
op written128 (a : BArray32.t) (d0 d : BArray128.t) (w : int) =
  forall j, 0 <= j < 128 =>
    d.[j] = if j < w then nth W8.zero (FIPS205_Address.compress (BArray32.to_list a)) j else d0.[j].

lemma adrs_compress_into128_h (d0 : BArray128.t) (a0 : BArray32.t) :
  hoare [M.__adrs_compress_into128 : dst = d0 /\ adrs = a0 ==>
         take 22 (BArray128.to_list res) = FIPS205_Address.compress (BArray32.to_list a0) /\
         drop 22 (BArray128.to_list res) = drop 22 (BArray128.to_list d0)].
proof.
proc.
while (0 <= i <= 12 /\ adrs = a0 /\ written128 a0 d0 dst (10 + i)).
+ wp; skip => &m [#] h0 hi ha hw hlt /=; do 2!(split; first smt()).
  move=> j hj; rewrite BArray128.get_setE 1:/# trunc_zext8 ha.
  case: (j = 10 + i{m}) => [-> | hne]; first by rewrite ifT 1:/# compress_nth 1:/# /adrsc_src /#.
  by rewrite hw // /#.
wp; while (0 <= i <= 8 /\ adrs = a0 /\ written128 a0 d0 dst (1 + i)).
+ wp; skip => &m [#] h0 hi ha hw hlt /=; do 2!(split; first smt()).
  move=> j hj; rewrite BArray128.get_setE 1:/# trunc_zext8 ha.
  case: (j = 1 + i{m}) => [-> | hne]; first by rewrite ifT 1:/# compress_nth 1:/# /adrsc_src /#.
  by rewrite hw // /#.
wp; skip => &m [-> ->] /=; split.
+ move=> j hj; rewrite BArray128.get_setE 1:/# trunc_zext8.
  case: (j = 0) => [-> /= | hne]; first by rewrite compress_nth.
  by rewrite ifF /#.
move=> d1 i1 hn1 [#] g0 g1 g3; split.
+ move=> j hj; rewrite BArray128.get_setE 1:/# trunc_zext8.
  case: (j = 9) => [-> /= | hne]; first by rewrite compress_nth.
  by rewrite (g3 j hj); smt().
move=> d2 i2 hn2 [#] k0 k1 k3; have hi2 : i2 = 12 by smt().
split; apply (eq_from_nth W8.zero).
+ by rewrite size_take // BArray128.size_to_list size_compress.
+ move=> j; rewrite size_take // BArray128.size_to_list /= => hj.
  by rewrite nth_take 1,2:/# BArray128.get_to_list k3 1:/# ifT /#.
+ by rewrite !size_drop // !BArray128.size_to_list.
move=> j; rewrite size_drop // BArray128.size_to_list /= => hj.
by rewrite !nth_drop 1..4:/# !BArray128.get_to_list k3 1:/# ifF /#.
qed.

lemma adrs_compress_into128_ll : islossless M.__adrs_compress_into128.
proof.
proc; while true (12 - i); 1: by auto => /#.
wp; while true (8 - i); 1: by auto => /#.
by auto => /#.
qed.

lemma adrs_compress_into128_correct (d0 : BArray128.t) (a0 : BArray32.t) :
  phoare [M.__adrs_compress_into128 : dst = d0 /\ adrs = a0 ==>
          take 22 (BArray128.to_list res) = FIPS205_Address.compress (BArray32.to_list a0) /\
          drop 22 (BArray128.to_list res) = drop 22 (BArray128.to_list d0)] = 1%r.
proof. by conseq adrs_compress_into128_ll (adrs_compress_into128_h d0 a0). qed.
