(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ADRS.ec
 * =======
 *
 * Functional correctness of the hash address code of the SLH-DSA core
 * (src/slhdsa/address.jinc) against the ADRS member functions of FIPS 205
 * Table 1 as specified in spec/slhdsa/FIPS205_Address.ec.
 *
 * Model. AddressExtracted is the jasmin2ec model of address.jinc for one
 * architecture; this file is checked once against each extracted pair
 * (proofs/Makefile). The source depends on no parameter set, so the same
 * theorems hold for all twelve. The x86-64 and AArch64 models differ only
 * in the instruction model they load; no procedure here uses an
 * architecture-specific instruction.
 *
 * Representation. The address is a 32-byte array (BArray32.t in the model,
 * u64[4] in the source). Its bytes, in order, are the FIPS 205 address:
 * every statement below is about to_list of the array, which is the byte
 * string the specification operators take. The procedures that store a
 * 32- or 64-bit word (the zeroing loop, setTypeAndClear, the copies) are
 * covered through the model's byte view of those stores, which is
 * little-endian on both targets; the proofs below are where that choice of
 * the source is checked.
 *
 * Theorems. Each procedure, from every initial address and argument,
 * returns the address the specification operator gives:
 *
 *     adrs_zero_correct                __adrs_zero: toByte(0, 32)
 *     adrs_set_layer_correct           __adrs_set_layer: setLayerAddress
 *     adrs_set_tree_correct            __adrs_set_tree: setTreeAddress
 *     adrs_set_type_and_clear_correct  __adrs_set_type_and_clear:
 *                                      setTypeAndClear, for a type below
 *                                      256 (FIPS 205 uses 0 to 6)
 *     adrs_set_keypair_correct         __adrs_set_keypair: setKeyPairAddress
 *     adrs_copy_keypair_correct        __adrs_copy_keypair: setKeyPairAddress
 *                                      of dst to getKeyPairAddress of src
 *     adrs_set_chain_correct           __adrs_set_chain: setChainAddress
 *     adrs_set_tree_height_correct     __adrs_set_tree_height: setTreeHeight
 *     adrs_set_hash_correct            __adrs_set_hash: setHashAddress
 *     adrs_set_tree_index_correct      __adrs_set_tree_index: setTreeIndex
 *     adrs_copy_correct                __adrs_copy: the source address
 *
 * Each is a probabilistic Hoare judgement with probability 1: the
 * procedure terminates and returns the specified address. The integer
 * arguments of the specification are the unsigned values of the machine
 * words the source takes: 32 bits for the layer, key pair, chain, height,
 * hash and index fields, 64 bits for the tree address. Each value fits its
 * field (4 bytes; 12 for the tree address), so the theorems need no range
 * condition on them.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
from Jasmin require import JWord JUtils.
require import BArray32 AddressExtracted.
require import Bytes FIPS205_Encoding FIPS205_Encoding_Props FIPS205_Address FIPS205_Address_Props.

(* ------------------------------------------------------------------ *)
(* Byte lists of the 32-byte array                                    *)

abbrev bytes_of (a : BArray32.t) : bytes = BArray32.to_list a.

lemma size_bytes_of a : size (bytes_of a) = 32.
proof. by rewrite BArray32.size_to_list. qed.

(* Two byte strings are the address of an array when they agree on every
   one of its 32 bytes. *)
lemma bytes_ofP (a : BArray32.t) (l : bytes) :
  size l = 32 =>
  (forall k, 0 <= k < 32 => a.[k] = nth W8.zero l k) =>
  bytes_of a = l.
proof.
move=> hs hk; apply (eq_from_nth W8.zero); first by rewrite size_bytes_of hs.
by move=> k; rewrite size_bytes_of => hk'; rewrite BArray32.get_to_list hk.
qed.

lemma nth_bytes_of (a : BArray32.t) k : nth W8.zero (bytes_of a) k = a.[k].
proof. by rewrite BArray32.get_to_list. qed.

(* A field of the address replaced by a byte string s at offset o. *)
lemma nth_splice (a : bytes) (s : bytes) o k :
  size a = 32 => 0 <= o => o + size s <= 32 =>
  nth W8.zero (take o a ++ s ++ drop (o + size s) a) k
  = if o <= k < o + size s then nth W8.zero s (k - o) else nth W8.zero a k.
proof.
move=> ha ho hos; rewrite -catA nth_cat size_take //.
have -> : (if o < size a then o else size a) = o by smt(size_ge0).
case: (k < o) => hko.
+ by rewrite ifF 1:/# nth_take.
rewrite nth_cat; case: (k - o < size s) => hks.
+ by rewrite ifT 1:/#.
rewrite ifF 1:/# nth_drop; [smt(size_ge0) | smt() | congr; ring].
qed.

(* ------------------------------------------------------------------ *)
(* toByte on words                                                    *)

lemma nth_toByte (x n k : int) :
  0 <= k < n => nth W8.zero (toByte x n) k = W8.of_int (x %/ 256 ^ (n - 1 - k)).
proof. by move=> hk; rewrite toByteE 1:/# /be_bytes nth_mkseq. qed.

lemma truncateu8_shr32 (v : W32.t) i :
  0 <= i < 32 => truncateu8 (v `>>` W8.of_int i) = W8.of_int (to_uint v %/ 2 ^ i).
proof. by move=> hi; rewrite /truncateu8 W32.shr_div_le. qed.

lemma truncateu8_shr64 (v : W64.t) i :
  0 <= i < 64 => truncateu8 (v `>>` W8.of_int i) = W8.of_int (to_uint v %/ 2 ^ i).
proof. by move=> hi; rewrite /truncateu8 W64.shr_div_le. qed.

lemma pow256 j : 0 <= j => 256 ^ j = 2 ^ (8 * j).
proof. by move=> hj; rewrite (_: 256 = 2 ^ 8) // -exprM. qed.

(* ------------------------------------------------------------------ *)
(* __store_be32: toByte(v, 4) at a byte offset                        *)

lemma store_be32_bytes (a : BArray32.t) o (v : W32.t) :
  0 <= o <= 28 =>
  bytes_of (a.[o <- truncateu8 (v `>>` W8.of_int 24)]
             .[o + 1 <- truncateu8 (v `>>` W8.of_int 16)]
             .[o + 2 <- truncateu8 (v `>>` W8.of_int 8)]
             .[o + 3 <- truncateu8 v])
  = take o (bytes_of a) ++ toByte (to_uint v) 4 ++ drop (o + 4) (bytes_of a).
proof.
move=> ho; apply bytes_ofP.
+ by rewrite !size_cat size_take 1:/# size_drop 1:/# size_toByte // size_bytes_of /#.
move=> k hk; have := nth_splice (bytes_of a) (toByte (to_uint v) 4) o k _ _ _.
+ by rewrite size_bytes_of.
+ smt().
+ by rewrite size_toByte /#.
rewrite size_toByte // => ->.
rewrite !BArray32.get_set_if nth_bytes_of.
case: (o <= k < o + 4) => hin; last first.
+ by rewrite !ifF /#.
have: k = o \/ k = o + 1 \/ k = o + 2 \/ k = o + 3 by smt().
move=> [->|[->|[->|->]]].
+ rewrite (_: o - o = 0) 1:/# nth_toByte //= !truncateu8_shr32 // /truncateu8; smt().
+ rewrite (_: o + 1 - o = 1) 1:/# nth_toByte //= !truncateu8_shr32 // /truncateu8; smt().
+ rewrite (_: o + 2 - o = 2) 1:/# nth_toByte //= !truncateu8_shr32 // /truncateu8; smt().
rewrite (_: o + 3 - o = 3) 1:/# nth_toByte //= !truncateu8_shr32 // /truncateu8; smt().
qed.

lemma store_be32_ll : islossless M.__store_be32.
proof. by proc; auto. qed.

lemma store_be32_h (a0 : BArray32.t) o0 (v0 : W32.t) :
  0 <= o0 <= 28 =>
  hoare [M.__store_be32 : arg = (a0, o0, v0) ==>
         bytes_of res = take o0 (bytes_of a0) ++ toByte (to_uint v0) 4
                        ++ drop (o0 + 4) (bytes_of a0)].
proof. by move=> ho; proc; auto => />; rewrite store_be32_bytes. qed.

lemma store_be32_ph (a0 : BArray32.t) o0 (v0 : W32.t) :
  0 <= o0 <= 28 =>
  phoare [M.__store_be32 : arg = (a0, o0, v0) ==>
          bytes_of res = take o0 (bytes_of a0) ++ toByte (to_uint v0) 4
                         ++ drop (o0 + 4) (bytes_of a0)] = 1%r.
proof. by move=> ho; conseq store_be32_ll (store_be32_h a0 o0 v0 ho). qed.

(* The specification setters that write one 32-bit word, as the same
   splice. *)
lemma slice_head (x : bytes) j : slice x 0 j = take j x.
proof. by rewrite /slice drop0. qed.

lemma slice_tail (x : bytes) i : 0 <= i <= 32 => size x = 32 => slice x i 32 = drop i x.
proof. by move=> hi hx; rewrite slice_drop. qed.

(* ------------------------------------------------------------------ *)
(* Setters of one 32-bit word                                         *)

lemma adrs_set_layer_correct (a0 : BArray32.t) (l0 : W32.t) :
  phoare [M.__adrs_set_layer : arg = (a0, l0) ==>
          bytes_of res = setLayerAddress (bytes_of a0) (to_uint l0)] = 1%r.
proof.
proc; call (store_be32_ph a0 0 l0 _) => //; auto => /> r ->.
by rewrite /setLayerAddress take0 /= slice_tail // size_bytes_of.
qed.

lemma adrs_set_keypair_correct (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_keypair : arg = (a0, i0) ==>
          bytes_of res = setKeyPairAddress (bytes_of a0) (to_uint i0)] = 1%r.
proof.
proc; call (store_be32_ph a0 20 i0 _) => //; auto => /> r ->.
by rewrite /setKeyPairAddress slice_head slice_tail // size_bytes_of.
qed.

lemma adrs_set_chain_correct (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_chain : arg = (a0, i0) ==>
          bytes_of res = setChainAddress (bytes_of a0) (to_uint i0)] = 1%r.
proof.
proc; call (store_be32_ph a0 24 i0 _) => //; auto => /> r ->.
by rewrite /setChainAddress slice_head slice_tail // size_bytes_of.
qed.

lemma adrs_set_tree_height_correct (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_tree_height : arg = (a0, i0) ==>
          bytes_of res = setTreeHeight (bytes_of a0) (to_uint i0)] = 1%r.
proof.
proc; call (store_be32_ph a0 24 i0 _) => //; auto => /> r ->.
by rewrite /setChainAddress slice_head slice_tail // size_bytes_of.
qed.

lemma adrs_set_hash_correct (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_hash : arg = (a0, i0) ==>
          bytes_of res = setHashAddress (bytes_of a0) (to_uint i0)] = 1%r.
proof.
proc; call (store_be32_ph a0 28 i0 _) => //; auto => /> r ->.
by rewrite /setHashAddress slice_head drop_oversize 1:size_bytes_of // cats0.
qed.

lemma adrs_set_tree_index_correct (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_tree_index : arg = (a0, i0) ==>
          bytes_of res = setTreeIndex (bytes_of a0) (to_uint i0)] = 1%r.
proof.
proc; call (store_be32_ph a0 28 i0 _) => //; auto => /> r ->.
by rewrite /setHashAddress slice_head drop_oversize 1:size_bytes_of // cats0.
qed.

(* ------------------------------------------------------------------ *)
(* Word stores, seen byte by byte                                     *)

lemma zero_bits8 i : W64.zero \bits8 i = W8.zero.
proof. by rewrite W8u8.get_zero. qed.

lemma zero32_bits8 i : W32.zero \bits8 i = W8.zero.
proof. by rewrite W4u8.get_zero. qed.

(* ------------------------------------------------------------------ *)
(* __adrs_zero: toByte(0, 32)                                         *)

lemma adrs_zero_ll : islossless M.__adrs_zero.
proof. by proc; while true (4 - i); auto => /#. qed.

lemma adrs_zero_h (a0 : BArray32.t) :
  hoare [M.__adrs_zero : arg = a0 ==> bytes_of res = toByte 0 32].
proof.
proc.
while (0 <= i <= 4 /\ z = W64.zero /\
       forall k, 0 <= k < 32 => adrs.[k] = if k < 8 * i then W8.zero else a0.[k]).
+ auto => /> &hr hi0 _ hk hi4; split; first smt().
  move=> k hk0 hk32; rewrite BArray32.get8_set64dE zero_bits8 hk 1:/#.
  by case: (8 * i{hr} <= k < 8 * i{hr} + 8) => /#.
auto => />; split; first smt().
move=> a i hi hi0 hi4 hk; rewrite toByte0 //; apply bytes_ofP; first by rewrite size_nseq.
by move=> k hk'; rewrite nth_nseq 1:// hk // /#.
qed.

lemma adrs_zero_correct (a0 : BArray32.t) :
  phoare [M.__adrs_zero : arg = a0 ==> bytes_of res = toByte 0 32] = 1%r.
proof. by conseq adrs_zero_ll (adrs_zero_h a0). qed.

(* ------------------------------------------------------------------ *)
(* __adrs_set_tree: setTreeAddress                                    *)

lemma adrs_set_tree_ll : islossless M.__adrs_set_tree.
proof. by proc; while true (8 - i); auto => /#. qed.

lemma adrs_set_tree_h (a0 : BArray32.t) (t0 : W64.t) :
  hoare [M.__adrs_set_tree : arg = (a0, t0) ==>
         bytes_of res = setTreeAddress (bytes_of a0) (to_uint t0)].
proof.
proc.
while (0 <= i <= 8 /\ tree = t0 /\
       forall k, 0 <= k < 32 => adrs.[k] =
         if 4 <= k < 8 then W8.zero
         else if 8 <= k < 8 + i then W8.of_int (to_uint t0 %/ 2 ^ (8 * (15 - k)))
         else a0.[k]).
+ auto => /> &hr hi0 _ hk hi8; split; first smt().
  move=> k hk0 hk32; rewrite BArray32.get_set_if truncateu8_shr64 1:/#.
  case: (k = 8 + i{hr}) => [->> | hne]; first by rewrite ifT 1:/# /= /#.
  by rewrite ifF 1:/# hk // /#.
auto => />; split.
+ move=> k hk0 hk32; rewrite BArray32.get8_set32dE zero32_bits8.
  by case: (4 <= k < 8) => /#.
move=> a i hi hi0 hi8 hk.
rewrite /setTreeAddress slice_head slice_tail ?size_bytes_of //.
apply bytes_ofP; first by rewrite !size_cat size_take // size_toByte // size_drop // size_bytes_of.
move=> k hk'; have := nth_splice (bytes_of a0) (toByte (to_uint t0) 12) 4 k _ _ _.
+ by rewrite size_bytes_of.
+ done.
+ by rewrite size_toByte.
rewrite size_toByte // => ->; rewrite ?nth_bytes_of.
have ->> : i = 8 by smt().
case: (4 <= k < 16) => hin; last by rewrite hk // /#.
rewrite hk // nth_toByte 1:/#.
have ht : 0 <= to_uint t0 < 2 ^ 64 by apply W64.to_uint_cmp.
case: (4 <= k < 8) => hlo.
+ rewrite ifT 1:/#.
  have -> : to_uint t0 %/ 256 ^ (12 - 1 - (k - 4)) = 0; last by [].
  apply divz_small; rewrite ger0_norm 1:expr_ge0 //; split; first smt().
  move=> _; apply (ltr_le_trans (2 ^ 64)); first by case: ht.
  by rewrite pow256 1:/#; apply ler_weexpn2l => /#.
by rewrite !ifT 1,2:/# pow256 1:/# (_: 8 * (12 - 1 - (k - 4)) = 8 * (15 - k)) 1:/#.
qed.

lemma adrs_set_tree_correct (a0 : BArray32.t) (t0 : W64.t) :
  phoare [M.__adrs_set_tree : arg = (a0, t0) ==>
          bytes_of res = setTreeAddress (bytes_of a0) (to_uint t0)] = 1%r.
proof. by conseq adrs_set_tree_ll (adrs_set_tree_h a0 t0). qed.

(* ------------------------------------------------------------------ *)
(* __adrs_set_type_and_clear: setTypeAndClear                         *)

(* Bytes 16 .. 31 of the result: the type as a 4-byte big-endian word,
   then twelve zero bytes. The source stores them as two little-endian
   64-bit words, the first holding the type at bit 24. *)
lemma type_word_bits8 (y j : int) :
  0 <= y < 256 => 0 <= j < 8 =>
  (W64.of_int (y `<<` 24)) \bits8 j = if j = 3 then W8.of_int y else W8.zero.
proof.
move=> hy hj; rewrite /(`<<`) /= W8u8.of_int_bits8_div //.
have: j = 0 \/ j = 1 \/ j = 2 \/ j = 3 \/ j = 4 \/ j = 5 \/ j = 6 \/ j = 7 by smt().
move=> [|[|[|[|[|[|[|]]]]]]] ->> /=.
+ by rewrite -W8.of_int_mod; smt().
+ by rewrite -W8.of_int_mod; smt().
+ by rewrite -W8.of_int_mod; smt().
+ by rewrite mulzK.
+ by rewrite divz_small; smt().
+ by rewrite divz_small; smt().
+ by rewrite divz_small; smt().
by rewrite divz_small; smt().
qed.

lemma adrs_set_type_and_clear_correct (a0 : BArray32.t) (y0 : int) :
  0 <= y0 < 256 =>
  phoare [M.__adrs_set_type_and_clear : arg = (a0, y0) ==>
          bytes_of res = setTypeAndClear (bytes_of a0) y0] = 1%r.
proof.
move=> hy; proc; auto => />.
rewrite /setTypeAndClear.
have -> : slice (bytes_of a0) 0 16 ++ toByte y0 4 ++ toByte 0 12
        = take 16 (bytes_of a0) ++ (toByte y0 4 ++ toByte 0 12) ++ drop 32 (bytes_of a0).
+ by rewrite drop_oversize 1:size_bytes_of // cats0 slice_head catA.
apply bytes_ofP; first by rewrite !size_cat size_take // !size_toByte // size_drop // size_bytes_of.
move=> k hk.
have := nth_splice (bytes_of a0) (toByte y0 4 ++ toByte 0 12) 16 k _ _ _.
+ by rewrite size_bytes_of.
+ done.
+ by rewrite size_cat !size_toByte.
rewrite size_cat !size_toByte // => /= ->.
rewrite !BArray32.get8_set64dE zero_bits8 /=.
case: (16 <= k < 32) => hin; last by rewrite !ifF 1..3:/# nth_bytes_of.
rewrite nth_cat size_toByte //.
case: (20 <= k) => h20.
+ rewrite (ifF (k - 16 < 4)) 1:/# nth_toByte 1:/# div0z.
  case: (24 <= k) => h24; first by rewrite ifT 1:/#.
  by rewrite ifF 1:/# ifT 1:/# type_word_bits8 // 1:/# ifF 1:/#.
rewrite (ifT (k - 16 < 4)) 1:/# ifF 1:/# ifT 1:/# type_word_bits8 // 1:/# nth_toByte 1:/#.
case: (k = 19) => [->> | hne] /=; first by rewrite ?expr0 ?divz1.
rewrite ifF 1:/# divz_small //; rewrite ger0_norm 1:expr_ge0 //; split; first smt().
move=> _; apply (ltr_le_trans 256); first smt().
by rewrite -{1}expr1; apply ler_weexpn2l => /#.
qed.

(* ------------------------------------------------------------------ *)
(* __adrs_copy_keypair: setKeyPairAddress(dst, getKeyPairAddress(src)) *)

(* toByte(toInt(X, n), n) = X for every n-byte string X. *)
lemma be_bytes_be_int (x : bytes) : be_bytes (size x) (be_int x) = x.
proof.
elim/last_ind: x => [|x c ih]; first by rewrite /be_bytes mkseq0.
rewrite size_rcons be_bytesS 1:size_ge0 be_int_rcons.
have hc : 0 <= to_uint c < 256 by apply W8.to_uint_cmp.
rewrite (_: (256 * be_int x + to_uint c) %/ 256 = be_int x).
+ by rewrite mulzC divzMDl // divz_small //; smt().
rewrite ih; congr.
by rewrite -W8.of_int_mod mulzC modzMDl modz_small 1:/# W8.to_uintK.
qed.

lemma toByte_toInt (x : bytes) n : size x = n => toByte (toInt x n) n = x.
proof.
move=> <-; rewrite toInt_be_int 1:size_ge0 // take_size toByteE 1:size_ge0.
exact be_bytes_be_int.
qed.

lemma adrs_copy_keypair_correct (d0 s0 : BArray32.t) :
  phoare [M.__adrs_copy_keypair : arg = (d0, s0) ==>
          bytes_of res = setKeyPairAddress (bytes_of d0) (getKeyPairAddress (bytes_of s0))] = 1%r.
proof.
proc; auto => />.
rewrite /setKeyPairAddress /getKeyPairAddress toByte_toInt.
+ by rewrite size_slice // size_bytes_of.
rewrite slice_head slice_tail ?size_bytes_of //.
apply bytes_ofP; first by rewrite !size_cat size_take // size_slice 1:size_bytes_of // size_drop.
move=> k hk; have := nth_splice (bytes_of d0) (slice (bytes_of s0) 20 24) 20 k _ _ _.
+ by rewrite size_bytes_of.
+ done.
+ by rewrite size_slice // size_bytes_of.
rewrite size_slice 1:size_bytes_of // => /= ->.
rewrite BArray32.get8_set32dE.
case: (20 <= k < 24) => hin; last by rewrite ifF 1:/# ?nth_bytes_of.
rewrite ifT 1:/# BArray32.get32d_byte 1:/# /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite ?nth_bytes_of; congr; ring.
qed.

(* ------------------------------------------------------------------ *)
(* __adrs_copy: the source address                                    *)

lemma adrs_copy_ll : islossless M.__adrs_copy.
proof. by proc; while true (4 - i); auto => /#. qed.

lemma adrs_copy_h (d0 s0 : BArray32.t) :
  hoare [M.__adrs_copy : arg = (d0, s0) ==> bytes_of res = bytes_of s0].
proof.
proc.
while (0 <= i <= 4 /\ src = s0 /\
       forall k, 0 <= k < 32 => dst.[k] = if k < 8 * i then s0.[k] else d0.[k]).
+ auto => /> &hr hi0 _ hk hi4; split; first smt().
  move=> k hk0 hk32; rewrite BArray32.get8_set64dE.
  case: (8 * i{hr} <= k < 8 * i{hr} + 8) => hin.
  + by rewrite /= ifT 1:/# ifT 1:/# BArray32.get64d_byte 1:/#; congr; ring.
  by rewrite hk //; smt().
auto => />; split; first smt().
move=> d i hi hi0 hi4 hk; apply bytes_ofP; first by rewrite size_bytes_of.
by move=> k hk'; rewrite nth_bytes_of hk // /#.
qed.

lemma adrs_copy_correct (d0 s0 : BArray32.t) :
  phoare [M.__adrs_copy : arg = (d0, s0) ==> bytes_of res = bytes_of s0] = 1%r.
proof. by conseq adrs_copy_ll (adrs_copy_h d0 s0). qed.
