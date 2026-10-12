(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validate_Encoding.ec
 * ====================
 *
 * Checks of Algorithms 2 to 4 (toInt, toByte, base_2b) and of the WOTS+
 * digit and checksum computation (Algorithms 7 and 8, lines 1 to 7).
 *
 * Two kinds of statement:
 *
 *     evaluations   the transcription, run on small concrete inputs, gives
 *                   the value the standard's pseudocode gives. Expected
 *                   values were computed independently of this file.
 *                   They exercise byte order, bit order across byte
 *                   boundaries (b = 6, 9, 12, 14) and the checksum shift.
 *
 *     general facts output sizes and ranges for all inputs, which later
 *                   proofs rely on.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_WOTS Validate_Params.

(* ------------------------------------------------------------------ *)
(* Evaluations                                                        *)

lemma toByte_ex1 : toByte 0x01020304 4 = map W8.of_int [1; 2; 3; 4].
proof. by rewrite /toByte /zeros /range -mkseq_nseq /mkseq -iotaredE /=. qed.

(* toByte keeps the n least significant bytes (x mod 256^n). *)
lemma toByte_ex2 : toByte 0x0102 1 = [W8.of_int 2].
proof. by rewrite /toByte /zeros /range -mkseq_nseq /mkseq -iotaredE /=. qed.

lemma toInt_ex1 : toInt (map W8.of_int [1; 2; 3; 4]) 4 = 0x01020304.
proof. by rewrite /toInt /range -iotaredE /= ?W8.of_uintK. qed.

lemma base_2b_ex12 : base_2b (map W8.of_int [0x12; 0x34; 0x56]) 12 2 = [0x123; 0x456].
proof.
by rewrite /base_2b /base_2b_out /bounded_while /base_2b_step /range -iotaredE /= ?W8.of_uintK.
qed.

lemma base_2b_ex6 : base_2b (map W8.of_int [0x12; 0x34; 0x56]) 6 4 = [4; 35; 17; 22].
proof.
by rewrite /base_2b /base_2b_out /bounded_while /base_2b_step /range -iotaredE /= ?W8.of_uintK.
qed.

lemma base_2b_ex9 : base_2b (map W8.of_int [0xde; 0xad; 0xbe; 0xef]) 9 3 = [445; 182; 503].
proof.
by rewrite /base_2b /base_2b_out /bounded_while /base_2b_step /range -iotaredE /= ?W8.of_uintK.
qed.

lemma base_2b_ex14 : base_2b (map W8.of_int [0xde; 0xad; 0xbe; 0xef]) 14 2 = [14251; 7150].
proof.
by rewrite /base_2b /base_2b_out /bounded_while /base_2b_step /range -iotaredE /= ?W8.of_uintK.
qed.

(* WOTS+ digits for n = 16. An all-zero message has digits 0, checksum
   32 * 15 = 480, shifted left by 4 to 0x1E00, giving digits 1, 14, 0; an
   all-0xff message has checksum 0. *)
lemma wots_digits_zero :
  wots_digits slh_dsa_sha2_128s (nseq 16 W8.zero) = nseq 32 0 ++ [1; 14; 0].
proof.
rewrite /wots_digits /len1 /len2 /w /cdiv /slh_dsa_sha2_128s /= gen_len2_16 /=.
rewrite /base_2b /base_2b_out /bounded_while /base_2b_step /toByte /zeros /range -!mkseq_nseq /mkseq -!iotaredE /=.
by rewrite ?W8.of_uintK.
qed.

lemma wots_digits_ones :
  wots_digits slh_dsa_sha2_128s (nseq 16 (W8.of_int 255)) = nseq 32 15 ++ [0; 0; 0].
proof.
rewrite /wots_digits /len1 /len2 /w /cdiv /slh_dsa_sha2_128s /= gen_len2_16 /=.
rewrite /base_2b /base_2b_out /bounded_while /base_2b_step /toByte /zeros /range -!mkseq_nseq /mkseq -!iotaredE /=.
by rewrite ?W8.of_uintK.
qed.

(* ------------------------------------------------------------------ *)
(* General facts                                                      *)

lemma size_toByte x n : 0 <= n => size (toByte x n) = n.
proof.
move=> ge0_n; rewrite /toByte.
have inv: forall (xs : int list) (st : int * bytes), size st.`2 = n =>
  size (foldl (fun (st : int * bytes) (i : int) =>
                 (st.`1 %/ 256, put st.`2 (n - 1 - i) (W8.of_int (st.`1 %% 256)))) st xs).`2 = n.
+ by elim=> [//|i xs ih] st h /=; apply ih => /=; rewrite size_put.
by apply inv => /=; rewrite size_zeros /#.
qed.

lemma size_base_2b_out x b st : size (base_2b_out x b st).`2 = size st.`2 + 1.
proof. by rewrite /base_2b_out; case: (bounded_while _ _ _ _) => [? ? ?] /=; rewrite size_rcons. qed.

lemma size_base_2b x b out_len : 0 <= out_len => size (base_2b x b out_len) = out_len.
proof.
move=> ge0; rewrite /base_2b.
have inv: forall (xs : int list) st,
  size (foldl (fun (st : (int * int * int) * int list) (_ : int) => base_2b_out x b st) st xs).`2
  = size st.`2 + size xs.
+ by elim=> [//|i xs ih] st /=; rewrite ih size_base_2b_out /#.
by rewrite inv size_range /#.
qed.

lemma base_2b_range x b out_len :
  all (fun v => 0 <= v < 2 ^ b) (base_2b x b out_len).
proof.
rewrite /base_2b.
have inv: forall (xs : int list) (st : (int * int * int) * int list),
  all (fun v => 0 <= v < 2 ^ b) st.`2 =>
  all (fun v => 0 <= v < 2 ^ b)
    (foldl (fun (st : (int * int * int) * int list) (_ : int) => base_2b_out x b st) st xs).`2.
+ elim=> [//|i xs ih] st h /=; apply ih.
  rewrite /base_2b_out; case: (bounded_while _ _ _ _) => [? ? ?] /=.
  rewrite -cats1 all_cat h /=; smt(modz_ge0 ltz_pmod expr_gt0).
by apply inv.
qed.
