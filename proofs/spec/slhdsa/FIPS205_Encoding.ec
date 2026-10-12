(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Encoding.ec
 * ===================
 *
 * Integer and base-2^b conversions of FIPS 205 section 4.4: Algorithms 2
 * (toInt), 3 (toByte) and 4 (base_2b). They are transcribed step by step;
 * closed forms used by proofs are stated and proven in
 * FIPS205_Encoding_Props.ec, not substituted here.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes.

(* Algorithm 2, toInt(X, n): total <- 256 * total + X[i] for i = 0 .. n-1. *)
op toInt (x : bytes) (n : int) : int =
  foldl (fun (total : int) (i : int) => 256 * total + W8.to_uint (nth W8.zero x i)) 0 (range 0 n).

(* Algorithm 3, toByte(x, n): for i = 0 .. n-1, S[n-1-i] <- total mod 256 and
   total <- total >> 8. S starts as n zero bytes; every position is written
   once. *)
op toByte (x : int) (n : int) : bytes =
  (foldl (fun (st : int * bytes) (i : int) =>
            (st.`1 %/ 256, put st.`2 (n - 1 - i) (W8.of_int (st.`1 %% 256))))
         (x, zeros n) (range 0 n)).`2.

(* Algorithm 4, base_2b(X, b, out_len). The state is ((in, bits, total),
   baseb). *)

(* Lines 6 to 8: append the next byte of X to total. *)
op base_2b_step (x : bytes) (s : int * int * int) : int * int * int =
  let (inp, bits, total) = s in
  (inp + 1, bits + 8, total * 2 ^ 8 + W8.to_uint (nth W8.zero x inp)).

(* Lines 5 to 11: one output digit. The inner while loop (lines 5 to 9)
   runs with fuel b, which suffices: bits >= 0 on entry and each step adds
   8, so bits >= b after at most b steps. *)
op base_2b_out (x : bytes) (b : int) (st : (int * int * int) * int list) : (int * int * int) * int list =
  let (inp, bits, total) =
    bounded_while b (fun (s : int * int * int) => s.`2 < b) (base_2b_step x) st.`1 in
  let bits = bits - b in
  ((inp, bits, total), rcons st.`2 ((total %/ 2 ^ bits) %% 2 ^ b)).

(* Lines 1 to 4, 12 and 13. *)
op base_2b (x : bytes) (b out_len : int) : int list =
  (foldl (fun (st : (int * int * int) * int list) (_ : int) => base_2b_out x b st)
         ((0, 0, 0), []) (range 0 out_len)).`2.
