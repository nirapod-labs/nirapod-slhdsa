(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Params.ec
 * =================
 *
 * The twelve SLH-DSA parameter sets of FIPS 205 Table 2 (section 11), and
 * the quantities derived from them in sections 5 (w, len1, len2, len) and
 * 9 (m), including Algorithm 1 (gen_len2).
 *
 * Every algorithm of the specification takes a parameter set as an explicit
 * argument. A parameter set is a record holding the Table 2 row as printed,
 * derived columns included (h', m, security category, public-key and
 * signature sizes). Keeping the printed values rather than recomputing them
 * lets the validation theories check the table against its own formulas:
 * h' = h / d, m from section 9, |pk| = 2n and the signature size of
 * Figure 17. The algorithms read h' and m from the record as the standard's
 * pseudocode does; the formulas are lemmas, not definitions.
 *)

require import AllCore List IntDiv.
require import Bytes.

(* Section 11: the hash-function family that instantiates H_msg, PRF,
   PRF_msg, F, H and T_l. *)
type hash_family = [ SHA2 | SHAKE ].

type params = {
  family    : hash_family;
  n         : int;   (* security parameter, bytes *)
  h         : int;   (* hypertree height *)
  d         : int;   (* hypertree layers *)
  hp        : int;   (* h', XMSS tree height *)
  a         : int;   (* FORS tree height *)
  k         : int;   (* FORS trees *)
  lgw       : int;   (* bits per WOTS+ hash chain *)
  m         : int;   (* message digest length, bytes *)
  category  : int;   (* claimed security category *)
  pk_bytes  : int;
  sig_bytes : int;
}.

(* ------------------------------------------------------------------ *)
(* Table 2                                                            *)

op slh_dsa_sha2_128s  = {| family = SHA2;  n = 16; h = 63; d = 7;  hp = 9; a = 12; k = 14; lgw = 4; m = 30; category = 1; pk_bytes = 32; sig_bytes = 7856  |}.
op slh_dsa_shake_128s = {| family = SHAKE; n = 16; h = 63; d = 7;  hp = 9; a = 12; k = 14; lgw = 4; m = 30; category = 1; pk_bytes = 32; sig_bytes = 7856  |}.
op slh_dsa_sha2_128f  = {| family = SHA2;  n = 16; h = 66; d = 22; hp = 3; a = 6;  k = 33; lgw = 4; m = 34; category = 1; pk_bytes = 32; sig_bytes = 17088 |}.
op slh_dsa_shake_128f = {| family = SHAKE; n = 16; h = 66; d = 22; hp = 3; a = 6;  k = 33; lgw = 4; m = 34; category = 1; pk_bytes = 32; sig_bytes = 17088 |}.
op slh_dsa_sha2_192s  = {| family = SHA2;  n = 24; h = 63; d = 7;  hp = 9; a = 14; k = 17; lgw = 4; m = 39; category = 3; pk_bytes = 48; sig_bytes = 16224 |}.
op slh_dsa_shake_192s = {| family = SHAKE; n = 24; h = 63; d = 7;  hp = 9; a = 14; k = 17; lgw = 4; m = 39; category = 3; pk_bytes = 48; sig_bytes = 16224 |}.
op slh_dsa_sha2_192f  = {| family = SHA2;  n = 24; h = 66; d = 22; hp = 3; a = 8;  k = 33; lgw = 4; m = 42; category = 3; pk_bytes = 48; sig_bytes = 35664 |}.
op slh_dsa_shake_192f = {| family = SHAKE; n = 24; h = 66; d = 22; hp = 3; a = 8;  k = 33; lgw = 4; m = 42; category = 3; pk_bytes = 48; sig_bytes = 35664 |}.
op slh_dsa_sha2_256s  = {| family = SHA2;  n = 32; h = 64; d = 8;  hp = 8; a = 14; k = 22; lgw = 4; m = 47; category = 5; pk_bytes = 64; sig_bytes = 29792 |}.
op slh_dsa_shake_256s = {| family = SHAKE; n = 32; h = 64; d = 8;  hp = 8; a = 14; k = 22; lgw = 4; m = 47; category = 5; pk_bytes = 64; sig_bytes = 29792 |}.
op slh_dsa_sha2_256f  = {| family = SHA2;  n = 32; h = 68; d = 17; hp = 4; a = 9;  k = 35; lgw = 4; m = 49; category = 5; pk_bytes = 64; sig_bytes = 49856 |}.
op slh_dsa_shake_256f = {| family = SHAKE; n = 32; h = 68; d = 17; hp = 4; a = 9;  k = 35; lgw = 4; m = 49; category = 5; pk_bytes = 64; sig_bytes = 49856 |}.

op parameter_sets : params list = [
  slh_dsa_sha2_128s; slh_dsa_shake_128s; slh_dsa_sha2_128f; slh_dsa_shake_128f;
  slh_dsa_sha2_192s; slh_dsa_shake_192s; slh_dsa_sha2_192f; slh_dsa_shake_192f;
  slh_dsa_sha2_256s; slh_dsa_shake_256s; slh_dsa_sha2_256f; slh_dsa_shake_256f
].

(* ------------------------------------------------------------------ *)
(* Section 5 and Algorithm 1                                          *)

(* Algorithm 1, gen_len2(n, lg_w). The while loop of lines 6 to 9 runs
   with state (len2, capacity) = (1, w) from line 4. Fuel max_checksum
   suffices whenever w >= 2: after j iterations capacity = w^(j+1) > j + 1,
   so the condition capacity <= max_checksum fails within max_checksum
   iterations. *)
op gen_len2 (n lgw : int) : int =
  let w = 2 ^ lgw in
  let len1 = (8 * n + lgw - 1) %/ lgw in
  let max_checksum = len1 * (w - 1) in
  (bounded_while max_checksum
     (fun (s : int * int) => s.`2 <= max_checksum)
     (fun (s : int * int) => (s.`1 + 1, s.`2 * w))
     (1, w)).`1.

(* Equations 5.1, 5.2 and 5.4; len2 (Equation 5.3) by Algorithm 1. *)
op w    (p : params) : int = 2 ^ p.`lgw.
op len1 (p : params) : int = cdiv (8 * p.`n) p.`lgw.
op len2 (p : params) : int = gen_len2 p.`n p.`lgw.
op len  (p : params) : int = len1 p + len2 p.
