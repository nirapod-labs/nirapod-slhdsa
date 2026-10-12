(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validate_Params.ec
 * ==================
 *
 * Checks of FIPS205_Params against FIPS 205 itself: Table 2 is consistent
 * with the formulas the standard gives for its derived columns, and
 * Algorithm 1 computes the len2 that section 3.1 states (3 for every set).
 *)

require import AllCore List IntDiv.
require import Bytes FIPS205_Params.

(* The fuel of a bounded while loop is irrelevant once the condition fails:
   the remaining steps are the identity. *)
lemma foldl_stopped ['a] (c : 'a -> bool) (b : 'a -> 'a) (s : 'a) (xs : int list) :
  !c s => foldl (fun (st : 'a) (_ : int) => if c st then b st else st) s xs = s.
proof. by move=> ncs; elim: xs => [//|x xs ih /=]; rewrite ncs /= ih. qed.

lemma iota_step i n : 0 < n => iota_ i n = i :: iota_ (i + 1) (n - 1).
proof. by move=> gt0_n; rewrite -(iotaS i (n - 1)) 1:/#. qed.

(* Algorithm 1 for lg_w = 4 and the three values of n. Three iterations of
   the loop (capacity 16, 256, 4096) exceed max_checksum = 2n * 15. *)
lemma gen_len2_16 : gen_len2 16 4 = 3.
proof.
rewrite /gen_len2 /bounded_while /= /range /=.
rewrite (iota_step 0) // /= (iota_step 1) // /= (iota_step 2) // /=.
by rewrite foldl_stopped.
qed.

lemma gen_len2_24 : gen_len2 24 4 = 3.
proof.
rewrite /gen_len2 /bounded_while /= /range /=.
rewrite (iota_step 0) // /= (iota_step 1) // /= (iota_step 2) // /=.
by rewrite foldl_stopped.
qed.

lemma gen_len2_32 : gen_len2 32 4 = 3.
proof.
rewrite /gen_len2 /bounded_while /= /range /=.
rewrite (iota_step 0) // /= (iota_step 1) // /= (iota_step 2) // /=.
by rewrite foldl_stopped.
qed.

(* Every row of Table 2 satisfies the relations FIPS 205 states between its
   columns:
     - lg_w = 4, hence w = 16, len1 = 2n and len2 = 3 (section 5, after
       Equation 5.4), and len2 meets Equation 5.3 in the form
       w^(len2-1) <= len1 * (w - 1) < w^len2;
     - h = d * h' (section 7);
     - m = ceil((h - h') / 8) + ceil(h' / 8) + ceil(k * a / 8) (section 9);
     - the public key is 2n bytes (Figure 16) and the signature
       (1 + k(1 + a) + h + d * len) * n bytes (Figure 17);
     - n = 16, 24, 32 claim categories 1, 3, 5 (section 11). *)
op table2_consistent (p : params) : bool =
     p.`lgw = 4
  /\ w p = 16
  /\ len1 p = 2 * p.`n
  /\ len2 p = 3
  /\ w p ^ (len2 p - 1) <= len1 p * (w p - 1) < w p ^ len2 p
  /\ p.`h = p.`d * p.`hp
  /\ p.`hp = p.`h %/ p.`d
  /\ p.`m = cdiv (p.`h - p.`hp) 8 + cdiv p.`hp 8 + cdiv (p.`k * p.`a) 8
  /\ p.`pk_bytes = 2 * p.`n
  /\ p.`sig_bytes = (1 + p.`k * (1 + p.`a) + p.`h + p.`d * len p) * p.`n
  /\ p.`category = (if p.`n = 16 then 1 else if p.`n = 24 then 3 else 5).

lemma table2_ok : all table2_consistent parameter_sets.
proof.
rewrite /parameter_sets /table2_consistent /w /len /len1 /len2 /cdiv.
rewrite /slh_dsa_sha2_128s /slh_dsa_shake_128s /slh_dsa_sha2_128f /slh_dsa_shake_128f.
rewrite /slh_dsa_sha2_192s /slh_dsa_shake_192s /slh_dsa_sha2_192f /slh_dsa_shake_192f.
rewrite /slh_dsa_sha2_256s /slh_dsa_shake_256s /slh_dsa_sha2_256f /slh_dsa_shake_256f /=.
by rewrite gen_len2_16 gen_len2_24 gen_len2_32.
qed.

lemma table2_size : size parameter_sets = 12 /\ uniq parameter_sets.
proof. by rewrite /parameter_sets. qed.
