(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Internal.ec
 * ===================
 *
 * The SLH-DSA internal functions of FIPS 205 section 9: Algorithms 18
 * (slh_keygen_internal), 19 (slh_sign_internal) and 20
 * (slh_verify_internal).
 *
 * Keys and signatures are byte strings in the formats of Figures 15 to 17:
 *
 *     SK  = SK.seed || SK.prf || PK.seed || PK.root     4n bytes
 *     PK  = PK.seed || PK.root                          2n bytes
 *     SIG = R || SIG_FORS || SIG_HT    (1 + k(1 + a) + h + d * len) * n bytes
 *
 * Randomness. Section 9 takes all random values as inputs. The optional
 * addrnd of Algorithm 19 is an option: Some r is the hedged variant
 * (opt_rand = r) and None the deterministic variant (opt_rand = PK.seed,
 * line 2).
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Hash.
require import FIPS205_XMSS FIPS205_Hypertree FIPS205_FORS.

(* Field accessors for the key formats of Figures 15 and 16. *)
op sk_seed_of (p : params) (sk : bytes) : bytes = slice sk 0 p.`n.
op sk_prf_of  (p : params) (sk : bytes) : bytes = slice sk p.`n (2 * p.`n).
op pk_seed_of (p : params) (sk : bytes) : bytes = slice sk (2 * p.`n) (3 * p.`n).
op pk_root_of (p : params) (sk : bytes) : bytes = slice sk (3 * p.`n) (4 * p.`n).

(* The signature length Algorithm 20 line 1 accepts (Figure 17). *)
op sig_length (p : params) : int = (1 + p.`k * (1 + p.`a) + p.`h + p.`d * len p) * p.`n.

(* Byte counts of the three digest fields of Algorithm 19 lines 6 to 8. *)
op md_bytes   (p : params) : int = cdiv (p.`k * p.`a) 8.
op tree_bytes (p : params) : int = cdiv (p.`h - p.`h %/ p.`d) 8.
op leaf_bytes (p : params) : int = cdiv p.`h (8 * p.`d).

(* Algorithm 19 lines 6 to 10 and Algorithm 20 lines 9 to 13:
   (md, idx_tree, idx_leaf) from the message digest. *)
op split_digest (p : params) (digest : bytes) : bytes * int * int =
  let md = slice digest 0 (md_bytes p) in
  let tmp_idx_tree = slice digest (md_bytes p) (md_bytes p + tree_bytes p) in
  let tmp_idx_leaf = slice digest (md_bytes p + tree_bytes p)
                                  (md_bytes p + tree_bytes p + leaf_bytes p) in
  let idx_tree = toInt tmp_idx_tree (tree_bytes p) %% 2 ^ (p.`h - p.`h %/ p.`d) in
  let idx_leaf = toInt tmp_idx_leaf (leaf_bytes p) %% 2 ^ (p.`h %/ p.`d) in
  (md, idx_tree, idx_leaf).

(* Algorithm 18, slh_keygen_internal(SK.seed, SK.prf, PK.seed). *)
op slh_keygen_internal (p : params) (sk_seed sk_prf pk_seed : bytes) : bytes * bytes =
  let a = setLayerAddress (toByte 0 32) (p.`d - 1) in                                  (* 1-2 *)
  let pk_root = xmss_node p sk_seed 0 p.`hp pk_seed a in                               (* 3 *)
  (sk_seed ++ sk_prf ++ pk_seed ++ pk_root, pk_seed ++ pk_root).                       (* 4 *)

(* Algorithm 19, slh_sign_internal(M, SK, addrnd). *)
op slh_sign_internal (p : params) (msg sk : bytes) (addrnd : bytes option) : bytes =
  let sk_seed = sk_seed_of p sk in
  let sk_prf  = sk_prf_of p sk in
  let pk_seed = pk_seed_of p sk in
  let pk_root = pk_root_of p sk in
  let opt_rand = odflt pk_seed addrnd in                                               (* 2 *)
  let r = PRF_msg p sk_prf opt_rand msg in                                             (* 3 *)
  let digest = H_msg p r pk_seed pk_root msg in                                        (* 5 *)
  let (md, idx_tree, idx_leaf) = split_digest p digest in                              (* 6-10 *)
  let a = setKeyPairAddress
            (setTypeAndClear (setTreeAddress (toByte 0 32) idx_tree) FORS_TREE)
            idx_leaf in                                                                (* 1, 11-13 *)
  let sig_fors = fors_sign p md sk_seed pk_seed a in                                   (* 14 *)
  let pk_fors = fors_pkFromSig p sig_fors md pk_seed a in                              (* 16 *)
  let sig_ht = ht_sign p pk_fors sk_seed pk_seed idx_tree idx_leaf in                  (* 17 *)
  r ++ sig_fors ++ sig_ht.                                                             (* 4, 15, 18 *)

(* Algorithm 20, slh_verify_internal(M, SIG, PK). *)
op slh_verify_internal (p : params) (msg sig pk : bytes) : bool =
  if size sig <> sig_length p then false                                                (* 1-3 *)
  else
    let pk_seed = slice pk 0 p.`n in
    let pk_root = slice pk p.`n (2 * p.`n) in
    let r = slice sig 0 p.`n in                                                        (* 5 *)
    let sig_fors = slice sig p.`n ((1 + p.`k * (1 + p.`a)) * p.`n) in                  (* 6 *)
    let sig_ht = slice sig ((1 + p.`k * (1 + p.`a)) * p.`n) (sig_length p) in           (* 7 *)
    let digest = H_msg p r pk_seed pk_root msg in                                      (* 8 *)
    let (md, idx_tree, idx_leaf) = split_digest p digest in                            (* 9-13 *)
    let a = setKeyPairAddress
              (setTypeAndClear (setTreeAddress (toByte 0 32) idx_tree) FORS_TREE)
              idx_leaf in                                                              (* 4, 14-16 *)
    let pk_fors = fors_pkFromSig p sig_fors md pk_seed a in                            (* 17 *)
    ht_verify p pk_fors sig_ht pk_seed idx_tree idx_leaf pk_root.                      (* 18 *)
