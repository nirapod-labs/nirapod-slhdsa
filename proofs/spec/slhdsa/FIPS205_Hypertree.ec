(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Hypertree.ec
 * ====================
 *
 * The SLH-DSA hypertree of FIPS 205 section 7: Algorithms 12 (ht_sign) and
 * 13 (ht_verify).
 *
 * Both algorithms walk the layers j = 1 .. d-1 with the state
 * (idx_tree, idx_leaf, ADRS, carried value); the folds below carry exactly
 * that state. idx_tree >> h' is floor(idx_tree / 2^h') (section 2.3), and
 * idx_tree mod 2^h' its h' least significant bits.
 *
 * Signature layout (Figure 13): d XMSS signatures of (h' + len) * n bytes,
 * layer 0 first.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Hash.
require import FIPS205_XMSS.

(* The length of one XMSS signature (Figure 11). *)
op xmss_sig_length (p : params) : int = (p.`hp + len p) * p.`n.

(* Algorithm 12, ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf).
   The state is (SIG_HT, root, idx_tree, ADRS). Line 14 recomputes root
   only below the top layer; the value it would compute at j = d - 1 is
   never read, and the condition is kept as written. *)
op ht_sign (p : params) (msg sk_seed pk_seed : bytes) (idx_tree idx_leaf : int) : bytes =
  let a = setTreeAddress (toByte 0 32) idx_tree in                                  (* 1-2 *)
  let sig_tmp = xmss_sign p msg sk_seed idx_leaf pk_seed a in                       (* 3 *)
  let root = xmss_pkFromSig p idx_leaf sig_tmp msg pk_seed a in                     (* 5 *)
  (foldl (fun (st : bytes * bytes * int * adrs) (j : int) =>
            let (sig_ht, root, idx_tree, a) = st in
            let idx_leaf = idx_tree %% 2 ^ p.`hp in                                 (* 7 *)
            let idx_tree = idx_tree %/ 2 ^ p.`hp in                                 (* 8 *)
            let a = setTreeAddress (setLayerAddress a j) idx_tree in                (* 9-10 *)
            let sig_tmp = xmss_sign p root sk_seed idx_leaf pk_seed a in            (* 11 *)
            let root = if j < p.`d - 1
                       then xmss_pkFromSig p idx_leaf sig_tmp root pk_seed a        (* 13-15 *)
                       else root in
            (sig_ht ++ sig_tmp, root, idx_tree, a))                                 (* 12 *)
         (sig_tmp, root, idx_tree, a) (range 1 p.`d)).`1.                          (* 4, 17 *)

(* Algorithm 13, ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root).
   The state is (node, idx_tree, ADRS). *)
op ht_verify (p : params) (msg sig_ht pk_seed : bytes) (idx_tree idx_leaf : int) (pk_root : bytes) : bool =
  let a = setTreeAddress (toByte 0 32) idx_tree in                                  (* 1-2 *)
  let sig_tmp = slice sig_ht 0 (xmss_sig_length p) in                              (* 3 *)
  let node = xmss_pkFromSig p idx_leaf sig_tmp msg pk_seed a in                     (* 4 *)
  let node =
    (foldl (fun (st : bytes * int * adrs) (j : int) =>
              let (node, idx_tree, a) = st in
              let idx_leaf = idx_tree %% 2 ^ p.`hp in                               (* 6 *)
              let idx_tree = idx_tree %/ 2 ^ p.`hp in                               (* 7 *)
              let a = setTreeAddress (setLayerAddress a j) idx_tree in              (* 8-9 *)
              let sig_tmp = slice sig_ht (j * xmss_sig_length p)
                                         ((j + 1) * xmss_sig_length p) in            (* 10 *)
              (xmss_pkFromSig p idx_leaf sig_tmp node pk_seed a, idx_tree, a))      (* 11 *)
           (node, idx_tree, a) (range 1 p.`d)).`1 in
  node = pk_root.                                                                   (* 13-17 *)
