(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_FORS.ec
 * ===============
 *
 * FORS of FIPS 205 section 8: Algorithms 14 (fors_skGen), 15 (fors_node),
 * 16 (fors_sign) and 17 (fors_pkFromSig).
 *
 * Algorithm 15 recurses on the node height like Algorithm 9 and is written
 * the same way (see FIPS205_XMSS): fors_node_rec recurses on the list of
 * heights still to build. Every recursive call sets the tree height and
 * index it hashes under, so passing the caller's address by value computes
 * what the by-reference pseudocode computes.
 *
 * Tree indices count continuously across the k trees (section 4.2): leaf j
 * of tree i has index i * 2^a + j, and its ancestor at height z has index
 * i * 2^(a-z) + floor(j / 2^z).
 *
 * Signature layout (Figure 14): for each tree i, the selected secret value
 * (n bytes) followed by its authentication path (a * n bytes).
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Hash.
require import FIPS205_XMSS.

(* Algorithm 14, fors_skGen(SK.seed, PK.seed, ADRS, idx). *)
op fors_skGen (p : params) (sk_seed pk_seed : bytes) (a : adrs) (idx : int) : bytes =
  let skADRS = setKeyPairAddress (setTypeAndClear a FORS_PRF) (getKeyPairAddress a) in  (* 1-3 *)
  PRF p pk_seed sk_seed (setTreeIndex skADRS idx).                                     (* 4-5 *)

op fors_node_rec (p : params) (sk_seed : bytes) (zs : int list) (i : int) (pk_seed : bytes) (a : adrs) : bytes =
  with zs = [] =>
    let sk = fors_skGen p sk_seed pk_seed a i in                                       (* 2 *)
    F p pk_seed (setTreeIndex (setTreeHeight a 0) i) sk                                (* 3-5 *)
  with zs = z :: zs' =>
    let lnode = fors_node_rec p sk_seed zs' (2 * i) pk_seed a in                       (* 7 *)
    let rnode = fors_node_rec p sk_seed zs' (2 * i + 1) pk_seed a in                   (* 8 *)
    H p pk_seed (setTreeIndex (setTreeHeight a z) i) (lnode ++ rnode).                 (* 9-11 *)

(* Algorithm 15, fors_node(SK.seed, i, z, PK.seed, ADRS). *)
op fors_node (p : params) (sk_seed : bytes) (i z : int) (pk_seed : bytes) (a : adrs) : bytes =
  fors_node_rec p sk_seed (rev (range 1 (z + 1))) i pk_seed a.

(* Algorithm 16, fors_sign(md, SK.seed, PK.seed, ADRS). *)
op fors_sign (p : params) (md sk_seed pk_seed : bytes) (a : adrs) : bytes =
  let indices = base_2b md p.`a p.`k in                                                (* 2 *)
  flatten (map (fun i =>
                  let idx = nth 0 indices i in
                  fors_skGen p sk_seed pk_seed a (i * 2 ^ p.`a + idx)                  (* 4 *)
                  ++ flatten (map (fun j =>
                                     let s = sibling (idx %/ 2 ^ j) in                 (* 6 *)
                                     fors_node p sk_seed (i * 2 ^ (p.`a - j) + s) j pk_seed a)  (* 7 *)
                                  (range 0 p.`a)))                                     (* 5-9 *)
               (range 0 p.`k)).                                                        (* 1, 3-11 *)

(* Algorithm 17, fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS). The state of
   the outer loop is (root array, ADRS); that of the inner loop is
   (node[0], ADRS), whose tree index at height j + 1 derives from the one at
   height j (lines 11 and 14). *)
op fors_pkFromSig (p : params) (sig_fors md pk_seed : bytes) (a : adrs) : bytes =
  let n = p.`n in
  let indices = base_2b md p.`a p.`k in                                                (* 1 *)
  let (roots, a) =
    foldl (fun (st : bytes list * adrs) (i : int) =>
             let (roots, a) = st in
             let idx = nth 0 indices i in
             let sk = slice sig_fors (i * (p.`a + 1) * n) ((i * (p.`a + 1) + 1) * n) in        (* 3 *)
             let a = setTreeIndex (setTreeHeight a 0) (i * 2 ^ p.`a + idx) in                  (* 4-5 *)
             let node0 = F p pk_seed a sk in                                                   (* 6 *)
             let auth = slice sig_fors ((i * (p.`a + 1) + 1) * n) ((i + 1) * (p.`a + 1) * n) in (* 7 *)
             let (node, a) =
               foldl (fun (st' : bytes * adrs) (j : int) =>
                        let (node, a) = st' in
                        let a = setTreeHeight a (j + 1) in                                     (* 9 *)
                        let auth_j = slice auth (j * n) ((j + 1) * n) in
                        if (idx %/ 2 ^ j) %% 2 = 0 then
                          let a = setTreeIndex a (getTreeIndex a %/ 2) in                      (* 11 *)
                          (H p pk_seed a (node ++ auth_j), a)                                  (* 12, 17 *)
                        else
                          let a = setTreeIndex a ((getTreeIndex a - 1) %/ 2) in                (* 14 *)
                          (H p pk_seed a (auth_j ++ node), a))                                 (* 15, 17 *)
                     (node0, a) (range 0 p.`a) in
             (rcons roots node, a))                                                            (* 19 *)
          ([], a) (range 0 p.`k) in
  let forspkADRS = setKeyPairAddress (setTypeAndClear a FORS_ROOTS) (getKeyPairAddress a) in   (* 21-23 *)
  T_l p pk_seed forspkADRS (flatten roots).                                                    (* 24 *)
