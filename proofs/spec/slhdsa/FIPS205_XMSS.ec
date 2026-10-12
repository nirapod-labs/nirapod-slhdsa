(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_XMSS.ec
 * ===============
 *
 * XMSS of FIPS 205 section 6: Algorithms 9 (xmss_node), 10 (xmss_sign) and
 * 11 (xmss_pkFromSig).
 *
 * Recursion. Algorithm 9 recurses on the node height z. EasyCrypt operators
 * recurse structurally, so xmss_node_rec recurses on the list of heights
 * [z; z-1; ...; 1] still to be built: its head is the height of the node
 * being computed and its tail is the list for both children. The empty
 * list is the leaf case z = 0. Both children receive the caller's address
 * unchanged, which is what the by-reference pseudocode computes as well:
 * lines 2-3 and 8-10 overwrite every field a recursive call reads, except
 * the layer and tree addresses, which no call changes.
 *
 * Signature layout (Figure 11): SIG_XMSS = sig || AUTH, with sig the
 * len * n byte WOTS+ signature and AUTH[j] the n-byte sibling at height j.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Hash.
require import FIPS205_WOTS.

(* x xor 1 for x >= 0 (section 2.3): the index of the sibling of node x. *)
op sibling (x : int) : int = if x %% 2 = 0 then x + 1 else x - 1.

op xmss_node_rec (p : params) (sk_seed : bytes) (zs : int list) (i : int) (pk_seed : bytes) (a : adrs) : bytes =
  with zs = [] =>
    wots_pkGen p sk_seed pk_seed (setKeyPairAddress (setTypeAndClear a WOTS_HASH) i)  (* 2-4 *)
  with zs = z :: zs' =>
    let lnode = xmss_node_rec p sk_seed zs' (2 * i) pk_seed a in                       (* 6 *)
    let rnode = xmss_node_rec p sk_seed zs' (2 * i + 1) pk_seed a in                   (* 7 *)
    H p pk_seed (setTreeIndex (setTreeHeight (setTypeAndClear a TREE) z) i)            (* 8-10 *)
      (lnode ++ rnode).                                                                (* 11 *)

(* Algorithm 9, xmss_node(SK.seed, i, z, PK.seed, ADRS). *)
op xmss_node (p : params) (sk_seed : bytes) (i z : int) (pk_seed : bytes) (a : adrs) : bytes =
  xmss_node_rec p sk_seed (rev (range 1 (z + 1))) i pk_seed a.

(* Algorithm 10, xmss_sign(M, SK.seed, idx, PK.seed, ADRS). *)
op xmss_sign (p : params) (msg sk_seed : bytes) (idx : int) (pk_seed : bytes) (a : adrs) : bytes =
  let auth = map (fun j => xmss_node p sk_seed (sibling (idx %/ 2 ^ j)) j pk_seed a)  (* 1-4 *)
                 (range 0 p.`hp) in
  let a' = setKeyPairAddress (setTypeAndClear a WOTS_HASH) idx in                       (* 5-6 *)
  let sig = wots_sign p msg sk_seed pk_seed a' in                                      (* 7 *)
  sig ++ flatten auth.                                                                 (* 8 *)

(* Algorithm 11, xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS).
   Lines 8 to 18 carry (node[0], ADRS): the tree index set at height k + 1
   is derived from the one set at height k (lines 11 and 14). *)
op xmss_pkFromSig (p : params) (idx : int) (sig_xmss msg pk_seed : bytes) (a : adrs) : bytes =
  let a = setKeyPairAddress (setTypeAndClear a WOTS_HASH) idx in                       (* 1-2 *)
  let sig  = slice sig_xmss 0 (len p * p.`n) in                                        (* 3 *)
  let auth = slice sig_xmss (len p * p.`n) ((len p + p.`hp) * p.`n) in                 (* 4 *)
  let node0 = wots_pkFromSig p sig msg pk_seed a in                                    (* 5 *)
  let a = setTreeIndex (setTypeAndClear a TREE) idx in                                 (* 6-7 *)
  (foldl (fun (st : bytes * adrs) (k : int) =>
            let node = st.`1 in
            let a = setTreeHeight st.`2 (k + 1) in                                     (* 9 *)
            let auth_k = slice auth (k * p.`n) ((k + 1) * p.`n) in
            if (idx %/ 2 ^ k) %% 2 = 0 then
              let a = setTreeIndex a (getTreeIndex a %/ 2) in                          (* 11 *)
              (H p pk_seed a (node ++ auth_k), a)                                      (* 12, 17 *)
            else
              let a = setTreeIndex a ((getTreeIndex a - 1) %/ 2) in                    (* 14 *)
              (H p pk_seed a (auth_k ++ node), a))                                     (* 15, 17 *)
         (node0, a) (range 0 p.`hp)).`1.                                               (* 19 *)
