(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_WOTS.ec
 * ===============
 *
 * WOTS+ of FIPS 205 section 5: Algorithms 5 (chain), 6 (wots_pkGen),
 * 7 (wots_sign) and 8 (wots_pkFromSig).
 *
 * Arrays of n-byte strings are byte strings (section 4.4): element i of a
 * WOTS+ signature sig is sig[i*n : (i+1)*n], and an array passed to T_len
 * is the concatenation of its elements.
 *
 * Loops. A loop that writes one array element per iteration from a fresh
 * address update is written as a map over the index range: each iteration
 * sets the chain address it reads (lines 5 and 7 of Algorithm 6), so no
 * state flows between iterations. Algorithm 5 threads its address, as the
 * pseudocode does. Lines 1 to 7 of Algorithms 7 and 8 are identical in the
 * standard and are shared here as wots_digits.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Hash.

(* Algorithm 5, chain(X, i, s, PK.seed, ADRS): for j = i .. i+s-1,
   ADRS.setHashAddress(j); tmp <- F(PK.seed, ADRS, tmp). *)
op chain (p : params) (x : bytes) (i s : int) (pk_seed : bytes) (a : adrs) : bytes =
  (foldl (fun (st : bytes * adrs) (j : int) =>
            let a' = setHashAddress st.`2 j in
            (F p pk_seed a' st.`1, a'))
         (x, a) (range i (i + s))).`1.

(* Algorithm 6, wots_pkGen(SK.seed, PK.seed, ADRS). *)
op wots_pkGen (p : params) (sk_seed pk_seed : bytes) (a : adrs) : bytes =
  let skADRS = setKeyPairAddress (setTypeAndClear a WOTS_PRF) (getKeyPairAddress a) in   (* 1-3 *)
  let tmp = map (fun i =>
                   let sk = PRF p pk_seed sk_seed (setChainAddress skADRS i) in           (* 5-6 *)
                   chain p sk 0 (w p - 1) pk_seed (setChainAddress a i))                (* 7-8 *)
                (range 0 (len p)) in
  let wotspkADRS = setKeyPairAddress (setTypeAndClear a WOTS_PK) (getKeyPairAddress a) in (* 10-12 *)
  T_l p pk_seed wotspkADRS (flatten tmp).                                                 (* 13 *)

(* Algorithms 7 and 8, lines 1 to 7: the len1 base-w digits of M followed by
   the len2 base-w digits of the checksum, shifted left by
   (8 - ((len2 * lg_w) mod 8)) mod 8 bits so that it fills whole bytes. *)
op wots_digits (p : params) (msg : bytes) : int list =
  let digits = base_2b msg p.`lgw (len1 p) in                                            (* 2 *)
  let csum = foldl (fun (c i : int) => c + w p - 1 - nth 0 digits i) 0 (range 0 (len1 p)) in   (* 1, 3-5 *)
  let csum = csum * 2 ^ ((8 - ((len2 p * p.`lgw) %% 8)) %% 8) in                       (* 6 *)
  digits ++ base_2b (toByte csum (cdiv (len2 p * p.`lgw) 8)) p.`lgw (len2 p).          (* 7 *)

(* Algorithm 7, wots_sign(M, SK.seed, PK.seed, ADRS). *)
op wots_sign (p : params) (msg sk_seed pk_seed : bytes) (a : adrs) : bytes =
  let digits = wots_digits p msg in
  let skADRS = setKeyPairAddress (setTypeAndClear a WOTS_PRF) (getKeyPairAddress a) in   (* 8-10 *)
  flatten (map (fun i =>
                  let sk = PRF p pk_seed sk_seed (setChainAddress skADRS i) in             (* 12-13 *)
                  chain p sk 0 (nth 0 digits i) pk_seed (setChainAddress a i))          (* 14-15 *)
               (range 0 (len p))).

(* Algorithm 8, wots_pkFromSig(sig, M, PK.seed, ADRS). *)
op wots_pkFromSig (p : params) (sig msg pk_seed : bytes) (a : adrs) : bytes =
  let digits = wots_digits p msg in
  let tmp = map (fun i =>
                   chain p (slice sig (i * p.`n) ((i + 1) * p.`n))
                         (nth 0 digits i) (w p - 1 - nth 0 digits i)
                         pk_seed (setChainAddress a i))                                  (* 8-11 *)
                (range 0 (len p)) in
  let wotspkADRS = setKeyPairAddress (setTypeAndClear a WOTS_PK) (getKeyPairAddress a) in (* 12-14 *)
  T_l p pk_seed wotspkADRS (flatten tmp).                                                 (* 15 *)
