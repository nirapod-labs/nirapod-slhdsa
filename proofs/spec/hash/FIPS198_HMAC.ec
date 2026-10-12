(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS198_HMAC.ec
 * ===============
 *
 * HMAC of FIPS 198-1 (July 2008), section 4, over a hash function given as
 * a function on byte strings with input block size B bytes. FIPS 205
 * section 11.2 uses it as HMAC-SHA-256 (B = 64) and HMAC-SHA-512
 * (B = 128) to instantiate PRF_msg.
 *
 * The output is the full L-byte MAC; FIPS 205 applies its own Trunc_n, so
 * the optional truncation to t bytes of FIPS 198-1 section 5 is not used.
 *)

require import AllCore List.
from Jasmin require import JWord.
require import Bytes FIPS180_SHA2.

(* Bytewise exclusive-or of two strings of equal length. *)
op xorb (x y : bytes) : bytes = map (fun (ab : byte * byte) => ab.`1 +^ ab.`2) (zip x y).

op ipad (b : int) : bytes = nseq b (W8.of_int 0x36).
op opad (b : int) : bytes = nseq b (W8.of_int 0x5c).

(* Table 1, steps 1 to 3: the key K0 of exactly B bytes. *)
op hmac_key (hash : bytes -> bytes) (b : int) (k : bytes) : bytes =
  if size k = b then k
  else if b < size k then hash k ++ zeros (b - size (hash k))
  else k ++ zeros (b - size k).

(* Table 1, steps 4 to 9:
   HMAC(K, text) = H((K0 xor opad) || H((K0 xor ipad) || text)). *)
op hmac (hash : bytes -> bytes) (b : int) (k text : bytes) : bytes =
  let k0 = hmac_key hash b k in
  hash (xorb k0 (opad b) ++ hash (xorb k0 (ipad b) ++ text)).

op hmac_sha256 (k text : bytes) : bytes = hmac SHA256.sha256 64 k text.
op hmac_sha512 (k text : bytes) : bytes = hmac SHA512.sha512 128 k text.
