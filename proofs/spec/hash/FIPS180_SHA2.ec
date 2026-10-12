(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS180_SHA2.ec
 * ===============
 *
 * The SHA-2 hash functions of FIPS 180-4 (August 2015): SHA-224, SHA-256,
 * SHA-384, SHA-512, SHA-512/224 and SHA-512/256.
 *
 * Scope. Messages are byte strings. FIPS 180-4 hashes bit strings of any
 * length l < 2^64 (SHA-224/256) or l < 2^128 (the SHA-512 family); every
 * input in FIPS 205 is a byte string, so this specification fixes l = 8 * |M|
 * and writes the padding of section 5.1 at byte granularity. The length
 * field is the bit length reduced modulo 2^64 (resp. 2^128) by the encoding,
 * which agrees with the standard on its whole input domain.
 *
 * Words. A FIPS 180-4 word is a Jasmin W32.t or W64.t. Addition modulo 2^w
 * is the word ring addition `+`; the bitwise operators of section 3.2 are
 * `&` (AND), `+^` (XOR), `invw` (complement); ROTR^n and SHR^n of section
 * 3.2 are `|>>>|` and `>>>`.
 *
 * Structure. Each family follows the standard's four stages: the functions
 * of section 4.1, the constants of section 4.2, preprocessing (padding,
 * parsing, initial hash value; sections 5.1 to 5.3), and the hash
 * computation of section 6, written as folds over the message blocks and
 * the rounds. Words are read and written big-endian (section 3.1, item 3).
 *
 * Constants. The tables are those printed in sections 4.2.2, 4.2.3 and 5.3.
 * `make check-constants` (proofs/tools/sha2_constants.py) re-derives each
 * one from its definition (cube and square roots of primes, and the
 * SHA-512/t IV generation function of section 5.3.6) and compares it with
 * this file.
 *)

require import AllCore List IntDiv.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord.
require import Bytes.

(* ------------------------------------------------------------------ *)
(* Section 3.1: big-endian words                                      *)

(* Section 3.1, item 3: a word is stored with its most significant byte
   first. W4u8.pack4 and W8u8.pack8 assemble a word from its bytes least
   significant first, so the big-endian reading of a byte string is the
   packing of its reversal, and the big-endian encoding of a word is the
   reversal of its little-endian byte list. *)
op be32 (b : bytes) : W32.t = W4u8.pack4 (rev b).
op be64 (b : bytes) : W64.t = W8u8.pack8 (rev b).

op w32_be (x : W32.t) : bytes = rev (W4u8.to_list x).
op w64_be (x : W64.t) : bytes = rev (W8u8.to_list x).

(* ================================================================== *)
(* SHA-224 and SHA-256                                                *)

theory SHA256.

(* Section 4.1.2: the six logical functions on 32-bit words. *)
op ch  (x y z : W32.t) : W32.t = (x `&` y) +^ (invw x `&` z).
op maj (x y z : W32.t) : W32.t = (x `&` y) +^ (x `&` z) +^ (y `&` z).

op bsig0 (x : W32.t) : W32.t = (x `|>>>|` 2)  +^ (x `|>>>|` 13) +^ (x `|>>>|` 22).
op bsig1 (x : W32.t) : W32.t = (x `|>>>|` 6)  +^ (x `|>>>|` 11) +^ (x `|>>>|` 25).
op ssig0 (x : W32.t) : W32.t = (x `|>>>|` 7)  +^ (x `|>>>|` 18) +^ (x `>>>` 3).
op ssig1 (x : W32.t) : W32.t = (x `|>>>|` 17) +^ (x `|>>>|` 19) +^ (x `>>>` 10).

(* Section 4.2.2: K_0 ... K_63, the first 32 bits of the fractional parts of
   the cube roots of the first 64 primes. *)
op K256 : W32.t list = map W32.of_int [
  0x428a2f98; 0x71374491; 0xb5c0fbcf; 0xe9b5dba5; 0x3956c25b; 0x59f111f1; 0x923f82a4; 0xab1c5ed5;
  0xd807aa98; 0x12835b01; 0x243185be; 0x550c7dc3; 0x72be5d74; 0x80deb1fe; 0x9bdc06a7; 0xc19bf174;
  0xe49b69c1; 0xefbe4786; 0x0fc19dc6; 0x240ca1cc; 0x2de92c6f; 0x4a7484aa; 0x5cb0a9dc; 0x76f988da;
  0x983e5152; 0xa831c66d; 0xb00327c8; 0xbf597fc7; 0xc6e00bf3; 0xd5a79147; 0x06ca6351; 0x14292967;
  0x27b70a85; 0x2e1b2138; 0x4d2c6dfc; 0x53380d13; 0x650a7354; 0x766a0abb; 0x81c2c92e; 0x92722c85;
  0xa2bfe8a1; 0xa81a664b; 0xc24b8b70; 0xc76c51a3; 0xd192e819; 0xd6990624; 0xf40e3585; 0x106aa070;
  0x19a4c116; 0x1e376c08; 0x2748774c; 0x34b0bcb5; 0x391c0cb3; 0x4ed8aa4a; 0x5b9cca4f; 0x682e6ff3;
  0x748f82ee; 0x78a5636f; 0x84c87814; 0x8cc70208; 0x90befffa; 0xa4506ceb; 0xbef9a3f7; 0xc67178f2
].

(* Section 5.3.3: H(0) for SHA-256 (square roots of the first 8 primes). *)
op H0_256 : W32.t list = map W32.of_int [
  0x6a09e667; 0xbb67ae85; 0x3c6ef372; 0xa54ff53a; 0x510e527f; 0x9b05688c; 0x1f83d9ab; 0x5be0cd19
].

(* Section 5.3.2: H(0) for SHA-224 (second 32 bits of the square roots of
   the 9th to 16th primes). *)
op H0_224 : W32.t list = map W32.of_int [
  0xc1059ed8; 0x367cd507; 0x3070dd17; 0xf70e5939; 0xffc00b31; 0x68581511; 0x64f98fa7; 0xbefa4fa4
].

(* Section 5.1.1: append the bit 1, then k zero bits with
   l + 1 + k = 448 (mod 512), then l as a 64-bit big-endian integer. For
   l = 8 * |M| the bit 1 and the first seven zero bits are the byte 0x80,
   and the remaining zero bits are (55 - |M|) mod 64 bytes. *)
op pad (m : bytes) : bytes =
  m ++ [W8.of_int 0x80] ++ zeros ((55 - size m) %% 64) ++ be_bytes 8 (8 * size m).

(* Section 5.2.1: the padded message as N blocks of sixteen 32-bit words. *)
op parse (p : bytes) : W32.t list list = map (fun b => map be32 (chunk 4 b)) (chunk 64 p).

type state = W32.t * W32.t * W32.t * W32.t * W32.t * W32.t * W32.t * W32.t.

op to_state (h : W32.t list) : state =
  (nth W32.zero h 0, nth W32.zero h 1, nth W32.zero h 2, nth W32.zero h 3,
   nth W32.zero h 4, nth W32.zero h 5, nth W32.zero h 6, nth W32.zero h 7).

op of_state (s : state) : W32.t list =
  let (a, b, c, d, e, f, g, h) = s in [a; b; c; d; e; f; g; h].

(* Section 6.2.2, step 1: the message schedule W_0 ... W_63. *)
op schedule (m : W32.t list) : W32.t list =
  foldl (fun (w : W32.t list) t =>
           rcons w (ssig1 (nth W32.zero w (t - 2)) + nth W32.zero w (t - 7)
                  + ssig0 (nth W32.zero w (t - 15)) + nth W32.zero w (t - 16)))
        m (range 16 64).

(* Section 6.2.2, step 3: round t on the working variables a ... h. *)
op round (w : W32.t list) (s : state) (t : int) : state =
  let (a, b, c, d, e, f, g, h) = s in
  let t1 = h + bsig1 e + ch e f g + nth W32.zero K256 t + nth W32.zero w t in
  let t2 = bsig0 a + maj a b c in
  (t1 + t2, a, b, c, d + t1, e, f, g).

(* Section 6.2.2, steps 1 to 4: one block M(i) applied to H(i-1). *)
op compress (hv : W32.t list) (m : W32.t list) : W32.t list =
  let w = schedule m in
  let s = foldl (round w) (to_state hv) (range 0 64) in
  map (fun (xy : W32.t * W32.t) => xy.`1 + xy.`2) (zip (of_state s) hv).

(* Section 6.2.2: H(N) from H(0). *)
op hash (h0 : W32.t list) (m : bytes) : W32.t list = foldl compress h0 (parse (pad m)).

(* Section 6.2.2: the 256-bit digest H0(N) || ... || H7(N). *)
op sha256 (m : bytes) : bytes = flatten (map w32_be (hash H0_256 m)).

(* Section 6.3: SHA-224 is SHA-256 with H(0) of section 5.3.2, truncated to
   its leftmost 224 bits. *)
op sha224 (m : bytes) : bytes = take 28 (flatten (map w32_be (hash H0_224 m))).

end SHA256.

(* ================================================================== *)
(* SHA-384, SHA-512, SHA-512/224 and SHA-512/256                      *)

theory SHA512.

(* Section 4.1.3: the six logical functions on 64-bit words. *)
op ch  (x y z : W64.t) : W64.t = (x `&` y) +^ (invw x `&` z).
op maj (x y z : W64.t) : W64.t = (x `&` y) +^ (x `&` z) +^ (y `&` z).

op bsig0 (x : W64.t) : W64.t = (x `|>>>|` 28) +^ (x `|>>>|` 34) +^ (x `|>>>|` 39).
op bsig1 (x : W64.t) : W64.t = (x `|>>>|` 14) +^ (x `|>>>|` 18) +^ (x `|>>>|` 41).
op ssig0 (x : W64.t) : W64.t = (x `|>>>|` 1)  +^ (x `|>>>|` 8)  +^ (x `>>>` 7).
op ssig1 (x : W64.t) : W64.t = (x `|>>>|` 19) +^ (x `|>>>|` 61) +^ (x `>>>` 6).

(* Section 4.2.3: K_0 ... K_79, the first 64 bits of the fractional parts of
   the cube roots of the first 80 primes. *)
op K512 : W64.t list = map W64.of_int [
  0x428a2f98d728ae22; 0x7137449123ef65cd; 0xb5c0fbcfec4d3b2f; 0xe9b5dba58189dbbc;
  0x3956c25bf348b538; 0x59f111f1b605d019; 0x923f82a4af194f9b; 0xab1c5ed5da6d8118;
  0xd807aa98a3030242; 0x12835b0145706fbe; 0x243185be4ee4b28c; 0x550c7dc3d5ffb4e2;
  0x72be5d74f27b896f; 0x80deb1fe3b1696b1; 0x9bdc06a725c71235; 0xc19bf174cf692694;
  0xe49b69c19ef14ad2; 0xefbe4786384f25e3; 0x0fc19dc68b8cd5b5; 0x240ca1cc77ac9c65;
  0x2de92c6f592b0275; 0x4a7484aa6ea6e483; 0x5cb0a9dcbd41fbd4; 0x76f988da831153b5;
  0x983e5152ee66dfab; 0xa831c66d2db43210; 0xb00327c898fb213f; 0xbf597fc7beef0ee4;
  0xc6e00bf33da88fc2; 0xd5a79147930aa725; 0x06ca6351e003826f; 0x142929670a0e6e70;
  0x27b70a8546d22ffc; 0x2e1b21385c26c926; 0x4d2c6dfc5ac42aed; 0x53380d139d95b3df;
  0x650a73548baf63de; 0x766a0abb3c77b2a8; 0x81c2c92e47edaee6; 0x92722c851482353b;
  0xa2bfe8a14cf10364; 0xa81a664bbc423001; 0xc24b8b70d0f89791; 0xc76c51a30654be30;
  0xd192e819d6ef5218; 0xd69906245565a910; 0xf40e35855771202a; 0x106aa07032bbd1b8;
  0x19a4c116b8d2d0c8; 0x1e376c085141ab53; 0x2748774cdf8eeb99; 0x34b0bcb5e19b48a8;
  0x391c0cb3c5c95a63; 0x4ed8aa4ae3418acb; 0x5b9cca4f7763e373; 0x682e6ff3d6b2b8a3;
  0x748f82ee5defb2fc; 0x78a5636f43172f60; 0x84c87814a1f0ab72; 0x8cc702081a6439ec;
  0x90befffa23631e28; 0xa4506cebde82bde9; 0xbef9a3f7b2c67915; 0xc67178f2e372532b;
  0xca273eceea26619c; 0xd186b8c721c0c207; 0xeada7dd6cde0eb1e; 0xf57d4f7fee6ed178;
  0x06f067aa72176fba; 0x0a637dc5a2c898a6; 0x113f9804bef90dae; 0x1b710b35131c471b;
  0x28db77f523047d84; 0x32caab7b40c72493; 0x3c9ebe0a15c9bebc; 0x431d67c49c100d4c;
  0x4cc5d4becb3e42b6; 0x597f299cfc657e2a; 0x5fcb6fab3ad6faec; 0x6c44198c4a475817
].

(* Section 5.3.5: H(0) for SHA-512 (square roots of the first 8 primes). *)
op H0_512 : W64.t list = map W64.of_int [
  0x6a09e667f3bcc908; 0xbb67ae8584caa73b; 0x3c6ef372fe94f82b; 0xa54ff53a5f1d36f1;
  0x510e527fade682d1; 0x9b05688c2b3e6c1f; 0x1f83d9abfb41bd6b; 0x5be0cd19137e2179
].

(* Section 5.3.4: H(0) for SHA-384 (square roots of the 9th to 16th primes). *)
op H0_384 : W64.t list = map W64.of_int [
  0xcbbb9d5dc1059ed8; 0x629a292a367cd507; 0x9159015a3070dd17; 0x152fecd8f70e5939;
  0x67332667ffc00b31; 0x8eb44a8768581511; 0xdb0c2e0d64f98fa7; 0x47b5481dbefa4fa4
].

(* Section 5.3.6.1: H(0) for SHA-512/224, from the SHA-512/t IV generation
   function of section 5.3.6 with t = 224. *)
op H0_512_224 : W64.t list = map W64.of_int [
  0x8c3d37c819544da2; 0x73e1996689dcd4d6; 0x1dfab7ae32ff9c82; 0x679dd514582f9fcf;
  0x0f6d2b697bd44da8; 0x77e36f7304c48942; 0x3f9d85a86a1d36c8; 0x1112e6ad91d692a1
].

(* Section 5.3.6.2: H(0) for SHA-512/256 (t = 256). *)
op H0_512_256 : W64.t list = map W64.of_int [
  0x22312194fc2bf72c; 0x9f555fa3c84c64c2; 0x2393b86b6f53b151; 0x963877195940eabd;
  0x96283ee2a88effe3; 0xbe5e1e2553863992; 0x2b0199fc2c85b8aa; 0x0eb72ddc81c52ca2
].

(* Section 5.1.2: append the bit 1, then k zero bits with
   l + 1 + k = 896 (mod 1024), then l as a 128-bit big-endian integer; at
   byte granularity, 0x80 followed by (111 - |M|) mod 128 zero bytes. *)
op pad (m : bytes) : bytes =
  m ++ [W8.of_int 0x80] ++ zeros ((111 - size m) %% 128) ++ be_bytes 16 (8 * size m).

(* Section 5.2.2: the padded message as N blocks of sixteen 64-bit words. *)
op parse (p : bytes) : W64.t list list = map (fun b => map be64 (chunk 8 b)) (chunk 128 p).

type state = W64.t * W64.t * W64.t * W64.t * W64.t * W64.t * W64.t * W64.t.

op to_state (h : W64.t list) : state =
  (nth W64.zero h 0, nth W64.zero h 1, nth W64.zero h 2, nth W64.zero h 3,
   nth W64.zero h 4, nth W64.zero h 5, nth W64.zero h 6, nth W64.zero h 7).

op of_state (s : state) : W64.t list =
  let (a, b, c, d, e, f, g, h) = s in [a; b; c; d; e; f; g; h].

(* Section 6.4.2, step 1: the message schedule W_0 ... W_79. *)
op schedule (m : W64.t list) : W64.t list =
  foldl (fun (w : W64.t list) t =>
           rcons w (ssig1 (nth W64.zero w (t - 2)) + nth W64.zero w (t - 7)
                  + ssig0 (nth W64.zero w (t - 15)) + nth W64.zero w (t - 16)))
        m (range 16 80).

(* Section 6.4.2, step 3: round t on the working variables a ... h. *)
op round (w : W64.t list) (s : state) (t : int) : state =
  let (a, b, c, d, e, f, g, h) = s in
  let t1 = h + bsig1 e + ch e f g + nth W64.zero K512 t + nth W64.zero w t in
  let t2 = bsig0 a + maj a b c in
  (t1 + t2, a, b, c, d + t1, e, f, g).

(* Section 6.4.2, steps 1 to 4. *)
op compress (hv : W64.t list) (m : W64.t list) : W64.t list =
  let w = schedule m in
  let s = foldl (round w) (to_state hv) (range 0 80) in
  map (fun (xy : W64.t * W64.t) => xy.`1 + xy.`2) (zip (of_state s) hv).

(* Section 6.4.2: H(N) from H(0). *)
op hash (h0 : W64.t list) (m : bytes) : W64.t list = foldl compress h0 (parse (pad m)).

op digest (h0 : W64.t list) (m : bytes) : bytes = flatten (map w64_be (hash h0 m)).

(* Section 6.4: the 512-bit digest. *)
op sha512 (m : bytes) : bytes = digest H0_512 m.

(* Sections 6.5 to 6.7: the same computation from another H(0), truncated
   to the leftmost 384, 224 or 256 bits. *)
op sha384     (m : bytes) : bytes = take 48 (digest H0_384 m).
op sha512_224 (m : bytes) : bytes = take 28 (digest H0_512_224 m).
op sha512_256 (m : bytes) : bytes = take 32 (digest H0_512_256 m).

end SHA512.
