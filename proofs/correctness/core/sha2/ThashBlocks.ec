(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ThashBlocks.ec
 * ==============
 *
 * Multi-block facts about the SHA-2 specification, for the SHA2 T_l of
 * FIPS 205 section 11.2, whose input after the seed block is longer than
 * one block.
 *
 * The seed block b1 is compressed once (ctx); the rest of the padded
 * message is the byte string
 *
 *     pad_tail256 64 r = r || 0x80 || zeros || L      (SHA-256, b = 64)
 *     pad_tail512 128 r = the same with 128-byte blocks and a 16-byte L
 *
 * with the zero count of FIPS 180-4 section 5.1.1 (5.1.2) for the whole
 * message b1 || r, and L its bit length. The hash is the fold of the
 * compression over the blocks of that string, started from the chaining
 * value after b1 (sha256_hash_seeded, sha512_hash_seeded). An
 * implementation that compresses the string block by block extends the
 * fold one block at a time (parse256_take_step, parse512_take_step).
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord.
require import Bytes FIPS180_SHA2 FIPS180_SHA2_Blocks.

(* ------------------------------------------------------------------ *)
(* SHA-256                                                            *)

op pad_tail256 (off : int) (r : bytes) : bytes =
  r ++ [W8.of_int 0x80] ++ zeros ((55 - size r) %% 64) ++ be_bytes 8 (8 * (off + size r)).

lemma size_pad_tail256 off r :
  size (pad_tail256 off r) = size r + 9 + (55 - size r) %% 64.
proof. by rewrite /pad_tail256 !size_cat size_zeros size_be_bytes /=; smt(modz_ge0). qed.

(* Byte j of the padded tail, for a bit length below 2^16 (every T_l and
   T_k input of FIPS 205): the length field is six zero bytes and two
   bytes of the bit length. *)
lemma nth_pad_tail256 (r : bytes) (j : int) :
  8 * (64 + size r) < 65536 => 0 <= j < size (pad_tail256 64 r) =>
  nth W8.zero (pad_tail256 64 r) j =
    if j < size r then nth W8.zero r j
    else if j = size r then W8.of_int 128
    else if j < size (pad_tail256 64 r) - 2 then W8.zero
    else if j = size (pad_tail256 64 r) - 2 then W8.of_int (8 * (64 + size r) %/ 256)
    else W8.of_int (8 * (64 + size r)).
proof.
rewrite size_pad_tail256 => hb hj; rewrite /pad_tail256.
have hz : 0 <= (55 - size r) %% 64 < 64 by smt(modz_ge0 ltz_pmod).
have hs : size (r ++ [W8.of_int 128] ++ zeros ((55 - size r) %% 64))
          = size r + 1 + (55 - size r) %% 64.
+ by rewrite !size_cat size_zeros /#.
rewrite nth_cat hs; case: (j < size r + 1 + (55 - size r) %% 64) => h3.
+ rewrite nth_cat size_cat /=; case: (j < size r + 1) => h2.
  + rewrite nth_cat; case: (j < size r) => // h1.
    have -> : j - size r = 0 by smt().
    by rewrite /= ifT 1:/#.
  by rewrite /zeros nth_nseq 1:/# ifF 1:/# ifF 1:/# ifT 1:/#.
rewrite ifF 1:/# ifF 1:/# /be_bytes nth_mkseq 1:/# /=.
have hb' : 0 <= 8 * (64 + size r) < 65536 by smt(size_ge0).
case: (j < size r + 9 + (55 - size r) %% 64 - 2) => h4.
+ have hk : 1 <= 256 ^ (size r + 9 + (55 - size r) %% 64 - 3 - j) by smt(expr_gt0).
  rewrite (_ : 8 - 1 - (j - (size r + 1 + (55 - size r) %% 64))
             = 2 + (size r + 9 + (55 - size r) %% 64 - 3 - j)) 1:/#.
  rewrite exprD_nneg 1,2:/# expr2 /= divz_small //.
  by rewrite ger0_norm; smt().
case: (j = size r + 9 + (55 - size r) %% 64 - 2) => [hj2 | h5].
+ by rewrite hj2 /= (_ : 8 - 1 - (size r + 9 + (55 - size r) %% 64 - 2 - (size r + 1 + (55 - size r) %% 64)) = 1) 1:/# expr1.
by rewrite (_ : 8 - 1 - (j - (size r + 1 + (55 - size r) %% 64)) = 0) 1:/# expr0 divz1.
qed.

lemma sha256_hash_seeded (h0 : W32.t list) (b1 r : bytes) :
  size b1 = 64 =>
  SHA256.hash h0 (b1 ++ r)
  = foldl SHA256.compress (SHA256.compress h0 (words256 b1)) (SHA256.parse (pad_tail256 64 r)).
proof.
move=> hb; rewrite /SHA256.hash /SHA256.pad size_cat hb.
have -> : (55 - (64 + size r)) %% 64 = (55 - size r) %% 64.
+ by rewrite (_: 55 - (64 + size r) = (55 - size r) + (-1) * 64) 1:/# modzMDr.
have -> : b1 ++ r ++ [W8.of_int 0x80] ++ zeros ((55 - size r) %% 64) ++ be_bytes 8 (8 * (64 + size r))
        = b1 ++ pad_tail256 64 r by rewrite /pad_tail256 !catA.
rewrite /SHA256.parse chunk_cat; first by rewrite hb.
have hb0 : b1 <> [] by smt(size_eq0).
by rewrite -{1}hb (chunk_exact b1 hb0) /= /words256.
qed.

lemma sha256_seeded (b1 r : bytes) :
  size b1 = 64 =>
  SHA256.sha256 (b1 ++ r)
  = flatten (map w32_be (foldl SHA256.compress (SHA256.compress SHA256.H0_256 (words256 b1))
                                (SHA256.parse (pad_tail256 64 r)))).
proof. by move=> hb; rewrite /SHA256.sha256 sha256_hash_seeded. qed.

lemma parse256_take_step (l : bytes) (o : int) :
  0 <= o => 64 %| o => o + 64 <= size l =>
  SHA256.parse (take (o + 64) l)
  = SHA256.parse (take o l) ++ [words256 (take 64 (drop o l))].
proof.
move=> h0 hd hl.
have hs : size (take o l) = o by rewrite size_take //; smt().
have -> : take (o + 64) l = take o l ++ take 64 (drop o l).
+ by rewrite -{1}(cat_take_drop o l) take_cat hs ifF 1:/# (_ : o + 64 - o = 64) 1:/#.
have hx : size (take 64 (drop o l)) = 64 by rewrite size_take // size_drop //; smt().
have hx0 : take 64 (drop o l) <> [] by smt(size_eq0).
rewrite /SHA256.parse chunk_cat; first by rewrite hs.
have := chunk_exact (take 64 (drop o l)) hx0; rewrite hx => -> /=.
by rewrite map_cat /words256.
qed.

(* ------------------------------------------------------------------ *)
(* SHA-512                                                            *)

op pad_tail512 (off : int) (r : bytes) : bytes =
  r ++ [W8.of_int 0x80] ++ zeros ((111 - size r) %% 128) ++ be_bytes 16 (8 * (off + size r)).

lemma size_pad_tail512 off r :
  size (pad_tail512 off r) = size r + 17 + (111 - size r) %% 128.
proof. by rewrite /pad_tail512 !size_cat size_zeros size_be_bytes /=; smt(modz_ge0). qed.

lemma nth_pad_tail512 (r : bytes) (j : int) :
  8 * (128 + size r) < 65536 => 0 <= j < size (pad_tail512 128 r) =>
  nth W8.zero (pad_tail512 128 r) j =
    if j < size r then nth W8.zero r j
    else if j = size r then W8.of_int 128
    else if j < size (pad_tail512 128 r) - 2 then W8.zero
    else if j = size (pad_tail512 128 r) - 2 then W8.of_int (8 * (128 + size r) %/ 256)
    else W8.of_int (8 * (128 + size r)).
proof.
rewrite size_pad_tail512 => hb hj; rewrite /pad_tail512.
have hz : 0 <= (111 - size r) %% 128 < 128 by smt(modz_ge0 ltz_pmod).
have hs : size (r ++ [W8.of_int 128] ++ zeros ((111 - size r) %% 128))
          = size r + 1 + (111 - size r) %% 128.
+ by rewrite !size_cat size_zeros /#.
rewrite nth_cat hs; case: (j < size r + 1 + (111 - size r) %% 128) => h3.
+ rewrite nth_cat size_cat /=; case: (j < size r + 1) => h2.
  + rewrite nth_cat; case: (j < size r) => // h1.
    have -> : j - size r = 0 by smt().
    by rewrite /= ifT 1:/#.
  by rewrite /zeros nth_nseq 1:/# ifF 1:/# ifF 1:/# ifT 1:/#.
rewrite ifF 1:/# ifF 1:/# /be_bytes nth_mkseq 1:/# /=.
have hb' : 0 <= 8 * (128 + size r) < 65536 by smt(size_ge0).
case: (j < size r + 17 + (111 - size r) %% 128 - 2) => h4.
+ have hk : 1 <= 256 ^ (size r + 17 + (111 - size r) %% 128 - 3 - j) by smt(expr_gt0).
  rewrite (_ : 16 - 1 - (j - (size r + 1 + (111 - size r) %% 128))
             = 2 + (size r + 17 + (111 - size r) %% 128 - 3 - j)) 1:/#.
  rewrite exprD_nneg 1,2:/# expr2 /= divz_small //.
  by rewrite ger0_norm; smt().
case: (j = size r + 17 + (111 - size r) %% 128 - 2) => [hj2 | h5].
+ by rewrite hj2 /= (_ : 16 - 1 - (size r + 17 + (111 - size r) %% 128 - 2 - (size r + 1 + (111 - size r) %% 128)) = 1) 1:/# expr1.
by rewrite (_ : 16 - 1 - (j - (size r + 1 + (111 - size r) %% 128)) = 0) 1:/# expr0 divz1.
qed.

lemma sha512_hash_seeded (h0 : W64.t list) (b1 r : bytes) :
  size b1 = 128 =>
  SHA512.hash h0 (b1 ++ r)
  = foldl SHA512.compress (SHA512.compress h0 (words512 b1)) (SHA512.parse (pad_tail512 128 r)).
proof.
move=> hb; rewrite /SHA512.hash /SHA512.pad size_cat hb.
have -> : (111 - (128 + size r)) %% 128 = (111 - size r) %% 128.
+ by rewrite (_: 111 - (128 + size r) = (111 - size r) + (-1) * 128) 1:/# modzMDr.
have -> : b1 ++ r ++ [W8.of_int 0x80] ++ zeros ((111 - size r) %% 128) ++ be_bytes 16 (8 * (128 + size r))
        = b1 ++ pad_tail512 128 r by rewrite /pad_tail512 !catA.
rewrite /SHA512.parse chunk_cat; first by rewrite hb.
have hb0 : b1 <> [] by smt(size_eq0).
by rewrite -{1}hb (chunk_exact b1 hb0) /= /words512.
qed.

lemma sha512_seeded (b1 r : bytes) :
  size b1 = 128 =>
  SHA512.sha512 (b1 ++ r)
  = flatten (map w64_be (foldl SHA512.compress (SHA512.compress SHA512.H0_512 (words512 b1))
                                (SHA512.parse (pad_tail512 128 r)))).
proof. by move=> hb; rewrite /SHA512.sha512 /SHA512.digest sha512_hash_seeded. qed.

lemma parse512_take_step (l : bytes) (o : int) :
  0 <= o => 128 %| o => o + 128 <= size l =>
  SHA512.parse (take (o + 128) l)
  = SHA512.parse (take o l) ++ [words512 (take 128 (drop o l))].
proof.
move=> h0 hd hl.
have hs : size (take o l) = o by rewrite size_take //; smt().
have -> : take (o + 128) l = take o l ++ take 128 (drop o l).
+ by rewrite -{1}(cat_take_drop o l) take_cat hs ifF 1:/# (_ : o + 128 - o = 128) 1:/#.
have hx : size (take 128 (drop o l)) = 128 by rewrite size_take // size_drop //; smt().
have hx0 : take 128 (drop o l) <> [] by smt(size_eq0).
rewrite /SHA512.parse chunk_cat; first by rewrite hs.
have := chunk_exact (take 128 (drop o l)) hx0; rewrite hx => -> /=.
by rewrite map_cat /words512.
qed.
