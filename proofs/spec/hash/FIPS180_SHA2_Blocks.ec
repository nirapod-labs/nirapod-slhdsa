(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS180_SHA2_Blocks.ec
 * ======================
 *
 * Block-level facts about the SHA-2 specification of FIPS180_SHA2, for
 * implementations that hash a message as one fixed first block followed by
 * a short tail.
 *
 * FIPS 205 section 11.2 hashes PK.seed || toByte(0, b - n) || ADRSc || M
 * with SHA-256 (b = 64) or SHA-512 (b = 128). The first b bytes are the
 * same for every call with one key, so an implementation may compress them
 * once and keep the chaining value; when the rest fits with the padding
 * into one more block, the hash is two compressions. The lemmas below state
 * exactly that, with the length field counting the first block:
 *
 *     sha256 (b1 ++ r) = digest of compress (compress H0 b1) (r || pad)
 *         for |b1| = 64 and |r| <= 55            (sha256_two_blocks)
 *     sha512 (b1 ++ r) = the same with 128-byte blocks, |r| <= 111
 *                                                (sha512_two_blocks)
 *
 * where the tail block is r || 0x80 || zeros || L and L is the bit length
 * of b1 ++ r (section 5.1). They are properties of the specification, not
 * new definitions; implementation proofs use them to connect a kernel run
 * to the FIPS 205 functions.
 *)

require import AllCore List IntDiv.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord.
require import Bytes FIPS180_SHA2.

(* ------------------------------------------------------------------ *)
(* SHA-256                                                            *)

(* The sixteen big-endian words of a 64-byte block (section 5.2.1). *)
op words256 (b : bytes) : W32.t list = map be32 (chunk 4 b).

(* The final block after `off` bytes, of which r are pending, |r| <= 55. *)
op tail_block256 (off : int) (r : bytes) : bytes =
  r ++ [W8.of_int 0x80] ++ zeros (55 - size r) ++ be_bytes 8 (8 * (off + size r)).

lemma size_tail_block256 off r : size r <= 55 => size (tail_block256 off r) = 64.
proof.
move=> hr; rewrite /tail_block256 !size_cat size_zeros size_be_bytes /=.
by rewrite /max /#.
qed.

lemma sha256_hash_two_blocks (h0 : W32.t list) (b1 r : bytes) :
  size b1 = 64 => size r <= 55 =>
  SHA256.hash h0 (b1 ++ r)
  = SHA256.compress (SHA256.compress h0 (words256 b1)) (words256 (tail_block256 64 r)).
proof.
move=> hb hr; rewrite /SHA256.hash /SHA256.pad /SHA256.parse size_cat hb.
have -> : (55 - (64 + size r)) %% 64 = 55 - size r.
+ rewrite (_: 55 - (64 + size r) = (55 - size r) + (-1) * 64) 1:/# modzMDr.
  by rewrite pmod_small //; smt(size_ge0).
have -> : b1 ++ r ++ [W8.of_int 0x80] ++ zeros (55 - size r) ++ be_bytes 8 (8 * (64 + size r))
        = b1 ++ tail_block256 64 r.
+ by rewrite /tail_block256 !catA.
rewrite chunk_cat; first by rewrite hb.
have hb0 : b1 <> [] by smt(size_eq0).
have ht0 : tail_block256 64 r <> [] by smt(size_eq0 size_tail_block256).
rewrite -{1}hb (chunk_exact b1 hb0).
have := chunk_exact (tail_block256 64 r) ht0.
rewrite size_tail_block256 // => -> /=.
by rewrite /words256.
qed.

lemma sha256_two_blocks (b1 r : bytes) :
  size b1 = 64 => size r <= 55 =>
  SHA256.sha256 (b1 ++ r)
  = flatten (map w32_be (SHA256.compress (SHA256.compress SHA256.H0_256 (words256 b1))
                                         (words256 (tail_block256 64 r)))).
proof. by move=> hb hr; rewrite /SHA256.sha256 sha256_hash_two_blocks. qed.

(* ------------------------------------------------------------------ *)
(* SHA-512                                                            *)

(* The sixteen big-endian words of a 128-byte block (section 5.2.2). *)
op words512 (b : bytes) : W64.t list = map be64 (chunk 8 b).

(* The final block after `off` bytes, of which r are pending, |r| <= 111. *)
op tail_block512 (off : int) (r : bytes) : bytes =
  r ++ [W8.of_int 0x80] ++ zeros (111 - size r) ++ be_bytes 16 (8 * (off + size r)).

lemma size_tail_block512 off r : size r <= 111 => size (tail_block512 off r) = 128.
proof.
move=> hr; rewrite /tail_block512 !size_cat size_zeros size_be_bytes /=.
by rewrite /max /#.
qed.

lemma sha512_hash_two_blocks (h0 : W64.t list) (b1 r : bytes) :
  size b1 = 128 => size r <= 111 =>
  SHA512.hash h0 (b1 ++ r)
  = SHA512.compress (SHA512.compress h0 (words512 b1)) (words512 (tail_block512 128 r)).
proof.
move=> hb hr; rewrite /SHA512.hash /SHA512.pad /SHA512.parse size_cat hb.
have -> : (111 - (128 + size r)) %% 128 = 111 - size r.
+ rewrite (_: 111 - (128 + size r) = (111 - size r) + (-1) * 128) 1:/# modzMDr.
  by rewrite pmod_small //; smt(size_ge0).
have -> : b1 ++ r ++ [W8.of_int 0x80] ++ zeros (111 - size r) ++ be_bytes 16 (8 * (128 + size r))
        = b1 ++ tail_block512 128 r.
+ by rewrite /tail_block512 !catA.
rewrite chunk_cat; first by rewrite hb.
have hb0 : b1 <> [] by smt(size_eq0).
have ht0 : tail_block512 128 r <> [] by smt(size_eq0 size_tail_block512).
rewrite -{1}hb (chunk_exact b1 hb0).
have := chunk_exact (tail_block512 128 r) ht0.
rewrite size_tail_block512 // => -> /=.
by rewrite /words512.
qed.

lemma sha512_two_blocks (b1 r : bytes) :
  size b1 = 128 => size r <= 111 =>
  SHA512.sha512 (b1 ++ r)
  = flatten (map w64_be (SHA512.compress (SHA512.compress SHA512.H0_512 (words512 b1))
                                         (words512 (tail_block512 128 r)))).
proof. by move=> hb hr; rewrite /SHA512.sha512 /SHA512.digest sha512_hash_two_blocks. qed.
