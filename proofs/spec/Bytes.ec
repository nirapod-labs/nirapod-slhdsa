(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bytes.ec
 * ========
 *
 * Byte strings and the notation of FIPS 205 section 2.3, shared by the
 * hash-function and SLH-DSA specifications.
 *
 * A byte is a Jasmin 8-bit word; a byte string is a list of bytes. FIPS 205
 * defines a byte as an element of {0, ..., 255}; W8.to_uint and W8.of_int
 * are the two directions of that identification, and every conversion in the
 * specifications goes through them explicitly.
 *
 * Loops of the standards are written as folds over integer ranges. A range
 * is built from the axiomatised List.Iota and does not reduce by itself; to
 * evaluate a specification on concrete inputs, rewrite it to the Jasmin
 * library's iotared, whose unfolding the simplifier performs.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.

type byte  = W8.t.
type bytes = W8.t list.

(* X[i:j] (FIPS 205 section 2.3): the bytes of X at positions i to j - 1. *)
op slice (x : bytes) (i j : int) : bytes = take (j - i) (drop i x).

(* Trunc_l(X) (FIPS 205 section 2.3): the leftmost l bytes of X. *)
op trunc (l : int) (x : bytes) : bytes = take l x.

(* Ceiling of x / y for x >= 0 and y > 0, computed without rational
   arithmetic as FIPS 205 section 3.1 prescribes. *)
op cdiv (x y : int) : int = (x + y - 1) %/ y.

(* A zero byte string of length l. *)
op zeros (l : int) : bytes = nseq l W8.zero.

(* ------------------------------------------------------------------ *)
(* Basic facts                                                        *)

lemma size_slice (x : bytes) i j :
  0 <= i <= j <= size x => size (slice x i j) = j - i.
proof. move=> [#] ge0_i le_ij le_jx; rewrite /slice size_take 1:/# size_drop //#. qed.

lemma slice_cat_l (x y : bytes) i j :
  0 <= i <= j <= size x => slice (x ++ y) i j = slice x i j.
proof.
move=> [#] ge0_i le_ij le_jx; rewrite /slice drop_cat.
case: (i < size x) => [lt_ix|ge_ix]; last first.
+ have ->: j = i by smt().
  by rewrite !take0.
rewrite take_cat size_drop //.
case: (j - i < max 0 (size x - i)) => // ge.
have ->: j - i - max 0 (size x - i) = 0 by smt().
rewrite take0 cats0 (_: j - i = size (drop i x)) 2:take_size //.
by rewrite size_drop //#.
qed.

lemma slice_cat_r (x y : bytes) i j :
  size x <= i => slice (x ++ y) i j = slice y (i - size x) (j - size x).
proof. by move=> le_xi; rewrite /slice drop_cat ifF 1:/# /#. qed.

lemma slice_whole (x : bytes) : slice x 0 (size x) = x.
proof. by rewrite /slice drop0 /= take_size. qed.

lemma size_trunc l (x : bytes) : 0 <= l <= size x => size (trunc l x) = l.
proof. by move=> ?; rewrite /trunc size_take //#. qed.

lemma size_zeros l : size (zeros l) = max 0 l.
proof. by rewrite /zeros size_nseq. qed.

(* cdiv is the ceiling of section 2.3: ceil(x / y) = -floor(-x / y). *)
lemma cdivE x y : 0 < y => cdiv x y = - ((- x) %/ y).
proof.
move=> gt0_y; rewrite /cdiv.
have -> : x + y - 1 = (x - 1) + 1 * y by ring.
rewrite divzMDr 1:/#.
smt(divz_eq modz_ge0 ltz_pmod).
qed.

(* ------------------------------------------------------------------ *)
(* Big-endian integer encodings                                       *)

(* The k-byte big-endian encoding of x mod 256^k: the convention of FIPS 180-4
   section 3.1 for words and length fields, of FIPS 205 section 4.4 for
   integers, and of RFC 8017 I2OSP when x < 256^k. *)
op be_bytes (k x : int) : bytes =
  mkseq (fun i => W8.of_int (x %/ 256 ^ (k - 1 - i))) k.

(* The integer whose big-endian encoding is b. *)
op be_int (b : bytes) : int = foldl (fun acc (c : byte) => 256 * acc + W8.to_uint c) 0 b.

lemma size_be_bytes k x : size (be_bytes k x) = max 0 k.
proof. by rewrite /be_bytes size_mkseq. qed.

(* ------------------------------------------------------------------ *)
(* Loops                                                              *)

(* A while loop whose body runs at most `fuel` times: each of the `fuel`
   steps applies `body` if `cond` holds and is the identity otherwise. Once
   `cond` fails it stays failed (the state no longer changes), so whenever
   `cond` fails within `fuel` steps the result is exactly that of the
   unbounded while loop. Every use in the specifications states its fuel
   and the reason it suffices. *)
op bounded_while ['a] (fuel : int) (cond : 'a -> bool) (body : 'a -> 'a) (s : 'a) : 'a =
  foldl (fun (st : 'a) (_ : int) => if cond st then body st else st) s (range 0 fuel).
