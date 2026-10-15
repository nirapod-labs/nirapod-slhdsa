(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * SHA512_Blocks.ec
 * ================
 *
 * Functional correctness of the memory entry points of the portable
 * SHA-512 compression kernel (src/hash/sha2/sha512_compress.jinc):
 * _sha512_compress_one compresses the 128 bytes at p, and
 * _sha512_compress_blocks the n consecutive 128-byte blocks at p, against
 * FIPS 180-4 section 6.4.2 (spec/hash/FIPS180_SHA2.ec).
 *
 * Memory is viewed through memread of crypto-specs JWordList: the byte
 * list mem.[a], ..., mem.[a + len - 1]. One block must lie at or below 2^64
 * (to_uint p + 128 <= 2^64); n blocks must end below it
 * (to_uint p + 128 n < 2^64), because the kernel advances p past the last
 * block. Either way the address arithmetic of the kernel does not wrap.
 *
 * Theorems:
 *     sha512_compress_one_total     _sha512_compress_one computes compress
 *                                   on the big-endian words of the block
 *                                   at p;
 *     sha512_compress_blocks_total  _sha512_compress_blocks folds compress
 *                                   over the n blocks at p, which is the
 *                                   parse of section 5.2.2 of those bytes.
 *
 * Both are total correctness (phoare ... = 1%r).
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils JMemory.
require import BArray64 BArray128.
require import HashExtracted ArchWord.
require import Bytes FIPS180_SHA2 SHA512_Compress.
require JWordList.
import SHA512.

abbrev memread = JWordList.memread.

(* ------------------------------------------------------------------ *)
(* Memory as bytes                                                    *)

lemma size_memread mem a l : 0 <= l => size (memread mem a l) = l.
proof. exact JWordList.size_memread. qed.

lemma memread_add mem a x y : 0 <= x => 0 <= y =>
  memread mem a (x + y) = memread mem a x ++ memread mem (a + x) y.
proof. exact JWordList.memread_add. qed.

(* The big-endian word at a, as the kernel reads it: a little-endian load
   followed by a byte reversal. *)
lemma bswap_load32 mem a :
  WordSpec.bswap64 (loadW64 mem a) = be64 (memread mem a 8).
proof.
rewrite /WordSpec.bswap64 /be64; do 3!congr.
apply (eq_from_nth (W8.of_int 0)); first by rewrite W8u8.size_to_list size_memread.
move=> j; rewrite W8u8.size_to_list => hj.
rewrite W8u8.nth_to_list /JWordList.memread nth_mkseq //=.
by rewrite loadW64_bits8.
qed.

lemma memread_word mem a k : 0 <= k < 16 =>
  take 8 (drop (8 * k) (memread mem a 128)) = memread mem (a + 8 * k) 8.
proof.
move=> hk; rewrite /JWordList.memread drop_mkseq 1:/# take_mkseq 1:/#.
by apply eq_mkseq => x /=; rewrite addzA.
qed.

(* One more block of memory adds one block to the parse. *)
lemma parse_memreadS mem a k : 0 <= k =>
  parse (memread mem a (128 * (k + 1)))
  = rcons (parse (memread mem a (128 * k))) (map be64 (chunk 8 (memread mem (a + 128 * k) 128))).
proof.
move=> hk; rewrite /parse (_ : 128 * (k + 1) = 128 * k + 128) 1:/#.
rewrite memread_add 1,2:/# chunk_cat; first by rewrite size_memread 1:/# dvdz_mulr.
have hne : memread mem (a + 128 * k) 128 <> [] by rewrite -size_eq0 size_memread.
have := chunk_exact (memread mem (a + 128 * k) 128) hne.
rewrite size_memread // => ->.
by rewrite map_cat /= cats1.
qed.

lemma parse_memread0 mem a : parse (memread mem a 0) = [].
proof. by rewrite /parse JWordList.memread0 /chunk /= mkseq0. qed.

(* ------------------------------------------------------------------ *)
(* One block from memory                                              *)

lemma sha512_compress_one_correct (h0 : W64.t list) (p0 : W64.t) :
  hoare [M._sha512_compress_one :
           hwords h = h0 /\ p = p0 /\ W64.to_uint p0 + 128 <= W64.modulus ==>
           hwords res.`1 = compress h0 (map be64 (chunk 8 (memread Glob.mem (W64.to_uint p0) 128)))].
proof.
proc.
ecall (sha512_rounds_correct h0 (map be64 (chunk 8 (memread Glob.mem (W64.to_uint p0) 128)))).
while (0 <= i <= 16 /\ hwords h = h0 /\ p = p0 /\ W64.to_uint p0 + 128 <= W64.modulus /\
       forall k, 0 <= k < i =>
         BArray128.get64 w k = be64 (memread Glob.mem (W64.to_uint p0 + 8 * k) 8)).
+ wp; ecall (bswap64_spec x); auto => /> &hr hi0 hi16 hb hk hlt; split; first smt().
  move=> k hk1 hk2; rewrite BArray128.get_set64E 1,2:/#.
  case: (i{hr} = k) => [<-|ne]; last by apply hk => /#.
  rewrite bswap_load32; congr; congr.
  rewrite W64.to_uintD_small W64.of_uintK; smt(W64.to_uint_cmp pmod_small).
auto => &hr [hh [<- hb]] /=; split; first by rewrite hh hb /=; smt().
move=> i w hlt [#] hi0 hi16 _ _ hk; split; first by [].
apply (eq_from_nth W64.zero).
+ by rewrite /mwords size_map size_iota size_map size_chunk // size_memread.
move=> k; rewrite /mwords size_map size_iota => hk'.
rewrite (nth_map 0) 1:size_iota 1:/# nth_iota 1:/# (nth_map []).
+ by rewrite size_chunk // size_memread /#.
have hc : 0 <= k < size (memread Glob.mem{hr} (W64.to_uint p{hr}) 128) %/ 8.
+ by rewrite size_memread /#.
by rewrite /= (nth_chunk8 _ _ hc) memread_word 1:/# -(hk k) /#.
qed.

lemma sha512_compress_one_ll : islossless M._sha512_compress_one.
proof.
proc; call sha512_rounds_ll; inline *.
while (0 <= i <= 16) (16 - i); first by auto => /#.
by auto => /#.
qed.

lemma sha512_compress_one_total (h0 : W64.t list) (p0 : W64.t) :
  phoare [M._sha512_compress_one :
           hwords h = h0 /\ p = p0 /\ W64.to_uint p0 + 128 <= W64.modulus ==>
           hwords res.`1 = compress h0 (map be64 (chunk 8 (memread Glob.mem (W64.to_uint p0) 128)))]
  = 1%r.
proof. by conseq sha512_compress_one_ll (sha512_compress_one_correct h0 p0). qed.

(* ------------------------------------------------------------------ *)
(* n blocks from memory                                               *)

lemma sha512_compress_blocks_total (h0 : W64.t list) (p0 n0 : W64.t) :
  phoare [M._sha512_compress_blocks :
           hwords h = h0 /\ p = p0 /\ n = n0 /\
           W64.to_uint p0 + 128 * W64.to_uint n0 < W64.modulus ==>
           hwords res.`1
           = foldl compress h0 (parse (memread Glob.mem (W64.to_uint p0) (128 * W64.to_uint n0)))]
  = 1%r.
proof.
proc; sp; wp.
while (0 <= W64.to_uint n <= W64.to_uint n0 /\ more = (n <> W64.zero) /\
       W64.to_uint p = W64.to_uint p0 + 128 * (W64.to_uint n0 - W64.to_uint n) /\
       W64.to_uint p0 + 128 * W64.to_uint n0 < W64.modulus /\
       hwords h = foldl compress h0
         (parse (memread Glob.mem (W64.to_uint p0) (128 * (W64.to_uint n0 - W64.to_uint n)))))
      (W64.to_uint n).
+ move=> z; wp.
  ecall (sha512_compress_one_total (hwords h) p).
  auto => /> &hr hn0 hnn hp hb hh hne.
  have hn1 : 1 <= W64.to_uint n{hr}.
  + case: (W64.to_uint n{hr} = 0) => h1; last smt().
    by move: hne; rewrite W64.to_uint_eq h1.
  split; first smt().
  move=> _ [h' ms'] /= hh'.
  rewrite /Jslh.SLH64.protect_64 /=.
  have hsub : W64.to_uint (n{hr} - W64.one) = W64.to_uint n{hr} - 1.
  + by rewrite W64.to_uintB 1:W64.uleE /= 1:/#.
  have hadd : W64.to_uint (p{hr} + W64.of_int 128) = W64.to_uint p{hr} + 128.
  + by rewrite W64.to_uintD_small /= /#.
  rewrite hsub hadd hh'; do! split; 1..3: smt().
  + rewrite (_ : W64.to_uint n0 - (W64.to_uint n{hr} - 1)
               = (W64.to_uint n0 - W64.to_uint n{hr}) + 1) 1:/#.
    by rewrite parse_memreadS 1:/# foldl_rcons hh hp.
  smt().
auto => &hr [#] -> hh -> -> hb; split.
+ have -> : 128 * (W64.to_uint n0 - W64.to_uint n0) = 0 by ring.
  by rewrite parse_memread0 /= hh; smt(W64.to_uint_cmp).
move=> h1 more0 n1 p1; split.
+ move=> [#] hn0 _ -> _ _ _ hle; rewrite negbK W64.to_uint_eq /=; smt().
move=> hm [#] _ _ hmore _ _ hh1.
have hn : W64.to_uint n1 = 0 by move: hm; rewrite hmore negbK => ->.
by rewrite hh1 hn.
qed.
