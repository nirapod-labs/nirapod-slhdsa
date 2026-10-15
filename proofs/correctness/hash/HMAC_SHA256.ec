(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * HMAC_SHA256.ec
 * ==============
 *
 * Functional correctness of the HMAC-SHA-256 steps of src/hash/sha2/
 * hmac.jinc over the portable SHA-256 kernel, against FIPS 198-1
 * (spec/hash/FIPS198_HMAC.ec).
 *
 * The code computes HMAC in three parts, for a key block K0 the caller
 * has already formed (K padded with zeros to 64 bytes):
 *
 *     __hmac_sha256_init      the chaining values after the blocks
 *                             K0 xor ipad and K0 xor opad
 *     (the caller absorbs the text into the inner stream)
 *     __hmac_sha256_finalize  the inner digest, then the outer hash of
 *                             (K0 xor opad) || inner digest
 *
 * Theorems (total correctness):
 *     hmac_sha256_init_total      the two chaining values, compress H0
 *                                 over K0 xor ipad and over K0 xor opad;
 *                                 the caller's inner stream, with
 *                                 total = 64 and an empty buffer, is
 *                                 then stream256 H0 (K0 xor ipad)
 *     hmac_sha256_finalize_total  the tag of the absorbed inner message
 *     hmac_sha256_blocks          for |K| <= 64 that tag is
 *                                 HMAC-SHA-256(K, text)
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils JMemory.
require import BArray32 BArray64.
require import HashExtracted ArchWord.
require import Bytes FIPS180_SHA2 FIPS180_SHA2_Blocks FIPS198_HMAC.
require import SHA256_Compress SHA256_Blocks SHA256_Stream.
import SHA256.

(* ------------------------------------------------------------------ *)
(* The key block FIPS 198-1 forms for a short key                     *)

lemma hmac_key_short (k : bytes) : size k <= 64 =>
  hmac_key sha256 64 k = k ++ zeros (64 - size k).
proof.
move=> hk; rewrite /hmac_key; case: (size k = 64) => h64.
+ by rewrite h64 /zeros nseq0 cats0.
by rewrite ifF 1:/#.
qed.

(* For a key of at most one block, HMAC is two hashes of the padded key
   blocks: the form the code computes. *)
lemma hmac_sha256_blocks (k text : bytes) : size k <= 64 =>
  hmac_sha256 k text
  = sha256 (xorb (k ++ zeros (64 - size k)) (opad 64)
            ++ sha256 (xorb (k ++ zeros (64 - size k)) (ipad 64) ++ text)).
proof. by move=> hk; rewrite /hmac_sha256 /hmac /= hmac_key_short. qed.

(* ------------------------------------------------------------------ *)
(* Byte views                                                         *)

lemma nth_xorb (x y : bytes) j : size x = size y => 0 <= j < size x =>
  nth W8.zero (xorb x y) j = nth W8.zero x j +^ nth W8.zero y j.
proof.
move=> hs hj; rewrite /xorb (nth_map (W8.zero, W8.zero)) 1:size_zip 1:/#.
by rewrite nth_zip.
qed.

lemma size_xorb (x y : bytes) : size x = size y => size (xorb x y) = size x.
proof. by move=> hs; rewrite /xorb size_map size_zip /#. qed.

(* The eight bytes of the kernel's pad words. *)
lemma mi_bits8 k : 0 <= k < 8 => W64.of_int 3906369333256140342 \bits8 k = W8.of_int 0x36.
proof.
move=> hk; rewrite W8u8.of_int_bits8_div //.
have : k = 0 \/ k = 1 \/ k = 2 \/ k = 3 \/ k = 4 \/ k = 5 \/ k = 6 \/ k = 7 by smt().
by move=> [|[|[|[|[|[|[|]]]]]]] ->; apply W8.to_uint_eq; rewrite !W8.of_uintK.
qed.

lemma mo_bits8 k : 0 <= k < 8 => W64.of_int 6655295901103053916 \bits8 k = W8.of_int 0x5c.
proof.
move=> hk; rewrite W8u8.of_int_bits8_div //.
have : k = 0 \/ k = 1 \/ k = 2 \/ k = 3 \/ k = 4 \/ k = 5 \/ k = 6 \/ k = 7 by smt().
by move=> [|[|[|[|[|[|[|]]]]]]] ->; apply W8.to_uint_eq; rewrite !W8.of_uintK.
qed.

(* A buffer whose bytes are those of the key xor a constant byte. *)
lemma xor_block (b k : BArray64.t) (c : W8.t) :
  (forall j, 0 <= j < 64 => b.[j] = k.[j] +^ c) =>
  BArray64.to_list b = xorb (BArray64.to_list k) (nseq 64 c).
proof.
move=> hb; apply (eq_from_nth W8.zero).
+ by rewrite size_xorb ?size_nseq !BArray64.size_to_list.
move=> j; rewrite BArray64.size_to_list => hj.
rewrite nth_xorb ?size_nseq ?BArray64.size_to_list // nth_nseq //.
by rewrite !BArray64.get_to_list hb.
qed.

(* ------------------------------------------------------------------ *)
(* The two padded key blocks                                          *)

lemma hmac_sha256_init_correct (K : BArray64.t) :
  hoare [M.__hmac_sha256_init :
           k0 = K ==>
           hwords res.`1 = compress H0_256 (words256 (xorb (BArray64.to_list K) (ipad 64))) /\
           hwords res.`2 = compress H0_256 (words256 (xorb (BArray64.to_list K) (opad 64)))].
proof.
proc.
ecall (sha256_compress_correct (hwords outer) opad); call sha256_init_correct.
ecall (sha256_compress_correct (hwords inner) ipad); call sha256_init_correct.
while (0 <= i <= 8 /\ k0 = K /\ mi = W64.of_int 3906369333256140342 /\
       mo = W64.of_int 6655295901103053916 /\
       forall j, 0 <= j < 8 * i =>
         ipad.[j] = K.[j] +^ W8.of_int 0x36 /\ opad.[j] = K.[j] +^ W8.of_int 0x5c).
+ auto => /> &hr hi0 hi8 hj hlt; split; first smt().
  move=> j hj0 hj1; rewrite !BArray64.get8_set64dE.
  case: (8 * i{hr} <= j) => hlo.
  + rewrite !ifT 1,2:/# !W8u8.xorb8E BArray64.get64d_byte 1:/# mi_bits8 1:/# mo_bits8 1:/#.
    by rewrite (_ : 8 * i{hr} + (j - 8 * i{hr}) = j) 1:/#.
  by rewrite !ifF 1,2:/#; apply hj => /#.
auto => />; split; first smt().
move=> i ipad1 opad1 hn hi0 hi8 hj h1 hh1 h2 hh2 h3 hh3 h4 hh4.
rewrite hh4 hh3 hh2 hh1 /words256 /ipad /opad; split; congr; congr; congr.
+ by apply xor_block => j hj'; have := hj j _; [smt() | move=> [-> _]].
by apply xor_block => j hj'; have := hj j _; [smt() | move=> [_ ->]].
qed.

(* ------------------------------------------------------------------ *)
(* The inner digest and the outer hash                                *)

lemma hmac_sha256_finalize_correct (ib ob text : bytes) : size ob = 64 =>
  hoare [M.__hmac_sha256_finalize :
           stream256 H0_256 (ib ++ text) inner buf total /\
           hwords outer = compress H0_256 (words256 ob) /\ size (ib ++ text) < 2^61 ==>
           BArray32.to_list res.`1 = sha256 (ob ++ sha256 (ib ++ text))].
proof.
move=> hob; proc.
ecall (sha256_finalize_correct H0_256 (ob ++ sha256 (ib ++ text))); wp.
while (0 <= i <= 4 /\ (forall j, 0 <= j < 8 * i => buf.[j] = digest.[j]) /\
       BArray32.to_list digest = sha256 (ib ++ text) /\
       hwords inner = compress H0_256 (words256 ob)).
+ auto => /> &hr hi0 hi4 hj hd hh hlt; split; first smt().
  move=> j hj0 hj1; rewrite BArray64.get8_set64dE.
  case: (8 * i{hr} <= j) => hlo.
  + by rewrite ifT 1:/# BArray32.get64d_byte 1:/#; congr; smt().
  by rewrite ifF 1:/#; apply hj => /#.
wp; while (0 <= i <= 8 /\
           (forall k, 0 <= k < i => BArray32.get32 inner k = BArray32.get32 outer k) /\
           hwords outer = compress H0_256 (words256 ob) /\
           BArray32.to_list digest = sha256 (ib ++ text)).
+ auto => /> &hr hi0 hi8 hk ho hd hlt; split; first smt().
  move=> k hk0 hk1; rewrite BArray32.get_set32E 1,2:/#.
  by case: (i{hr} = k) => [<-|ne] //; apply hk => /#.
wp; ecall (sha256_finalize_correct H0_256 (ib ++ text)).
auto => /> &hr _ _ _ ho hm [d1 inner1 buf1 ms1] /= _; split; first smt().
move=> i2 inner2 hn hi0 hi8 hk hd; split.
+ split; first smt().
  rewrite -ho /hwords; apply eq_in_map => k /mem_iota hk'; apply hk => /#.
move=> buf2 i3 hn' hi0' hi4 hj hh2.
have hsd : size (sha256 (ib ++ text)) = 32 by rewrite -hd BArray32.size_to_list.
have htl : tail256 ob = [] by rewrite -size_eq0 size_tail256 hob.
have hpd : parse (ob ++ sha256 (ib ++ text)) = [words256 ob].
+ by rewrite parse_cat htl /= (parse_short (sha256 (ib ++ text))) 1:/# cats0 (parse_block ob hob).
have htd : tail256 (ob ++ sha256 (ib ++ text)) = sha256 (ib ++ text).
+ by rewrite tail_cat htl /= tail_short /#.
rewrite /stream256 hpd htd /= size_cat hob hsd /=; do! split.
+ by rewrite hh2 /words256.
by move=> j hj'; rewrite hj 1:/# -hd BArray32.get_to_list.
qed.

(* ------------------------------------------------------------------ *)
(* Termination and total correctness                                  *)

lemma hmac_sha256_init_ll : islossless M.__hmac_sha256_init.
proof.
proc; call sha256_compress_ll; call sha256_init_ll; call sha256_compress_ll; call sha256_init_ll.
by while (true) (8 - i); auto => /#.
qed.

lemma hmac_sha256_finalize_ll : islossless M.__hmac_sha256_finalize.
proof.
proc; call sha256_finalize_ll; wp.
while (true) (4 - i); first by auto => /#.
wp; while (true) (8 - i); first by auto => /#.
by wp; call sha256_finalize_ll; auto => /#.
qed.

lemma hmac_sha256_init_total (K : BArray64.t) :
  phoare [M.__hmac_sha256_init :
           k0 = K ==>
           hwords res.`1 = compress H0_256 (words256 (xorb (BArray64.to_list K) (ipad 64))) /\
           hwords res.`2 = compress H0_256 (words256 (xorb (BArray64.to_list K) (opad 64)))] = 1%r.
proof. by conseq hmac_sha256_init_ll (hmac_sha256_init_correct K). qed.

lemma hmac_sha256_finalize_total (ib ob text : bytes) : size ob = 64 =>
  phoare [M.__hmac_sha256_finalize :
           stream256 H0_256 (ib ++ text) inner buf total /\
           hwords outer = compress H0_256 (words256 ob) /\ size (ib ++ text) < 2^61 ==>
           BArray32.to_list res.`1 = sha256 (ob ++ sha256 (ib ++ text))] = 1%r.
proof. by move=> hob; conseq hmac_sha256_finalize_ll (hmac_sha256_finalize_correct ib ob text hob). qed.
