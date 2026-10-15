(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ShakeSponge.ec
 * ==============
 *
 * The absorbing phase of the Keccak sponge (FIPS 202 section 4) seen one
 * byte at a time, as the single-way sponge of src/hash/keccak/sponge.jinc
 * writes it. The specification (Keccak1600_Spec) absorbs whole r8-byte
 * blocks, then pads the remainder; the code XORs its input into the
 * 200-byte state lane by lane, permutes when a block is full, and adds the
 * domain byte and the final pad bit last. This file relates the two.
 *
 * abs_state r8 m is the state after the full blocks of m are absorbed and
 * the bytes of the incomplete last block are XORed in, not yet padded:
 *
 *     abs_state r8 m = stateabsorb (stateabsorb_iblocks (chunk r8 m) st0)
 *                                  (chunkremains r8 m)
 *
 * and absorbing r8 m st pos says that the code's state st holds it, with
 * the byte position pos = size m %% r8 of the next input byte. Appending
 * bytes that do not fill the block XORs them in at that position
 * (abs_cat_lt); appending bytes that fill it XORs them and permutes
 * (abs_cat_eq). XORing the trail byte at the position and 0x80 at byte
 * r8 - 1 gives ABSORB1600 trail r8 m (abs_final), so for an output of at
 * most r8 bytes the hash is a prefix of the permuted state (squeeze_one,
 * shake256_one for SHAKE256, r8 = 136).
 *
 * Byte views. stbytes (lanes st) is the state of the code (BArray200)
 * as the specification's byte array (stbytes_lanes); get8_xor64 reads a
 * lane XOR byte by byte, bits8_ds and bits8_top give the bytes of the
 * domain word 0x1F and of 2^63.
 *
 * All lemmas are about the specification and the array model; none
 * refers to a procedure, so the file is checked against every pair.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
from JazzEC require import Array25 WArray200.
require import BArray200 KeccakState.
require import Keccakf1600_Spec Keccak1600_Spec JWordList.
require BitEncoding.
import BitEncoding.BitChunking.

op abs_state (r8 : int) (m : W8.t list) : state =
  stateabsorb (stateabsorb_iblocks (chunk r8 m) st0) (chunkremains r8 m).

op absorbing (r8 : int) (m : W8.t list) (st : BArray200.t) (pos : W64.t) : bool =
  to_uint pos = size m %% r8 /\ lanes st = abs_state r8 m.

op xorb_at (w : WArray200.t) (o : int) (bs : W8.t list) : WArray200.t =
  WArray200.init (fun j => if o <= j < o + size bs then w.[j] `^` nth W8.zero bs (j - o) else w.[j]).

lemma xorb_atE w o bs j : 0 <= j < 200 =>
  (xorb_at w o bs).[j] = if o <= j < o + size bs then w.[j] `^` nth W8.zero bs (j - o) else w.[j].
proof. by move=> hj; rewrite /xorb_at WArray200.initiE. qed.

(* The lanes of a byte array are its bytes read as a Keccak state. *)
lemma stbytes_lanes (st : BArray200.t) j : 0 <= j < 200 => (stbytes (lanes st)).[j] = st.[j].
proof.
move=> hj; rewrite WArray200.initiE //= lanesE 1:/#.
by rewrite BArray200.get64d_byte 1:/#; congr; smt().
qed.

lemma stbytes_bytes2state (x : W8.t list) : stbytes (bytes2state x) = WArray200.of_list x.
proof. by rewrite -bytes2stbytesP stwordsK. qed.

lemma stbytes_stateabsorb (s : state) (x : W8.t list) j : 0 <= j < 200 =>
  (stbytes (stateabsorb s x)).[j] = (stbytes s).[j] `^` nth W8.zero x j.
proof.
move=> hj; rewrite /stateabsorb stbytes_addstate /addstbytes WArray200.map2iE //.
by rewrite stbytes_bytes2state WArray200.get_of_list.
qed.

lemma chunk_one ['a] r (l : 'a list) : 0 < r => size l = r => chunk r l = [l].
proof. by move=> hr hl; rewrite /chunk hl divzz (_ : r <> 0) 1:/# b2i1 mkseq1 /= drop0 -hl take_size. qed.

lemma iblocks_cat (l1 l2 : W8.t list list) s :
  stateabsorb_iblocks (l1 ++ l2) s = stateabsorb_iblocks l2 (stateabsorb_iblocks l1 s).
proof. by rewrite /stateabsorb_iblocks foldl_cat. qed.

lemma abs_cat_lt r8 (m bs : W8.t list) : 0 < r8 <= 200 => size m %% r8 + size bs < r8 =>
  stbytes (abs_state r8 (m ++ bs)) = xorb_at (stbytes (abs_state r8 m)) (size m %% r8) bs.
proof.
move=> hr hs; rewrite /abs_state chunk_cat' 1:/# chunkremains_cat 1:/#.
have hrem := size_chunkremains r8 m.
rewrite (chunk0 r8 (chunkremains r8 m ++ bs)) 1:size_cat 1:/# cats0.
rewrite (chunkremains_small r8 (chunkremains r8 m ++ bs)) 1:size_cat 1:/#.
apply WArray200.tP => j hj; rewrite stbytes_stateabsorb // /xorb_at.
rewrite xorb_atE // stbytes_stateabsorb //.
rewrite nth_cat hrem; case: (j < size m %% r8) => hj1.
+ by rewrite ifF 1:/#.
rewrite (nth_default _ (chunkremains r8 m)) 1:/# W8.xorw0.
case: (size m %% r8 <= j < size m %% r8 + size bs) => hj2 //.
by rewrite nth_default 1:/# W8.xorw0.
qed.

lemma abs_cat_eq r8 (m bs : W8.t list) : 0 < r8 <= 200 => size m %% r8 + size bs = r8 =>
  abs_state r8 (m ++ bs) = keccak_f1600_op (stwords (xorb_at (stbytes (abs_state r8 m)) (size m %% r8) bs)).
proof.
move=> hr hs; rewrite /abs_state chunk_cat' 1:/# chunkremains_cat 1:/#.
have hrem := size_chunkremains r8 m.
have hsz : size (chunkremains r8 m ++ bs) = r8 by rewrite size_cat /#.
rewrite (chunk_one r8 (chunkremains r8 m ++ bs)) 1,2:/#.
rewrite (chunkremains_nil r8 (chunkremains r8 m ++ bs)) 1:/# 1:hsz 1:dvdzz iblocks_cat {1}/stateabsorb_iblocks /=.
have -> : forall s, stateabsorb s [] = s.
+ move=> s; rewrite /stateabsorb bytes2state0; apply Array25.tP => i hi.
  rewrite /addstate /st0 /init_25_64 !Array25.initiE //= Array25.initiE //= W64.xorw0.
congr; apply stbytes_inj; rewrite stwordsK; apply WArray200.tP => j hj.
rewrite stbytes_stateabsorb // xorb_atE // stbytes_stateabsorb //.
rewrite nth_cat hrem; case: (j < size m %% r8) => hj1.
+ by rewrite ifF 1:/#.
rewrite (nth_default _ (chunkremains r8 m)) 1:/# W8.xorw0.
case: (size m %% r8 <= j < size m %% r8 + size bs) => hj2 //.
by rewrite nth_default 1:/# W8.xorw0.
qed.

(* Padding: the domain byte at the absorb position, then the top bit of the last rate byte
   (FIPS 202 pad10*1 in the byte order of appendix B.2; both may hit byte r8 - 1). *)
lemma abs_final r8 (m : W8.t list) trail : 0 < r8 <= 200 =>
  stwords (xorb_at (xorb_at (stbytes (abs_state r8 m)) (size m %% r8) [trail]) (r8 - 1) [W8.of_int 128])
  = ABSORB1600 trail r8 m.
proof.
move=> hr; rewrite /ABSORB1600 /stateabsorb_last /addratebit /abs_state; apply stbytes_inj; rewrite !stwordsK.
have hrem := size_chunkremains r8 m.
rewrite /addratebit8; apply WArray200.tP => j hj.
have hlt : size m %% r8 < r8 by smt().
rewrite WArray200.get_setE 1:/# xorb_atE //.
case: (j = r8 - 1) => [->|hj1] /=.
+ rewrite xorb_atE 1:/# !stbytes_stateabsorb 1,2:/# nth_rcons hrem.
  case: (r8 - 1 < size m %% r8) => hj2; first by smt().
  case: (r8 - 1 = size m %% r8) => hj3.
  rewrite -hj3 /= (_ : r8 - 1 < r8) 1:/# /= (nth_default _ (chunkremains r8 m)) 1:/# W8.xorw0 //.
  by rewrite (_ : r8 - 1 < r8) 1:/# /= ifF 1:/# (nth_default _ (chunkremains r8 m)) 1:/# W8.xorw0.
rewrite ifF 1:/# xorb_atE // !stbytes_stateabsorb // nth_rcons hrem.
case: (j < size m %% r8) => hj2; first by rewrite ifF 1:/# /=.
case: (j = size m %% r8) => hj3.
+ by rewrite ifT 1:/# hj3 /= (nth_default _ (chunkremains r8 m)) 1:/# W8.xorw0.
by rewrite ifF 1:/# (nth_default _ (chunkremains r8 m)) 1:/# !W8.xorw0.
qed.

lemma squeeze_one r8 len (s : state) : 0 < len <= r8 =>
  SQUEEZE1600 r8 len s = take len (state2bytes (keccak_f1600_op s)).
proof.
move=> hl; rewrite /SQUEEZE1600 (_ : (len - 1) %/ r8 + 1 = 1) 1:/#.
rewrite /squeezeblocks iota1 /= /flatten /= cats0 /squeezestate_i /squeezestate /st_i iter1.
by rewrite take_take /#.
qed.

lemma shake256_one (m : W8.t list) len : 0 < len <= 136 =>
  SHAKE256 m len = take len (state2bytes (keccak_f1600_op (ABSORB1600 SHAKE_DS_BYTE 136 m))).
proof. by move=> hl; rewrite /SHAKE256 /KECCAK1600 squeeze_one. qed.

(* Lane XOR read byte by byte (the core pads with 64-bit lane XORs). *)
lemma get8_xor64 (st : BArray200.t) (l : int) (w : W64.t) j : 0 <= l < 25 => 0 <= j < 200 =>
  (BArray200.set64d st (8 * l) (BArray200.get64d st (8 * l) `^` w)).[j] =
  if 8 * l <= j < 8 * l + 8 then st.[j] `^` (w \bits8 (j - 8 * l)) else st.[j].
proof.
move=> hl hj; rewrite BArray200.get8_set64dE.
case: (8 * l <= j < 8 * l + 8) => h //=.
by rewrite ifT 1:/# BArray200.get64d_byte 1:/#; congr; congr; smt().
qed.

lemma bits8_ds k : 0 <= k < 8 => (W64.of_int 31) \bits8 k = if k = 0 then W8.of_int 31 else W8.zero.
proof.
move=> hk; rewrite W8u8.of_int_bits8_div //; case: (k = 0) => [->//|hk0].
rewrite divz_small //; have : 2 ^ 8 <= 2 ^ (8 * k) by apply StdOrder.IntOrder.ler_weexpn2l; smt().
smt().
qed.

lemma bits8_top k : 0 <= k < 8 =>
  (W64.of_int 9223372036854775808) \bits8 k = if k = 7 then W8.of_int 128 else W8.zero.
proof.
move=> hk; rewrite W8u8.of_int_bits8_div //.
have : k = 0 \/ k = 1 \/ k = 2 \/ k = 3 \/ k = 4 \/ k = 5 \/ k = 6 \/ k = 7 by smt().
by move=> [|[|[|[|[|[|[|]]]]]]] ->.
qed.

(* A message shorter than the rate has not been permuted: the state is its bytes. *)
lemma abs_short r8 (m : W8.t list) j : 0 < r8 => size m < r8 => 0 <= j < 200 =>
  (stbytes (abs_state r8 m)).[j] = nth W8.zero m j.
proof.
move=> hr hm hj; rewrite /abs_state chunk0 // chunkremains_small // /stateabsorb_iblocks /=.
by rewrite stbytes_stateabsorb // WArray200.initiE //= /st0 /init_25_64 Array25.initiE 1:/# /= W8u8.get_zero W8.xor0w.
qed.
