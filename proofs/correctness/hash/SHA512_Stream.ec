(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * SHA512_Stream.ec
 * ================
 *
 * Functional correctness of the streaming SHA-512 family of src/hash/sha2/
 * sha512.jinc over the portable compression kernel, against FIPS 180-4
 * sections 5.1.2, 5.2.2 and 6.4.2 (spec/hash/FIPS180_SHA2.ec).
 *
 * Stream state. After a message m has been absorbed from a starting
 * chaining value h0, the state (h, buf, total) satisfies stream512 h0 m:
 *
 *     total  = |m|
 *     h      = compress folded from h0 over the complete 128-byte blocks
 *              of m (parse m: chunk drops an incomplete last block)
 *     buf    holds the |m| mod 128 bytes after those blocks in its first
 *            cells (pending); the other cells are unconstrained
 *
 * A caller that writes the state itself establishes stream512 directly:
 * for |m| < 128 the second clause is hwords h = h0.
 *
 * Theorems (total correctness):
 *     sha512_absorb_mem_total      absorbing l bytes from memory at p
 *                                  extends m by those bytes
 *     sha512_finalize_total        padding and the last one or two blocks
 *                                  give the FIPS 180-4 hash of m from h0
 *     sha512_mem_total             one-shot SHA-512 of l bytes at p
 *     sha384_mem_total             SHA-384: the first 48 output bytes
 *     sha512_224_mem_total         SHA-512/224: the first 28 output bytes
 *     sha512_256_mem_total         SHA-512/256: the first 32 output bytes
 *
 * Address bounds are strict (p + l < 2^64): the kernel advances its input
 * pointer past the last byte it reads. Lengths are below 2^61 bytes, so
 * the upper word of the 128-bit length field is zero.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils JMemory.
require import BArray64 BArray128.
require import HashExtracted ArchWord.
require import Bytes FIPS180_SHA2 SHA512_Compress SHA512_Blocks.
require JWordList.
import SHA512.

(* ------------------------------------------------------------------ *)
(* The stream state                                                   *)

(* The bytes of m after its complete blocks. *)
op tail512 (m : bytes) : bytes = drop (128 * (size m %/ 128)) m.

(* The first size r cells of buf are r. *)
op pending (buf : BArray128.t) (r : bytes) =
  forall i, 0 <= i < size r => BArray128.get8 buf i = nth W8.zero r i.

op stream512 (h0 : W64.t list) (m : bytes) (h : BArray64.t) (buf : BArray128.t) (total : W64.t) =
     W64.to_uint total = size m
  /\ hwords h = foldl compress h0 (parse m)
  /\ pending buf (tail512 m).

(* ------------------------------------------------------------------ *)
(* Blocks and tails of a concatenation                                *)

lemma size_tail512 (m : bytes) : size (tail512 m) = size m %% 128.
proof. rewrite /tail512 size_drop; smt(size_ge0 divz_eq modz_ge0 divz_ge0). qed.

lemma parse_short (t : bytes) : size t < 128 => parse t = [].
proof. by move=> ht; rewrite /parse JWordList.chunk0. qed.

lemma tail_short (t : bytes) : size t < 128 => tail512 t = t.
proof.
move=> ht; rewrite /tail512 (_ : size t %/ 128 = 0); first smt(pdiv_small size_ge0).
by rewrite drop0.
qed.

(* A prefix of whole blocks parses on its own and leaves no tail. *)
lemma parse_blocks_cat (x z : bytes) : 128 %| size x => parse (x ++ z) = parse x ++ parse z.
proof. by move=> hx; rewrite /parse chunk_cat // map_cat. qed.

lemma tail_blocks_cat (x z : bytes) : 128 %| size x => tail512 (x ++ z) = tail512 z.
proof.
move=> /dvdzP [q hq]; rewrite /tail512 size_cat hq.
rewrite (_ : (q * 128 + size z) %/ 128 = q + size z %/ 128).
+ by rewrite divzMDl.
rewrite drop_cat hq; smt(divz_ge0 size_ge0).
qed.

lemma split_blocks (m : bytes) : m = take (128 * (size m %/ 128)) m ++ tail512 m.
proof. by rewrite /tail512 cat_take_drop. qed.

lemma dvd_head (m : bytes) : 128 %| size (take (128 * (size m %/ 128)) m).
proof.
rewrite size_take; first smt(divz_ge0 size_ge0).
case: (128 * (size m %/ 128) < size m) => hlt; first by rewrite dvdz_mulr.
have -> : size m = 128 * (size m %/ 128) by smt(divz_eq modz_ge0 size_ge0).
by rewrite dvdz_mulr.
qed.

lemma parse_cat (m y : bytes) : parse (m ++ y) = parse m ++ parse (tail512 m ++ y).
proof.
have hm := split_blocks m.
have -> : parse m = parse (take (128 * (size m %/ 128)) m).
+ rewrite {1}hm parse_blocks_cat 1:dvd_head (parse_short (tail512 m)) ?cats0 //.
  by rewrite size_tail512; smt(modz_cmp).
by rewrite {1}hm -catA parse_blocks_cat 1:dvd_head.
qed.

lemma tail_cat (m y : bytes) : tail512 (m ++ y) = tail512 (tail512 m ++ y).
proof. by rewrite {1}(split_blocks m) -catA tail_blocks_cat 1:dvd_head. qed.

(* Writing one more pending byte. *)
lemma pending_rcons (buf : BArray128.t) (r : bytes) x :
  pending buf r => size r < 128 =>
  pending (BArray128.set8 buf (size r) x) (rcons r x).
proof.
move=> hp hr i; rewrite size_rcons => hi.
rewrite BArray128.get_setE 1:size_ge0 1:/# nth_rcons.
by case: (i = size r) => [->|ne] /=; [| rewrite (_ : i < size r) 1:/# /= hp /#].
qed.

lemma pending_take (buf : BArray128.t) (r : bytes) k :
  pending buf r => pending buf (take k r).
proof.
move=> hp i hi; case: (0 <= k) => hk; last by move: hi; rewrite take_le0 /#.
move: hi; rewrite size_take // => hi.
by rewrite nth_take 1,2:/# hp /#.
qed.

(* A full buffer is the block. *)
lemma pending_full (buf : BArray128.t) (r : bytes) :
  pending buf r => size r = 128 => BArray128.to_list buf = r.
proof.
move=> hp hr; apply (eq_from_nth W8.zero).
+ by rewrite BArray128.size_to_list hr.
move=> i; rewrite BArray128.size_to_list => hi.
by rewrite -(hp i) 1:/# -BArray128.get_to_list.
qed.

lemma trunc_zext (b : W8.t) : truncateu8 (zeroextu64 b) = b.
proof.
apply W8.to_uint_eq; rewrite to_uint_truncateu8 to_uint_zeroextu64.
exact W8.to_uint_mod.
qed.

(* A 128-byte list is one block. *)
lemma parse_block (b : bytes) : size b = 128 => parse b = [map be64 (chunk 8 b)].
proof.
move=> hb; rewrite /parse.
have hne : b <> [] by rewrite -size_eq0 hb.
by have := chunk_exact b hne; rewrite hb => ->.
qed.

(* Extending m so that its tail fills one block: one more compression. *)
lemma close_block h0 (m y : bytes) (b : BArray128.t) :
  BArray128.to_list b = tail512 m ++ y =>
  compress (foldl compress h0 (parse m)) (map be64 (chunk 8 (BArray128.to_list b)))
  = foldl compress h0 (parse (m ++ y))
  /\ tail512 (m ++ y) = [].
proof.
move=> hb; have hs : size (tail512 m ++ y) = 128 by rewrite -hb BArray128.size_to_list.
rewrite parse_cat (parse_block _ hs) foldl_cat /= hb; split; first by [].
by rewrite tail_cat /tail512 hs /= drop_oversize 1:hs.
qed.

(* Extending m within its last block: no compression. *)
lemma short_ext (m y : bytes) : size (tail512 m ++ y) < 128 =>
  parse (m ++ y) = parse m /\ tail512 (m ++ y) = tail512 m ++ y.
proof.
move=> hs; rewrite parse_cat (parse_short _ hs) cats0 /=.
by rewrite tail_cat (tail_short _ hs).
qed.

(* Extending a block-aligned m by whole blocks. *)
lemma blocks_ext (m x : bytes) : tail512 m = [] => 128 %| size x =>
  parse (m ++ x) = parse m ++ parse x /\ tail512 (m ++ x) = [].
proof.
move=> hm hx; split; first by rewrite parse_cat hm.
rewrite tail_cat hm /= /tail512; move: hx => /dvdzP [q hq].
by rewrite hq mulzK // drop_oversize /#.
qed.

(* The bytes the first loop of the absorb moves into the buffer: up to
   the end of the pending block, none when the buffer is empty. *)
op nfill (r l : int) : int = if r = 0 then 0 else min l (128 - r).

lemma nfill_bounds r l : 0 <= r < 128 => 0 <= l =>
  0 <= nfill r l <= l /\ r + nfill r l <= 128.
proof. by rewrite /nfill /#. qed.

lemma trunc_load mem a : truncateu8 (zeroextu64 (loadW8 mem a)) = loadW8 mem a.
proof. exact trunc_zext. qed.

lemma fill_count (f l : W64.t) : W64.to_uint f < 128 =>
  W64.to_uint (if f = W64.zero then f
               else if l \ult W64.of_int 128 - f then l else W64.of_int 128 - f)
  = nfill (W64.to_uint f) (W64.to_uint l).
proof.
move=> hf; rewrite /nfill; case: (f = W64.zero) => [->|hz] //=.
have hf0 : W64.to_uint f <> 0 by move: hz; apply contra => h; apply W64.to_uint_eq.
have hs : W64.to_uint (W64.of_int 128 - f) = 128 - W64.to_uint f.
+ by rewrite W64.to_uintB 1:W64.uleE /= 1:/#.
rewrite hf0 /=; case: (l \ult W64.of_int 128 - f); rewrite W64.ultE hs /#.
qed.

(* The input as the absorb splits it: nf bytes into the pending block,
   whole blocks, then the rest. *)
lemma absorb_split mem (m : bytes) a l nf : 0 <= nf <= l =>
  m ++ memread mem a l
  = ((m ++ memread mem a nf) ++ memread mem (a + nf) (128 * ((l - nf) %/ 128)))
    ++ memread mem (a + nf + 128 * ((l - nf) %/ 128)) ((l - nf) %% 128).
proof.
move=> hnf; have hl : l = nf + (128 * ((l - nf) %/ 128) + (l - nf) %% 128) by smt(divz_eq).
rewrite {1}hl memread_add 1,2:/# memread_add; smt(divz_ge0 modz_ge0 catA).
qed.

lemma pending_nil (buf : BArray128.t) : pending buf [].
proof. by move=> i /= /#. qed.

lemma and127 (w : W64.t) : W64.to_uint (w `&` W64.of_int 127) = W64.to_uint w %% 128.
proof.
rewrite (_ : W64.of_int 127 = W64.of_int (2^7 - 1)) // W64.and_mod // W64.of_uintK.
by rewrite (pmod_small _ W64.modulus); smt(modz_ge0 modz_cmp).
qed.

(* ------------------------------------------------------------------ *)
(* Absorbing bytes from memory                                        *)

lemma sha512_compress_blocks_correct (h0 : W64.t list) (p0 n0 : W64.t) :
  hoare [M._sha512_compress_blocks :
           hwords h = h0 /\ p = p0 /\ n = n0 /\
           W64.to_uint p0 + 128 * W64.to_uint n0 < W64.modulus ==>
           hwords res.`1
           = foldl compress h0 (parse (memread Glob.mem (W64.to_uint p0) (128 * W64.to_uint n0)))].
proof. by conseq (sha512_compress_blocks_total h0 p0 n0). qed.

(* The absorb runs in three phases: complete the pending block from the
   input (nfill bytes), compress the whole blocks that follow straight
   from memory, then copy the rest into the buffer. Each phase extends
   the absorbed message by the bytes it consumed. *)
lemma sha512_absorb_mem_correct (h0 : W64.t list) (m : bytes) (p0 l0 : W64.t) :
  hoare [M._sha512_absorb_mem :
           stream512 h0 m h buf total /\ in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
           size m + W64.to_uint l0 < W64.modulus ==>
           stream512 h0 (m ++ memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))
             res.`1 res.`2 res.`3].
proof.
proc.
seq 11 : (W64.to_uint fill = size m %% 128 /\
          W64.to_uint end_0 = size m %% 128 + nfill (size m %% 128) (W64.to_uint l0) /\
          W64.to_uint total = size m + W64.to_uint l0 /\
          W64.to_uint inlen = W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0) /\
          in_0 = p0 /\ more = (fill \ult end_0) /\
          hwords h = foldl compress h0 (parse m) /\ pending buf (tail512 m) /\
          W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
          size m + W64.to_uint l0 < W64.modulus).
+ auto => /> &hr ht hh hp hb1 hb2.
  have hf : W64.to_uint (total{hr} `&` W64.of_int 127) = size m %% 128 by rewrite and127 ht.
  have hr64 : 0 <= size m %% 128 < 128 by smt(modz_ge0 modz_cmp).
  have hL := W64.to_uint_cmp l0.
  have [[hn0 hnl] hnr] := nfill_bounds (size m %% 128) (W64.to_uint l0) hr64 _; first smt().
  move: (fill_count (total{hr} `&` W64.of_int 127) l0 _); first by rewrite hf /#.
  move: (if _ = _ then _ else _) => x; rewrite hf => hx.
  rewrite W64.to_uintD_small 1:/# hf hx /= W64.to_uintD_small 1:/# ht /=.
  by rewrite W64.to_uintB 1:W64.uleE /#.
(* Phase 1: complete the pending block. *)
seq 1 : (W64.to_uint fill = size m %% 128 + nfill (size m %% 128) (W64.to_uint l0) /\
         W64.to_uint total = size m + W64.to_uint l0 /\
         W64.to_uint inlen = W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0) /\
         W64.to_uint in_0 = W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) /\
         hwords h = foldl compress h0 (parse m) /\
         pending buf (tail512 m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) /\
         W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
            size m + W64.to_uint l0 < W64.modulus).
+ while (size m %% 128 <= W64.to_uint fill <= W64.to_uint end_0 /\
         W64.to_uint end_0 = size m %% 128 + nfill (size m %% 128) (W64.to_uint l0) /\
         W64.to_uint in_0 = W64.to_uint p0 + (W64.to_uint fill - size m %% 128) /\
         W64.to_uint total = size m + W64.to_uint l0 /\
         W64.to_uint inlen = W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0) /\
         more = (fill \ult end_0) /\
         hwords h = foldl compress h0 (parse m) /\
         pending buf (tail512 m ++ memread Glob.mem (W64.to_uint p0) (W64.to_uint fill - size m %% 128)) /\
         W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
            size m + W64.to_uint l0 < W64.modulus).
  + auto => /> &hr hlo hhi he hi ht hn hh hp hb1 hb2 hlt.
    have hr64 : 0 <= size m %% 128 < 128 by smt(modz_ge0 modz_cmp).
    have [[hn0 hnl] hnr] := nfill_bounds (size m %% 128) (W64.to_uint l0) hr64 _; first smt(W64.to_uint_cmp).
    move: hlt; rewrite W64.ultE => hlt.
    have hf1 : W64.to_uint (fill{hr} + W64.one) = W64.to_uint fill{hr} + 1.
    + by rewrite W64.to_uintD_small /= /#.
    have hi1 : W64.to_uint (in_0{hr} + W64.one) = W64.to_uint in_0{hr} + 1.
    + by rewrite W64.to_uintD_small /= /#.
    rewrite hf1 hi1; split; first smt().
    split; first smt().
    rewrite (_ : W64.to_uint fill{hr} + 1 - size m %% 128
               = (W64.to_uint fill{hr} - size m %% 128) + 1) 1:/#.
    rewrite JWordList.memreadS 1:/# -rcons_cat trunc_load hi.
    have hsz : size (tail512 m ++ memread Glob.mem{hr} (W64.to_uint p0) (W64.to_uint fill{hr} - size m %% 128))
               = W64.to_uint fill{hr}.
    + by rewrite size_cat size_tail512 size_memread /#.
    by rewrite -{1}hsz; apply pending_rcons => //; rewrite hsz /#.
  auto => /> &hr hf he ht hi hh hp hb1 hb2; split.
  + rewrite hf (_ : size m %% 128 - size m %% 128 = 0) 1:/# JWordList.memread0 cats0 hp /=.
    smt(nfill_bounds modz_ge0 modz_cmp W64.to_uint_cmp).
  move=> buf1 fill1 in1 more1 _ hlo hhi hi1 hult hp1.
  have hfe : W64.to_uint fill1 = W64.to_uint end_0{hr}.
  + by move: hult; rewrite W64.ultE; smt().
  have hj : W64.to_uint fill1 - size m %% 128 = nfill (size m %% 128) (W64.to_uint l0) by smt().
  by move: hp1; rewrite hi1 hj hfe he.
(* The block is compressed if it is now full. Afterwards the buffer is
   empty or the input is used up. *)
seq 3 : (W64.to_uint total = size m + W64.to_uint l0 /\
         W64.to_uint inlen = W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0) /\
         W64.to_uint in_0 = W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) /\
         hwords h = foldl compress h0 (parse (m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0)))) /\
         pending buf (tail512 (m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0)))) /\
         (tail512 (m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) = [] \/ W64.to_uint inlen = 0) /\
         W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
         size m + W64.to_uint l0 < W64.modulus).
+ have hr64 : 0 <= size m %% 128 < 128 by smt(modz_ge0 modz_cmp).
  have [[hn0 hnl] hnr] := nfill_bounds (size m %% 128) (W64.to_uint l0) hr64 _; first smt(W64.to_uint_cmp).
  have hsz : forall mem, size (tail512 m ++ memread mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0)))
             = size m %% 128 + nfill (size m %% 128) (W64.to_uint l0).
  + by move=> mem; rewrite size_cat size_tail512 size_memread.
  seq 2 : (#pre /\ full = (fill = W64.of_int 128)); first by auto.
  if.
  + wp; ecall (sha512_compress_correct (hwords h) buf).
    auto => /> &hr hf ht hi hin hh hp hb1 hb2 [h1 ms1] /= hh1.
    have hl := pending_full _ _ hp _; first by rewrite hsz -hf.
    have [hc ht0] := close_block h0 m (memread Glob.mem{hr} (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) buf{hr} hl.
    rewrite /Jslh.SLH64.protect_64 /Jslh.SLH64.protect_ptr /= hh1 hh hc ht0 /=.
    by move=> i; rewrite /= /#.
  auto => /> &hr hf ht hi hin hh hp hb1 hb2 hfull.
  have hlt : size m %% 128 + nfill (size m %% 128) (W64.to_uint l0) < 128.
  + have : W64.to_uint fill{hr} <> 128.
    + by move: hfull; apply contra => h64; apply W64.to_uint_eq; rewrite h64.
    smt().
  have [hpm htm] := short_ext m (memread Glob.mem{hr} (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) _; first by rewrite hsz.
  rewrite hpm hh htm hp /=.
  case: (size m %% 128 = 0) => hr0.
  + by left; rewrite -size_eq0 size_cat size_tail512 size_memread 1:/# /nfill hr0.
  by right; rewrite hi; move: hlt; rewrite /nfill hr0 /= /#.
(* Phase 2: the whole blocks that follow, straight from memory, then
   the remainder length, inlen mod 128 on both paths. *)
seq 6 : (W64.to_uint total = size m + W64.to_uint l0 /\
         W64.to_uint inlen = (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %% 128 /\
         W64.to_uint in_0 = W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) /\
         W64.to_uint off = 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128) /\
         hwords h = foldl compress h0 (parse ((m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128)))) /\
         pending buf (tail512 ((m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128)))) /\
         (tail512 ((m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128))) = [] \/ W64.to_uint inlen = 0) /\
         W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
         size m + W64.to_uint l0 < W64.modulus).
+ have hr64 : 0 <= size m %% 128 < 128 by smt(modz_ge0 modz_cmp).
  have [[hn0 hnl] hnr] := nfill_bounds (size m %% 128) (W64.to_uint l0) hr64 _; first smt(W64.to_uint_cmp).
  wp; seq 4 : (#pre /\ off = W64.zero /\ W64.to_uint n = (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128 /\ more = (n <> W64.zero)).
  + by auto => /> &hr ht hi hin hh hp hd hb1 hb2; rewrite W64.shr_div_le // hi.
  if.
  + wp; ecall (sha512_compress_blocks_correct (hwords h) in_0 n).
    auto => /> &hr ht hi hin hh hp hd hb1 hb2 hn hne.
    have hk1 : 1 <= (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128.
    + have : W64.to_uint n{hr} <> 0 by move: hne; apply contra => h0'; apply W64.to_uint_eq.
      smt(divz_ge0).
    have hkk : 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128) <= (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) by smt(divz_eq modz_ge0).
    split; first by rewrite hin hn /#.
    move=> _ [h1 ms1] /= hh1.
    rewrite /Jslh.SLH64.protect_64 /Jslh.SLH64.protect_ptr /= hh1 hh hin hn.
    have htl : tail512 (m ++ memread Glob.mem{hr} (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) = [] by case: hd => // /#.
    have [hpx htx] := blocks_ext (m ++ memread Glob.mem{hr} (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) (memread Glob.mem{hr} (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128))) htl _.
    + by rewrite size_memread 1:/# dvdz_mulr.
    rewrite hpx htx foldl_cat /=; split; first by rewrite and127 hi.
    rewrite /(`<<`) /(`>>`) W64.to_uint_shl // W64.to_uint_shr // hi /=.
    by rewrite pmod_small; smt(divz_ge0 W64.to_uint_cmp).
  auto => /> &hr ht hi hin hh hp hd hb1 hb2 hk0.
  have hk64 : (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %% 128 = (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) by rewrite {2}(divz_eq (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) 128) -hk0.
  by rewrite and127 hi -hk0 /= hk64 /= cats0 hh hp /=; smt().
(* Phase 3: the rest goes into the buffer. *)
wp; while (0 <= W64.to_uint fill <= W64.to_uint inlen /\
       W64.to_uint inlen = (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %% 128 /\
       W64.to_uint in_0 = W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) /\
       W64.to_uint off = 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128) + W64.to_uint fill /\
       W64.to_uint total = size m + W64.to_uint l0 /\
       more = (fill \ult inlen) /\
       hwords h = foldl compress h0 (parse ((m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128)))) /\
       pending buf (tail512 ((m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128))) ++ memread Glob.mem (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) + 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128)) (W64.to_uint fill)) /\
       (tail512 ((m ++ memread Glob.mem (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128))) = [] \/ W64.to_uint inlen = 0) /\
       W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
         size m + W64.to_uint l0 < W64.modulus).
+ auto => /> &hr hf0 hfi hi hin hoff ht hh hp hd hb1 hb2 hlt.
  have hr64 : 0 <= size m %% 128 < 128 by smt(modz_ge0 modz_cmp).
  have [[hn0 hnl] hnr] := nfill_bounds (size m %% 128) (W64.to_uint l0) hr64 _; first smt(W64.to_uint_cmp).
  move: hlt; rewrite W64.ultE => hlt.
  have htl : tail512 ((m ++ memread Glob.mem{hr} (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem{hr} (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128))) = [] by case: hd => // /#.
  have hkk : 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128) + (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %% 128 = (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) by smt(divz_eq).
  have hf1 : W64.to_uint (fill{hr} + W64.one) = W64.to_uint fill{hr} + 1.
  + by rewrite W64.to_uintD_small /= /#.
  have ho1 : W64.to_uint (off{hr} + W64.one) = W64.to_uint off{hr} + 1.
  + by rewrite W64.to_uintD_small /=; smt(W64.to_uint_cmp).
  have hio : W64.to_uint (in_0{hr} + off{hr}) = (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) + 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128)) + W64.to_uint fill{hr}.
  + by rewrite W64.to_uintD_small; smt(W64.to_uint_cmp).
  rewrite hf1 ho1; split; first smt().
  split; first smt().
  rewrite JWordList.memreadS 1:/# -rcons_cat trunc_load hio.
  have hsz : size (tail512 ((m ++ memread Glob.mem{hr} (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem{hr} (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128))) ++ memread Glob.mem{hr} (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) + 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128)) (W64.to_uint fill{hr}))
             = W64.to_uint fill{hr}.
  + by rewrite htl /= size_memread /#.
  by rewrite -{1}hsz; apply pending_rcons => //; rewrite hsz /#.
auto => /> &hr ht hi hin hoff hh hp hd hb1 hb2.
have hr64 : 0 <= size m %% 128 < 128 by smt(modz_ge0 modz_cmp).
have [[hn0 hnl] hnr] := nfill_bounds (size m %% 128) (W64.to_uint l0) hr64 _; first smt(W64.to_uint_cmp).
split.
+ by rewrite cats0 hp /=; smt(W64.to_uint_cmp).
move=> buf1 fill1 more1 off1 _ hf0 hfi hoff1 hult hp1.
have hfe : W64.to_uint fill1 = W64.to_uint inlen{hr}.
+ by move: hult; rewrite W64.ultE; smt().
rewrite (absorb_split _ _ _ _ (nfill (size m %% 128) (W64.to_uint l0))) 1:/#.
have [hpm htm] := short_ext ((m ++ memread Glob.mem{hr} (W64.to_uint p0) (nfill (size m %% 128) (W64.to_uint l0))) ++ memread Glob.mem{hr} (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0)) (128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128))) (memread Glob.mem{hr} (W64.to_uint p0 + nfill (size m %% 128) (W64.to_uint l0) + 128 * ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %/ 128)) ((W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) %% 128)) _.
+ rewrite size_cat size_memread; first smt(modz_ge0).
  case: hd => [-> /=|h0']; first smt(modz_cmp).
  rewrite -hi h0' /=; smt(size_tail512 modz_cmp).
rewrite hpm htm hh /=; split.
+ have := divz_eq (W64.to_uint l0 - nfill (size m %% 128) (W64.to_uint l0)) 128.
  by rewrite ht !size_cat !size_memread; smt(divz_ge0 modz_ge0).
by move: hp1; rewrite hfe hi.
qed.

(* Each loop advances a counter towards a bound fixed before it starts. *)
lemma sha512_compress_blocks_ll : islossless M._sha512_compress_blocks.
proof.
proc; wp; while (more = (n <> W64.zero)) (W64.to_uint n).
+ move=> z; wp; call sha512_compress_one_ll; auto => /> &hr hne r.
  have hn0 : W64.to_uint n{hr} <> 0 by move: hne; apply contra => h0; apply W64.to_uint_eq.
  by rewrite /Jslh.SLH64.protect_64 W64.to_uintB 1:W64.uleE /=; smt(W64.to_uint_cmp).
by auto => /> n1 h0; apply W64.to_uint_eq; smt(W64.to_uint_cmp).
qed.

lemma sha512_absorb_mem_ll : islossless M._sha512_absorb_mem.
proof.
proc.
seq 11 : (more = (fill \ult end_0)) 1%r 1%r 0%r 0%r => //; last by hoare; auto.
+ by auto.
seq 1 : true 1%r 1%r 0%r 0%r => //.
+ while (more = (fill \ult end_0)) (W64.to_uint end_0 - W64.to_uint fill).
  + move=> z; auto => /> &hr; rewrite W64.ultE => hlt.
    have /= hb := W64.to_uint_cmp end_0{hr}.
    by rewrite W64.to_uintD_small; rewrite /=; smt().
  by auto => /> &hr f; rewrite W64.ultE /#.
seq 3 : true 1%r 1%r 0%r 0%r => //.
+ by sp; if; [wp; call sha512_compress_ll |]; auto.
seq 6 : true 1%r 1%r 0%r 0%r => //.
+ by sp; if; [wp; call sha512_compress_blocks_ll |]; auto.
wp; while (more = (fill \ult inlen)) (W64.to_uint inlen - W64.to_uint fill).
+ move=> z; auto => /> &hr; rewrite W64.ultE => hlt.
  have /= hb := W64.to_uint_cmp inlen{hr}.
  by rewrite W64.to_uintD_small; rewrite /=; smt().
by auto => /> &hr f; rewrite W64.ultE /#.
qed.

lemma sha512_absorb_mem_total (h0 : W64.t list) (m : bytes) (p0 l0 : W64.t) :
  phoare [M._sha512_absorb_mem :
           stream512 h0 m h buf total /\ in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\
           size m + W64.to_uint l0 < W64.modulus ==>
           stream512 h0 (m ++ memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))
             res.`1 res.`2 res.`3] = 1%r.
proof. by conseq sha512_absorb_mem_ll (sha512_absorb_mem_correct h0 m p0 l0). qed.

(* ------------------------------------------------------------------ *)
(* Padding and output                                                 *)

(* Byte k of a byte-reversed word is byte k of its big-endian encoding. *)
lemma bswapw_bits8 (x : W64.t) k : 0 <= k < 8 =>
  WordSpec.bswap64 x \bits8 k = nth W8.zero (w64_be x) k.
proof.
by move=> hk; rewrite /WordSpec.bswap64 /w64_be W8u8.get_pack8 // size_rev W8u8.size_to_list.
qed.

lemma bswap64_bits8 (x : W64.t) k : 0 <= k < 8 =>
  WordSpec.bswap64 x \bits8 k = nth W8.zero (be_bytes 8 (W64.to_uint x)) k.
proof.
move=> hk; rewrite /WordSpec.bswap64 W8u8.get_pack8 1:size_rev 1:W8u8.size_to_list //.
rewrite nth_rev 1:W8u8.size_to_list // W8u8.size_to_list W8u8.nth_to_list.
rewrite W8u8.bits8_div 1:/# /be_bytes nth_mkseq //=.
by rewrite (_ : 8 * (8 - (k + 1)) = 8 * (8 - 1 - k)) 1:/# exprM.
qed.

(* The output: the eight words of h, each big-endian. *)
lemma out_bytes (out : BArray64.t) (hv : W64.t list) :
  size hv = 8 =>
  (forall i, 0 <= i < 8 => BArray64.get64 out i = WordSpec.bswap64 (nth W64.zero hv i)) =>
  BArray64.to_list out = flatten (map w64_be hv).
proof.
move=> hs hk.
have hall : all (fun (s : bytes) => size s = 8) (map w64_be hv).
+ by rewrite allP => x /mapP [y [_ ->]] /=; rewrite /w64_be size_rev W8u8.size_to_list.
apply (eq_from_nth W8.zero).
+ rewrite BArray64.size_to_list (size_flatten_ctt 8); last by rewrite size_map hs.
  by move=> x /mapP [y [_ ->]]; rewrite /w64_be size_rev W8u8.size_to_list.
move=> j; rewrite BArray64.size_to_list => hj.
rewrite BArray64.get_to_list (BitEncoding.BitChunking.nth_flatten _ 8) // (nth_map W64.zero) 1:/#.
rewrite -bswapw_bits8 1:/# -(hk (j %/ 8)) 1:/# BArray64.get64d_byte 1:/#.
by congr; smt(divz_eq).
qed.

(* The last block: 112 pending bytes, then the 128-bit length field as two
   big-endian words. *)
lemma len_block (buf : BArray128.t) (pre : bytes) (a b : W64.t) :
  pending buf pre => size pre = 112 =>
  BArray128.to_list
    (BArray128.set64d (BArray128.set64d buf 112 (WordSpec.bswap64 a)) 120 (WordSpec.bswap64 b))
  = pre ++ be_bytes 8 (W64.to_uint a) ++ be_bytes 8 (W64.to_uint b).
proof.
move=> hp hs; apply (eq_from_nth W8.zero).
+ by rewrite BArray128.size_to_list !size_cat !size_be_bytes hs.
move=> i; rewrite BArray128.size_to_list => hi.
rewrite BArray128.get_to_list !BArray128.get8_set64dE !nth_cat !size_cat hs size_be_bytes.
rewrite (_ : max 0 8 = 8) //=.
case: (120 <= i) => h120.
+ by rewrite ifT 1:/# ifF 1:/# bswap64_bits8 /#.
case: (112 <= i) => h112.
+ by rewrite ifF 1:/# ifT 1:/# ifT 1:/# ifF 1:/# bswap64_bits8 /#.
rewrite ifF 1:/# ifF 1:/# ifT 1:/# ifT 1:/#.
by have := hp i _; smt().
qed.

(* A length below 2^64 has a zero upper half. *)
lemma be16 (x : int) : 0 <= x < 2^64 => be_bytes 16 x = be_bytes 8 0 ++ be_bytes 8 x.
proof.
move=> hx; apply (eq_from_nth W8.zero); first by rewrite size_cat !size_be_bytes.
move=> i; rewrite size_be_bytes => hi.
rewrite nth_cat size_be_bytes (_ : max 0 8 = 8) // /be_bytes /=.
case: (i < 8) => h8.
+ rewrite !nth_mkseq 1,2:/# /=.
  have hlt : x < 256 ^ (15 - i).
  + apply (ltr_le_trans (2^64)); first by case: hx.
    rewrite (_ : 256 = 2^8) // -exprM; apply ler_weexpn2l => /#.
  by rewrite pdiv_small 1:/#.
by rewrite !nth_mkseq 1,2:/# /= /#.
qed.

(* The message with its 0x80 byte appended and, when the length field no
   longer fits in that block, zeros to the end of the block: what the
   buffer and h hold before the length is written. *)
op mfin (m : bytes) : bytes =
  if size m %% 128 <= 111 then m ++ [W8.of_int 128]
  else m ++ [W8.of_int 128] ++ zeros (127 - size m %% 128).

lemma mod128_shift (a x : int) : 0 <= a - x %% 128 < 128 => (a - x) %% 128 = a - x %% 128.
proof.
move=> h; rewrite {1}(divz_eq x 128).
rewrite (_ : a - (x %/ 128 * 128 + x %% 128) = (a - x %% 128) + (- (x %/ 128)) * 128) 1:/#.
by rewrite modzMDr pmod_small.
qed.

lemma size_mfin (m : bytes) :
  size (mfin m) %% 128 = if size m %% 128 <= 111 then size m %% 128 + 1 else 0.
proof.
have hr := modz_cmp (size m) 128; rewrite /mfin; case: (size m %% 128 <= 111) => h /=.
+ by rewrite size_cat /= -modzDml pmod_small /#.
rewrite !size_cat size_zeros /= (_ : max 0 (127 - size m %% 128) = 127 - size m %% 128) 1:/#.
rewrite {1}(divz_eq (size m) 128).
rewrite (_ : size m %/ 128 * 128 + size m %% 128 + 1 + (127 - size m %% 128) = (size m %/ 128 + 1) * 128) 1:/#.
exact modzMl.
qed.

lemma pad_fin (m : bytes) :
  SHA512.pad m = mfin m ++ (zeros (112 - size (mfin m) %% 128) ++ be_bytes 16 (8 * size m)).
proof.
have hr := modz_cmp (size m) 128; rewrite size_mfin /SHA512.pad /mfin.
case: (size m %% 128 <= 111) => h /=.
+ by rewrite mod128_shift 1:/# !catA /#.
rewrite (_ : 111 - size m = (239 - size m) + (-1) * 128) 1:/# modzMDr mod128_shift 1:/#.
rewrite /zeros (_ : 239 - size m %% 128 = (127 - size m %% 128) + 112) 1:/# -cat_nseq 1,2:/#.
by rewrite !catA.
qed.

lemma trunc_const (x : int) : 0 <= x < 256 => truncateu8 (W64.of_int x) = W8.of_int x.
proof.
move=> hx; apply W8.to_uint_eq; rewrite to_uint_truncateu8 W64.of_uintK W8.of_uintK.
have h1 : x %% W64.modulus = x by rewrite pmod_small /#.
have h2 : x %% W8.modulus = x by rewrite pmod_small /#.
by rewrite h1 h2.
qed.

(* The low word of the length field, 8 |m|, and its high word, zero. *)
lemma bitlen (t : W64.t) : W64.to_uint t < 2^61 =>
  W64.to_uint (t `<<` W8.of_int 3) = 8 * W64.to_uint t.
proof.
move=> ht; have := W64.to_uint_cmp t; move: ht.
by rewrite /(`<<`) W64.to_uint_shl //= => ht hb; rewrite pmod_small /#.
qed.


lemma bitlen_hi (t : W64.t) : W64.to_uint t < 2^61 => W64.to_uint (t `>>` W8.of_int 61) = 0.
proof.
move=> ht; have /= hb := W64.to_uint_cmp t; move: ht => /= ht.
by rewrite W64.shr_div_le //= pdiv_small /#.
qed.

(* Padding: the 0x80 byte, zeros, the length field, in one or two final
   blocks (FIPS 180-4 section 5.1.2). *)
lemma sha512_finalize_correct (h0 : W64.t list) (m : bytes) :
  hoare [M._sha512_finalize :
           stream512 h0 m h buf total /\ size m < 2^61 ==>
           BArray64.to_list res.`1 = flatten (map w64_be (SHA512.hash h0 m))].
proof.
proc.
seq 7 : (W64.to_uint fill = size m %% 128 + 1 /\ two_blocks = (W64.of_int 112 \ult fill) /\
         z = W64.zero /\ W64.to_uint total = size m /\
         hwords h = foldl compress h0 (parse m) /\
         pending buf (rcons (tail512 m) (W8.of_int 128)) /\ size m < 2^61).
+ auto => /> &hr ht hh hp hm.
  have hr := modz_cmp (size m) 128.
  have hf : W64.to_uint (total{hr} `&` W64.of_int 127) = size m %% 128 by rewrite and127 ht.
  rewrite W64.to_uintD_small hf /= 1:/# trunc_const //.
  by rewrite -size_tail512; apply pending_rcons => //; rewrite size_tail512 /#.
(* Two final blocks when 0x80 leaves no room for the length field. *)
seq 1 : (W64.to_uint fill = size (mfin m) %% 128 /\ size (mfin m) %% 128 <= 112 /\
         z = W64.zero /\ W64.to_uint total = size m /\
         hwords h = foldl compress h0 (parse (mfin m)) /\
         pending buf (tail512 (mfin m)) /\ size m < 2^61).
+ if.
  + seq 3 : (W64.to_uint fill = 128 /\ z = W64.zero /\ W64.to_uint total = size m /\
             hwords h = foldl compress h0 (parse m) /\
             pending buf (rcons (tail512 m) (W8.of_int 128) ++ zeros (127 - size m %% 128)) /\ 112 <= size m %% 128 /\ size m < 2^61).
    + wp; while (size m %% 128 + 1 <= W64.to_uint fill <= 128 /\ more = (fill \ult W64.of_int 128) /\
                 z = W64.zero /\ W64.to_uint total = size m /\
                 hwords h = foldl compress h0 (parse m) /\
                 pending buf (rcons (tail512 m) (W8.of_int 128) ++ zeros (W64.to_uint fill - size m %% 128 - 1)) /\
                 112 <= size m %% 128 /\ size m < 2^61).
      + auto => /> &hr h1 h2 ht hh hp h56 hm; rewrite W64.ultE /= => hlt.
        have hf1 : W64.to_uint (fill{hr} + W64.one) = W64.to_uint fill{hr} + 1.
        + by rewrite W64.to_uintD_small /= /#.
        rewrite hf1; split; first smt().
        rewrite (_ : W64.to_uint fill{hr} + 1 - size m %% 128 - 1 = (W64.to_uint fill{hr} - size m %% 128 - 1) + 1) 1:/#.
        rewrite /zeros nseqSr 1:/# -rcons_cat (trunc_const 0) //.
        have hsz : size (rcons (tail512 m) (W8.of_int 128) ++ nseq (W64.to_uint fill{hr} - size m %% 128 - 1) W8.zero) = W64.to_uint fill{hr}.
        + by rewrite size_cat size_rcons size_tail512 size_nseq /#.
        by rewrite -{1}hsz; apply pending_rcons => //; rewrite hsz /#.
      auto => /> &hr hf ht hh hp hm; rewrite W64.ultE /= hf => h56.
      split.
      + rewrite (_ : size m %% 128 + 1 - size m %% 128 - 1 = 0) 1:/# /zeros nseq0 cats0 hp /=.
        smt(modz_cmp).
      move=> buf1 fill1 more1 _ hlo hhi hult hp1 _.
      have hfe : W64.to_uint fill1 = 128 by move: hult; rewrite W64.ultE /= /#.
      by rewrite hfe /=; move: hp1; rewrite hfe; smt().
    wp; ecall (sha512_compress_correct (hwords h) buf).
    auto => /> &hr hf ht hh hp h56 hm [h1 ms1] /= hh1.
    have hb : rcons (tail512 m) (W8.of_int 128) ++ zeros (127 - size m %% 128) = tail512 m ++ ([W8.of_int 128] ++ zeros (127 - size m %% 128)).
    + by rewrite -cats1 catA.
    have hl := pending_full _ _ hp _.
    + by rewrite size_cat size_rcons size_tail512 size_zeros /#.
    have [hc ht0] := close_block h0 m ([W8.of_int 128] ++ zeros (127 - size m %% 128)) buf{hr} _.
    + by rewrite hl hb.
    have hmf : mfin m = m ++ ([W8.of_int 128] ++ zeros (127 - size m %% 128)).
    + by rewrite /mfin ifF 1:/# -catA.
    rewrite /Jslh.SLH64.protect_ptr /Jslh.SLH64.protect_64 /= size_mfin (_ : !(size m %% 128 <= 111)) 1:/# /=.
    by rewrite hh1 hh hc hmf ht0 pending_nil.
  auto => /> &hr hf ht hh hp hm; rewrite W64.ultE /= hf => h55.
  have hmf : mfin m = m ++ [W8.of_int 128] by rewrite /mfin (_ : size m %% 128 <= 111) 1:/#.
  have [hpm htm] := short_ext m [W8.of_int 128] _.
  + by rewrite size_cat size_tail512 /=; smt(modz_cmp).
  rewrite size_mfin ifT 1:/# /= hmf hpm hh htm cats1 hp /=; smt(modz_cmp).
(* Zeros up to the length field. *)
seq 3 : (pending buf (tail512 (mfin m) ++ zeros (112 - size (mfin m) %% 128)) /\ size (mfin m) %% 128 <= 112 /\
         W64.to_uint total = size m /\
         hwords h = foldl compress h0 (parse (mfin m)) /\ size m < 2^61).
+ wp; while (size (mfin m) %% 128 <= W64.to_uint fill <= 112 /\ size (mfin m) %% 128 <= 112 /\ more = (fill \ult W64.of_int 112) /\
             z = W64.zero /\ W64.to_uint total = size m /\
             hwords h = foldl compress h0 (parse (mfin m)) /\
             pending buf (tail512 (mfin m) ++ zeros (W64.to_uint fill - size (mfin m) %% 128)) /\ size m < 2^61).
  + auto => /> &hr h1 h2 h3 ht hh hp hm; rewrite W64.ultE /= => hlt.
    have hf1 : W64.to_uint (fill{hr} + W64.one) = W64.to_uint fill{hr} + 1.
    + by rewrite W64.to_uintD_small /= /#.
    rewrite hf1; split; first smt().
    rewrite (_ : W64.to_uint fill{hr} + 1 - size (mfin m) %% 128 = (W64.to_uint fill{hr} - size (mfin m) %% 128) + 1) 1:/#.
    rewrite /zeros nseqSr 1:/# -rcons_cat (trunc_const 0) //.
    have hsz : size (tail512 (mfin m) ++ nseq (W64.to_uint fill{hr} - size (mfin m) %% 128) W8.zero) = W64.to_uint fill{hr}.
    + by rewrite size_cat size_tail512 size_nseq /#.
    by rewrite -{1}hsz; apply pending_rcons => //; rewrite hsz /#.
  auto => /> &hr hf hs ht hh hp hm; split.
  + by rewrite hf /= /zeros nseq0 cats0 hp; smt(modz_ge0).
  move=> buf1 fill1 more1 _ hlo hhi hult hp1.
  have hfe : W64.to_uint fill1 = 112 by move: hult; rewrite W64.ultE /= /#.
  by move: hp1; rewrite hfe; smt().
(* The length block, then the output words big-endian. *)
wp; while (0 <= i <= 8 /\ hwords h = SHA512.hash h0 m /\
           forall k, 0 <= k < i => BArray64.get64 out k = WordSpec.bswap64 (BArray64.get64 h k)).
+ wp; ecall (bswap64_spec x); auto => /> &hr hi0 hi8 hh hk hlt; split; first smt().
  move=> k hk0 hk1; rewrite BArray64.get_set64E 1,2:/#.
  by case: (i{hr} = k) => [<-|ne] //; apply hk => /#.
wp; ecall (sha512_compress_correct (hwords h) buf); wp; ecall (bswap64_spec t); wp.
ecall (bswap64_spec t); auto => /> &hr hp hs ht hh hm [h1 ms1] /= hh1.
have hsz : size (tail512 (mfin m) ++ zeros (112 - size (mfin m) %% 128)) = 112.
+ by rewrite size_cat size_tail512 size_zeros; smt(modz_ge0).
have hl := len_block _ _ (total{hr} `>>` W8.of_int 61) (total{hr} `<<` W8.of_int 3) hp hsz.
have [hc _] := close_block h0 (mfin m) (zeros (112 - size (mfin m) %% 128) ++ be_bytes 16 (8 * size m))
  (BArray128.set64d (BArray128.set64d buf{hr} 112 (WordSpec.bswap64 (total{hr} `>>` W8.of_int 61)))
     120 (WordSpec.bswap64 (total{hr} `<<` W8.of_int 3))) _.
+ rewrite hl bitlen 1:/# bitlen_hi 1:/# ht be16; first smt(size_ge0).
  by rewrite !catA.
split.
+ rewrite /Jslh.SLH64.protect_ptr /= hh1 hh hc -pad_fin /SHA512.hash /=.
  by move=> k; smt().
move=> i out1 hn hi0 hi8 _ hk.
have -> : SHA512.hash h0 m = hwords h1.
+ by rewrite hh1 hh hc -pad_fin.
apply out_bytes; first exact size_hwords.
by move=> k hk'; rewrite nth_hwords // hk /#.
qed.

lemma bswap64_ll : islossless M.__bswap64.
proof. by proc; auto. qed.

lemma sha512_finalize_ll : islossless M._sha512_finalize.
proof.
proc.
seq 7 : true 1%r 1%r 0%r 0%r => //; first by auto.
seq 1 : true 1%r 1%r 0%r 0%r => //.
+ if; last by auto.
  seq 2 : (more = (fill \ult W64.of_int 128)) 1%r 1%r 0%r 0%r => //; last by hoare; auto.
  + by auto.
  wp; call sha512_compress_ll; wp.
  while (more = (fill \ult W64.of_int 128)) (128 - W64.to_uint fill).
  + move=> z0; auto => /> &hr; rewrite W64.ultE /= => hlt.
    by rewrite W64.to_uintD_small /= /#.
  by auto => /> f; rewrite W64.ultE /= /#.
seq 1 : (more = (fill \ult W64.of_int 112)) 1%r 1%r 0%r 0%r => //; last by hoare; auto.
+ by auto.
seq 1 : true 1%r 1%r 0%r 0%r => //.
+ while (more = (fill \ult W64.of_int 112)) (112 - W64.to_uint fill).
  + move=> z0; auto => /> &hr; rewrite W64.ultE /= => hlt.
    by rewrite W64.to_uintD_small /= /#.
  by auto => /> f; rewrite W64.ultE /= /#.
wp; while (true) (8 - i).
+ by move=> z0; wp; call bswap64_ll; auto => /#.
wp; call sha512_compress_ll; wp; call bswap64_ll; wp; call bswap64_ll.
by auto => /#.
qed.

lemma sha512_finalize_total (h0 : W64.t list) (m : bytes) :
  phoare [M._sha512_finalize :
           stream512 h0 m h buf total /\ size m < 2^61 ==>
           BArray64.to_list res.`1 = flatten (map w64_be (SHA512.hash h0 m))] = 1%r.
proof. by conseq sha512_finalize_ll (sha512_finalize_correct h0 m). qed.


(* ------------------------------------------------------------------ *)
(* One-shot SHA-512, SHA-384, SHA-512/224 and SHA-512/256             *)

lemma hwords_eq (h : BArray64.t) (iv : W64.t list) : size iv = 8 =>
  (forall k, 0 <= k < 8 => BArray64.get64 h k = nth W64.zero iv k) => hwords h = iv.
proof.
move=> hs hk; apply (eq_from_nth W64.zero); first by rewrite size_hwords hs.
by move=> k; rewrite size_hwords => hk'; rewrite nth_hwords // hk.
qed.

lemma sha512_load_iv_correct (iv0 : BArray64.t) :
  hoare [M.__sha512_load_iv :
           iv = iv0 ==> forall k, 0 <= k < 8 => BArray64.get64 res k = BArray64.get64 iv0 k].
proof.
proc; while (0 <= i <= 8 /\ iv = iv0 /\
             forall k, 0 <= k < i => BArray64.get64 h k = BArray64.get64 iv0 k).
+ auto => /> &hr hi0 hi8 hk hlt; split; first smt().
  move=> k hk0 hk1; rewrite BArray64.get_set64E 1,2:/#.
  by case: (i{hr} = k) => [<-|ne] //; apply hk => /#.
auto => /> &hr; split; first smt().
by move=> hv i hn hi0 hi8 hk k hk0 hk1; apply hk => /#.
qed.

lemma sha512_load_iv_ll : islossless M.__sha512_load_iv.
proof. by proc; while (true) (8 - i); auto => /#. qed.

lemma sha512_init_ll : islossless M.__sha512_init.
proof. by proc; call sha512_load_iv_ll. qed.

lemma IV512_kernel k : 0 <= k < 8 => BArray64.get64 sHA512_IV k = nth W64.zero H0_512 k.
proof. by move=> hk; rewrite BArray64.get64_of_list64 1://; congr; rewrite /H0_512 /=. qed.

lemma sha512_init_correct : hoare [M.__sha512_init : true ==> hwords res = H0_512].
proof.
proc; ecall (sha512_load_iv_correct sHA512_IV); auto => /> r hr.
by apply hwords_eq; [rewrite /H0_512 | move=> k hk; rewrite hr // IV512_kernel].
qed.

lemma IV384_kernel k : 0 <= k < 8 => BArray64.get64 sHA384_IV k = nth W64.zero H0_384 k.
proof. by move=> hk; rewrite BArray64.get64_of_list64 1://; congr; rewrite /H0_384 /=. qed.

lemma sha384_init_correct : hoare [M.__sha384_init : true ==> hwords res = H0_384].
proof.
proc; ecall (sha512_load_iv_correct sHA384_IV); auto => /> r hr.
by apply hwords_eq; [rewrite /H0_384 | move=> k hk; rewrite hr // IV384_kernel].
qed.

lemma IV512_224_kernel k : 0 <= k < 8 => BArray64.get64 sHA512_224_IV k = nth W64.zero H0_512_224 k.
proof. by move=> hk; rewrite BArray64.get64_of_list64 1://; congr; rewrite /H0_512_224 /=. qed.

lemma sha512_224_init_correct : hoare [M.__sha512_224_init : true ==> hwords res = H0_512_224].
proof.
proc; ecall (sha512_load_iv_correct sHA512_224_IV); auto => /> r hr.
by apply hwords_eq; [rewrite /H0_512_224 | move=> k hk; rewrite hr // IV512_224_kernel].
qed.

lemma IV512_256_kernel k : 0 <= k < 8 => BArray64.get64 sHA512_256_IV k = nth W64.zero H0_512_256 k.
proof. by move=> hk; rewrite BArray64.get64_of_list64 1://; congr; rewrite /H0_512_256 /=. qed.

lemma sha512_256_init_correct : hoare [M.__sha512_256_init : true ==> hwords res = H0_512_256].
proof.
proc; ecall (sha512_load_iv_correct sHA512_256_IV); auto => /> r hr.
by apply hwords_eq; [rewrite /H0_512_256 | move=> k hk; rewrite hr // IV512_256_kernel].
qed.

lemma sha512_mem_from_correct (h0 : W64.t list) (p0 l0 : W64.t) :
  hoare [M.__sha512_mem_from :
           hwords h = h0 /\ in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           BArray64.to_list res.`1
           = flatten (map w64_be (SHA512.hash h0 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))))].
proof.
proc.
ecall (sha512_finalize_correct h0 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))); wp.
ecall (sha512_absorb_mem_correct h0 [] p0 l0); wp.
while (true); first by auto.
auto => /> &hr hb hl buf1 i1 _.
rewrite parse_short // tail_short //= pending_nil /=; split; first smt(W64.to_uint_cmp).
by move=> _ r *; rewrite size_memread; smt(W64.to_uint_cmp).
qed.

lemma sha512_mem_correct (p0 l0 : W64.t) :
  hoare [M._sha512_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           BArray64.to_list res.`1 = SHA512.sha512 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))].
proof.
proc; ecall (sha512_mem_from_correct H0_512 p0 l0); call sha512_init_correct.
by auto => /> &hr _ _ h1 _ r ->; rewrite /SHA512.sha512 /SHA512.digest.
qed.

lemma sha512_mem_ll : islossless M._sha512_mem.
proof.
proc; inline M.__sha512_mem_from M.__sha512_init.
wp; call sha512_finalize_ll; wp; call sha512_absorb_mem_ll; wp.
while (true) (16 - i); first by auto => /#.
wp; call sha512_load_iv_ll.
by auto => /#.
qed.

lemma sha512_mem_total (p0 l0 : W64.t) :
  phoare [M._sha512_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           BArray64.to_list res.`1 = SHA512.sha512 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))] = 1%r.
proof. by conseq sha512_mem_ll (sha512_mem_correct p0 l0). qed.

lemma sha384_mem_correct (p0 l0 : W64.t) :
  hoare [M._sha384_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           take 48 (BArray64.to_list res.`1) = SHA512.sha384 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))].
proof.
proc; ecall (sha512_mem_from_correct H0_384 p0 l0); call sha384_init_correct.
by auto => /> &hr _ _ h1 _ r ->; rewrite /SHA512.sha384 /SHA512.digest.
qed.

lemma sha384_mem_ll : islossless M._sha384_mem.
proof.
proc; inline M.__sha512_mem_from M.__sha384_init.
wp; call sha512_finalize_ll; wp; call sha512_absorb_mem_ll; wp.
while (true) (16 - i); first by auto => /#.
wp; call sha512_load_iv_ll.
by auto => /#.
qed.

lemma sha384_mem_total (p0 l0 : W64.t) :
  phoare [M._sha384_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           take 48 (BArray64.to_list res.`1) = SHA512.sha384 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))] = 1%r.
proof. by conseq sha384_mem_ll (sha384_mem_correct p0 l0). qed.

lemma sha512_224_mem_correct (p0 l0 : W64.t) :
  hoare [M._sha512_224_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           take 28 (BArray64.to_list res.`1) = SHA512.sha512_224 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))].
proof.
proc; ecall (sha512_mem_from_correct H0_512_224 p0 l0); call sha512_224_init_correct.
by auto => /> &hr _ _ h1 _ r ->; rewrite /SHA512.sha512_224 /SHA512.digest.
qed.

lemma sha512_224_mem_ll : islossless M._sha512_224_mem.
proof.
proc; inline M.__sha512_mem_from M.__sha512_224_init.
wp; call sha512_finalize_ll; wp; call sha512_absorb_mem_ll; wp.
while (true) (16 - i); first by auto => /#.
wp; call sha512_load_iv_ll.
by auto => /#.
qed.

lemma sha512_224_mem_total (p0 l0 : W64.t) :
  phoare [M._sha512_224_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           take 28 (BArray64.to_list res.`1) = SHA512.sha512_224 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))] = 1%r.
proof. by conseq sha512_224_mem_ll (sha512_224_mem_correct p0 l0). qed.

lemma sha512_256_mem_correct (p0 l0 : W64.t) :
  hoare [M._sha512_256_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           take 32 (BArray64.to_list res.`1) = SHA512.sha512_256 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))].
proof.
proc; ecall (sha512_mem_from_correct H0_512_256 p0 l0); call sha512_256_init_correct.
by auto => /> &hr _ _ h1 _ r ->; rewrite /SHA512.sha512_256 /SHA512.digest.
qed.

lemma sha512_256_mem_ll : islossless M._sha512_256_mem.
proof.
proc; inline M.__sha512_mem_from M.__sha512_256_init.
wp; call sha512_finalize_ll; wp; call sha512_absorb_mem_ll; wp.
while (true) (16 - i); first by auto => /#.
wp; call sha512_load_iv_ll.
by auto => /#.
qed.

lemma sha512_256_mem_total (p0 l0 : W64.t) :
  phoare [M._sha512_256_mem :
           in_0 = p0 /\ inlen = l0 /\
           W64.to_uint p0 + W64.to_uint l0 < W64.modulus /\ W64.to_uint l0 < 2^61 ==>
           take 32 (BArray64.to_list res.`1) = SHA512.sha512_256 (memread Glob.mem (W64.to_uint p0) (W64.to_uint l0))] = 1%r.
proof. by conseq sha512_256_mem_ll (sha512_256_mem_correct p0 l0). qed.
