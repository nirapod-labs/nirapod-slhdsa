(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sponge.ec
 * =========
 *
 * Functional correctness of the single-way Keccak sponge of
 * src/hash/keccak/sponge.jinc against FIPS 202 section 4
 * (Keccak1600_Spec), in the byte view of ShakeSponge.ec: the state st with
 * byte position pos holds the message m when absorbing r8 m st pos, that
 * is, when the full r8-byte blocks of m are absorbed and the bytes of the
 * incomplete last block are XORed in at [0, size m %% r8).
 *
 * The sponge calls the permutation _keccakf1600, whose model differs
 * between the kernels a pair builds. Its correctness is the section
 * hypothesis kf_h (with kf_ll for termination); the theorems below hold
 * under it and take it as their first premises once the section is
 * closed. Sponge_Portable.ec, on the pairs that build the portable kernel,
 * and Sponge_KernelSpec.ec, on aarch64/a64scalar, discharge both with that
 * kernel's Keccak-f[1600] theorems.
 *
 * Theorems (total correctness, under kf_h and kf_ll):
 *     keccak_finalize_total    the state after padding and permuting is
 *                              Keccak-f of ABSORB1600 trail r8 m
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils JMemory.
from JazzEC require import Array25 WArray200.
require import BArray200 KeccakState.
require import Keccakf1600_Spec Keccak1600_Spec JWordList.
require import HashExtracted ArchWord ShakeSponge.

(* ------------------------------------------------------------------ *)
(* Byte operations of the code                                        *)

lemma trunc_bits8 (x : W64.t) : truncateu8 x = x \bits8 0.
proof. by apply W8.to_uint_eq; rewrite to_uint_truncateu8 W8u8.bits8_div // W8.of_uintK. qed.

lemma trunc_bit (x : W64.t) (i : int) : 0 <= i < 8 => (truncateu8 x).[i] = x.[i].
proof. by move=> hi; rewrite trunc_bits8 W8u8.bits8E W8.initiE. qed.

lemma trunc_zext8 (b : W8.t) : truncateu8 (zeroextu64 b) = b.
proof.
apply W8.to_uint_eq; rewrite to_uint_truncateu8 to_uint_zeroextu64.
by rewrite pmod_small //; apply W8.to_uint_cmp.
qed.

(* The code XORs a byte into the state through a 64-bit register. *)
lemma trunc_xor8 (b : W8.t) (w : W64.t) : truncateu8 (zeroextu64 b `^` w) = b `^` truncateu8 w.
proof.
apply W8.wordP => i hi; rewrite trunc_bit // W64.xorwE W8.xorwE (trunc_bit w) //.
by rewrite -(trunc_bit (zeroextu64 b) i hi) trunc_zext8.
qed.

lemma trunc_128 : truncateu8 (W64.of_int 128) = W8.of_int 128.
proof. by apply W8.to_uint_eq; rewrite to_uint_truncateu8 W64.of_uintK !W8.of_uintK. qed.

(* ------------------------------------------------------------------ *)
(* XOR of memory bytes into the state (__keccak_xor_mem)              *)

(* The state s with the memory bytes at q, q + 1, ... XORed into the
   bytes [p, e): the effect of __keccak_xor_mem once pos has reached e. *)
op xorx (s : BArray200.t) (p : int) (mem : global_mem_t) (q e : int) : BArray200.t =
  BArray200.init (fun j => if p <= j < e then s.[j] `^` loadW8 mem (q + (j - p)) else s.[j]).

lemma xorxE s p mem q e j : 0 <= j < 200 =>
  (xorx s p mem q e).[j] = if p <= j < e then s.[j] `^` loadW8 mem (q + (j - p)) else s.[j].
proof. by move=> hj; rewrite /xorx BArray200.initiE. qed.

lemma xorx0 s p mem q : xorx s p mem q p = s.
proof. by apply BArray200.tP => j hj; rewrite xorxE // ifF 1:/#. qed.

lemma xorx_byte s p mem q e : p <= e => 0 <= e < 200 =>
  xorx s p mem q (e + 1) = (xorx s p mem q e).[e <- (xorx s p mem q e).[e] `^` loadW8 mem (q + (e - p))].
proof.
move=> hp he; apply BArray200.tP => j hj.
by rewrite BArray200.get_setE 1:/# !xorxE // 1:/#; smt().
qed.

lemma xorx_lane s p mem q e : p <= e => 0 <= e => e + 8 <= 200 =>
  xorx s p mem q (e + 8) =
  BArray200.set64d (xorx s p mem q e) e (BArray200.get64d (xorx s p mem q e) e `^` loadW64 mem (q + (e - p))).
proof.
move=> hp he he8; apply BArray200.tP => j hj.
rewrite BArray200.get8_set64dE xorxE //.
case: (e <= j < e + 8 /\ 0 <= j < 200) => h /=; last by rewrite ?xorxE // /#.
rewrite BArray200.get64d_byte 1:/# loadW64_bits8 1:/# xorxE 1:/# ifT 1:/# ifF 1:/#.
by congr; congr; ring.
qed.

(* The word minimum the code computes is at most its first argument. *)
lemma umin_le (a b : W64.t) : to_uint (if a \ult b then a else b) <= to_uint a.
proof. by case: (a \ult b) => h //; move: h; rewrite W64.ultE /#. qed.

(* The word bound with 2^64 as a literal, which smt can use. *)
lemma ucmp (x : W64.t) : 0 <= to_uint x < 18446744073709551616.
proof. by have /= := W64.to_uint_cmp x. qed.

(* Counter steps that stay below 2^64. *)
lemma inc1 (x : W64.t) : to_uint x + 1 < 18446744073709551616 => to_uint (x + W64.one) = to_uint x + 1.
proof. by move=> h; rewrite W64.to_uintD_small W64.to_uint1 // /#. qed.

lemma inc8 (x : W64.t) : to_uint x + 8 < 18446744073709551616 => to_uint (x + W64.of_int 8) = to_uint x + 8.
proof.
have h8 : to_uint (W64.of_int 8) = 8 by rewrite W64.of_uintK.
by move=> h; have := W64.to_uintD_small x (W64.of_int 8); rewrite h8 /= => /(_ h).
qed.

lemma dec8 (x : W64.t) : 8 <= to_uint x => to_uint (x - W64.of_int 8) = to_uint x - 8.
proof.
have h8 : to_uint (W64.of_int 8) = 8 by rewrite W64.of_uintK.
by move=> h; have := W64.to_uintB x (W64.of_int 8); rewrite W64.uleE h8 => /(_ h).
qed.

lemma xor_mem_h (s0 : BArray200.t) (mem0 : global_mem_t) (p k q : int) :
  hoare [M.__keccak_xor_mem :
    st = s0 /\ Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint n_ = k /\
    to_uint in_0 + to_uint off_ = q /\ p + k <= 200 /\ q + k <= W64.modulus /\
    to_uint off_ + k < W64.modulus
    ==> Glob.mem = mem0 /\ res.`1 = xorx s0 p mem0 q (p + k)].
proof.
proc.
seq 11 : ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint end_0 = p + to_uint head /\ to_uint head + to_uint n = k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)).
+ auto => /> &hr hpk hqk hok.
  have hm := umin_le n_{hr} ((- pos_{hr}) `&` W64.of_int 7).
  have hc := ucmp pos_{hr}.
  by rewrite xorx0 /= W64.to_uintD_small 1:/# W64.to_uintB 1:W64.uleE 1:/#; smt(ucmp).
seq 1 : ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint end_0 = p + to_uint head /\ to_uint head + to_uint n = k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0) /\ !more).
+ while ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint end_0 = p + to_uint head /\ to_uint head + to_uint n = k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)); last by skip => /> *.
  auto => /> &hr; rewrite W64.ultE => *.
  have hc := ucmp in_0{hr}; have hn0 := ucmp n{hr}; have hh0 := ucmp head{hr}.
  have e1 : to_uint (pos{hr} + W64.one) = to_uint pos{hr} + 1 by apply inc1; smt(ucmp).
  have e2 : to_uint (off{hr} + W64.one) = to_uint off{hr} + 1 by apply inc1; smt(ucmp).
  have e3 : to_uint (in_0{hr} + off{hr}) = to_uint in_0{hr} + to_uint off{hr}.
  + by rewrite W64.to_uintD_small; smt(ucmp).
  rewrite trunc_xor8 trunc_zext8 e1 e2 e3 xorx_byte 1,2:/#.
  have -> : to_uint in_0{hr} + to_uint off{hr} = to_uint in_0{hr} + to_uint off_{hr} + (to_uint pos{hr} - to_uint pos_{hr}) by smt().
  smt(ucmp).
seq 2 : ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint pos - p + to_uint n = k) /\ more = ((W64.of_int 8) \ule n)).
+ by auto => /> &hr; rewrite W64.ultE => *; smt(ucmp).
seq 1 : ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint pos - p + to_uint n = k) /\ more = ((W64.of_int 8) \ule n) /\ !more).
+ while ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint pos - p + to_uint n = k) /\ more = ((W64.of_int 8) \ule n)); last by skip => /> *.
  auto => /> &hr; rewrite W64.uleE /= => *.
  have hc := ucmp in_0{hr}; have hn0 := ucmp n{hr}; have hh0 := ucmp head{hr}.
  have e1 : to_uint (pos{hr} + W64.of_int 8) = to_uint pos{hr} + 8 by apply inc8; smt(ucmp).
  have e2 : to_uint (off{hr} + W64.of_int 8) = to_uint off{hr} + 8 by apply inc8; smt(ucmp).
  have e4 : to_uint (n{hr} - W64.of_int 8) = to_uint n{hr} - 8 by apply dec8; smt(ucmp).
  have e3 : to_uint (in_0{hr} + off{hr}) = to_uint in_0{hr} + to_uint off{hr}.
  + by rewrite W64.to_uintD_small; smt(ucmp).
  rewrite e1 e2 e4 e3 xorx_lane 1..3:/#.
  have -> : to_uint in_0{hr} + to_uint off{hr} = to_uint in_0{hr} + to_uint off_{hr} + (to_uint pos{hr} - to_uint pos_{hr}) by smt().
  smt(ucmp).
seq 4 : ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint end_0 = p + k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)).
+ by auto => /> &hr; rewrite W64.uleE /= => *; rewrite W64.to_uintD_small; smt(ucmp).
seq 1 : ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint end_0 = p + k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0) /\ !more).
+ while ((Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint in_0 + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ st = xorx s0 p mem0 q (to_uint pos) /\
    to_uint end_0 = p + k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)); last by skip => /> *.
  auto => /> &hr; rewrite W64.ultE => *.
  have hc := ucmp in_0{hr}; have hn0 := ucmp n{hr}; have hh0 := ucmp head{hr}.
  have e1 : to_uint (pos{hr} + W64.one) = to_uint pos{hr} + 1 by apply inc1; smt(ucmp).
  have e2 : to_uint (off{hr} + W64.one) = to_uint off{hr} + 1 by apply inc1; smt(ucmp).
  have e3 : to_uint (in_0{hr} + off{hr}) = to_uint in_0{hr} + to_uint off{hr}.
  + by rewrite W64.to_uintD_small; smt(ucmp).
  rewrite trunc_xor8 trunc_zext8 e1 e2 e3 xorx_byte 1,2:/#.
  have -> : to_uint in_0{hr} + to_uint off{hr} = to_uint in_0{hr} + to_uint off_{hr} + (to_uint pos{hr} - to_uint pos_{hr}) by smt().
  smt(ucmp).
by auto => /> &hr; rewrite W64.ultE => *; smt(ucmp).
qed.

lemma xor_mem_ll : islossless M.__keccak_xor_mem.
proof.
proc.
seq 11 : (more = (pos \ult end_0)) 1%r 1%r 0%r 0%r => //; last by hoare; auto.
+ by auto.
seq 1 : true 1%r 1%r 0%r 0%r => //.
+ while (more = (pos \ult end_0)) (to_uint end_0 - to_uint pos).
  + move=> z; auto => /> &hr; rewrite W64.ultE => hlt.
    by rewrite inc1; smt(ucmp).
  by auto => /> &hr p; rewrite W64.ultE; smt(ucmp).
seq 2 : (more = ((W64.of_int 8) \ule n)) 1%r 1%r 0%r 0%r => //; last by hoare; auto.
+ by auto.
seq 1 : true 1%r 1%r 0%r 0%r => //.
+ while (more = ((W64.of_int 8) \ule n)) (to_uint n).
  + by move=> z; auto => /> &hr; rewrite W64.uleE /= => h8; rewrite dec8 // /#.
  by auto => /> n0; rewrite W64.uleE /=; smt(ucmp).
wp; while (more = (pos \ult end_0)) (to_uint end_0 - to_uint pos).
+ move=> z; auto => /> &hr; rewrite W64.ultE => hlt.
  by rewrite inc1; smt(ucmp).
by auto => /> &hr p; rewrite W64.ultE; smt(ucmp).
qed.

(* ------------------------------------------------------------------ *)
(* One absorbing step in the byte view                                *)

lemma xorx_xorb (s : BArray200.t) p mem q k : 0 <= p => 0 <= k => p + k <= 200 =>
  stbytes (lanes (xorx s p mem q (p + k))) = xorb_at (stbytes (lanes s)) p (memread mem q k).
proof.
move=> hp hk hpk; apply WArray200.tP => j hj.
rewrite xorb_atE // !stbytes_lanes // xorxE // size_memread //.
by case: (p <= j < p + k) => h //; rewrite nth_memread 1:/#.
qed.

(* k bytes that leave the block incomplete: XORed in, pos advances. *)
lemma absorb_lt r8 (m : W8.t list) st (pos pos' : W64.t) mem q k :
  0 < r8 < 200 => absorbing r8 m st pos => 0 <= k => to_uint pos + k < r8 =>
  to_uint pos' = to_uint pos + k =>
  absorbing r8 (m ++ memread mem q k) (xorx st (to_uint pos) mem q (to_uint pos + k)) pos'.
proof.
move=> hr [hpos hst] hk hlt hp'; split.
+ by rewrite size_cat size_memread // hp' -modzDml -hpos pmod_small //; smt(ucmp).
apply stbytes_inj; rewrite abs_cat_lt 1:/#; first by rewrite size_memread // -hpos.
by rewrite -hst -hpos xorx_xorb //; smt(ucmp).
qed.

(* k bytes that complete the block: the block is ready for the permutation. *)
lemma absorb_eq r8 (m : W8.t list) st (pos : W64.t) mem q k :
  0 < r8 < 200 => absorbing r8 m st pos => 0 <= k => to_uint pos + k = r8 =>
  size (m ++ memread mem q k) %% r8 = 0 /\
  abs_state r8 (m ++ memread mem q k) = keccak_f1600_op (lanes (xorx st (to_uint pos) mem q (to_uint pos + k))).
proof.
move=> hr [hpos hst] hk heq; split.
+ by rewrite size_cat size_memread // -modzDml -hpos heq modzz.
rewrite abs_cat_eq 1:/#; first by rewrite size_memread // -hpos.
by congr; apply stbytes_inj; rewrite stwordsK -hst -hpos xorx_xorb //; smt(ucmp).
qed.

(* The block length the code takes: n = min(inlen, rate - pos). *)
lemma absorb_n (pos rate inlen : W64.t) : to_uint pos < to_uint rate =>
  to_uint (if inlen \ult (rate - pos) then inlen else rate - pos) <= to_uint inlen /\
  to_uint pos + to_uint (if inlen \ult (rate - pos) then inlen else rate - pos) <= to_uint rate /\
  (inlen <> W64.zero => 0 < to_uint (if inlen \ult (rate - pos) then inlen else rate - pos)).
proof.
move=> hlt; have hb : to_uint (rate - pos) = to_uint rate - to_uint pos.
+ by rewrite W64.to_uintB // W64.uleE /#.
have h0 : inlen <> W64.zero => 0 < to_uint inlen.
+ by move=> hne; have := ucmp inlen; smt(W64.to_uint_eq W64.to_uint0).
case: (inlen \ult (rate - pos)) => h /=; move: h; rewrite W64.ultE hb; smt(ucmp).
qed.

lemma xor_mem_true : hoare [M.__keccak_xor_mem : true ==> true].
proof.
proc; wp; while true; first by auto.
wp; while true; first by auto.
wp; while true; first by auto.
by auto.
qed.

(* ------------------------------------------------------------------ *)
(* The sponge procedures, under the permutation's correctness         *)

section.

declare axiom kf_h (s0 : BArray200.t) :
  hoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)].
declare axiom kf_ll : islossless M._keccakf1600.

lemma keccak_finalize_h (r8 : int) (m0 : W8.t list) (trail : W8.t) :
  hoare [M._keccak_finalize :
    absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200 /\ truncateu8 ds = trail
    ==> lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 m0)].
proof.
proc; ecall (kf_h st); auto => /> &hr hpos hst hr0 hr1 r ->; congr.
have hrm : to_uint (rate{hr} - W64.one) = to_uint rate{hr} - 1.
+ rewrite W64.to_uintB; first by rewrite W64.uleE W64.to_uint1 /#.
  by rewrite W64.to_uint1.
rewrite -abs_final // -hst -hpos; apply stbytes_inj; rewrite stwordsK; apply WArray200.tP => j hj.
have hp0 : 0 <= to_uint pos{hr} < 200 by smt().
have hr2 : 0 <= to_uint rate{hr} - 1 < 200 by smt().
rewrite stbytes_lanes // !xorb_atE //= !BArray200.get_setE ?hrm // !trunc_xor8 ?trunc_128.
rewrite stbytes_lanes //.
case: (j = to_uint rate{hr} - 1) => h1; case: (j = to_uint pos{hr}) => h2.
+ have -> : j = to_uint pos{hr} by smt().
  smt().
+ have -> : (to_uint pos{hr} <= j < to_uint pos{hr} + 1) = false by smt().
  have -> : j - (to_uint rate{hr} - 1) = 0 by smt().
  smt(W8.xorw0).
+ have -> : (to_uint rate{hr} - 1 <= j < to_uint rate{hr}) = false by smt().
  have -> : j - to_uint pos{hr} = 0 by smt().
  smt(W8.xorw0).
have -> : (to_uint rate{hr} - 1 <= j < to_uint rate{hr}) = false by smt().
have -> : (to_uint pos{hr} <= j < to_uint pos{hr} + 1) = false by smt().
smt().
qed.

lemma keccak_finalize_ll : islossless M._keccak_finalize.
proof. by proc; call kf_ll; auto. qed.

lemma keccak_finalize_total (r8 : int) (m0 : W8.t list) (trail : W8.t) :
  phoare [M._keccak_finalize :
    absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200 /\ truncateu8 ds = trail
    ==> lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 m0)] = 1%r.
proof. by conseq keccak_finalize_ll (keccak_finalize_h r8 m0 trail). qed.

lemma keccak_absorb_mem_h (r8 : int) (m0 : W8.t list) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  hoare [M._keccak_absorb_mem :
    Glob.mem = mem0 /\ absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 < 200
    /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0
    /\ absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint l0)) res.`1 res.`2].
proof.
proc.
wp; while (Glob.mem = mem0 /\ to_uint rate = r8 /\ 0 < r8 < 200 /\ in_0 = p0 /\
    to_uint p0 + to_uint l0 <= W64.modulus /\ to_uint off + to_uint inlen = to_uint l0 /\
    absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint off)) st pos /\ more = (inlen <> W64.zero)).
+ seq 9 : (Glob.mem = mem0 /\ to_uint rate = r8 /\ 0 < r8 < 200 /\ in_0 = p0 /\
    to_uint p0 + to_uint l0 <= W64.modulus /\ to_uint off + to_uint inlen = to_uint l0 /\
    full = (pos = rate) /\ to_uint pos <= r8 /\
    (to_uint pos < r8 => absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint off)) st pos) /\
    (to_uint pos = r8 => size (m0 ++ memread mem0 (to_uint p0) (to_uint off)) %% r8 = 0 /\
       abs_state r8 (m0 ++ memread mem0 (to_uint p0) (to_uint off)) = keccak_f1600_op (lanes st))).
  + wp; ecall (xor_mem_h st mem0 (to_uint pos) (to_uint n) (to_uint in_0 + to_uint off)).
    auto => /> &hr hr0 hr1 hpl hoff hpos hst hne.
    have hpr : to_uint pos{hr} < to_uint rate{hr} by rewrite hpos; smt(modz_ge0 ltz_pmod).
    have habs : absorbing (to_uint rate{hr}) (m0 ++ memread mem0 (to_uint p0) (to_uint off{hr})) st{hr} pos{hr} by done.
    have [hn1 [hn2 hn3]] := absorb_n pos{hr} rate{hr} inlen{hr} hpr.
    have hn4 := hn3 hne.
    move: hn1 hn2 hn4; pose n := (if _ then _ else _); move=> hn1 hn2 hn4.
    have ep : to_uint (pos{hr} + n) = to_uint pos{hr} + to_uint n by rewrite W64.to_uintD_small; smt(ucmp).
    have eo : to_uint (off{hr} + n) = to_uint off{hr} + to_uint n by rewrite W64.to_uintD_small; smt(ucmp).
    have ei : to_uint (inlen{hr} - n) = to_uint inlen{hr} - to_uint n by rewrite W64.to_uintB // W64.uleE.
    have em : memread mem0 (to_uint p0) (to_uint off{hr} + to_uint n) =
              memread mem0 (to_uint p0) (to_uint off{hr}) ++ memread mem0 (to_uint p0 + to_uint off{hr}) (to_uint n).
    + by rewrite memread_add; smt(ucmp).
    have hl0 := ucmp l0.
    split; first by move: hn1 hn2 hl0 hr1 hpl hoff; clear habs hst; smt().
    move=> _ _ _ r ->; rewrite ep eo ei em catA.
    split; first smt().
    split; first by smt().
    have hr : 0 < to_uint rate{hr} < 200 by done.
    have hk0 : 0 <= to_uint n by smt().
    split; first by move=> hlt; have := absorb_lt _ _ _ _ _ mem0 (to_uint p0 + to_uint off{hr}) _ hr habs hk0 hlt ep; rewrite /absorbing ep.
    by move=> heq; apply (absorb_eq _ _ _ _ mem0 (to_uint p0 + to_uint off{hr}) _ hr habs hk0 heq).
  if.
  + wp; ecall (kf_h st); auto => /> &hr.
    by rewrite /Jslh.SLH64.protect_64 /= => _ _ _ _ [hm hs] r ->; rewrite hm hs.
  auto => /> &hr _ _ _ _ hle hlt _ hne.
  have h : to_uint pos{hr} < to_uint rate{hr}.
  + by move: hne; rewrite W64.to_uint_eq; smt().
  by have := hlt h; rewrite /absorbing.
auto => /> &hr hm hst hr0 hr1 hpl; split; first by rewrite cats0.
move=> inlen' more' off' pos' rate' st' _ _ hoff' hp' hs' h0.
have hz : inlen' = W64.zero by smt().
have ho : to_uint off' = to_uint l0 by rewrite -hoff' hz W64.to_uint0.
by rewrite hp' hs' ho.
qed.

lemma keccak_absorb_mem_ll :
  phoare [M._keccak_absorb_mem : to_uint pos < to_uint rate ==> true] = 1%r.
proof.
proc; wp.
while (to_uint pos < to_uint rate /\ more = (inlen <> W64.zero)) (to_uint inlen).
+ move=> z.
  conseq (: true ==> true) (: to_uint pos < to_uint rate /\ more = (inlen <> W64.zero) /\ more /\
           to_uint inlen = z ==> to_uint pos < to_uint rate /\ more = (inlen <> W64.zero) /\ to_uint inlen < z).
  + by move=> &hr />.
  + by move=> &hr />.
  + seq 9 : (0 < to_uint rate /\ full = (pos = rate) /\ to_uint pos <= to_uint rate /\ to_uint inlen < z).
    + wp; call xor_mem_true; auto => /> &hr hpr hne.
      have [hn1 [hn2 hn3]] := absorb_n pos{hr} rate{hr} inlen{hr} hpr.
      have hn4 := hn3 hne.
      move: hn1 hn2 hn4; pose n := (if _ then _ else _); move=> hn1 hn2 hn4.
      have ep : to_uint (pos{hr} + n) = to_uint pos{hr} + to_uint n by rewrite W64.to_uintD_small; smt(ucmp).
      have ei : to_uint (inlen{hr} - n) = to_uint inlen{hr} - to_uint n by rewrite W64.to_uintB // W64.uleE.
      rewrite ep ei; smt(ucmp).
    if.
    + wp; ecall (kf_h st); auto => /> &hr *; rewrite /Jslh.SLH64.protect_64 /=; smt(ucmp).
    by auto => /> &hr h0 hle hlt; rewrite W64.to_uint_eq; smt().
  seq 9 : true 1%r 1%r 0%r 0%r => //.
  + by wp; call xor_mem_ll; auto.
  by if; [wp; call kf_ll |]; auto.
by auto => /> &hr hlt; smt(ucmp W64.to_uint_eq W64.to_uint0).
qed.

lemma keccak_absorb_mem_total (r8 : int) (m0 : W8.t list) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._keccak_absorb_mem :
    Glob.mem = mem0 /\ absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 < 200
    /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0
    /\ absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint l0)) res.`1 res.`2] = 1%r.
proof.
conseq keccak_absorb_mem_ll (keccak_absorb_mem_h r8 m0 mem0 p0 l0) => // &hr h; split; last by exact h.
have [ha [hr hr0]] : absorbing r8 m0 st{hr} pos{hr} /\ to_uint rate{hr} = r8 /\ 0 < r8 by smt().
move: ha; rewrite /absorbing => -[hpos _].
by rewrite hpos hr; smt(ltz_pmod).
qed.

end section.
