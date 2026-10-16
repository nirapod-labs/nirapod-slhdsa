(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * SpongeSqueeze.ec
 * ================
 *
 * Functional correctness of the squeezing phase of the single-way Keccak
 * sponge of src/hash/keccak/sponge.jinc against FIPS 202 section 4
 * (Keccak1600_Spec SQUEEZE1600).
 *
 * The output stream of a sponge whose absorbed state is s is the byte
 * sequence sqbyte r8 s 0, sqbyte r8 s 1, ...: byte t is byte t %% r8 of
 * Keccak-f applied t %/ r8 + 1 times to s. SQUEEZE1600 r8 len s is its
 * first len bytes (SQUEEZE1600_seq). The code permutes lazily, so after t
 * output bytes the state st with byte position pos satisfies
 * squeezing r8 s t st pos: pos <= r8, t - pos is a whole number of blocks
 * b, and st holds Keccak-f applied b + 1 times to s. _keccak_finalize
 * leaves squeezing r8 s 0 st 0 with s = ABSORB1600 trail r8 m.
 *
 * As in Sponge.ec, the permutation's correctness is the section
 * hypothesis kf_h (with kf_ll), a premise of every theorem that calls the
 * permutation once the section is closed; Sponge_Portable.ec and
 * Sponge_KernelSpec.ec discharge it.
 *
 * Theorems:
 *     extract_mem_h, extract_mem_ll   __keccak_extract_mem writes state
 *                                     bytes [p, p + k) to memory at q
 *     keccak_squeeze_mem_total        (under kf_h and kf_ll) the memory
 *                                     at out receives bytes
 *                                     [t0, t0 + outlen) of the stream
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils JMemory.
from JazzEC require import Array25 WArray200.
require import BArray200 KeccakState.
require import Keccakf1600_Spec Keccak1600_Spec JWordList.
require FIPS202_SHA3_Spec.
require import HashExtracted ArchWord ShakeSponge Sponge.

(* ------------------------------------------------------------------ *)
(* The output stream                                                  *)

op sqbyte (r8 : int) (s : state) (t : int) : W8.t =
  (stbytes (FIPS202_SHA3_Spec.st_i s (t %/ r8 + 1))).[t %% r8].

lemma nth_squeezeblocks r8 (s : state) nb t : 0 < r8 <= 200 => 0 <= nb => 0 <= t < r8 * nb =>
  nth W8.zero (squeezeblocks r8 s nb) t = sqbyte r8 s t.
proof.
move=> hr hnb ht; elim/natind: nb hnb t ht => [nb hle hge t ht | nb hnb ih _ t ht]; first smt().
rewrite squeezeblocksS // nth_cat size_squeezeblocks //.
case: (t < r8 * nb) => hlt; first by apply ih => /#.
have hq : t %/ r8 = nb.
+ by rewrite (_ : t = nb * r8 + (t - r8 * nb)) 1:/# divzMDl 1:/# divz_small /#.
have hm : t %% r8 = t - r8 * nb.
+ by rewrite {1}(_ : t = nb * r8 + (t - r8 * nb)) 1:/# modzMDl modz_small /#.
rewrite /= /squeezestate_i /squeezestate nth_take 1,2:/# state2bytesE /sqbyte hq hm.
by rewrite /FIPS202_SHA3_Spec.st_i /= iter1 iterS.
qed.

lemma SQUEEZE1600_seq r8 (s : state) len : 0 < r8 <= 200 => 0 <= len =>
  SQUEEZE1600 r8 len s = mkseq (sqbyte r8 s) len.
proof.
move=> hr hl; apply (eq_from_nth W8.zero); first by rewrite size_SQUEEZE1600 // size_mkseq /#.
move=> i; rewrite size_SQUEEZE1600 // => hi.
rewrite nth_mkseq 1:/# /SQUEEZE1600 nth_take 1,2:/# nth_squeezeblocks //; smt(divz_ge0 divz_eq modz_cmp).
qed.

(* Bytes [t0, t0 + n) of the stream. *)
op sqseq (r8 : int) (s : state) (t0 n : int) : W8.t list = mkseq (fun i => sqbyte r8 s (t0 + i)) n.

lemma size_sqseq r8 s t0 n : 0 <= n => size (sqseq r8 s t0 n) = n.
proof. by move=> hn; rewrite /sqseq size_mkseq lez_maxr. qed.

lemma nth_sqseq r8 s t0 n i : 0 <= i < n => nth W8.zero (sqseq r8 s t0 n) i = sqbyte r8 s (t0 + i).
proof. by move=> hi; rewrite /sqseq nth_mkseq. qed.

lemma sqseq0 r8 s t0 : sqseq r8 s t0 0 = [].
proof. by rewrite /sqseq mkseq0. qed.

lemma sqseq_SQUEEZE r8 (s : state) t0 n : 0 < r8 <= 200 => 0 <= t0 => 0 <= n =>
  sqseq r8 s t0 n = drop t0 (SQUEEZE1600 r8 (t0 + n) s).
proof.
move=> hr ht hn; rewrite SQUEEZE1600_seq // 1:/#; apply (eq_from_nth W8.zero).
+ by rewrite size_sqseq // size_drop // size_mkseq /#.
move=> i; rewrite size_sqseq // => hi.
by rewrite nth_sqseq // nth_drop // 1:/# nth_mkseq /#.
qed.

(* The squeezing state after t output bytes. *)
op squeezing (r8 : int) (s : state) (t : int) (st : BArray200.t) (pos : W64.t) : bool =
  to_uint pos <= r8 /\ to_uint pos <= t /\ (t - to_uint pos) %% r8 = 0 /\
  lanes st = FIPS202_SHA3_Spec.st_i s ((t - to_uint pos) %/ r8 + 1).

lemma squeezing_final r8 (s : state) (st : BArray200.t) : 0 <= r8 =>
  lanes st = keccak_f1600_op s => squeezing r8 s 0 st W64.zero.
proof. by move=> hr hl; rewrite /squeezing W64.to_uint0 /= hl /FIPS202_SHA3_Spec.st_i iter1. qed.

lemma squeezing_byte r8 s t st (pos : W64.t) i : 0 < r8 <= 200 => squeezing r8 s t st pos =>
  0 <= i => to_uint pos + i < r8 => st.[to_uint pos + i] = sqbyte r8 s (t + i).
proof.
move=> hr [hp [ht [hm hl]]] hi hpi.
have hc := ucmp pos.
have hd : (t - to_uint pos) %/ r8 * r8 = t - to_uint pos by apply divzK; rewrite dvdzE.
have hq : (t + i) %/ r8 = (t - to_uint pos) %/ r8.
+ rewrite (_ : t + i = (t - to_uint pos) %/ r8 * r8 + (to_uint pos + i)) 1:/# divzMDl 1:/#.
  by rewrite (divz_small (to_uint pos + i) r8) /#.
have hm' : (t + i) %% r8 = to_uint pos + i.
+ by rewrite (_ : t + i = (t - to_uint pos) %/ r8 * r8 + (to_uint pos + i)) 1:/# modzMDl modz_small /#.
by rewrite /sqbyte hq hm' -hl stbytes_lanes /#.
qed.

lemma squeezing_perm r8 s t (st st' : BArray200.t) (pos : W64.t) : 0 < r8 <= 200 =>
  squeezing r8 s t st pos => to_uint pos = r8 => lanes st' = keccak_f1600_op (lanes st) =>
  squeezing r8 s t st' W64.zero.
proof.
move=> hr [hp [ht [hm hl]]] heq hf; move: hm hl; rewrite heq => hm hl.
have hd : (t - r8) %/ r8 * r8 = t - r8 by apply divzK; rewrite dvdzE.
have hq : t %/ r8 = (t - r8) %/ r8 + 1.
+ by rewrite {1}(_ : t = ((t - r8) %/ r8 + 1) * r8 + 0) 1:/# divzMDl 1:/# div0z.
have hm2 : t %% r8 = 0.
+ by rewrite (_ : t = ((t - r8) %/ r8 + 1) * r8 + 0) 1:/# modzMDl mod0z.
rewrite /squeezing W64.to_uint0 /= hf hq hm2 /= hl /FIPS202_SHA3_Spec.st_i.
split; first smt().
by rewrite (iterS ((t - r8) %/ r8 + 1)) //; smt(divz_ge0).
qed.

lemma squeezing_step r8 s t st (pos pos' : W64.t) n : 0 <= n => squeezing r8 s t st pos =>
  to_uint pos' = to_uint pos + n => to_uint pos + n <= r8 => squeezing r8 s (t + n) st pos'.
proof.
move=> hn [hp [ht [hm hl]]] hp' hle; rewrite /squeezing hp'.
by rewrite (_ : t + n - (to_uint pos + n) = t - to_uint pos) 1:/#; smt().
qed.

(* ------------------------------------------------------------------ *)
(* State bytes to memory (__keccak_extract_mem)                       *)

(* Memory mem with the state bytes [p, e) of s stored from address a. *)
op extx (mem : global_mem_t) (a : int) (s : BArray200.t) (p e : int) : global_mem_t =
  stores mem a (mkseq (fun i => s.[p + i]) (e - p)).

lemma extxE mem a s p e j : p <= e =>
  (extx mem a s p e).[j] = if a <= j < a + (e - p) then s.[p + (j - a)] else mem.[j].
proof.
move=> hpe; rewrite /extx get_storesE size_mkseq lez_maxr 1:/#.
by case: (a <= j < a + (e - p)) => h //; rewrite nth_mkseq 1:/#.
qed.

lemma extx0 mem a s p : extx mem a s p p = mem.
proof. by apply mem_eq_ext => j; rewrite extxE //; smt(). qed.

lemma extx_byte mem a s p e : p <= e =>
  extx mem a s p (e + 1) = storeW8 (extx mem a s p e) (a + (e - p)) s.[e].
proof.
move=> hpe; apply mem_eq_ext => j.
by rewrite storeW8E get_setE (extxE _ _ _ _ (e + 1)) 1:/# extxE //; smt().
qed.

lemma extx_lane mem a s p e : p <= e => 0 <= e => e + 8 <= 200 =>
  extx mem a s p (e + 8) = storeW64 (extx mem a s p e) (a + (e - p)) (BArray200.get64d s e).
proof.
move=> hpe he he8; apply mem_eq_ext => j.
rewrite storeW64E (extxE _ _ _ _ (e + 8)) 1:/# get_storesE W8u8.size_to_list extxE //.
case: (a + (e - p) <= j < a + (e - p) + 8) => h /=.
+ by rewrite ifT 1:/# !BArray200.get64d_byte //; smt().
smt().
qed.

(* Appending the stored state bytes extends the stored stream prefix. *)
lemma extx_sqseq mem o r8 s t0 k (st : BArray200.t) p n : 0 <= k => 0 <= p => 0 <= n =>
  (forall i, 0 <= i < n => st.[p + i] = sqbyte r8 s (t0 + k + i)) =>
  extx (stores mem o (sqseq r8 s t0 k)) (o + k) st p (p + n) = stores mem o (sqseq r8 s t0 (k + n)).
proof.
move=> hk hp hn hb; apply mem_eq_ext => j.
rewrite extxE 1:/# !get_storesE !size_sqseq // 1:/#.
case: (o + k <= j < o + k + (p + n - p)) => h /=.
+ by rewrite ifT 1:/# nth_sqseq 1:/# hb 1:/#; congr; ring.
case: (o <= j < o + k) => h2 /=.
+ by rewrite ifT 1:/# !nth_sqseq /#.
smt().
qed.

lemma extract_mem_h (s0 : BArray200.t) (mem0 : global_mem_t) (p k q : int) :
  hoare [M.__keccak_extract_mem :
    st = s0 /\ Glob.mem = mem0 /\ to_uint pos_ = p /\ to_uint n_ = k /\
    to_uint out + to_uint off_ = q /\ p + k <= 200 /\ q + k <= W64.modulus /\
    to_uint off_ + k < W64.modulus
    ==> Glob.mem = extx mem0 q s0 p (p + k)].
proof.
proc.
seq 11 : ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint end_0 = p + to_uint head /\ to_uint head + to_uint n = k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)).
+ auto => /> &hr hpk hqk hok.
  have hm := umin_le n_{hr} ((- pos_{hr}) `&` W64.of_int 7).
  have hc := ucmp pos_{hr}.
  by rewrite extx0 /= W64.to_uintD_small 1:/# W64.to_uintB 1:W64.uleE 1:/#; smt(ucmp).
seq 1 : ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint end_0 = p + to_uint head /\ to_uint head + to_uint n = k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0) /\ !more).
+ while ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint end_0 = p + to_uint head /\ to_uint head + to_uint n = k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)); last by skip => /> *.
  auto => /> &hr; rewrite W64.ultE => *.
  have hc := ucmp out{hr}; have hn0 := ucmp n{hr}; have hh0 := ucmp head{hr}.
  have e1 : to_uint (pos{hr} + W64.one) = to_uint pos{hr} + 1 by apply inc1; smt(ucmp).
  have e2 : to_uint (off{hr} + W64.one) = to_uint off{hr} + 1 by apply inc1; smt(ucmp).
  have e3 : to_uint (out{hr} + off{hr}) = to_uint out{hr} + to_uint off{hr}.
  + by rewrite W64.to_uintD_small; smt(ucmp).
  rewrite trunc_zext8 e1 e2 e3 extx_byte 1:/#.
  have -> : to_uint out{hr} + to_uint off{hr} = to_uint out{hr} + to_uint off_{hr} + (to_uint pos{hr} - to_uint pos_{hr}) by smt().
  smt(ucmp).
seq 2 : ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint pos - p + to_uint n = k) /\ more = ((W64.of_int 8) \ule n)).
+ by auto => /> &hr; rewrite W64.ultE => *; smt(ucmp).
seq 1 : ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint pos - p + to_uint n = k) /\ more = ((W64.of_int 8) \ule n) /\ !more).
+ while ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint pos - p + to_uint n = k) /\ more = ((W64.of_int 8) \ule n)); last by skip => /> *.
  auto => /> &hr; rewrite W64.uleE /= => *.
  have hc := ucmp out{hr}; have hn0 := ucmp n{hr}; have hh0 := ucmp head{hr}.
  have e1 : to_uint (pos{hr} + W64.of_int 8) = to_uint pos{hr} + 8 by apply inc8; smt(ucmp).
  have e2 : to_uint (off{hr} + W64.of_int 8) = to_uint off{hr} + 8 by apply inc8; smt(ucmp).
  have e4 : to_uint (n{hr} - W64.of_int 8) = to_uint n{hr} - 8 by apply dec8; smt(ucmp).
  have e3 : to_uint (out{hr} + off{hr}) = to_uint out{hr} + to_uint off{hr}.
  + by rewrite W64.to_uintD_small; smt(ucmp).
  rewrite e1 e2 e4 e3 extx_lane 1..3:/#.
  have -> : to_uint out{hr} + to_uint off{hr} = to_uint out{hr} + to_uint off_{hr} + (to_uint pos{hr} - to_uint pos_{hr}) by smt().
  smt(ucmp).
seq 4 : ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint end_0 = p + k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)).
+ by auto => /> &hr; rewrite W64.uleE /= => *; rewrite W64.to_uintD_small; smt(ucmp).
seq 1 : ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint end_0 = p + k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0) /\ !more).
+ while ((st = s0 /\ to_uint pos_ = p /\ to_uint out + to_uint off_ = q /\ 0 <= p /\ p + k <= 200 /\
    q + k <= W64.modulus /\ to_uint off_ + k < W64.modulus /\ p <= to_uint pos /\
    to_uint off = to_uint off_ + (to_uint pos - p) /\ Glob.mem = extx mem0 q s0 p (to_uint pos) /\
    to_uint end_0 = p + k /\ to_uint pos <= to_uint end_0) /\ more = (pos \ult end_0)); last by skip => /> *.
  auto => /> &hr; rewrite W64.ultE => *.
  have hc := ucmp out{hr}; have hn0 := ucmp n{hr}; have hh0 := ucmp head{hr}.
  have e1 : to_uint (pos{hr} + W64.one) = to_uint pos{hr} + 1 by apply inc1; smt(ucmp).
  have e2 : to_uint (off{hr} + W64.one) = to_uint off{hr} + 1 by apply inc1; smt(ucmp).
  have e3 : to_uint (out{hr} + off{hr}) = to_uint out{hr} + to_uint off{hr}.
  + by rewrite W64.to_uintD_small; smt(ucmp).
  rewrite trunc_zext8 e1 e2 e3 extx_byte 1:/#.
  have -> : to_uint out{hr} + to_uint off{hr} = to_uint out{hr} + to_uint off_{hr} + (to_uint pos{hr} - to_uint pos_{hr}) by smt().
  smt(ucmp).
by auto => /> &hr; rewrite W64.ultE => *; congr; smt(ucmp).
qed.

lemma extract_mem_ll : islossless M.__keccak_extract_mem.
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

lemma extract_mem_true : hoare [M.__keccak_extract_mem : true ==> true].
proof.
proc; wp; while true; first by auto.
wp; while true; first by auto.
wp; while true; first by auto.
by auto.
qed.

(* ------------------------------------------------------------------ *)
(* _keccak_squeeze_mem, under the permutation's correctness           *)

section.

declare axiom kf_h (s0 : BArray200.t) :
  hoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)].
declare axiom kf_ll : islossless M._keccakf1600.

lemma keccak_squeeze_mem_h (r8 : int) (s : state) (t0 : int) (mem0 : global_mem_t) (o0 l0 : W64.t) :
  hoare [M._keccak_squeeze_mem :
    Glob.mem = mem0 /\ squeezing r8 s t0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200
    /\ out = o0 /\ outlen = l0 /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0) (drop t0 (SQUEEZE1600 r8 (t0 + to_uint l0) s))
    /\ squeezing r8 s (t0 + to_uint l0) res.`1 res.`2].
proof.
proc.
wp; while (Glob.mem = stores mem0 (to_uint o0) (sqseq r8 s t0 (to_uint off)) /\ to_uint rate = r8 /\
    0 < r8 <= 200 /\ out = o0 /\ to_uint o0 + to_uint l0 <= W64.modulus /\
    to_uint off + to_uint outlen = to_uint l0 /\ squeezing r8 s (t0 + to_uint off) st pos /\
    more = (outlen <> W64.zero)).
+ seq 3 : (Glob.mem = stores mem0 (to_uint o0) (sqseq r8 s t0 (to_uint off)) /\ to_uint rate = r8 /\
    0 < r8 <= 200 /\ out = o0 /\ to_uint o0 + to_uint l0 <= W64.modulus /\
    to_uint off + to_uint outlen = to_uint l0 /\ squeezing r8 s (t0 + to_uint off) st pos /\
    to_uint pos < r8 /\ outlen <> W64.zero).
  + seq 2 : (Glob.mem = stores mem0 (to_uint o0) (sqseq r8 s t0 (to_uint off)) /\ to_uint rate = r8 /\
      0 < r8 <= 200 /\ out = o0 /\ to_uint o0 + to_uint l0 <= W64.modulus /\
      to_uint off + to_uint outlen = to_uint l0 /\ squeezing r8 s (t0 + to_uint off) st pos /\
      outlen <> W64.zero /\ empty = (pos = rate)); first by auto; smt().
    if.
    + wp; ecall (kf_h st); auto => &hr [#] hm hr hr0 hr1 ho hpl hoff hsq hne he hemp r hrl.
      have hsq' : squeezing r8 s (t0 + to_uint off{hr}) r.`1 W64.zero.
      + by apply (squeezing_perm r8 s (t0 + to_uint off{hr}) st{hr} r.`1 pos{hr}); smt().
      by rewrite /Jslh.SLH64.protect_64 /=; smt(W64.to_uint0).
    auto => &hr [#] hm hr hr0 hr1 ho hpl hoff hsq hne he hemp.
    have hp : to_uint pos{hr} <= r8 by move: hsq; rewrite /squeezing => -[].
    by smt(W64.to_uint_eq).
  wp; ecall (extract_mem_h st Glob.mem (to_uint pos) (to_uint n) (to_uint out + to_uint off)).
  auto => &hr [#] hm hr hr0 hr1 ho hpl hoff hsq hpr hne /=.
  have hpr' : to_uint pos{hr} < to_uint rate{hr} by rewrite hr.
  have [hn1 [hn2 hn3]] := absorb_n pos{hr} rate{hr} outlen{hr} hpr'.
  have hn4 := hn3 hne.
  move: hn1 hn2 hn4; pose n := (if _ then _ else _); move=> hn1 hn2 hn4.
  have hl0 := ucmp l0; have ho0 := ucmp o0; have hof := ucmp off{hr}; have hpo := ucmp pos{hr}.
  have ep : to_uint (pos{hr} + n) = to_uint pos{hr} + to_uint n by rewrite W64.to_uintD_small; smt(ucmp).
  have eo : to_uint (off{hr} + n) = to_uint off{hr} + to_uint n by rewrite W64.to_uintD_small; smt(ucmp).
  have ei : to_uint (outlen{hr} - n) = to_uint outlen{hr} - to_uint n by rewrite W64.to_uintB // W64.uleE.
  have hb : forall i, 0 <= i < to_uint n => st{hr}.[to_uint pos{hr} + i] = sqbyte r8 s (t0 + to_uint off{hr} + i).
  + by move=> i hi; apply (squeezing_byte r8 s (t0 + to_uint off{hr}) st{hr} pos{hr} i); smt().
  have hmem : extx (stores mem0 (to_uint o0) (sqseq r8 s t0 (to_uint off{hr}))) (to_uint o0 + to_uint off{hr})
      st{hr} (to_uint pos{hr}) (to_uint pos{hr} + to_uint n) = stores mem0 (to_uint o0) (sqseq r8 s t0 (to_uint off{hr} + to_uint n)).
  + by apply extx_sqseq; [smt(ucmp) | smt(ucmp) | smt(ucmp) | exact hb].
  have hsq2 : squeezing r8 s (t0 + (to_uint off{hr} + to_uint n)) st{hr} (pos{hr} + n).
  + have -> : t0 + (to_uint off{hr} + to_uint n) = t0 + to_uint off{hr} + to_uint n by ring.
    by apply (squeezing_step r8 s (t0 + to_uint off{hr}) st{hr} pos{hr} (pos{hr} + n) (to_uint n)); smt(ucmp).
  split; first by clear hm hsq hb hmem hsq2 hn3; smt().
  move=> _ mm ->; rewrite eo ei hm ho hmem; clear hm hsq hb hmem hn3; smt(ucmp).
auto => &hr [#] hm hsq hr hr0 hr1 ho hl hpl.
have ht0 : 0 <= t0 by move: hsq; rewrite /squeezing; smt(ucmp).
split; first by rewrite W64.to_uint0 /= sqseq0 store0; smt().
move=> mm mr of' ou' ol' po' ra' st' hnm [#] hm' _ _ _ _ _ hof' hsq' hmr.
have hz : to_uint ol' = 0 by smt(W64.to_uint0).
have he : to_uint of' = to_uint l0 by smt().
rewrite hm' he; split; first by rewrite sqseq_SQUEEZE //; smt(ucmp).
by move: hsq'; rewrite he.
qed.

lemma keccak_squeeze_mem_ll :
  phoare [M._keccak_squeeze_mem : to_uint pos <= to_uint rate /\ 0 < to_uint rate ==> true] = 1%r.
proof.
proc; wp.
while (to_uint pos <= to_uint rate /\ 0 < to_uint rate /\ more = (outlen <> W64.zero)) (to_uint outlen).
+ move=> z.
  conseq (: true ==> true) (: to_uint pos <= to_uint rate /\ 0 < to_uint rate /\ more = (outlen <> W64.zero) /\
           more /\ to_uint outlen = z ==>
           to_uint pos <= to_uint rate /\ 0 < to_uint rate /\ more = (outlen <> W64.zero) /\ to_uint outlen < z).
  + by move=> &hr />.
  + by move=> &hr />.
  + seq 3 : (0 < to_uint rate /\ to_uint pos < to_uint rate /\ outlen <> W64.zero /\ to_uint outlen = z).
    + seq 2 : (0 < to_uint rate /\ to_uint pos <= to_uint rate /\ outlen <> W64.zero /\ to_uint outlen = z /\
               empty = (pos = rate)); first by auto.
      if.
      + by wp; ecall (kf_h st); auto => /> &hr *; rewrite /Jslh.SLH64.protect_64 /=; smt(ucmp).
      by auto => /> &hr h0 hle hne hne'; smt(W64.to_uint_eq).
    wp; call extract_mem_true; auto => /> &hr h0 hlt hne.
    have [hn1 [hn2 hn3]] := absorb_n pos{hr} rate{hr} outlen{hr} hlt.
    have hn4 := hn3 hne.
    move: hn1 hn2 hn4; pose n := (if _ then _ else _); move=> hn1 hn2 hn4.
    have ep : to_uint (pos{hr} + n) = to_uint pos{hr} + to_uint n by rewrite W64.to_uintD_small; smt(ucmp).
    have ei : to_uint (outlen{hr} - n) = to_uint outlen{hr} - to_uint n by rewrite W64.to_uintB // W64.uleE.
    rewrite ep ei; smt(ucmp).
  seq 3 : true 1%r 1%r 0%r 0%r => //.
  + by sp; if; [wp; call kf_ll; auto | auto].
  by wp; call extract_mem_ll; auto.
by auto => /> &hr hle h0; smt(ucmp W64.to_uint_eq W64.to_uint0).
qed.

lemma keccak_squeeze_mem_total (r8 : int) (s : state) (t0 : int) (mem0 : global_mem_t) (o0 l0 : W64.t) :
  phoare [M._keccak_squeeze_mem :
    Glob.mem = mem0 /\ squeezing r8 s t0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200
    /\ out = o0 /\ outlen = l0 /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0) (drop t0 (SQUEEZE1600 r8 (t0 + to_uint l0) s))
    /\ squeezing r8 s (t0 + to_uint l0) res.`1 res.`2] = 1%r.
proof.
conseq keccak_squeeze_mem_ll (keccak_squeeze_mem_h r8 s t0 mem0 o0 l0) => // &hr h; split; last by exact h.
have [hsq [hr hr0]] : squeezing r8 s t0 st{hr} pos{hr} /\ to_uint rate{hr} = r8 /\ 0 < r8 by smt().
by move: hsq; rewrite /squeezing => -[hp _]; smt().
qed.

end section.
