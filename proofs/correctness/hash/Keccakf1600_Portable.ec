(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Keccakf1600_Portable.ec
 * =======================
 *
 * Functional correctness of the shared scalar Keccak-f[1600] kernel
 * (src/hash/keccak/keccakf1600.jinc) against keccak_f1600_op, the
 * Keccak-f[1600] operator of the crypto-specs FIPS 202 theories
 * (Keccakf1600_Spec), which crypto-specs proves equal to its procedure for
 * FIPS 202 sections 3.3 and 3.4 (keccak_f1600_ph).
 *
 * Model. HashExtracted is the jasmin2ec model of one (architecture,
 * variant) pair; this file is checked once against each pair whose
 * KeccakKernel is the shared kernel (proofs/Makefile). The kernel source
 * has no architecture-specific part. The state view lanes, the ρ-offset
 * walk and the step operators at one lane come from KeccakState.
 *
 * Theorems:
 *     keccak_round_correct  __keccak_round computes keccak_pround_op (one
 *                           round without ι) on the lanes of its input
 *                           (partial correctness);
 *     keccakf1600_correct   _keccakf1600 computes keccak_f1600_op on the
 *                           lanes of st (partial correctness);
 *     keccakf1600_total     the same with termination: from every initial
 *                           state the procedure returns, with the
 *                           specified result.
 *
 * The structure of the round proof (θ parities, θ correction, the
 * plane-by-plane ρ/π gather and χ row) follows the reference-kernel proof
 * of formosa-keccak (https://github.com/formosa-crypto/formosa-keccak,
 * revision fe5d22f, proof/amd64/ref/Keccakf1600_ref.ec), re-done for this
 * kernel's loops and array model; nothing is copied from it.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
from JazzEC require import Array5 Array24 Array25.
require import BArray40 BArray192 BArray200.
require import HashExtracted.
require import Keccakf1600_Spec KeccakState.

(* ------------------------------------------------------------------ *)
(* Word and array facts                                               *)

op rotl_ref (x : W64.t) (r : int) : W64.t = if r = 0 then x else x `|<<<|` (r %% 256).

lemma rotl_refE (x : W64.t) r : 0 <= r < 64 => rotl_ref x r = x `|<<<|` r.
proof.
move=> hr; rewrite /rotl_ref; case: (r = 0) => [-> | hne].
+ by apply W64.all_eq_eq; rewrite /all_eq.
by rewrite pmod_small /#.
qed.

lemma rotl64_spec (x0 : W64.t) (r0 : int) :
  hoare [M.__rotl64 : x = x0 /\ r = r0 ==> res = rotl_ref x0 r0].
proof.
proc; auto => />; rewrite /rotl_ref; split => [hne | heq].
+ by rewrite hne /(`|<<|`) W8.of_uintK.
by rewrite heq.
qed.

lemma get_set64_40 (s : BArray40.t) i j w :
  0 <= i < 5 =>
  BArray40.get64 (BArray40.set64 s i w) j = if i = j then w else BArray40.get64 s j.
proof. by move=> hi; rewrite BArray40.get_set64E /#. qed.

(* ------------------------------------------------------------------ *)
(* One round without ι                                                *)

lemma keccak_round_correct (a0 : BArray200.t) :
  hoare [M.__keccak_round : a = a0 ==> lanes res = keccak_pround_op (lanes a0)].
proof.
proc.
(* θ, column parities *)
seq 5 : (a = a0 /\ forall i, 0 <= i < 5 => BArray40.get64 c i = (keccak_C (lanes a0)).[i]).
+ while (a = a0 /\ 0 <= x <= 5 /\
         forall i, 0 <= i < x => BArray40.get64 c i = (keccak_C (lanes a0)).[i]).
  + wp; unroll for ^while; auto => /> &m hx0 _ ih hx5; split; first smt().
    move=> i hi0 hi; rewrite get_set64_40 1:/#.
    case: (x{m} = i) => [<<- | hne]; last by apply ih => /#.
    by rewrite keccak_CE 1:/# !lanesE /#.
  by auto => /> /#.
(* θ, corrections *)
seq 2 : (#pre /\ forall i, 0 <= i < 5 =>
           BArray40.get64 d i = (keccak_D (keccak_C (lanes a0))).[i]).
+ while (#pre /\ 0 <= x <= 5 /\
         forall i, 0 <= i < x => BArray40.get64 d i = (keccak_D (keccak_C (lanes a0))).[i]).
  + auto => /> &m hc hx0 _ ih hx5; split; first smt().
    move=> i hi0 hi; rewrite get_set64_40 1:/#.
    case: (x{m} = i) => [<<- | hne]; last by apply ih => /#.
    rewrite keccak_DE 1:/# -!hc 1,2:/#.
    by rewrite /(`|<<|`) W8.of_uintK.
  by auto => /> /#.
(* planes *)
while (a = a0 /\ 0 <= y <= 5 /\
       (forall i, 0 <= i < 5 => BArray40.get64 d i = (keccak_D (keccak_C (lanes a0))).[i]) /\
       forall k, 0 <= k < 5 * y => BArray200.get64 e k = (keccak_pround_op (lanes a0)).[k]);
  last first.
+ auto => /> &m hc hd; split; first smt().
  move=> e y ? ? ? he; have ->> : y = 5 by smt().
  apply Array25.ext_eq => k hk; rewrite lanesE 1:// he /#.
(* χ of plane y *)
seq 2 : (#pre /\ forall i, 0 <= i < 5 => BArray40.get64 b i = (rpt (lanes a0)).[i + 5 * y]).
+ while (#pre /\ 0 <= x <= 5 /\
         forall i, 0 <= i < x => BArray40.get64 b i = (rpt (lanes a0)).[i + 5 * y]).
  + wp; ecall (rotl64_spec (BArray40.get64 b x) r).
    ecall (keccak_rho_spec xs x).
    auto => /> &m hy0 _ hd he hy5 hx0 _ ih hx5; split; first smt().
    move=> _ _; split; first smt().
    move=> i hi0 hi; rewrite get_set64_40 1:/#.
    case: (x{m} = i) => [<<- | hne]; last by rewrite !get_set64_40 1..3:/# hne /= ih /#.
    rewrite get_set64_40 1:/# /= get_set64_40 1:/# /= rptE 1,2:/# lanesE 1:/# hd 1:/#.
    rewrite (pmod_small x{m} 5) 1:/# (pmod_small ((x{m} + 3 * y{m}) %% 5) 5) 1:/#.
    have hb := rhotates_bound ((x{m} + 3 * y{m}) %% 5 + 5 * x{m}) _; first smt().
    by rewrite rotl_refE.
  auto => />; smt().
seq 2 : (a = a0 /\ 0 <= y < 5 /\
         (forall i, 0 <= i < 5 => BArray40.get64 d i = (keccak_D (keccak_C (lanes a0))).[i]) /\
         forall k, 0 <= k < 5 * y + 5 => BArray200.get64 e k = (keccak_pround_op (lanes a0)).[k]).
+ while (a = a0 /\ 0 <= y < 5 /\
         (forall i, 0 <= i < 5 => BArray40.get64 d i = (keccak_D (keccak_C (lanes a0))).[i]) /\
         (forall i, 0 <= i < 5 => BArray40.get64 b i = (rpt (lanes a0)).[i + 5 * y]) /\
         0 <= x <= 5 /\
         forall k, 0 <= k < x + 5 * y => BArray200.get64 e k = (keccak_pround_op (lanes a0)).[k]).
  + auto => /> &m hy0 hy5 hd hb hx0 _ ih hx5; split; first smt().
    move=> k hk0 hk; rewrite get_set64_200 1:/#.
    case: (x{m} + 5 * y{m} = k) => [<<- | hne]; last by apply ih => /#.
    by rewrite proundE 1,2:/# !hb 1..3:/# W64.xorwC.
  auto => />; smt().
auto => /> &m hy0 hy5 hd he; split; first smt().
move=> k hk0 hk; apply he => /#.
qed.

(* ------------------------------------------------------------------ *)
(* ι and the permutation                                              *)

lemma keccakf1600_correct (s0 : BArray200.t) :
  hoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)].
proof.
proc; wp.
while (0 <= to_uint ir <= 24 /\ 2 %| to_uint ir /\ more = (to_uint ir < 24) /\
       lanes st = rounds (lanes s0) (to_uint ir)).
+ wp; ecall (keccak_round_correct e).
  wp; ecall (keccak_round_correct st).
  auto => /> &m hi0 hi24 hev ih hlt e1 he1 st1 hst1.
  have hu1 : to_uint (ir{m} + W64.one) = to_uint ir{m} + 1 by rewrite to_uintD_small /#.
  have hu2 : to_uint (ir{m} + W64.of_int 2) = to_uint ir{m} + 2 by rewrite to_uintD_small /#.
  rewrite ultE hu2 /=.
  have hm : to_uint ir{m} %% 2 = 0 by rewrite -dvdzE.
  have hle : to_uint ir{m} + 2 <= 24.
  + case: (to_uint ir{m} = 23) => [h | h]; first by move: hm; rewrite h.
    smt().
  split; first smt().
  split; first by rewrite dvdzE -modzDm hm.
  rewrite lanes_iota0 hst1 lanes_iota0 he1 ih.
  rewrite kECCAK_RCE 1:/# hu1 kECCAK_RCE 1:/#.
  by rewrite (roundsS _ (to_uint ir{m} + 1)) 1:/# roundsS 1:/# /keccak_round_op.
auto => />; split.
+ by rewrite /rounds /= ?iota0.
smt(rounds24).
qed.

(* Every loop runs over a constant range, so the kernel terminates on every
   input. *)
lemma rotl64_ll : islossless M.__rotl64.
proof. by proc; auto. qed.

lemma keccak_round_ll : islossless M.__keccak_round.
proof.
proc.
while (0 <= y <= 5) (5 - y).
+ move=> z; wp; while (0 <= x <= 5) (5 - x); first by auto => /#.
  wp; while (0 <= x <= 5) (5 - x).
  + by move=> z'; wp; call rotl64_ll; wp; call keccak_rho_ll; auto => /#.
  by auto => /#.
wp; while (0 <= x <= 5) (5 - x); first by auto => /#.
wp; while (0 <= x <= 5) (5 - x).
+ move=> z; wp; while (0 <= y <= 5) (5 - y); first by auto => /#.
  by auto => /#.
by auto => /#.
qed.

lemma keccakf1600_ll : islossless M._keccakf1600.
proof.
proc; wp.
while (0 <= to_uint ir <= 24 /\ 2 %| to_uint ir /\ more = (to_uint ir < 24))
      (24 - to_uint ir).
+ move=> z; wp; call keccak_round_ll; wp; call keccak_round_ll; auto => /> &m hi0 hi24 hev hlt.
  have hu2 : to_uint (ir{m} + W64.one + W64.one) = to_uint ir{m} + 2.
  + by rewrite -W64.WRingA.addrA to_uintD_small /#.
  have hm : to_uint ir{m} %% 2 = 0 by rewrite -dvdzE.
  have hle : to_uint ir{m} + 2 <= 24.
  + case: (to_uint ir{m} = 23) => [h | h]; first by move: hm; rewrite h.
    smt().
  rewrite ultE hu2 /=; split; last smt().
  by split; [smt() | rewrite dvdzE -modzDm hm].
by auto => /> /#.
qed.

lemma keccakf1600_total (s0 : BArray200.t) :
  phoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)] = 1%r.
proof. by conseq keccakf1600_ll (keccakf1600_correct s0). qed.
