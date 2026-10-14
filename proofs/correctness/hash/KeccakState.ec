(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * KeccakState.ec
 * ==============
 *
 * The Keccak state of the extracted models and the facts every Keccak
 * kernel proof uses, checked against every pair:
 *
 *   lanes          reads a u64[25] state (a 200-byte array in the model)
 *                  as the 25 words of the crypto-specs state, lane x + 5y
 *                  at word x + 5y (crypto-specs idx);
 *   kECCAK_RCE     the round-constant table of the source is rc_spec;
 *   lanes_iota     ι on the model is keccak_iota_op;
 *   rounds         the first n rounds of keccak_f1600_op;
 *   keccak_rho_spec  __keccak_rho, shared by every kernel, returns the
 *                  FIPS 202 ρ offset of lane (x, y) (the Algorithm 2 walk
 *                  of FIPS 202 section 3.2.2, against the rhotates table);
 *   keccak_CE, keccak_DE, rptE, proundE
 *                  θ, ρ, π and χ of crypto-specs read at one lane.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
from JazzEC require import Array5 Array24 Array25.
require import BArray192 BArray200.
require import HashExtracted.
require import Keccakf1600_Spec.

op lanes (s : BArray200.t) : state = Array25.init (fun i => BArray200.get64 s i).

lemma lanesE s i : 0 <= i < 25 => (lanes s).[i] = BArray200.get64 s i.
proof. by move=> hi; rewrite /lanes Array25.initiE. qed.

lemma get_set64_200 (s : BArray200.t) i j w :
  0 <= i < 25 =>
  BArray200.get64 (BArray200.set64 s i w) j = if i = j then w else BArray200.get64 s j.
proof. by move=> hi; rewrite BArray200.get_set64E /#. qed.

lemma rhotates_bound i : 0 <= i < 25 => 0 <= to_uint rhotates.[i] < 64.
proof.
have h : forall i, i \in iota_ 0 25 => 0 <= to_uint rhotates.[i] < 64.
+ rewrite -allP -iotaredE /rhotates /=.
  by do !split; rewrite Array25.get_of_list //= of_uintK.
by move=> hi; apply h; rewrite mem_iota /#.
qed.

lemma kECCAK_RCE i : 0 <= i < 24 => BArray192.get64 kECCAK_RC i = rc_spec.[i].
proof.
move=> hi; rewrite BArray192.get64_of_list64 1:// /rc_spec Array24.get_of_list 1:/#.
have : i \in iota_ 0 24 by rewrite mem_iota /#.
move=> {hi}; move: i; rewrite -allP -iotaredE /=.
by do !split.
qed.

lemma lanes_iota (s : BArray200.t) (c : W64.t) :
  lanes (BArray200.set64 s 0 (BArray200.get64 s 0 `^` c)) = keccak_iota_op c (lanes s).
proof.
apply Array25.ext_eq => k hk; rewrite /keccak_iota_op Array25.get_setE 1:// !lanesE //.
by rewrite get_set64_200 1:// /#.
qed.

lemma lanes_iota0 (s : BArray200.t) (c : W64.t) :
  lanes (BArray200.set64d s 0 (BArray200.get64d s 0 `^` c)) = keccak_iota_op c (lanes s).
proof. by have /= := lanes_iota s c. qed.

op rounds (A : state) (n : int) : state =
  foldl (fun s ir => keccak_round_op rc_spec.[ir] s) A (iota_ 0 n).

lemma roundsS (A : state) n : 0 <= n =>
  rounds A (n + 1) = keccak_round_op rc_spec.[n] (rounds A n).
proof. by move=> hn; rewrite /rounds iotaSr // foldl_rcons. qed.

lemma rounds24 (A : state) : rounds A 24 = keccak_f1600_op A.
proof. by rewrite /rounds /keccak_f1600_op. qed.

(* ------------------------------------------------------------------ *)
(* ρ offsets: __keccak_rho walks Algorithm 2 of FIPS 202              *)

(* One step of the walk from (1, 0), recording the offset when the walk
   is at p. *)
op rho_step (p : int * int) (a : int * int * int) (t : int) : int * int * int =
  (a.`2, (2 * a.`1 + 3 * a.`2) %% 5,
   if (a.`1, a.`2) = p then (t + 1) * (t + 2) %/ 2 %% 64 else a.`3).

op rho_walk (p : int * int) (n : int) : int * int * int =
  foldl (rho_step p) (1, 0, 0) (iota_ 0 n).

op all_lanes : (int * int) list =
  [(0,0);(1,0);(2,0);(3,0);(4,0);(0,1);(1,1);(2,1);(3,1);(4,1);
   (0,2);(1,2);(2,2);(3,2);(4,2);(0,3);(1,3);(2,3);(3,3);(4,3);
   (0,4);(1,4);(2,4);(3,4);(4,4)].

lemma all_lanesP (x y : int) : 0 <= x < 5 => 0 <= y < 5 => (x, y) \in all_lanes.
proof. by rewrite /all_lanes /=; smt(). qed.

lemma rho_walk_table (p : int * int) :
  p \in all_lanes => (rho_walk p 24).`3 = to_uint rhotates.[idx p].
proof.
move: p; rewrite -allP.
rewrite /all_lanes /rho_walk /rho_step /rhotates -iotaredE /=.
by do !split; rewrite Array25.get_of_list //= of_uintK.
qed.

lemma keccak_rho_spec (x0 y0 : int) :
  hoare [M.__keccak_rho : x = x0 /\ y = y0 /\ 0 <= x0 < 5 /\ 0 <= y0 < 5
         ==> res = to_uint rhotates.[idx (x0, y0)]].
proof.
proc.
while (0 <= t <= 24 /\ x = x0 /\ y = y0 /\ 0 <= x0 < 5 /\ 0 <= y0 < 5 /\
       (cx, cy, r) = rho_walk (x0, y0) t).
+ auto => /> &m ht0 _ hx0 hx1 hy0 hy1 ih ht24.
  have hs : rho_walk (x0, y0) (t{m} + 1) = rho_step (x0, y0) (rho_walk (x0, y0) t{m}) t{m}.
  + by rewrite /rho_walk iotaSr // foldl_rcons.
  split => [hcx hcy | hne]; rewrite ?hcx ?hcy hs -ih /rho_step /= /#.
auto => /> hx0 hx1 hy0 hy1; split; first by rewrite /rho_walk iota0.
move=> cx cy r t ? ? ?; have ->: t = 24 by smt().
move=> hw; have := rho_walk_table (x0, y0) (all_lanesP _ _ _ _).
+ smt().
+ smt().
by rewrite -hw.
qed.

lemma keccak_rho_ll : islossless M.__keccak_rho.
proof. by proc; while (0 <= t <= 24) (24 - t); auto => /#. qed.

lemma keccak_CE (A : state) x : 0 <= x < 5 =>
  (keccak_C A).[x] = A.[x] `^` A.[x + 5] `^` A.[x + 10] `^` A.[x + 15] `^` A.[x + 20].
proof. by move=> hx; rewrite /keccak_C /init_5_64 Array5.initiE. qed.

lemma keccak_DE (C : W64.t Array5.t) x : 0 <= x < 5 =>
  (keccak_D C).[x] = (C.[(x + 1) %% 5] `|<<<|` 1) `^` C.[(x + 4) %% 5].
proof.
move=> hx; rewrite /keccak_D /init_5_64 Array5.initiE //= W64.xorwC.
have -> : (x - 1) %% 5 = (x + 4) %% 5 by smt().
done.
qed.

(* The ρ/π/θ value that lands in lane (x, y), and the χ output there. *)
op rpt (A : state) = keccak_pi_op (keccak_rho_op (keccak_theta_op A)).

lemma rptE (A : state) x y : 0 <= x < 5 => 0 <= y < 5 =>
  (rpt A).[x + 5 * y] =
  (A.[(x + 3 * y) %% 5 + 5 * x] `^` (keccak_D (keccak_C A)).[(x + 3 * y) %% 5])
    `|<<<|` to_uint rhotates.[(x + 3 * y) %% 5 + 5 * x].
proof.
move=> hx hy; rewrite /rpt /keccak_pi_op /keccak_rho_op /keccak_theta_op /init_25_64.
rewrite Array25.initiE 1:/# /=.
have -> : (x + 5 * y) %% 5 = x by smt().
have -> : (x + 5 * y) %/ 5 = y by smt().
rewrite Array25.initiE 1:/# /= Array25.initiE 1:/# /=.
have -> : x %% 5 = x by smt().
by have -> : ((x + 3 * y) %% 5 + 5 * x) %% 5 = (x + 3 * y) %% 5 by smt().
qed.

lemma proundE (A : state) x y : 0 <= x < 5 => 0 <= y < 5 =>
  (keccak_pround_op A).[x + 5 * y] =
  (rpt A).[x + 5 * y] `^` (invw (rpt A).[(x + 1) %% 5 + 5 * y] `&` (rpt A).[(x + 2) %% 5 + 5 * y]).
proof.
move=> hx hy; rewrite /keccak_pround_op /keccak_chi_op -/(rpt A) /init_25_64.
rewrite Array25.initiE 1:/# /=.
have -> : (x + 5 * y) %% 5 = x by smt().
have -> : (x + 5 * y) %/ 5 = y by smt().
by rewrite /idx /= (pmod_small x 5) 1:/# (pmod_small y 5) 1:/#.
qed.
