(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * KernelSpec.ec (aarch64/a64scalar)
 * =================================
 *
 * Functional correctness of the kernel the aarch64/a64scalar pair
 * replaces: the register-resident Keccak-f[1600] kernel
 * (src/hash/keccak/aarch64/scalar/keccakf1600.jinc), the single-way
 * Keccak kernel of the AArch64 scalar variant, against keccak_f1600_op of the
 * crypto-specs FIPS 202 theories.
 *
 * The round is proven phase by phase, each against a state invariant
 * that says, lane by lane, which value the lane holds:
 *
 *   θ    after the five parities, the columns are corrected in the
 *        order 0, 2, 3, 1, 4; theta_part names the columns done and the
 *        lanes of the current column done. The lanes the source moves to
 *        the stack and back (21 to 24) are written back unchanged, before
 *        their column is corrected.
 *   ρ/π  the in-place walk along the 24-cycle of the π permutation from
 *        lane 1 (pi_cycle): a lane already visited holds its ρ/π value,
 *        every other lane its θ value.
 *   χ    row by row; row 0 keeps its new lane 0 aside (s0), so lane 0
 *        holds its ρ/π value until ι.
 *   ι    the round constant from the table, added to s0 as it returns.
 *
 * The differences in form between kernel and specification are the A64
 * instruction forms: BIC for the and-not of χ, a right rotation by 63 for
 * the θ left rotation by 1, and a left rotation by a W8 count for ρ.
 *
 * Theorems:
 *     keccak_round_regs_correct  __keccak_round_regs a ir computes round
 *                                ir of Keccak-f[1600] on the lanes of a
 *                                (partial correctness);
 *     keccakf1600_correct        _keccakf1600 computes keccak_f1600_op
 *                                on the lanes of st (partial correctness);
 *     keccakf1600_total          the same with termination.
 *)

require import AllCore List IntDiv.
from Jasmin require import JModel_armv8a.
from JazzEC require import Array5 Array24 Array25.
require import BArray192 BArray200.
require import HashExtracted.
require import Keccakf1600_Spec KeccakState.

(* ------------------------------------------------------------------ *)
(* A64 instruction forms                                              *)

lemma bicE (x y : W64.t) : BIC_64 x y = invw y `&` x.
proof. by rewrite /BIC_64 W64.andwC. qed.

lemma ror63E (x : W64.t) : x `|>>|` W8.of_int 63 = x `|<<<|` 1.
proof.
rewrite /(`|>>|`) W8.of_uintK /=.
by apply W64.wordP => i hi; rewrite W64.rorwE W64.rolwE hi /= /#.
qed.

lemma rolW8E (x : W64.t) r : 0 <= r < 64 => x `|<<|` W8.of_int r = x `|<<<|` r.
proof. by move=> hr; rewrite /(`|<<|`) W8.of_uintK pmod_small /#. qed.

(* ------------------------------------------------------------------ *)
(* θ                                                                  *)

op Cv (a0 : BArray200.t) = keccak_C (lanes a0).
op Dv (a0 : BArray200.t) = keccak_D (Cv a0).

lemma parity_spec (a0 : BArray200.t) (x0 : int) :
  hoare [M.__parity : a = a0 /\ x = x0 /\ 0 <= x0 < 5 ==> res = (Cv a0).[x0]].
proof.
proc; auto => /> h0 h5.
by rewrite /Cv keccak_CE // !lanesE /#.
qed.

(* D[x] in the form the kernel computes it. *)
lemma Dv_ror (a0 : BArray200.t) x : 0 <= x < 5 =>
  (Dv a0).[x] = (Cv a0).[(x + 4) %% 5] `^` ((Cv a0).[(x + 1) %% 5] `|>>|` W8.of_int 63).
proof. by move=> hx; rewrite /Dv keccak_DE // ror63E W64.xorwC. qed.

(* What θ keeps from its first phase: the parities and the lanes moved to
   the stack. *)
pred kept (a0 : BArray200.t) (c0 c1 c2 c3 c4 s21 s22 s23 s24 : W64.t) =
  c0 = (Cv a0).[0] /\ c1 = (Cv a0).[1] /\ c2 = (Cv a0).[2] /\
  c3 = (Cv a0).[3] /\ c4 = (Cv a0).[4] /\
  s21 = BArray200.get64 a0 21 /\ s22 = BArray200.get64 a0 22 /\
  s23 = BArray200.get64 a0 23 /\ s24 = BArray200.get64 a0 24.

(* Lane i holds its θ value when its column is in cs, or when it is in
   column x, being corrected, at a row below y; every other lane holds
   its input value. *)
op theta_part (a0 a : BArray200.t) (cs : int list) (x y : int) =
  forall i, 0 <= i < 25 =>
    BArray200.get64 a i =
      if i %% 5 \in cs \/ (i %% 5 = x /\ i %/ 5 < y)
      then BArray200.get64 a0 i `^` (Dv a0).[i %% 5]
      else BArray200.get64 a0 i.

lemma theta_part0 (a0 : BArray200.t) x : theta_part a0 a0 [] x 0.
proof. by move=> i hi /=; rewrite (: !(i %/ 5 < 0)) 1:/#. qed.

lemma theta_step (a0 a : BArray200.t) cs x y :
  0 <= x < 5 => 0 <= y < 5 => !(x \in cs) => theta_part a0 a cs x y =>
  theta_part a0
    (BArray200.set64 a (x + 5 * y) (BArray200.get64 a (x + 5 * y) `^` (Dv a0).[x]))
    cs x (y + 1).
proof.
move=> hx hy hcs h i hi; rewrite get_set64_200 1:/#.
have hm : (x + 5 * y) %% 5 = x by smt().
have hd : (x + 5 * y) %/ 5 = y by smt().
case: (x + 5 * y = i) => [<<- | hne].
+ by rewrite h 1:/# hm hd hcs /= (: y < y + 1) 1:/#.
rewrite h 1://; congr.
have -> // : (i %% 5 = x /\ i %/ 5 < y + 1) = (i %% 5 = x /\ i %/ 5 < y).
smt(divz_eq).
qed.

lemma theta_col (a0 a : BArray200.t) cs x y j :
  0 <= x < 5 => 0 <= y < 5 => !(x \in cs) => j = x + 5 * y => theta_part a0 a cs x y =>
  theta_part a0 (BArray200.set64 a j (BArray200.get64 a j `^` (Dv a0).[x])) cs x (y + 1).
proof. by move=> hx hy hcs ->; apply theta_step. qed.

(* A column loop that has run to the end has finished its column. *)
lemma theta_next (a0 a : BArray200.t) cs x x' :
  theta_part a0 a cs x 5 => theta_part a0 a (x :: cs) x' 0.
proof.
move=> h i hi; rewrite h 1:// /=; congr.
by rewrite (: !(i %/ 5 < 0)) 1:/# (: i %/ 5 < 5) 1:/# /= orbC.
qed.

(* A lane written back from the stack before its column is corrected. *)
lemma theta_restore (a0 a : BArray200.t) cs x j :
  0 <= j < 25 => !(j %% 5 \in cs) => theta_part a0 a cs x 0 =>
  theta_part a0 (BArray200.set64 a j (BArray200.get64 a0 j)) cs x 0.
proof.
move=> hj hcs h i hi; rewrite get_set64_200 1://.
case: (j = i) => [<<- | hne]; last by apply h.
by rewrite hcs /= (: !(j %/ 5 < 0)) 1:/#.
qed.

lemma theta_all (a0 a : BArray200.t) x :
  theta_part a0 a [4; 1; 3; 2; 0] x 0 =>
  forall i, 0 <= i < 25 =>
    BArray200.get64 a i = (keccak_theta_op (lanes a0)).[i].
proof.
move=> h i hi; rewrite h 1:// /keccak_theta_op /init_25_64 Array25.initiE 1:// /=.
rewrite (: i %% 5 = 4 \/ i %% 5 = 1 \/ i %% 5 = 3 \/ i %% 5 = 2 \/ i %% 5 = 0) 1:/#.
by rewrite lanesE 1:// /Dv /Cv.
qed.

(* ------------------------------------------------------------------ *)
(* ρ/π: the walk along the π cycle                                    *)

(* The lane whose ρ-rotated value π moves into lane c. *)
op pi_src (c : int) = (c %% 5 + 3 * (c %/ 5)) %% 5 + 5 * (c %% 5).

(* The 24-cycle of pi_src through every lane but 0, from lane 1. *)
op pi_cycle : int list =
  [1; 6; 9; 22; 14; 20; 2; 12; 13; 19; 23; 15; 4; 24; 21; 8; 16; 5; 3; 18; 17; 11; 7; 10].

lemma pi_cycle_step k : 0 <= k < 24 =>
  pi_src (nth 0 pi_cycle k) = nth 0 (rcons pi_cycle 1) (k + 1).
proof.
have h : forall k, k \in iota_ 0 24 =>
  pi_src (nth 0 pi_cycle k) = nth 0 (rcons pi_cycle 1) (k + 1).
+ by rewrite -allP -iotaredE /pi_cycle /pi_src.
by move=> hk; apply h; rewrite mem_iota /#.
qed.

lemma pi_cycle_one k : 0 <= k < 24 =>
  (nth 0 (rcons pi_cycle 1) (k + 1) = 1) = (k = 23).
proof.
have h : forall k, k \in iota_ 0 24 => (nth 0 (rcons pi_cycle 1) (k + 1) = 1) = (k = 23).
+ by rewrite -allP -iotaredE /pi_cycle.
by move=> hk; apply h; rewrite mem_iota /#.
qed.

lemma pi_cycle_index k : 0 <= k < 24 => index (nth 0 pi_cycle k) pi_cycle = k.
proof.
have h : forall k, k \in iota_ 0 24 => index (nth 0 pi_cycle k) pi_cycle = k.
+ by rewrite -allP -iotaredE /pi_cycle.
by move=> hk; apply h; rewrite mem_iota /#.
qed.

lemma pi_cycle_range k : 0 <= k < 24 => 0 < nth 0 pi_cycle k < 25.
proof.
have h : forall k, k \in iota_ 0 24 => 0 < nth 0 pi_cycle k < 25.
+ by rewrite -allP -iotaredE /pi_cycle.
by move=> hk; apply h; rewrite mem_iota /#.
qed.

lemma pi_cycle_all i : 0 <= i < 25 => (index i pi_cycle < 24) = (i <> 0).
proof.
have h : forall i, i \in iota_ 0 25 => (index i pi_cycle < 24) = (i <> 0).
+ by rewrite -allP -iotaredE /pi_cycle.
by move=> hi; apply h; rewrite mem_iota /#.
qed.

lemma index_step (i k : int) : 0 <= k < 24 =>
  (index i pi_cycle < k + 1) = (index i pi_cycle < k \/ i = nth 0 pi_cycle k).
proof.
move=> hk; case: (i = nth 0 pi_cycle k) => [-> | hne]; first by rewrite pi_cycle_index /#.
case: (index i pi_cycle = k) => [hik | /#].
have : nth 0 pi_cycle (index i pi_cycle) = i.
+ by apply nth_index; rewrite -index_mem /pi_cycle /= /#.
by rewrite hik => /#.
qed.

lemma thetaE (A : state) i : 0 <= i < 25 =>
  (keccak_theta_op A).[i] = A.[i] `^` (keccak_D (keccak_C A)).[i %% 5].
proof. by move=> hi; rewrite /keccak_theta_op /init_25_64 Array25.initiE. qed.

(* The ρ/π value of lane c: the θ value of lane pi_src c, rotated. *)
lemma rpt_src (A : state) c : 0 <= c < 25 =>
  (rpt A).[c] = (keccak_theta_op A).[pi_src c] `|<<<|` to_uint rhotates.[pi_src c].
proof.
move=> hc; have := rptE A (c %% 5) (c %/ 5) _ _; 1,2: smt().
have -> : c %% 5 + 5 * (c %/ 5) = c by smt().
move=> ->; rewrite /pi_src thetaE 1:/#.
by have -> : ((c %% 5 + 3 * (c %/ 5)) %% 5 + 5 * (c %% 5)) %% 5 = (c %% 5 + 3 * (c %/ 5)) %% 5
  by smt().
qed.

lemma rpt0 (A : state) : (rpt A).[0] = (keccak_theta_op A).[0].
proof.
rewrite rpt_src // /pi_src /=.
by apply W64.wordP => i hi; rewrite W64.rolwE hi /= W64.to_uint0 /= pmod_small.
qed.

op rhopi_inv (a0 a : BArray200.t) (k : int) =
  forall i, 0 <= i < 25 =>
    BArray200.get64 a i =
      if index i pi_cycle < k then (rpt (lanes a0)).[i]
      else (keccak_theta_op (lanes a0)).[i].

lemma pi_cycle_rcons k : 0 <= k < 24 => nth 0 (rcons pi_cycle 1) k = nth 0 pi_cycle k.
proof. by move=> hk; rewrite nth_rcons /pi_cycle /= (: k < 24) 1:/#. qed.

(* One step of the walk: lane c = nth 0 pi_cycle k receives the rotated
   θ value of lane pi_src c, read from the state (not yet visited) or,
   for the last step, from the copy of lane 1 taken before the walk. *)
lemma rhopi_step (a0 a : BArray200.t) k (v : W64.t) :
  0 <= k < 24 => rhopi_inv a0 a k =>
  v = (if pi_src (nth 0 pi_cycle k) = 1 then (keccak_theta_op (lanes a0)).[1]
       else BArray200.get64 a (pi_src (nth 0 pi_cycle k))) =>
  rhopi_inv a0
    (BArray200.set64 a (nth 0 pi_cycle k)
       (v `|<<|` W8.of_int (to_uint rhotates.[pi_src (nth 0 pi_cycle k)])))
    (k + 1).
proof.
move=> hk h hv i hi.
have hc := pi_cycle_range k hk.
have hs := pi_cycle_step k hk.
have hsr : 0 <= pi_src (nth 0 pi_cycle k) < 25.
+ rewrite hs; case: (k = 23) => [-> // | h23].
  by rewrite pi_cycle_rcons 1:/#; have := pi_cycle_range (k + 1) _ => /#.
rewrite get_set64_200 1:/# index_step 1://.
case: (nth 0 pi_cycle k = i) => [<<- | hne]; last first.
+ by rewrite h 1:// (eq_sym i) hne.
rewrite pi_cycle_index 1:// /= rolW8E 1:rhotates_bound 1:// rpt_src 1:/#.
congr; rewrite hv; case: (pi_src (nth 0 pi_cycle k) = 1) => [-> // | h1].
rewrite h 1://.
have hk23 : k <> 23 by move: h1; rewrite hs pi_cycle_one.
have -> : pi_src (nth 0 pi_cycle k) = nth 0 pi_cycle (k + 1).
+ by rewrite hs pi_cycle_rcons /#.
by rewrite pi_cycle_index 1:/# (: !(k + 1 < k)) 1:/#.
qed.

(* ------------------------------------------------------------------ *)
(* χ                                                                  *)

(* χ at lane j = x + 5y in the BIC form of the kernel, with j1 and j2 the
   lanes x + 1 and x + 2 of row y. *)
lemma chi_at (A : state) x y j j1 j2 : 0 <= x < 5 => 0 <= y < 5 =>
  j = x + 5 * y => j1 = (x + 1) %% 5 + 5 * y => j2 = (x + 2) %% 5 + 5 * y =>
  (keccak_pround_op A).[j] = (rpt A).[j] `^` BIC_64 (rpt A).[j2] (rpt A).[j1].
proof. by move=> hx hy -> -> ->; rewrite proundE // bicE. qed.

(* χ row by row. Rows below y hold their χ values, except lane 0, which
   keeps its ρ/π value until ι (the kernel keeps its χ value aside); in
   row y, the lanes x + 5y with x in ks hold theirs; every other lane
   holds its ρ/π value. *)
op row_inv (a0 a : BArray200.t) (y : int) (ks : int list) =
  forall j, 0 <= j < 25 =>
    BArray200.get64 a j =
      if (j <> 0 /\ j < 5 * y) \/ (5 * y <= j < 5 * y + 5 /\ j - 5 * y \in ks)
      then (keccak_pround_op (lanes a0)).[j] else (rpt (lanes a0)).[j].

lemma row_set (a0 a : BArray200.t) y ks x j v :
  0 <= y < 5 => 0 <= x < 5 => j = x + 5 * y => row_inv a0 a y ks =>
  v = (keccak_pround_op (lanes a0)).[j] =>
  row_inv a0 (BArray200.set64 a j v) y (x :: ks).
proof.
move=> hy hx -> h -> i hi; rewrite get_set64_200 1:/#.
case: (x + 5 * y = i) => [<<- | hne].
+ by rewrite (: x + 5 * y - 5 * y = x) 1:/# /=; smt().
rewrite h 1://; congr.
by rewrite eq_iff; split => [[|[? ?]] | [|[? ?]]]; smt().
qed.

lemma row_first (a0 a : BArray200.t) :
  (forall i, 0 <= i < 25 => BArray200.get64 a i = (rpt (lanes a0)).[i]) =>
  row_inv a0 a 0 [].
proof. by move=> h i hi; rewrite h // (: !(i <> 0 /\ i < 0)) 1:/#. qed.

(* Reads of the state at a lane given by its byte offset, the form of a
   constant index once it is simplified. *)
lemma rpt_read (a0 a : BArray200.t) y ks b :
  row_inv a0 a y ks => 0 <= y < 5 => 0 <= b < 200 => b %% 8 = 0 =>
  5 * y <= b %/ 8 < 5 * y + 5 => !(b %/ 8 - 5 * y \in ks) =>
  BArray200.get64d a b = (rpt (lanes a0)).[b %/ 8].
proof.
move=> h hy hb hm hr hks; have := h (b %/ 8) _; first smt().
rewrite (: 8 * (b %/ 8) = b) 1:/# => ->.
by rewrite hks /= (: !(b %/ 8 <> 0 /\ b %/ 8 < 5 * y)) 1:/#.
qed.

(* The same at a lane index. *)
lemma row_read (a0 a : BArray200.t) y ks j :
  row_inv a0 a y ks => 0 <= y < 5 => 5 * y <= j < 5 * y + 5 =>
  !(j - 5 * y \in ks) =>
  BArray200.get64 a j = (rpt (lanes a0)).[j].
proof.
move=> h hy hj hks; rewrite h 1:/# hks /=.
by rewrite (: !(j <> 0 /\ j < 5 * y)) 1:/#.
qed.

lemma row_next (a0 a : BArray200.t) y ks :
  0 <= y < 5 => (forall x, 0 <= x < 5 => (x \in ks) \/ (y = 0 /\ x = 0)) =>
  (y = 0 => !(0 \in ks)) => row_inv a0 a y ks => row_inv a0 a (y + 1) [].
proof.
move=> hy hks hk0 h i hi; rewrite h 1:// /=; congr.
rewrite eq_iff; split.
+ case=> [/#| [[hi0 hi5] hin]]; split; last smt().
  by apply/negP => ->>; move: hin hk0; rewrite (: y = 0) 1:/#.
move=> [hi0 hi5]; case: (i < 5 * y) => hlt; first by left.
right; split; first smt().
have [// | [hy0 hx0]] := hks (i - 5 * y) _; first smt().
by move: hi0; rewrite hy0 /= -hx0 hy0.
qed.

(* A write to lane 0, once its constant index is simplified. *)
lemma get_set64_0 (s : BArray200.t) j w : 0 <= j < 25 =>
  BArray200.get64d (BArray200.set64d s 0 w) (8 * j) =
  if j = 0 then w else BArray200.get64 s j.
proof. by move=> hj; have /= := get_set64_200 s 0 j w _; rewrite // (eq_sym 0). qed.

(* ------------------------------------------------------------------ *)
(* One round                                                          *)

lemma keccak_round_regs_correct (a0 : BArray200.t) (ir0 : int) :
  hoare [M.__keccak_round_regs : a = a0 /\ ir = ir0 /\ 0 <= ir0 < 24
         ==> lanes res = keccak_round_op rc_spec.[ir0] (lanes a0)].
proof.
proc.
(* θ: the parities, the lanes moved to the stack, and D[0] *)
seq 11 : (ir = ir0 /\ 0 <= ir0 < 24 /\ a = a0 /\
          kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\ d = (Dv a0).[0]).
+ wp; ecall (parity_spec a 4); wp; ecall (parity_spec a 3); wp.
  ecall (parity_spec a 2); wp; ecall (parity_spec a 1); ecall (parity_spec a 0).
  by auto => />; rewrite (Dv_ror _ 0).
(* θ, column 0 *)
seq 2 : (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         theta_part a0 a [0] 2 0).
+ while (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         d = (Dv a0).[0] /\ 0 <= y <= 5 /\ theta_part a0 a [] 0 y).
  + auto => /> &m *; split; first smt().
    by apply (theta_col _ _ [] 0 y{m}) => /#.
  auto => /> &m *; split; first by apply theta_part0.
  move=> a1 y1 *; apply theta_next; have ->> // : y1 = 5 by smt().
(* θ, column 2, after lane 22 returns *)
seq 4 : (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         theta_part a0 a [2; 0] 3 0).
+ while (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         d = (Dv a0).[2] /\ 0 <= y <= 5 /\ theta_part a0 a [0] 2 y).
  + auto => /> &m *; split; first smt().
    by apply (theta_col _ _ [0] 2 y{m}) => /#.
  auto => /> &m *; split; [split | ].
  + by rewrite (Dv_ror _ 2).
  + by apply (theta_restore _ _ _ _ 22) => //; smt().
  move=> a1 y1 *; apply theta_next; have ->> // : y1 = 5 by smt().
(* θ, column 3, after lane 23 returns *)
seq 4 : (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         theta_part a0 a [3; 2; 0] 1 0).
+ while (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         d = (Dv a0).[3] /\ 0 <= y <= 5 /\ theta_part a0 a [2; 0] 3 y).
  + auto => /> &m *; split; first smt().
    by apply (theta_col _ _ [2; 0] 3 y{m}) => /#.
  auto => /> &m *; split; [split | ].
  + by rewrite (Dv_ror _ 3).
  + by apply (theta_restore _ _ _ _ 23) => //; smt().
  move=> a1 y1 *; apply theta_next; have ->> // : y1 = 5 by smt().
(* θ, column 1, after lane 21 returns *)
seq 4 : (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         theta_part a0 a [1; 3; 2; 0] 4 0).
+ while (ir = ir0 /\ 0 <= ir0 < 24 /\ kept a0 c0 c1 c2 c3 c4 s21 s22 s23 s24 /\
         d = (Dv a0).[1] /\ 0 <= y <= 5 /\ theta_part a0 a [3; 2; 0] 1 y).
  + auto => /> &m *; split; first smt().
    by apply (theta_col _ _ [3; 2; 0] 1 y{m}) => /#.
  auto => /> &m *; split; [split | ].
  + by rewrite (Dv_ror _ 1).
  + by apply (theta_restore _ _ _ _ 21) => //; smt().
  move=> a1 y1 *; apply theta_next; have ->> // : y1 = 5 by smt().
(* θ, column 4, after lane 24 returns *)
seq 4 : (ir = ir0 /\ 0 <= ir0 < 24 /\
         forall i, 0 <= i < 25 => BArray200.get64 a i = (keccak_theta_op (lanes a0)).[i]).
+ while (ir = ir0 /\ 0 <= ir0 < 24 /\
         d = (Dv a0).[4] /\ 0 <= y <= 5 /\ theta_part a0 a [1; 3; 2; 0] 4 y).
  + auto => /> &m *; split; first smt().
    by apply (theta_col _ _ [1; 3; 2; 0] 4 y{m}) => /#.
  auto => /> &m *; split; [split | ].
  + by rewrite (Dv_ror _ 4).
  + by apply (theta_restore _ _ _ _ 24) => //; smt().
  move=> a1 y1 ? ? ? ? ht i hi0 hi25.
  have ->> : y1 = 5 by smt().
  by apply (theta_all a0 a1 0 (theta_next _ _ _ _ _ ht)); rewrite hi0 hi25.
(* ρ/π *)
seq 3 : (ir = ir0 /\ 0 <= ir0 < 24 /\ cur = 1 /\ k = 0 /\
         t0 = (keccak_theta_op (lanes a0)).[1] /\ rhopi_inv a0 a 0).
+ auto => /> &m h0 h24 ht; split; first by rewrite -ht.
  move=> i hi; have hn : !(index i pi_cycle < 0) by smt(index_ge0).
  by rewrite ht // hn.
seq 1 : (ir = ir0 /\ 0 <= ir0 < 24 /\
         forall i, 0 <= i < 25 => BArray200.get64 a i = (rpt (lanes a0)).[i]).
+ while (ir = ir0 /\ 0 <= ir0 < 24 /\ 0 <= k <= 24 /\ cur = nth 0 (rcons pi_cycle 1) k /\
         t0 = (keccak_theta_op (lanes a0)).[1] /\ rhopi_inv a0 a k).
  + wp; ecall (keccak_rho_spec ((x + 3 * y) %% 5) x); auto => /> &m *.
    have hk : 0 <= k{m} < 24 by smt().
    have hc := pi_cycle_range k{m} hk.
    have e : forall c, (c %% 5 + 3 * (c %/ 5)) %% 5 + 5 * (c %% 5) = pi_src c by done.
    rewrite (pi_cycle_rcons k{m} hk) !modz_mod !e.
    have hs := pi_cycle_step k{m} hk.
    split; first smt().
    move=> *; split => hs1; (split; first smt()); (split; first by rewrite hs);
      by apply rhopi_step => //; rewrite hs1.
  auto => /> &m h0 h24 hinv0 a1 k1 hk1 hk10 hk124 hinv1 i hi0 hi25.
  have ->> : k1 = 24 by smt().
  rewrite hinv1 1:/# pi_cycle_all 1:/#.
  by case: (i = 0) => h /=; [rewrite h rpt0 | done].
(* χ, row 0: its lane 0 goes to s0 *)
seq 12 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
          row_inv a0 a 1 []).
+ seq 3 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
           row_inv a0 a 0 []).
  + auto => /> &m h0 h24 hr; have hr0 := row_first _ _ hr; split => //.
    rewrite !(rpt_read _ _ 0 [] _ hr0) //=.
    by rewrite (chi_at _ 0 0 0 1 2) // W64.xorwC.
  seq 2 : (#pre /\ t1 = (keccak_pround_op (lanes a0)).[1]).
  + auto => /> &m h0 h24 hr; rewrite !(rpt_read _ _ 0 [] _ hr) //=.
    by rewrite (chi_at _ 1 0 1 2 3) // W64.xorwC.
  seq 2 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
           t1 = (keccak_pround_op (lanes a0)).[1] /\ row_inv a0 a 0 [2]).
  + auto => /> &m h0 h24 hr; apply (row_set _ _ 0 [] 2 2) => //.
    by rewrite !(rpt_read _ _ 0 [] _ hr) //= (chi_at _ 2 0 2 3 4).
  seq 2 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
           t1 = (keccak_pround_op (lanes a0)).[1] /\ row_inv a0 a 0 [3; 2]).
  + auto => /> &m h0 h24 hr; apply (row_set _ _ 0 [2] 3 3) => //.
    by rewrite !(rpt_read _ _ 0 [2] _ hr) //= (chi_at _ 3 0 3 4 0).
  seq 2 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
           t1 = (keccak_pround_op (lanes a0)).[1] /\ row_inv a0 a 0 [4; 3; 2]).
  + auto => /> &m h0 h24 hr; apply (row_set _ _ 0 [3; 2] 4 4) => //.
    by rewrite !(rpt_read _ _ 0 [3; 2] _ hr) //= (chi_at _ 4 0 4 0 1).
  auto => /> &m h0 h24 hr.
  apply (row_next _ _ 0 [1; 4; 3; 2]) => //; first smt().
  by apply (row_set _ _ 0 [4; 3; 2] 1 1).
(* χ, rows 1 to 4 *)
seq 2 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
         row_inv a0 a 5 []).
+ while (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
         1 <= y <= 5 /\ row_inv a0 a y []).
  + seq 4 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
             1 <= y < 5 /\ i = 5 * y /\ row_inv a0 a y [] /\
             t0 = BIC_64 (rpt (lanes a0)).[i + 2] (rpt (lanes a0)).[i + 1] /\
             t1 = BIC_64 (rpt (lanes a0)).[i + 3] (rpt (lanes a0)).[i + 2] /\
             t2 = BIC_64 (rpt (lanes a0)).[i + 4] (rpt (lanes a0)).[i + 3]).
    + auto => /> &m h0 h24 hy0 hy5 hr hy1.
      by rewrite !(row_read _ _ y{m} [] _ hr); smt().
    seq 1 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
             1 <= y < 5 /\ i = 5 * y /\ row_inv a0 a y [2] /\
             t0 = BIC_64 (rpt (lanes a0)).[i + 2] (rpt (lanes a0)).[i + 1] /\
             t1 = BIC_64 (rpt (lanes a0)).[i + 3] (rpt (lanes a0)).[i + 2]).
    + auto => /> &m h0 h24 hy1 hy5 hr.
      apply (row_set _ _ y{m} [] 2 _ _ _ _ _ hr); [smt() | smt() | smt() | ].
      rewrite (chi_at _ 2 y{m} (5 * y{m} + 2) (5 * y{m} + 3) (5 * y{m} + 4)) 1..5:/#.
      by rewrite !(row_read _ _ y{m} [] _ hr); smt().
    seq 2 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
             1 <= y < 5 /\ i = 5 * y /\ row_inv a0 a y [3; 2] /\
             t0 = BIC_64 (rpt (lanes a0)).[i + 2] (rpt (lanes a0)).[i + 1] /\
             t1 = BIC_64 (rpt (lanes a0)).[i + 3] (rpt (lanes a0)).[i + 2]).
    + auto => /> &m h0 h24 hy1 hy5 hr.
      apply (row_set _ _ y{m} [2] 3 _ _ _ _ _ hr); [smt() | smt() | smt() | ].
      rewrite (chi_at _ 3 y{m} (5 * y{m} + 3) (5 * y{m} + 4) (5 * y{m})) 1..5:/#.
      by rewrite !(row_read _ _ y{m} [2] _ hr); smt().
    seq 2 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
             1 <= y < 5 /\ i = 5 * y /\ row_inv a0 a y [4; 3; 2] /\
             t0 = BIC_64 (rpt (lanes a0)).[i + 2] (rpt (lanes a0)).[i + 1] /\
             t1 = BIC_64 (rpt (lanes a0)).[i + 3] (rpt (lanes a0)).[i + 2]).
    + auto => /> &m h0 h24 hy1 hy5 hr.
      apply (row_set _ _ y{m} [3; 2] 4 _ _ _ _ _ hr); [smt() | smt() | smt() | ].
      rewrite (chi_at _ 4 y{m} (5 * y{m} + 4) (5 * y{m}) (5 * y{m} + 1)) 1..5:/#.
      by rewrite !(row_read _ _ y{m} [3; 2] _ hr); smt().
    seq 1 : (ir = ir0 /\ 0 <= ir0 < 24 /\ s0 = (keccak_pround_op (lanes a0)).[0] /\
             1 <= y < 5 /\ i = 5 * y /\ row_inv a0 a y [0; 4; 3; 2] /\
             t1 = BIC_64 (rpt (lanes a0)).[i + 3] (rpt (lanes a0)).[i + 2]).
    + auto => /> &m h0 h24 hy1 hy5 hr.
      apply (row_set _ _ y{m} [4; 3; 2] 0 _ _ _ _ _ hr); [smt() | smt() | smt() | ].
      rewrite (chi_at _ 0 y{m} (5 * y{m}) (5 * y{m} + 1) (5 * y{m} + 2)) 1..5:/#.
      by rewrite !(row_read _ _ y{m} [4; 3; 2] _ hr); smt().
    auto => /> &m h0 h24 hy1 hy5 hr; split; first smt().
    apply (row_next _ _ y{m} [1; 0; 4; 3; 2]); [smt() | smt() | smt() | ].
    apply (row_set _ _ y{m} [0; 4; 3; 2] 1 _ _ _ _ _ hr); [smt() | smt() | smt() | ].
    rewrite (chi_at _ 1 y{m} (5 * y{m} + 1) (5 * y{m} + 2) (5 * y{m} + 3)) 1..5:/#.
    by rewrite !(row_read _ _ y{m} [0; 4; 3; 2] _ hr); smt().
  auto => /> &m h0 h24 hr a1 y1 ? ? ? hr1.
  by have ->> : y1 = 5 by smt().
(* ι *)
auto => /> &m h0 h24 hr.
apply Array25.ext_eq => k hk.
rewrite lanesE // /keccak_round_op /keccak_iota_op Array25.get_setE 1://.
rewrite !get_set64_0 // kECCAK_RCE //.
case: (k = 0) => [->> // | hk0].
by rewrite hr 1:// /= (: k < 25) 1:/# hk0.
qed.

(* ------------------------------------------------------------------ *)
(* The permutation                                                    *)

lemma keccakf1600_correct (s0 : BArray200.t) :
  hoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)].
proof.
proc.
(* the lanes into registers *)
seq 3 : (st = s0 /\ forall k, 0 <= k < 25 => BArray200.get64 a k = BArray200.get64 s0 k).
+ while (0 <= i <= 25 /\ st = s0 /\
         forall k, 0 <= k < i => BArray200.get64 a k = BArray200.get64 s0 k).
  + auto => /> &m hi0 _ h hi; split; first smt().
    move=> k hk0 hk; rewrite get_set64_200 1:/#.
    by case: (i{m} = k) => [-> // | hne]; apply h => /#.
  auto => />; split; first smt().
  by move=> a1 i1 hi1 hi0 hi25 h k hk0 hk; apply h => /#.
(* the 24 rounds *)
seq 2 : (lanes a = keccak_f1600_op (lanes s0)).
+ while (0 <= ir <= 24 /\ lanes a = rounds (lanes s0) ir).
  + wp; ecall (keccak_round_regs_correct a ir); auto => /> &m h0 _ hl h24 a1 ha1.
    by split; [smt() | rewrite ha1 hl roundsS].
  auto => /> &m h.
  have hl : lanes a{m} = lanes s0 by apply Array25.ext_eq => k hk; rewrite !lanesE // h.
  split => [| a1 ir1 h24 h0 hle ha1]; first by rewrite hl /rounds iota0.
  by rewrite -rounds24 ha1 (: ir1 = 24) 1:/#.
(* the lanes back to memory *)
while (0 <= i <= 25 /\ lanes a = keccak_f1600_op (lanes s0) /\
       forall k, 0 <= k < i => BArray200.get64 st k = BArray200.get64 a k).
+ auto => /> &m hi0 _ ha h hi; split; first smt().
  move=> k hk0 hk; rewrite get_set64_200 1:/#.
  by case: (i{m} = k) => [-> // | hne]; apply h => /#.
auto => /> &m ha; split; first smt().
move=> st1 i1 hi1 hi0 hi25 h; rewrite -ha.
by apply Array25.ext_eq => k hk; rewrite !lanesE // h /#.
qed.

(* Every loop runs over a constant range, so the kernel terminates on every
   input. *)
lemma parity_ll : islossless M.__parity.
proof. by proc; auto. qed.

lemma keccak_round_regs_ll : islossless M.__keccak_round_regs.
proof.
proc.
wp; while (0 <= y <= 5) (5 - y); first by auto => /#.
wp; while (0 <= k <= 24) (24 - k); first by move=> z; wp; call keccak_rho_ll; auto => /#.
wp; while (0 <= y <= 5) (5 - y); first by auto => /#.
wp; while (0 <= y <= 5) (5 - y); first by auto => /#.
wp; while (0 <= y <= 5) (5 - y); first by auto => /#.
wp; while (0 <= y <= 5) (5 - y); first by auto => /#.
wp; while (0 <= y <= 5) (5 - y); first by auto => /#.
wp; call parity_ll; wp; call parity_ll; wp; call parity_ll; wp; call parity_ll.
by call parity_ll; auto => /#.
qed.

lemma keccakf1600_ll : islossless M._keccakf1600.
proof.
proc.
while (0 <= i <= 25) (25 - i); first by auto => /#.
wp; while (0 <= ir <= 24) (24 - ir); first by move=> z; wp; call keccak_round_regs_ll; auto => /#.
wp; while (0 <= i <= 25) (25 - i); first by auto => /#.
by auto => /#.
qed.

lemma keccakf1600_total (s0 : BArray200.t) :
  phoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)] = 1%r.
proof. by conseq keccakf1600_ll (keccakf1600_correct s0). qed.
