(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * SHA256_Compress.ec
 * ==================
 *
 * Functional correctness of the one-block entry point _sha256_compress of
 * the scalar SHA-256 compression kernel (src/hash/sha2/sha256_compress.jinc)
 * against FIPS 180-4 section 6.2.2 as specified in
 * spec/hash/FIPS180_SHA2.ec. The kernel's entry points that read blocks
 * from memory, _sha256_compress_one and _sha256_compress_blocks, are not
 * covered.
 *
 * Model. HashExtracted is the jasmin2ec model of one (architecture,
 * variant) pair; this file is checked once against each pair whose
 * Sha2Kernel is the scalar kernel (proofs/Makefile). The kernel source is
 * shared, so the two models differ only in the byte reversal __bswap32
 * (BSWAP on x86-64, REV on AArch64), which this file uses through the
 * lemma bswap32_spec of the per-architecture theory ArchWord.
 *
 * Representation. The chaining value h is u32[8], H_0 .. H_7 as native
 * words (hwords); the message schedule window w is u32[16] (mwords). The
 * byte layout of a u32 inside the arrays is that of the model's get32, the
 * same on both architectures.
 *
 * Theorems:
 *     sha256_rounds_correct     __sha256_rounds computes compress on the
 *                               message words already in w (Hoare logic:
 *                               partial correctness);
 *     sha256_compress_correct   _sha256_compress computes compress on the
 *                               big-endian words of the 64-byte block
 *                               (partial correctness);
 *     sha256_compress_total     the same with termination: from every
 *                               initial state the procedure returns,
 *                               with the specified result.
 *
 * The kernel keeps a 16-word schedule window and rotates the working
 * variables over eight slots instead of shifting them; the loop invariants
 * below state both correspondences.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils.
require import BArray32 BArray64 BArray256.
require import HashExtracted ArchWord.
require import Bytes FIPS180_SHA2.
import SHA256.

(* ------------------------------------------------------------------ *)
(* Views of the arrays as word lists                                  *)

op hwords (h : BArray32.t) : W32.t list = map (BArray32.get32 h) (iota_ 0 8).
op mwords (w : BArray64.t) : W32.t list = map (BArray64.get32 w) (iota_ 0 16).

lemma nth_hwords h k : 0 <= k < 8 => nth W32.zero (hwords h) k = BArray32.get32 h k.
proof. by move=> hk; rewrite /hwords (nth_map 0) 1:size_iota 1:/# nth_iota. qed.

lemma nth_mwords w k : 0 <= k < 16 => nth W32.zero (mwords w) k = BArray64.get32 w k.
proof. by move=> hk; rewrite /mwords (nth_map 0) 1:size_iota 1:/# nth_iota. qed.

lemma size_hwords h : size (hwords h) = 8.
proof. by rewrite /hwords size_map size_iota. qed.

(* ------------------------------------------------------------------ *)
(* Facts about the specification                                      *)

(* The schedule of section 6.2.2 step 1 after W_0 .. W_{j-1} are known. *)
op sched_step (w : W32.t list) (t : int) : W32.t list =
  rcons w (ssig1 (nth W32.zero w (t - 2)) + nth W32.zero w (t - 7)
         + ssig0 (nth W32.zero w (t - 15)) + nth W32.zero w (t - 16)).

op sched (m : W32.t list) (j : int) : W32.t list = foldl sched_step m (range 16 j).

lemma schedE m : schedule m = sched m 64.
proof. by rewrite /schedule /sched /sched_step. qed.

lemma schedS m j : 16 <= j => sched m (j + 1) = sched_step (sched m j) j.
proof. by move=> hj; rewrite /sched rangeSr 1:/# -cats1 foldl_cat. qed.

lemma size_sched m j : size m = 16 => 16 <= j => size (sched m j) = j.
proof.
move=> hm; elim/natind: j => [j hj hb | j hj ih hb]; first by smt().
case: (j = 15) => [->> /=|ne]; first by rewrite /sched range_geq.
by rewrite schedS 1:/# /sched_step size_rcons ih /#.
qed.

(* Elements already computed never change. *)
lemma nth_sched_stable m i j k :
  size m = 16 => 16 <= j <= k => 0 <= i < j =>
  nth W32.zero (sched m k) i = nth W32.zero (sched m j) i.
proof.
move=> hm [hj hjk] hi.
have h : forall d, 0 <= d => nth W32.zero (sched m (j + d)) i = nth W32.zero (sched m j) i.
+ elim/natind => [d hd hd' | d hd ih _]; first by have ->: d = 0 by smt().
  rewrite addzA schedS 1:/# /sched_step nth_rcons size_sched // 1:/#.
  by rewrite ifT 1:/# ih.
have := h (k - j) _; first by smt().
by have ->: j + (k - j) = k by ring.
qed.

lemma nth_schedule_lo m t :
  size m = 16 => 0 <= t < 16 => nth W32.zero (schedule m) t = nth W32.zero m t.
proof.
move=> hm ht; rewrite schedE (nth_sched_stable _ _ 16) // /sched.
by rewrite range_geq.
qed.

lemma nth_schedule_hi m t :
  size m = 16 => 16 <= t < 64 =>
  nth W32.zero (schedule m) t
  = ssig1 (nth W32.zero (schedule m) (t - 2)) + nth W32.zero (schedule m) (t - 7)
  + ssig0 (nth W32.zero (schedule m) (t - 15)) + nth W32.zero (schedule m) (t - 16).
proof.
move=> hm ht; rewrite !schedE.
have -> : nth W32.zero (sched m 64) t = nth W32.zero (sched m (t + 1)) t.
+ by rewrite (nth_sched_stable m t (t + 1) 64) // /#.
rewrite schedS 1:/# /sched_step nth_rcons size_sched // 1:/# /=.
rewrite -(nth_sched_stable m (t - 2) t 64) 1,2,3:/#.
rewrite -(nth_sched_stable m (t - 7) t 64) 1,2,3:/#.
rewrite -(nth_sched_stable m (t - 15) t 64) 1,2,3:/#.
by rewrite -(nth_sched_stable m (t - 16) t 64) 1,2,3:/#.
qed.

(* The working variables after t rounds, as the list [a; b; ...; h]. *)
op vars (hv w : W32.t list) (t : int) : W32.t list =
  of_state (foldl (round w) (to_state hv) (range 0 t)).

lemma vars0 hv w : size hv = 8 => vars hv w 0 = hv.
proof.
move=> hs; rewrite /vars range_geq //= /to_state /of_state /=.
apply (eq_from_nth W32.zero) => //= [|i hi]; first by rewrite hs.
by smt().
qed.

lemma size_vars hv w t : size (vars hv w t) = 8.
proof. by rewrite /vars /of_state; case: (foldl _ _ _). qed.

(* T1 and T2 of section 6.2.2 step 3, on the list of working variables. *)
op T1 (vs w : W32.t list) (t : int) : W32.t =
  nth W32.zero vs 7 + bsig1 (nth W32.zero vs 4)
  + ch (nth W32.zero vs 4) (nth W32.zero vs 5) (nth W32.zero vs 6)
  + nth W32.zero K256 t + nth W32.zero w t.

op T2 (vs : W32.t list) : W32.t =
  bsig0 (nth W32.zero vs 0) + maj (nth W32.zero vs 0) (nth W32.zero vs 1) (nth W32.zero vs 2).

(* One round on the list of working variables. *)
lemma varsS hv w t : 0 <= t =>
  vars hv w (t + 1) =
    let v = vars hv w t in
    [T1 v w t + T2 v; nth W32.zero v 0; nth W32.zero v 1; nth W32.zero v 2;
     nth W32.zero v 3 + T1 v w t; nth W32.zero v 4; nth W32.zero v 5; nth W32.zero v 6].
proof.
move=> ht; rewrite /vars rangeSr // -cats1 foldl_cat /=.
by case: (foldl _ _ _) => a b c d e f g h; rewrite /round /of_state /T1 /T2.
qed.

(* compress in terms of vars. *)
lemma compressE hv m :
  compress hv m
  = map (fun (xy : W32.t * W32.t) => xy.`1 + xy.`2) (zip (vars hv (schedule m) 64) hv).
proof. by rewrite /compress /vars. qed.

lemma nth_compress hv m k :
  size hv = 8 => 0 <= k < 8 =>
  nth W32.zero (compress hv m) k = nth W32.zero (vars hv (schedule m) 64) k + nth W32.zero hv k.
proof.
move=> hs hk; rewrite compressE (nth_map (W32.zero, W32.zero)).
+ by rewrite size_zip size_vars hs.
by rewrite nth_zip // size_vars hs.
qed.

lemma size_compress hv m : size hv = 8 => size (compress hv m) = 8.
proof. by move=> hs; rewrite compressE size_map size_zip size_vars hs. qed.

(* ------------------------------------------------------------------ *)
(* The two rewritten Boolean functions of the kernel                  *)

lemma ch_kernel (e f g : W32.t) : ((f +^ g) `&` e) +^ g = ch e f g.
proof.
rewrite /ch; apply W32.wordP => i hi.
by rewrite !(W32.xorwE, W32.andwE, W32.invwE) hi /=; smt().
qed.

lemma maj_kernel (a b c : W32.t) : ((a +^ b) `&` c) +^ (a `&` b) = maj a b c.
proof.
rewrite /maj; apply W32.wordP => i hi.
by rewrite !(W32.xorwE, W32.andwE) /=; smt().
qed.

lemma Sigma0_kernel (x : W32.t) :
  (x `|>>|` W8.of_int 2) +^ (x `|>>|` W8.of_int 13) +^ (x `|>>|` W8.of_int 22) = bsig0 x.
proof. by rewrite /bsig0 /(`|>>|`) !W8.of_uintK. qed.

lemma Sigma1_kernel (x : W32.t) :
  (x `|>>|` W8.of_int 6) +^ (x `|>>|` W8.of_int 11) +^ (x `|>>|` W8.of_int 25) = bsig1 x.
proof. by rewrite /bsig1 /(`|>>|`) !W8.of_uintK. qed.

lemma sigma0_kernel (x : W32.t) :
  (x `|>>|` W8.of_int 7) +^ (x `|>>|` W8.of_int 18) +^ (x `>>` W8.of_int 3) = ssig0 x.
proof. by rewrite /ssig0 /(`|>>|`) /(`>>`) !W8.of_uintK. qed.

lemma sigma1_kernel (x : W32.t) :
  (x `|>>|` W8.of_int 17) +^ (x `|>>|` W8.of_int 19) +^ (x `>>` W8.of_int 10) = ssig1 x.
proof. by rewrite /ssig1 /(`|>>|`) /(`>>`) !W8.of_uintK. qed.

(* ------------------------------------------------------------------ *)
(* The round-constant table                                           *)

lemma K256_kernel t : 0 <= t < 64 =>
  BArray256.get32 sHA256_K t = nth W32.zero K256 t.
proof.
move=> ht; rewrite BArray256.get32_of_list32 1://.
by congr; rewrite /K256 /=.
qed.

(* ------------------------------------------------------------------ *)
(* The slot rotation                                                  *)

(* Invariant of the round loop: variable k (a = 0, ..., h = 7) of round t
   is in slot (k - t) mod 8, written ((k + 64) - t) %% 8 by the kernel. *)
op slots_ok (v : BArray32.t) (vs : W32.t list) (t : int) =
  forall k, 0 <= k < 8 => BArray32.get32 v ((k + 64 - t) %% 8) = nth W32.zero vs k.

lemma slots_step (v : BArray32.t) vs t t1 t2 :
  0 <= t < 64 => slots_ok v vs t =>
  slots_ok
    (BArray32.set32
       (BArray32.set32 v ((3 + 64 - t) %% 8) (BArray32.get32 v ((3 + 64 - t) %% 8) + t1))
       ((7 + 64 - t) %% 8) (t1 + t2))
    [t1 + t2; nth W32.zero vs 0; nth W32.zero vs 1; nth W32.zero vs 2;
     nth W32.zero vs 3 + t1; nth W32.zero vs 4; nth W32.zero vs 5; nth W32.zero vs 6] (t + 1).
proof.
move=> ht hok k hk.
rewrite !BArray32.get_set32E; 1..4: smt().
have: k = 0 \/ k = 1 \/ k = 2 \/ k = 3 \/ k = 4 \/ k = 5 \/ k = 6 \/ k = 7 by smt().
case=> [->|[->|[->|[->|[->|[->|[->|->]]]]]]] /=.
+ by rewrite ifT 1:/#.
+ by rewrite ifF 1:/# ifF 1:/# -(hok 0) // /#.
+ by rewrite ifF 1:/# ifF 1:/# -(hok 1) // /#.
+ by rewrite ifF 1:/# ifF 1:/# -(hok 2) // /#.
+ by rewrite ifF 1:/# ifT 1:/# (hok 3) // /#.
+ by rewrite ifF 1:/# ifF 1:/# -(hok 4) // /#.
+ by rewrite ifF 1:/# ifF 1:/# -(hok 5) // /#.
by rewrite ifF 1:/# ifF 1:/# -(hok 6) // /#.
qed.

(* The second half of a kernel round (T2, the two stores, the rotation):
   e' = d + T1 goes to the slot of d, a' = T1 + T2 to the slot of h. The
   reads of a, b and c come after the store to d's slot, which is not one
   of theirs. *)
lemma round_finish (v : BArray32.t) vs t (t1 : W32.t) :
  0 <= t < 64 => slots_ok v vs t =>
  slots_ok
    (BArray32.set32
       (BArray32.set32 v ((3 + 64 - t) %% 8) (BArray32.get32 v ((3 + 64 - t) %% 8) + t1))
       ((7 + 64 - t) %% 8)
       (t1 + bsig0 (BArray32.get32
                      (BArray32.set32 v ((3 + 64 - t) %% 8)
                         (BArray32.get32 v ((3 + 64 - t) %% 8) + t1)) ((0 + 64 - t) %% 8))
           + (((BArray32.get32
                  (BArray32.set32 v ((3 + 64 - t) %% 8)
                     (BArray32.get32 v ((3 + 64 - t) %% 8) + t1)) ((0 + 64 - t) %% 8)
                `^`
                BArray32.get32
                  (BArray32.set32 v ((3 + 64 - t) %% 8)
                     (BArray32.get32 v ((3 + 64 - t) %% 8) + t1)) ((1 + 64 - t) %% 8))
               `&`
               BArray32.get32
                 (BArray32.set32 v ((3 + 64 - t) %% 8)
                    (BArray32.get32 v ((3 + 64 - t) %% 8) + t1)) ((2 + 64 - t) %% 8))
              `^`
              (BArray32.get32
                 (BArray32.set32 v ((3 + 64 - t) %% 8)
                    (BArray32.get32 v ((3 + 64 - t) %% 8) + t1)) ((0 + 64 - t) %% 8)
               `&`
               BArray32.get32
                 (BArray32.set32 v ((3 + 64 - t) %% 8)
                    (BArray32.get32 v ((3 + 64 - t) %% 8) + t1)) ((1 + 64 - t) %% 8)))))
    [t1 + T2 vs; nth W32.zero vs 0; nth W32.zero vs 1; nth W32.zero vs 2;
     nth W32.zero vs 3 + t1; nth W32.zero vs 4; nth W32.zero vs 5; nth W32.zero vs 6] (t + 1).
proof.
move=> ht hok.
have hr : forall k, 0 <= k < 3 =>
  BArray32.get32 (BArray32.set32 v ((3 + 64 - t) %% 8) (BArray32.get32 v ((3 + 64 - t) %% 8) + t1))
                 ((k + 64 - t) %% 8) = nth W32.zero vs k.
+ move=> k hk; rewrite BArray32.get_set32E; 1,2: smt(modz_ge0 ltz_pmod).
  by rewrite ifF; [smt(modz_ge0 ltz_pmod divz_eq) | apply hok => /#].
rewrite (hr 0) // (hr 1) // (hr 2) // maj_kernel -/(T2 vs) (_: t1 + T2 vs = t1 + T2 vs) //.
have := slots_step v vs t t1 (T2 vs) ht hok.
by rewrite /T2 W32.WRingA.addrA.
qed.

(* ------------------------------------------------------------------ *)
(* The four section 4.1.2 functions of the kernel                     *)

lemma Sigma0_spec (x0 : W32.t) : hoare [M.__Sigma0_256 : x = x0 ==> res = bsig0 x0].
proof. by proc; auto => />; rewrite -Sigma0_kernel. qed.

lemma Sigma1_spec (x0 : W32.t) : hoare [M.__Sigma1_256 : x = x0 ==> res = bsig1 x0].
proof. by proc; auto => />; rewrite -Sigma1_kernel. qed.

lemma sigma0_spec (x0 : W32.t) : hoare [M.__sigma0_256 : x = x0 ==> res = ssig0 x0].
proof. by proc; auto => />; rewrite -sigma0_kernel. qed.

lemma sigma1_spec (x0 : W32.t) : hoare [M.__sigma1_256 : x = x0 ==> res = ssig1 x0].
proof. by proc; auto => />; rewrite -sigma1_kernel. qed.

(* ------------------------------------------------------------------ *)
(* The kernel                                                         *)

(* Invariant of the schedule window at the head of round t: slot j mod 16
   holds W_j for every j in [max 0 (t - 16), max 16 t). *)
op window_ok (w : BArray64.t) (ws : W32.t list) (t : int) =
  forall j, max 0 (t - 16) <= j < max 16 t => BArray64.get32 w (j %% 16) = nth W32.zero ws j.

lemma mod16_eq t j : 0 <= t - j < 16 => t %% 16 = j %% 16 => j = t.
proof. smt(divz_eq modz_ge0 ltz_pmod). qed.

lemma win_bounds t d : 16 <= t < 64 => 1 <= d <= 16 =>
  max 0 (t - 16) <= t - d < max 16 t.
proof. by move=> ht hd; rewrite /max /#. qed.

(* One schedule step of the window: slot t mod 16 holds W_{t-16}, its last
   reader, and receives W_t. *)
lemma window_step (w : BArray64.t) m t :
  size m = 16 => 16 <= t < 64 => window_ok w (schedule m) t =>
  let wt = ssig1 (BArray64.get32 w ((t - 2) %% 16)) + ssig0 (BArray64.get32 w ((t - 15) %% 16))
         + BArray64.get32 w ((t - 7) %% 16) + BArray64.get32 w (t %% 16) in
  window_ok (BArray64.set32 w (t %% 16) wt) (schedule m) (t + 1) /\
  wt = nth W32.zero (schedule m) t.
proof.
move=> hm ht hw /=.
have hmod : (t - 16) %% 16 = t %% 16.
+ by rewrite (_: t - 16 = t + (-1) * 16) 1:/# modzMDr.
have e2  := hw (t - 2) (win_bounds t 2 ht _); first done.
have e15 := hw (t - 15) (win_bounds t 15 ht _); first done.
have e7  := hw (t - 7) (win_bounds t 7 ht _); first done.
have e16 := hw (t - 16) (win_bounds t 16 ht _); first done.
rewrite hmod in e16.
have hwt : ssig1 (BArray64.get32 w ((t - 2) %% 16)) + ssig0 (BArray64.get32 w ((t - 15) %% 16))
         + BArray64.get32 w ((t - 7) %% 16) + BArray64.get32 w (t %% 16)
         = nth W32.zero (schedule m) t.
+ rewrite e2 e15 e7 e16 (nth_schedule_hi m t hm ht); ring.
rewrite hwt /=; move=> j; rewrite /max /= => hj.
have hj' : 0 <= t - j < 16 by move: hj ht; clear hw e2 e15 e7 e16 hwt hmod; smt().
rewrite BArray64.get_set32E; 1,2: smt(modz_ge0 ltz_pmod).
case: (t %% 16 = j %% 16) => heq; first by rewrite (mod16_eq t j hj' heq).
apply hw; rewrite /max; move: hj ht heq; clear hw e2 e15 e7 e16 hwt hmod hj'; smt().
qed.

lemma sha256_rounds_correct (h0 : W32.t list) (m : W32.t list) :
  hoare [M.__sha256_rounds :
           hwords h = h0 /\ mwords w = m ==> hwords res = compress h0 m].
proof.
proc.
seq 4 : (hwords h = h0 /\ mwords w = m /\ slots_ok v (vars h0 (schedule m) 0) 0).
+ while (0 <= i <= 8 /\ hwords h = h0 /\ mwords w = m /\
         forall k, 0 <= k < i => BArray32.get32 v k = nth W32.zero h0 k).
  + auto => /> &hr hi hi8 hk hlt; split; first smt().
    move=> k0 hk0 hk1.
    rewrite BArray32.get_set32E 1,2:/#.
    case: (i{hr} = k0) => [<-|ne]; last by rewrite hk /#.
    by rewrite nth_hwords.
  auto => /> &hr; split; first smt().
  move=> i0 v0 hlt hi hi8 hv k hk.
  rewrite (vars0 _ _ (size_hwords h{hr})) (_: (k + 64 - 0) %% 8 = k) 1:/#.
  by apply hv => /#.

(* Rounds 0 .. 63. *)
seq 2 : (hwords h = h0 /\ size m = 16 /\ slots_ok v (vars h0 (schedule m) 64) 64).
+ while (0 <= t <= 64 /\ hwords h = h0 /\ size m = 16 /\
         slots_ok v (vars h0 (schedule m) t) t /\ window_ok w (schedule m) t).
  + seq 1 : (0 <= t < 64 /\ hwords h = h0 /\ size m = 16 /\
               slots_ok v (vars h0 (schedule m) t) t /\ window_ok w (schedule m) (t + 1) /\
               t1 = nth W32.zero (schedule m) t).
    + if.
      + wp; ecall (sigma0_spec x); wp; ecall (sigma1_spec x); wp; skip => />.
        move=> &hr ht0 _ hm _ hw ht64 ht16.
        by have := window_step w{hr} m t{hr} hm _ hw; 1: smt().
      auto => /> &hr ht0 _ hm _ hw ht64 ht16.
      have e := hw t{hr} _; first by rewrite /max; move: ht0 ht16; clear hw; smt().
      have hts : 0 <= t{hr} < 16 by move: ht0 ht16; clear hw e; smt().
      split; last by rewrite -e pmod_small.
      move=> j hj; apply hw; move: hj ht0 ht16; rewrite /max; clear hw e; smt().
    seq 11 : (0 <= t < 64 /\ hwords h = h0 /\ size m = 16 /\
              slots_ok v (vars h0 (schedule m) t) t /\ window_ok w (schedule m) (t + 1) /\
              t1 = T1 (vars h0 (schedule m) t) (schedule m) t).
    + wp; ecall (Sigma1_spec (BArray32.get32 v ((4 + 64 - t) %% 8))); wp; skip.
      move=> &hr [#] ht0 ht64 hh hm hs hw -> r ->.
      rewrite /T1 -(hs 7) // -(hs 4) // -(hs 5) // -(hs 6) // -ch_kernel K256_kernel //.
      split; first smt().
      do 4!(split; first done).
      by ring.
    wp; ecall (Sigma0_spec (BArray32.get32 v ((0 + 64 - t) %% 8))); wp; skip.
    move=> &hr [#] ht0 ht64 hh hm hs hw -> /= r ->.
    rewrite (varsS _ _ _ ht0) /=; split; first by smt().
    do 2!(split; first done).
    by split; [apply round_finish | done].
  auto => /> &hr hv; split.
  + split; first by rewrite /mwords size_map size_iota.
    move=> j; rewrite /max /= => hj.
    rewrite pmod_small 1:/#.
    rewrite nth_schedule_lo; first by rewrite /mwords size_map size_iota.
    + smt().
    by rewrite nth_mwords.
  move=> t v w hlt ht0 ht64 _ hs _.
  by have <- : t = 64 by smt().

(* H(i) = H(i-1) + working variables, word by word. *)
while (0 <= i <= 8 /\ size m = 16 /\ size h0 = 8 /\
       slots_ok v (vars h0 (schedule m) 64) 64 /\
       (forall k, 0 <= k < i => BArray32.get32 h k = nth W32.zero (compress h0 m) k) /\
       (forall k, i <= k < 8 => BArray32.get32 h k = nth W32.zero h0 k)).
+ auto => /> &hr hi0 hi8 hm hs8 hs hdone hrest hlt; split; first smt().
  split => k hk1 hk2.
  + rewrite BArray32.get_set32E; 1,2: by move: hi0 hlt; clear hs hdone hrest; smt().
    case: (i{hr} = k) => [<-|ne]; last by apply hdone; move: hk1 hk2 ne; clear hs hdone hrest; smt().
    have hv := hs i{hr} _; first by move: hi0 hlt; clear hs hdone hrest; smt().
    have he : (i{hr} + 64 - 64) %% 8 = i{hr} by move: hi0 hlt; clear hs hdone hrest hv; smt().
    move: hv; rewrite he => hv.
    have hi' : 0 <= i{hr} < 8 by move: hi0 hlt; clear hs hdone hrest hv he; smt().
    rewrite (nth_compress _ _ _ hs8 hi') hv (hrest i{hr}) 1:/#.
    by ring.
  rewrite BArray32.get_set32E; 1,2: by move: hi0 hlt; clear hs hdone hrest; smt().
  rewrite ifF; first by move: hk1; clear hs hdone hrest; smt().
  by apply hrest; move: hk1 hk2; clear hs hdone hrest; smt().
auto => /> &hr hm hs; split.
+ split; first by rewrite size_hwords.
  split; first by move=> k hk1 hk2; move: hk1 hk2; clear hs; smt().
  by move=> k hk1 hk2; rewrite nth_hwords.
move=> h1 i0 hlt hi0 hi8 hsz hdone _.
apply (eq_from_nth W32.zero); first by rewrite size_hwords size_compress.
move=> k; rewrite size_hwords => hk.
by rewrite nth_hwords // hdone; move: hk hlt hi8; clear hs hdone; smt().
qed.

(* ------------------------------------------------------------------ *)
(* The kernel entry point on a 64-byte block                          *)

lemma nth_chunk4 (bs : W8.t list) k :
  0 <= k < size bs %/ 4 => nth [] (chunk 4 bs) k = take 4 (drop (4 * k) bs).
proof. by move=> hk; rewrite /chunk nth_mkseq. qed.

(* Message word k of the block, read big-endian (section 5.2.1). *)
lemma bswap_get32 (blk : BArray64.t) k : 0 <= k < 16 =>
  WordSpec.bswap32 (BArray64.get32 blk k) = be32 (take 4 (drop (4 * k) (BArray64.to_list blk))).
proof.
move=> hk; rewrite /WordSpec.bswap32 /be32 BArray64.get32dE; do 3!congr.
apply (eq_from_nth W8.zero).
+ by rewrite W4u8.size_to_list size_take // size_drop 1:/# BArray64.size_to_list /#.
move=> j; rewrite W4u8.size_to_list => hj.
rewrite W4u8.nth_to_list W4u8.get_pack4 1:BArray64.size_sub //.
rewrite nth_take // 1:/# nth_drop 1,2:/# BArray64.get_to_list.
by rewrite BArray64.nth_sub.
qed.

lemma sha256_compress_correct (h0 : W32.t list) (blk : BArray64.t) :
  hoare [M._sha256_compress :
           hwords h = h0 /\ block = blk ==>
           hwords res.`1 = compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))].
proof.
proc.
ecall (sha256_rounds_correct h0 (map be32 (chunk 4 (BArray64.to_list blk)))).
while (0 <= i <= 16 /\ hwords h = h0 /\ block = blk /\
       forall k, 0 <= k < i =>
         BArray64.get32 w k = be32 (take 4 (drop (4 * k) (BArray64.to_list blk)))).
+ wp; ecall (bswap32_spec x); auto => /> &hr hi0 hi16 hk hlt; split; first smt().
  move=> k hk1 hk2; rewrite BArray64.get_set32E 1,2:/#.
  case: (i{hr} = k) => [<-|ne]; first by rewrite bswap_get32 /#.
  by apply hk => /#.
auto => />; split; first by move=> k hk1 hk2; move: hk1 hk2; smt().
move=> i w hlt hi0 hi16 hk.
apply (eq_from_nth W32.zero).
+ by rewrite /mwords size_map size_iota size_map size_chunk // BArray64.size_to_list.
move=> k; rewrite /mwords size_map size_iota => hk'.
rewrite (nth_map 0) 1:size_iota 1:/# nth_iota 1:/# (nth_map []).
+ by rewrite size_chunk // BArray64.size_to_list /#.
have hc : 0 <= k < size (BArray64.to_list blk) %/ 4 by rewrite BArray64.size_to_list /#.
by rewrite /= (nth_chunk4 _ _ hc) (hk k) /#.
qed.

(* ------------------------------------------------------------------ *)
(* Termination and total correctness                                  *)

(* Every loop of the kernel runs over a constant range, so both
   procedures terminate on every input. *)
lemma sha256_rounds_ll : islossless M.__sha256_rounds.
proof.
proc; inline *.
while (0 <= i <= 8) (8 - i); first by auto => /#.
wp; while (0 <= t <= 64) (64 - t); first by auto => /#.
wp; while (0 <= i <= 8) (8 - i); first by auto => /#.
by auto => /#.
qed.

lemma sha256_compress_ll : islossless M._sha256_compress.
proof.
proc; call sha256_rounds_ll; inline *.
while (0 <= i <= 16) (16 - i); first by auto => /#.
by auto => /#.
qed.

lemma sha256_compress_total (h0 : W32.t list) (blk : BArray64.t) :
  phoare [M._sha256_compress :
           hwords h = h0 /\ block = blk ==>
           hwords res.`1 = compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))] = 1%r.
proof. by conseq sha256_compress_ll (sha256_compress_correct h0 blk). qed.
