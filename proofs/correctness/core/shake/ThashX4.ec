(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ThashX4.ec (SHAKE sets)
 * =======================
 *
 * The four-way tweakable hashes of a SHAKE set: _thash_prf_x4,
 * _thash_f_x4 and _thash_t_len_x4, on the portable four-way Keccak
 * kernel.
 *
 * The four-way state is u64[100], lane j of instance k at word 4 j + k
 * (keccak_x4.jinc), so instance k is the 25 words lane4w st k, and a
 * store to word 4 j + k changes lane j of instance k only (lane4w_set,
 * lane4w_xor). The portable _keccakf1600_x4 gathers each instance into a
 * one-way state, permutes it with _keccakf1600 and scatters it back; the
 * proof follows that loop, with the instances below k permuted and the
 * others intact.
 *
 * Each hash is proved instance by instance on the lanes of the state
 * (a Keccak state, Array25 of words), and closed with the one-way sponge
 * lemmas of Thash.ec through of_lanes, the byte array whose lanes are a
 * given state:
 *   - PRF and F: __shake_x4_seeded_head writes PK.seed and ADRS_k (words
 *     4k .. 4k + 3 of adrs) into instance k, the payload (SK.seed, or
 *     lane k of x) follows; body_word is word w of instance k. The message
 *     is 2n + 32 bytes, one block: its words are its bytes
 *     (body_absorbed), and pad_w adds the SHAKE256 padding at lane
 *     2n/8 + 4 and lane 16 (shake_final_w).
 *   - T_len: lane pos of every instance absorbs word i of its len n-byte
 *     message, and a full block is permuted; the loop keeps
 *         lane4w st k = abs_state 136 (PK.seed || ADRS_k || M_k[0 : 8 i])
 *     for every k (tl_st), one step being absorb_w_lt or absorb_w_eq.
 *   - __shake_x4_extract_n writes word i of instance k to word n/8 k + i
 *     of the output, so lane k of the output is the first n bytes of
 *     instance k (lane_words, x4_final).
 *
 * Theorems (total correctness, every input):
 *     keccakf1600_x4_total    every instance k < 4 of the result is
 *                             keccak_f1600_op of instance k of the input;
 *     thash_prf_x4_total      lane k of the result is PRF of lane k of adrs;
 *     thash_f_x4_total        lane k of the result is F of lane k of adrs
 *                             and of x;
 *     thash_t_len_x4_total    lane k of the result is T_len of lane k of
 *                             adrs and of in.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils Jslh.
require import Bytes FIPS205_Params FIPS205_Hash.
from JazzEC require import Array25 WArray200.
require import FIPS202_Bytes BArray128 BArray200 BArray800 KeccakState Keccakf1600_Spec Keccak1600_Spec.
require import ShakeSponge SetModel CoreExtracted WotsLeaf Wots HashKernels.
require Thash.

(* Instance k of a four-way state. *)
op lane4w (st : BArray800.t) (k : int) : state = Array25.init (fun j => BArray800.get64 st (4 * j + k)).

lemma lane4wE (st : BArray800.t) (k j : int) : 0 <= j < 25 =>
  (lane4w st k).[j] = BArray800.get64 st (4 * j + k).
proof. by move=> hj; rewrite /lane4w Array25.initiE. qed.

lemma get_set64_800 (s : BArray800.t) i j w :
  0 <= i < 100 =>
  BArray800.get64 (BArray800.set64 s i w) j = if i = j then w else BArray800.get64 s j.
proof. by move=> hi; rewrite BArray800.get_set64E /#. qed.

(* The permutation on a one-way state given by its lanes. *)
lemma keccakf1600_lanes (A : state) :
  phoare [M._keccakf1600 : lanes st = A ==> lanes res.`1 = keccak_f1600_op A] = 1%r.
proof. by proc*; exlim st => s0; call (keccakf1600_total s0); auto. qed.

lemma keccakf1600_x4_total (s0 : BArray800.t) :
  phoare [M._keccakf1600_x4 : st = s0 ==>
    forall k, 0 <= k < 4 => lane4w res.`1 k = keccak_f1600_op (lane4w s0 k)] = 1%r.
proof.
proc.
while (0 <= k <= 4 /\
       (forall k', 0 <= k' < k => lane4w st k' = keccak_f1600_op (lane4w s0 k')) /\
       (forall k', k <= k' < 4 => lane4w st k' = lane4w s0 k'))
      (4 - k).
+ move=> z.
  wp.
  while (0 <= j <= 25 /\ 0 <= k < 4 /\ 4 - k = z /\
         lanes one = keccak_f1600_op (lane4w s0 k) /\
         (forall k', 0 <= k' < k => lane4w st k' = keccak_f1600_op (lane4w s0 k')) /\
         (forall k', k < k' < 4 => lane4w st k' = lane4w s0 k') /\
         (forall j', 0 <= j' < j => BArray800.get64 st (4 * j' + k) = BArray200.get64 one j'))
        (25 - j).
  + move=> z1; wp; skip => &m [#] hj0 hj1 hk0 hk1 hkz hone hlo hhi hw hlt hz1.
    have hlo' : forall k', 0 <= k' < k{m} =>
      lane4w (BArray800.set64 st{m} (4 * j{m} + k{m}) (BArray200.get64 one{m} j{m})) k' =
      keccak_f1600_op (lane4w s0 k').
    + move=> k' hk'; rewrite -hlo //; apply Array25.tP => i hi.
      by rewrite !lane4wE // get_set64_800 1:/# ifF 1:/#.
    have hhi' : forall k', k{m} < k' < 4 =>
      lane4w (BArray800.set64 st{m} (4 * j{m} + k{m}) (BArray200.get64 one{m} j{m})) k' = lane4w s0 k'.
    + move=> k' hk'; rewrite -hhi //; apply Array25.tP => i hi.
      by rewrite !lane4wE // get_set64_800 1:/# ifF 1:/#.
    have hw' : forall j', 0 <= j' < j{m} + 1 =>
      BArray800.get64 (BArray800.set64 st{m} (4 * j{m} + k{m}) (BArray200.get64 one{m} j{m})) (4 * j' + k{m}) =
      BArray200.get64 one{m} j'.
    + move=> j' hj'; rewrite get_set64_800 1:/#.
      by case: (j' = j{m}) => [-> // | hne]; rewrite ifF 1:/# hw /#.
    by do !split; try (exact hlo'); try (exact hhi'); try (exact hw'); smt().
  wp; call (keccakf1600_lanes (lane4w s0 (4 - z))).
  while (0 <= j <= 25 /\ 0 <= k < 4 /\ 4 - k = z /\
         (forall k', 0 <= k' < k => lane4w st k' = keccak_f1600_op (lane4w s0 k')) /\
         (forall k', k <= k' < 4 => lane4w st k' = lane4w s0 k') /\
         (forall j', 0 <= j' < j => BArray200.get64 one j' = BArray800.get64 st (4 * j' + k)))
        (25 - j).
  + move=> z1; wp; skip => &m [#] hj0 hj1 hk0 hk1 hkz hlo hhi hw hlt hz1.
    have hw' : forall j', 0 <= j' < j{m} + 1 =>
      BArray200.get64 (BArray200.set64 one{m} j{m} (BArray800.get64 st{m} (4 * j{m} + k{m}))) j' =
      BArray800.get64 st{m} (4 * j' + k{m}).
    + move=> j' hj'; rewrite get_set64_200 1:/#.
      by case: (j' = j{m}) => [-> // | hne]; rewrite ifF 1:/# hw /#.
    by do !split; try (exact hw'); smt().
  wp; skip => &m [#] hk0 hk1 hlo hhi hlt hz; split; first smt().
  move=> j1 o1; split; first smt().
  move=> hge [#] hj0 hj1 _ _ _ _ _ hw.
  have hl : lanes o1 = lane4w s0 (4 - z).
  + rewrite -hhi 1:/#; apply Array25.tP => i hi.
    by rewrite lanesE // lane4wE // hw /#.
  rewrite andaE; split; first exact hl.
  move=> r hr; rewrite /protect_ptr /=; split; first smt().
  move=> j2 st2; split; first smt().
  move=> hge2 [#] hj20 hj21 _ _ _ hone2 hlo2 hhi2 hw2.
  have hk : lane4w st2 k{m} = keccak_f1600_op (lane4w s0 k{m}).
  + rewrite -hone2; apply Array25.tP => i hi.
    by rewrite lanesE // lane4wE // hw2 /#.
  have hA : forall k', 0 <= k' < k{m} + 1 => lane4w st2 k' = keccak_f1600_op (lane4w s0 k').
  + by move=> k' hk'; case: (k' = k{m}) => [-> // | hne]; apply hlo2; smt().
  have hB : forall k', k{m} + 1 <= k' < 4 => lane4w st2 k' = lane4w s0 k'.
  + by move=> k' hk'; apply hhi2; smt().
  by do !split; try (exact hA); try (exact hB); smt().
by wp; skip => &m -> /=; smt().
qed.

(* ------------------------------------------------------------------ *)
(* The seeded head                                                    *)

(* Word w of instance k after the seeded head: PK.seed, then the 32-byte
   address of lane k (words 4 k .. 4 k + 3 of adrs), then zeros. *)
op head_word (c0 : Node.t) (a0 : BArray128.t) (k w : int) : W64.t =
  if w < P.`n %/ 8 then Node.get64 c0 w
  else if w < P.`n %/ 8 + 4 then BArray128.get64 a0 (4 * k + (w - P.`n %/ 8))
  else W64.zero.

lemma keccak_x4_init_h :
  hoare [M.__keccak_x4_init : true ==> forall w, 0 <= w < 100 => BArray800.get64 res w = W64.zero].
proof.
proc; while (0 <= i <= 100 /\ z = W64.zero /\ forall w, 0 <= w < i => BArray800.get64 st w = W64.zero).
+ by wp; skip => &m [#] h0 h1 hz hw hlt; do !(split; first smt()); move=> w hw'; rewrite get_set64_800 1:/#; smt().
by wp; skip => &m _; split; [smt() | move=> i0 st0; smt()].
qed.

lemma shake_x4_seeded_head_h (c0 : Node.t) (a0 : BArray128.t) :
  hoare [M.__shake_x4_seeded_head : ctx = c0 /\ adrs = a0 ==>
    forall k w, 0 <= k < 4 => 0 <= w < 25 => BArray800.get64 res (4 * w + k) = head_word c0 a0 k w].
proof.
have hn := n_val.
proc.
while (0 <= k <= 4 /\ adrs = a0 /\
       forall k' w, 0 <= k' < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k') =
         if P.`n %/ 8 <= w < P.`n %/ 8 + 4 /\ k <= k' then W64.zero else head_word c0 a0 k' w).
+ wp; while (0 <= i <= 4 /\ 0 <= k < 4 /\ adrs = a0 /\
             forall k' w, 0 <= k' < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k') =
               if P.`n %/ 8 <= w < P.`n %/ 8 + 4 /\ (k < k' \/ (k = k' /\ i <= w - P.`n %/ 8)) then W64.zero
               else head_word c0 a0 k' w).
  + wp; skip => &m [#] hi0 hi1 hk0 hk1 ha hw hlt; do !(split; first smt()).
    move=> k' w hk' hw'; rewrite get_set64_800 1:/#.
    case: (4 * (P.`n %/ 8 + i{m}) + k{m} = 4 * w + k') => he.
    + have [hw1 hk1'] : w = P.`n %/ 8 + i{m} /\ k' = k{m} by smt().
      by rewrite /head_word ha hw1 hk1'; smt().
    by rewrite hw //; smt().
  wp; skip => &m [#] hk0 hk1 ha hw hlt; split.
  + do !(split; first smt()); move=> k' w hk' hw'; rewrite hw //; smt().
  move=> i0 st0 hge [#] hi0 hi1 hk0' hk1' ha' hw'; do !(split; first smt()).
  by move=> k' w hk' hw2; rewrite hw' //; smt().
wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ ctx = c0 /\ adrs = a0 /\
           forall k' w, 0 <= k' < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k') =
             if w < i then Node.get64 c0 w else W64.zero).
+ wp; while (0 <= k <= 4 /\ 0 <= i < inc /\ inc = P.`n %/ 8 /\ ctx = c0 /\ adrs = a0 /\ t = Node.get64 c0 i /\
             forall k' w, 0 <= k' < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k') =
               if w < i \/ (w = i /\ k' < k) then Node.get64 c0 w else W64.zero).
  + wp; skip => &m [#] hk0 hk1 hi0 hi1 hinc hc ha ht hw hlt; do !(split; first smt()).
    move=> k' w hk' hw'; rewrite get_set64_800 1:/#.
    case: (4 * i{m} + k{m} = 4 * w + k') => he.
    + have [hw1 hk1'] : w = i{m} /\ k' = k{m} by smt().
      by rewrite ht hw1 hk1'; smt().
    by rewrite hw //; smt().
  wp; skip => &m [#] hi0 hi1 hinc hc ha hw hlt; split.
  + do !(split; first smt()); move=> k' w hk' hw'; rewrite hw //; smt().
  move=> k1 st1 hge [#] hk0 hk1 hi0' hi1' hinc' hc' ha' ht hw'; do !(split; first smt()).
  by move=> k' w hk' hw2; rewrite hw' //; smt().
wp; ecall (keccak_x4_init_h); wp; skip => &m [#] hc ha r hr; split.
+ by do !(split; first smt()); move=> k' w hk' hw'; rewrite hr /#.
move=> i0 st0 hge [#] hi0 hi1 hinc _ _ hw; split.
+ by do !(split; first smt()); move=> k' w hk' hw'; rewrite hw //; smt().
move=> k1 st1 hge1 [#] hk0 hk1 _ hw1 k' w hk' hw'.
by rewrite hw1 //; smt().
qed.

lemma keccak_x4_init_ll : islossless M.__keccak_x4_init.
proof. by proc; while true (100 - i); auto => /#. qed.

lemma shake_x4_seeded_head_ll : islossless M.__shake_x4_seeded_head.
proof.
proc; while true (4 - k).
+ by move=> z; wp; while true (4 - i); auto => /#.
wp; while true (inc - i).
+ by move=> z; wp; while true (4 - k); auto => /#.
by wp; call keccak_x4_init_ll; auto => /#.
qed.

(* ------------------------------------------------------------------ *)
(* Instance views of the stores                                       *)

lemma lane4w_set (st : BArray800.t) (ix j k k' : int) (v : W64.t) :
  ix = 4 * j + k => 0 <= j < 25 => 0 <= k < 4 => 0 <= k' < 4 =>
  lane4w (BArray800.set64 st ix v) k' = if k' = k then (lane4w st k).[j <- v] else lane4w st k'.
proof.
move=> -> hj hk hk'; apply Array25.tP => i hi.
rewrite lane4wE // get_set64_800 1:/#.
case: (k' = k) => hkk.
+ by rewrite hkk /= Array25.get_setE // lane4wE //; smt().
by rewrite /= lane4wE //; smt().
qed.

(* A lane XOR at word ix = 4 j + k changes lane j of instance k only. *)
lemma lane4w_xor (st : BArray800.t) (ix j k k' : int) (w : W64.t) :
  ix = 4 * j + k => 0 <= j < 25 => 0 <= k < 4 => 0 <= k' < 4 =>
  lane4w (BArray800.set64 st ix (BArray800.get64 st ix `^` w)) k' =
  if k' = k then (lane4w st k).[j <- (lane4w st k).[j] `^` w] else lane4w st k'.
proof. by move=> hix hj hk hk'; rewrite (lane4w_set _ _ j k) // lane4wE // hix. qed.

(* ------------------------------------------------------------------ *)
(* The sponge on a state given by its lanes                           *)

(* The one-way state whose lanes are A: the bridge to the lemmas of
   Thash.ec, which are stated on the byte array of the one-way kernel. *)
op of_lanes (A : state) : BArray200.t = BArray200.of_list64 (Array25.to_list A).

lemma lanes_of_lanes (A : state) : lanes (of_lanes A) = A.
proof.
apply Array25.tP => i hi; rewrite lanesE // /of_lanes BArray200.get64_of_list64.
+ by rewrite Array25.size_to_list.
by rewrite (nth_change_dfl witness) 1:Array25.size_to_list 1:/# Array25.get_to_list.
qed.

lemma lanes_xor_set (st : BArray200.t) (p : int) (w : W64.t) : 0 <= p < 25 =>
  lanes (BArray200.set64 st p (BArray200.get64 st p `^` w)) = (lanes st).[p <- (lanes st).[p] `^` w].
proof.
move=> hp; apply Array25.tP => i hi.
rewrite lanesE // get_set64_200 // Array25.get_setE //.
by case: (i = p) => [-> /= | hne]; [rewrite lanesE | rewrite ifF 1:/# lanesE].
qed.

lemma absorb_w_lt (A : state) (m bs : W8.t list) (p : int) (w : W64.t) :
  0 <= p => p + 1 < 17 => 8 * p = size m %% 136 => size bs = 8 =>
  (forall k, 0 <= k < 8 => w \bits8 k = nth W8.zero bs k) =>
  A = abs_state 136 m => A.[p <- A.[p] `^` w] = abs_state 136 (m ++ bs).
proof.
move=> h0 h1 hp hs hw hA.
have := Thash.absorb_lane_lt (of_lanes A) m bs p w h0 h1 hp hs hw _; first by rewrite lanes_of_lanes.
by rewrite lanes_xor_set 1:/# lanes_of_lanes.
qed.

lemma absorb_w_eq (A : state) (m bs : W8.t list) (p : int) (w : W64.t) :
  p + 1 = 17 => 8 * p = size m %% 136 => size bs = 8 =>
  (forall k, 0 <= k < 8 => w \bits8 k = nth W8.zero bs k) =>
  A = abs_state 136 m => keccak_f1600_op A.[p <- A.[p] `^` w] = abs_state 136 (m ++ bs).
proof.
move=> h1 hp hs hw hA.
have := Thash.absorb_lane_eq (of_lanes A) m bs p w h1 hp hs hw _; first by rewrite lanes_of_lanes.
by rewrite lanes_xor_set 1:/# lanes_of_lanes.
qed.

(* The SHAKE256 padding of FIPS 202 at lane p (domain bits 1111) and the
   top bit of lane 16, the last lane of the 136-byte block. *)
op pad_w (A : state) (p : int) : state =
  let A1 = A.[p <- A.[p] `^` W64.of_int 31] in A1.[16 <- A1.[16] `^` W64.of_int 9223372036854775808].

lemma shake_final_w (msg r : W8.t list) (p : int) (A : state) :
  0 <= p < 17 => 8 * p = size msg %% 136 => A = abs_state 136 msg => size r = P.`n =>
  (forall j, 0 <= j < P.`n => nth W8.zero r j = (stbytes (keccak_f1600_op (pad_w A p))).[j]) =>
  r = shake256 msg (8 * P.`n).
proof.
move=> hp hpm hA hs hr; have hn := n_val.
have h := Thash.shake_final msg p (of_lanes A) (of_lanes (keccak_f1600_op (pad_w A p))) (Node.of_list r) hp hpm _ _ _.
+ by rewrite lanes_of_lanes.
+ by rewrite lanes_of_lanes lanes_xor_set // lanes_xor_set 1:/# lanes_of_lanes /pad_w.
+ move=> j hj; rewrite Node.of_listK 1:/# hr //.
  by rewrite -(stbytes_lanes (of_lanes (keccak_f1600_op (pad_w A p)))) 1:/# lanes_of_lanes.
by rewrite -h Node.of_listK 1:/#.
qed.

(* A state whose bytes are those of a message shorter than the rate. *)
lemma words_absorbed (A : state) (msg : W8.t list) :
  size msg < 136 =>
  (forall w b, 0 <= w < 25 => 0 <= b < 8 => A.[w] \bits8 b = nth W8.zero msg (8 * w + b)) =>
  A = abs_state 136 msg.
proof.
move=> hs hA; apply stbytes_inj; apply WArray200.tP => j hj.
rewrite abs_short // WArray200.initiE //= hA 1,2:/#; congr; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Lanes of byte lists                                                *)

lemma lane_nth (m k j : int) (l : 'a list) (d : 'a) :
  0 <= m => 0 <= k => 0 <= j < m => nth d (lane m k l) j = nth d l (m * k + j).
proof. by move=> hm hk hj; rewrite /lane nth_take 1,2:/# nth_drop /#. qed.

lemma size_lane (m k : int) (l : 'a list) :
  0 <= m => 0 <= k => m * (k + 1) <= size l => size (lane m k l) = m.
proof. by move=> hm hk hs; rewrite /lane size_take // size_drop 1:/#; smt(). qed.

lemma size_adrs_lane (a0 : BArray128.t) (k : int) : 0 <= k < 4 => size (lane 32 k (BArray128.to_list a0)) = 32.
proof. by move=> hk; rewrite size_lane //; smt(BArray128.size_to_list). qed.

(* Word w of instance k after the seeded head and an n-byte payload pl k
   (word i of instance k is pl k i): PK.seed, ADRS_k, the payload, zeros. *)
op body_word (c0 : Node.t) (a0 : BArray128.t) (pl : int -> int -> W64.t) (k w : int) : W64.t =
  if w < P.`n %/ 8 + 4 then head_word c0 a0 k w
  else if w < 2 * (P.`n %/ 8) + 4 then pl k (w - (P.`n %/ 8 + 4)) else W64.zero.

lemma body_absorbed (c0 : Node.t) (a0 : BArray128.t) (pl : int -> int -> W64.t) (k : int) (X : W8.t list) :
  0 <= k < 4 => size X <= P.`n =>
  (forall i b, 0 <= i < P.`n %/ 8 => 0 <= b < 8 => pl k i \bits8 b = nth W8.zero X (8 * i + b)) =>
  Array25.init (body_word c0 a0 pl k) =
  abs_state 136 ((Node.to_list c0 ++ lane 32 k (BArray128.to_list a0)) ++ X).
proof.
move=> hk hX hpl; have hn := n_val.
have hsa : size (lane 32 k (BArray128.to_list a0)) = 32.
+ by rewrite size_lane //; smt(BArray128.size_to_list).
apply words_absorbed; first by rewrite !size_cat Node.size_to_list hsa; smt().
move=> w b hw hb; rewrite Array25.initiE //.
case: (w < P.`n %/ 8) => h1.
+ have -> : body_word c0 a0 pl k w = Node.get64 c0 w by rewrite /body_word /head_word ifT 1:/# ifT 1:/#.
  rewrite Node.get64d_byte 1:/# nth_cat size_cat Node.size_to_list hsa ifT 1:/#.
  by rewrite nth_cat Node.size_to_list ifT 1:/# Node.get_to_list.
case: (w < P.`n %/ 8 + 4) => h2.
+ have -> : body_word c0 a0 pl k w = BArray128.get64 a0 (4 * k + (w - P.`n %/ 8)).
  + by rewrite /body_word /head_word ifT 1:/# ifF 1:/# ifT 1:/#.
  rewrite BArray128.get64d_byte 1:/# nth_cat size_cat Node.size_to_list hsa ifT 1:/#.
  rewrite nth_cat Node.size_to_list ifF 1:/#.
  by rewrite lane_nth 1..3:/# BArray128.get_to_list; congr; smt().
case: (w < 2 * (P.`n %/ 8) + 4) => h3.
+ have -> : body_word c0 a0 pl k w = pl k (w - (P.`n %/ 8 + 4)) by rewrite /body_word ifF 1:/# ifT 1:/#.
  rewrite hpl 1,2:/# nth_cat size_cat Node.size_to_list hsa ifF 1:/#; congr; smt().
have -> : body_word c0 a0 pl k w = W64.zero by rewrite /body_word ifF 1:/# ifF 1:/#.
rewrite nth_cat size_cat Node.size_to_list hsa ifF 1:/# nth_default 1:/#.
by rewrite W8u8.get_zero.
qed.

(* Lane k of a four-way output whose words n/8 k + i are those of A. *)
lemma lane_words (o : Node4.t) (A : state) (k : int) : 0 <= k < 4 =>
  (forall i, 0 <= i < P.`n %/ 8 => Node4.get64 o (P.`n %/ 8 * k + i) = A.[i]) =>
  forall j, 0 <= j < P.`n => nth W8.zero (lane P.`n k (Node4.to_list o)) j = (stbytes A).[j].
proof.
move=> hk ho j hj; have hn := n_val.
rewrite lane_nth 1..3:/# Node4.get_to_list WArray200.initiE 1:/# /= -ho 1:/#.
by rewrite Node4.get64d_byte 1:/#; congr; smt().
qed.

lemma size_lane_n4 (o : Node4.t) (k : int) : 0 <= k < 4 => size (lane P.`n k (Node4.to_list o)) = P.`n.
proof. by move=> hk; rewrite size_lane //; smt(n_val Node4.size_to_list). qed.

(* ------------------------------------------------------------------ *)
(* Padding and extraction                                             *)

lemma shake_x4_pad_lanes_h (s0 : BArray800.t) (l0 : int) :
  hoare [M.__shake_x4_pad_lanes : st = s0 /\ lanes = l0 /\ 0 <= l0 < 16 ==>
    forall k, 0 <= k < 4 => lane4w res k = pad_w (lane4w s0 k) l0].
proof.
proc.
while (0 <= k <= 4 /\ lanes = l0 /\ 0 <= l0 < 16 /\ u = W64.of_int 9223372036854775808 /\
       (forall k', 0 <= k' < k => lane4w st k' = pad_w (lane4w s0 k') l0) /\
       (forall k', k <= k' < 4 => lane4w st k' = lane4w s0 k')).
+ wp; skip => &m [#] hk0 hk1 hl hl0 hl1 hu hlo hhi hlt /=.
  pose st1 := BArray800.set64 st{m} (4 * lanes{m} + k{m}) (BArray800.get64 st{m} (4 * lanes{m} + k{m}) `^` W64.of_int 31).
  have e1 : forall k', 0 <= k' < 4 => lane4w st1 k' =
    if k' = k{m} then (lane4w st{m} k{m}).[l0 <- (lane4w st{m} k{m}).[l0] `^` W64.of_int 31] else lane4w st{m} k'.
  + by move=> k' hk'; rewrite /st1 (lane4w_xor _ _ l0 k{m}) 1..4:/#.
  have e2 : forall k', 0 <= k' < 4 =>
    lane4w (BArray800.set64 st1 (64 + k{m}) (BArray800.get64 st1 (64 + k{m}) `^` u{m})) k' =
    if k' = k{m} then (lane4w st1 k{m}).[16 <- (lane4w st1 k{m}).[16] `^` u{m}] else lane4w st1 k'.
  + by move=> k' hk'; rewrite (lane4w_xor _ _ 16 k{m}) 1..4:/#.
  have hA : forall k', 0 <= k' < k{m} + 1 =>
    lane4w (BArray800.set64 st1 (64 + k{m}) (BArray800.get64 st1 (64 + k{m}) `^` u{m})) k' =
    pad_w (lane4w s0 k') l0.
  + move=> k' hk'; rewrite e2 1:/# e1 1:/# e1 1:/#.
    case: (k' = k{m}) => [-> /= | hne]; first by rewrite hhi 1:/# /pad_w /= hu.
    by apply hlo; smt().
  have hB : forall k', k{m} + 1 <= k' < 4 =>
    lane4w (BArray800.set64 st1 (64 + k{m}) (BArray800.get64 st1 (64 + k{m}) `^` u{m})) k' = lane4w s0 k'.
  + by move=> k' hk'; rewrite e2 1:/# ifF 1:/# e1 1:/# ifF 1:/#; apply hhi; smt().
  by do !split; try (exact hA); try (exact hB); smt().
by wp; skip => &m [#] -> -> hl0 hl1 /=; smt().
qed.

lemma shake_x4_pad_lanes_ll : islossless M.__shake_x4_pad_lanes.
proof. by proc; while true (4 - k); auto => /#. qed.

lemma get_set64_n4 (s : Node4.t) i j w : 0 <= i < P.`n %/ 2 =>
  Node4.get64 (Node4.set64 s i w) j = if i = j then w else Node4.get64 s j.
proof. by move=> hi; rewrite Node4.get_set64E; smt(n_val). qed.

lemma shake_x4_extract_n_h (s0 : BArray800.t) :
  hoare [M.__shake_x4_extract_n : st = s0 ==>
    forall k i, 0 <= k < 4 => 0 <= i < P.`n %/ 8 => Node4.get64 res (P.`n %/ 8 * k + i) = (lane4w s0 k).[i]].
proof.
have hn := n_val.
proc.
while (0 <= k <= 4 /\ st = s0 /\
       forall k' i, 0 <= k' < k => 0 <= i < P.`n %/ 8 => Node4.get64 out (P.`n %/ 8 * k' + i) = (lane4w s0 k').[i]).
+ wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ 0 <= k < 4 /\ st = s0 /\
             (forall k' i', 0 <= k' < k => 0 <= i' < P.`n %/ 8 =>
                Node4.get64 out (P.`n %/ 8 * k' + i') = (lane4w s0 k').[i']) /\
             (forall i', 0 <= i' < i => Node4.get64 out (P.`n %/ 8 * k + i') = (lane4w s0 k).[i'])).
  + wp; skip => &m [#] hi0 hi1 hinc hk0 hk1 hs hlo hhi hlt /=.
    have hA : forall ix k' i', ix = P.`n %/ 8 * k{m} + i{m} => 0 <= k' < k{m} => 0 <= i' < P.`n %/ 8 =>
      Node4.get64 (Node4.set64 out{m} ix (BArray800.get64 st{m} (4 * i{m} + k{m})))
        (P.`n %/ 8 * k' + i') = (lane4w s0 k').[i'].
    + by move=> ix k' i' -> hk' hi'; rewrite get_set64_n4 1:/# ifF 1:/#; apply hlo.
    have hB : forall ix i', ix = P.`n %/ 8 * k{m} + i{m} => 0 <= i' < i{m} + 1 =>
      Node4.get64 (Node4.set64 out{m} ix (BArray800.get64 st{m} (4 * i{m} + k{m})))
        (P.`n %/ 8 * k{m} + i') = (lane4w s0 k{m}).[i'].
    + move=> ix i' -> hi'; rewrite get_set64_n4 1:/#.
      case: (i' = i{m}) => [-> | hne]; first by rewrite ifT 1:/# lane4wE 1:/# hs.
      by rewrite ifF 1:/#; apply hhi; smt().
    do !split; try (move=> k' i' hk' hi'; apply (hA _ k' i' _ hk' hi'); smt());
      try (move=> i' hi'; apply (hB _ i' _ hi'); smt()); smt().
  wp; skip => &m [#] hk0 hk1 hs hlo hlt; split; first smt().
  move=> i1 o1 hge [#] hi0 hi1 hinc _ _ _ hlo1 hhi1; do !(split; first smt()).
  move=> k' i' hk' hi'; case: (k' = k{m}) => [-> | hne]; first by apply hhi1 => /#.
  by apply hlo1 => /#.
by wp; skip => &m -> /=; smt().
qed.

lemma shake_x4_extract_n_ll : islossless M.__shake_x4_extract_n.
proof.
proc; while true (4 - k).
+ by move=> z; wp; while true (inc - i); auto => /#.
by auto => /#.
qed.

lemma keccakf1600_x4_h (s0 : BArray800.t) :
  hoare [M._keccakf1600_x4 : st = s0 ==>
    forall k, 0 <= k < 4 => lane4w res.`1 k = keccak_f1600_op (lane4w s0 k)].
proof. by conseq (keccakf1600_x4_total s0). qed.

lemma keccakf1600_x4_ll : islossless M._keccakf1600_x4.
proof. by proc*; exlim st => s0; call (keccakf1600_x4_total s0); auto. qed.

(* ------------------------------------------------------------------ *)
(* Closing a one-block or multi-block hash per instance               *)

lemma body_head (c0 : Node.t) (a0 : BArray128.t) (pl : int -> int -> W64.t) (k w : int) :
  w < P.`n %/ 8 + 4 => body_word c0 a0 pl k w = head_word c0 a0 k w.
proof. by move=> h; rewrite /body_word h. qed.

lemma head_zero (c0 : Node.t) (a0 : BArray128.t) (k w : int) :
  P.`n %/ 8 + 4 <= w => head_word c0 a0 k w = W64.zero.
proof. by move=> h; rewrite /head_word ifF 1:/# ifF 1:/#. qed.

lemma body_zero (c0 : Node.t) (a0 : BArray128.t) (pl : int -> int -> W64.t) (k w : int) :
  2 * (P.`n %/ 8) + 4 <= w => body_word c0 a0 pl k w = W64.zero.
proof. by move=> h; have hn := n_val; rewrite /body_word ifF 1:/# ifF 1:/#. qed.

lemma body_pl (c0 : Node.t) (a0 : BArray128.t) (pl : int -> int -> W64.t) (k w : int) :
  P.`n %/ 8 + 4 <= w < 2 * (P.`n %/ 8) + 4 => body_word c0 a0 pl k w = pl k (w - (P.`n %/ 8 + 4)).
proof. by move=> h; rewrite /body_word ifF 1:/# ifT 1:/#. qed.

(* Instance k of a four-way run that absorbed msg at lane position p, padded,
   permuted and extracted: lane k of the output is SHAKE256(msg). *)
lemma x4_final (msg : W8.t list) (p k : int) (A : state) (st1 st2 : BArray800.t) (o : Node4.t) :
  0 <= k < 4 => 0 <= p < 17 => 8 * p = size msg %% 136 => A = abs_state 136 msg =>
  lane4w st1 k = pad_w A p => lane4w st2 k = keccak_f1600_op (lane4w st1 k) =>
  (forall i, 0 <= i < P.`n %/ 8 => Node4.get64 o (P.`n %/ 8 * k + i) = (lane4w st2 k).[i]) =>
  lane P.`n k (Node4.to_list o) = shake256 msg (8 * P.`n).
proof.
move=> hk hp hpm hA h1 h2 h3.
apply (shake_final_w msg _ p A hp hpm hA (size_lane_n4 o k hk)).
by move=> j hj; rewrite (lane_words o (lane4w st2 k) k hk h3 j hj) h2 h1.
qed.

lemma x4_close (c0 : Node.t) (a0 : BArray128.t) (pl : int -> int -> W64.t) (k : int) (X : W8.t list)
               (st0 st1 st2 : BArray800.t) (o : Node4.t) :
  0 <= k < 4 => size X = P.`n =>
  (forall i b, 0 <= i < P.`n %/ 8 => 0 <= b < 8 => pl k i \bits8 b = nth W8.zero X (8 * i + b)) =>
  (forall w, 0 <= w < 25 => BArray800.get64 st0 (4 * w + k) = body_word c0 a0 pl k w) =>
  lane4w st1 k = pad_w (lane4w st0 k) (2 * (P.`n %/ 8) + 4) =>
  lane4w st2 k = keccak_f1600_op (lane4w st1 k) =>
  (forall i, 0 <= i < P.`n %/ 8 => Node4.get64 o (P.`n %/ 8 * k + i) = (lane4w st2 k).[i]) =>
  lane P.`n k (Node4.to_list o) =
  shake256 ((Node.to_list c0 ++ lane 32 k (BArray128.to_list a0)) ++ X) (8 * P.`n).
proof.
move=> hk hX hpl h0 h1 h2 h3; have hn := n_val.
have hA : lane4w st0 k = Array25.init (body_word c0 a0 pl k).
+ by apply Array25.tP => w hw; rewrite lane4wE // Array25.initiE // h0.
have hsa := size_adrs_lane a0 k hk.
apply (x4_final _ (2 * (P.`n %/ 8) + 4) k (lane4w st0 k) st1 st2 o hk _ _ _ h1 h2 h3).
+ smt().
+ by rewrite !size_cat Node.size_to_list hsa hX; smt().
by rewrite hA; apply body_absorbed => //; smt().
qed.

(* ------------------------------------------------------------------ *)
(* PRF                                                                *)

lemma thash_prf_x4_h (k0 c0 : Node.t) (a0 : BArray128.t) :
  hoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      PRF P (Node.to_list c0) (Node.to_list k0) (lane 32 k (BArray128.to_list a0))].
proof.
have hn := n_val.
pose pl := fun (_ i : int) => Node.get64 k0 i.
proc.
seq 2 : (sk_seed = k0 /\
         forall k w, 0 <= k < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k) = head_word c0 a0 k w).
+ by ecall (shake_x4_seeded_head_h c0 a0); auto.
seq 3 : (forall k w, 0 <= k < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k) = body_word c0 a0 pl k w).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ sk_seed = k0 /\
         forall k w, 0 <= k < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k) =
           if P.`n %/ 8 + 4 + i <= w then W64.zero else body_word c0 a0 pl k w).
  + wp; while (0 <= k <= 4 /\ 0 <= i < inc /\ inc = P.`n %/ 8 /\ sk_seed = k0 /\ t = Node.get64 k0 i /\
               forall k' w, 0 <= k' < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k') =
                 if P.`n %/ 8 + 4 + i < w \/ (w = P.`n %/ 8 + 4 + i /\ k <= k') then W64.zero
                 else body_word c0 a0 pl k' w).
    + wp; skip => &m [#] hk0 hk1 hi0 hi1 hinc hsk ht hw hlt /=.
      have hA : forall ix k' w, ix = 4 * (P.`n %/ 8 + 4 + i{m}) + k{m} => 0 <= k' < 4 => 0 <= w < 25 =>
        BArray800.get64 (BArray800.set64 st{m} ix t{m}) (4 * w + k') =
        if P.`n %/ 8 + 4 + i{m} < w \/ (w = P.`n %/ 8 + 4 + i{m} /\ k{m} + 1 <= k') then W64.zero
        else body_word c0 a0 pl k' w.
      + move=> ix k' w -> hk' hw'; rewrite get_set64_800 1:/#.
        case: (4 * (P.`n %/ 8 + 4 + i{m}) + k{m} = 4 * w + k') => he.
        + have [hw1 hk1'] : w = P.`n %/ 8 + 4 + i{m} /\ k' = k{m} by smt().
          by rewrite ifF 1:/# body_pl 1:/# /pl /= ht; congr; smt().
        by rewrite hw //; smt().
      by do !split; try (move=> k' w hk' hw'; apply (hA _ k' w _ hk' hw'); smt()); smt().
    wp; skip => &m [#] hi0 hi1 hinc hsk hw hlt /=; split.
    + by do !split; try (move=> k' w hk' hw'; rewrite hw //; smt()); smt().
    move=> k1 st1 hge [#] hk0 hk1 _ _ _ _ _ hw1.
    by do !split; try (move=> k' w hk' hw'; rewrite hw1 //; smt()); smt().
  wp; skip => &m [#] hsk hw /=; split.
  + by do !split; try (move=> k w hk hw'; rewrite hw //; smt(body_head head_zero)); smt().
  move=> i1 st1 hge [#] hi0 hi1 hinc _ hw1 k w hk hw'.
  by rewrite hw1 //; smt(body_zero).
ecall (shake_x4_extract_n_h st); wp; ecall (keccakf1600_x4_h st).
ecall (shake_x4_pad_lanes_h st (2 * (P.`n %/ 8) + 4)).
skip => &m hw; split; first smt().
move=> _ s1 hs1 [s2 ms2] /= hs2 o ho k hk.
rewrite /PRF Thash.family_shake /=.
have h0 : forall w, 0 <= w < 25 => BArray800.get64 st{m} (4 * w + k) = body_word c0 a0 pl k w.
+ by move=> w hw'; apply hw.
have h3 : forall i, 0 <= i < P.`n %/ 8 => Node4.get64 o (P.`n %/ 8 * k + i) = (lane4w s2 k).[i].
+ by move=> i hi; apply ho.
apply (x4_close c0 a0 pl k _ st{m} s1 s2 o hk _ _ h0 (hs1 k hk) (hs2 k hk) h3).
+ by rewrite Node.size_to_list; smt().
by move=> i b hi hb; rewrite /pl /= Node.get64d_byte 1:/#.
qed.

lemma thash_prf_x4_ll : islossless M._thash_prf_x4.
proof.
proc; call shake_x4_extract_n_ll; wp; call keccakf1600_x4_ll; call shake_x4_pad_lanes_ll.
while true (inc - i).
+ by move=> z; wp; while true (4 - k); auto => /#.
by wp; call shake_x4_seeded_head_ll; auto => /#.
qed.

lemma thash_prf_x4_total (k0 c0 : Node.t) (a0 : BArray128.t) :
  phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      PRF P (Node.to_list c0) (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r.
proof. by conseq thash_prf_x4_ll (thash_prf_x4_h k0 c0 a0). qed.

(* ------------------------------------------------------------------ *)
(* F                                                                  *)

lemma thash_f_x4_h (x0 : Node4.t) (c0 : Node.t) (a0 : BArray128.t) :
  hoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      F P (Node.to_list c0) (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))].
proof.
have hn := n_val.
pose pl := fun (k i : int) => Node4.get64 x0 (P.`n %/ 8 * k + i).
proc.
seq 2 : (x = x0 /\
         forall k w, 0 <= k < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k) = head_word c0 a0 k w).
+ by ecall (shake_x4_seeded_head_h c0 a0); auto.
seq 2 : (forall k w, 0 <= k < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k) = body_word c0 a0 pl k w).
+ while (0 <= k <= 4 /\ x = x0 /\
         forall k' w, 0 <= k' < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k') =
           if k <= k' /\ P.`n %/ 8 + 4 <= w then W64.zero else body_word c0 a0 pl k' w).
  + wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ 0 <= k < 4 /\ x = x0 /\
               forall k' w, 0 <= k' < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k') =
                 if (k < k' /\ P.`n %/ 8 + 4 <= w) \/ (k = k' /\ P.`n %/ 8 + 4 + i <= w) then W64.zero
                 else body_word c0 a0 pl k' w).
    + wp; skip => &m [#] hi0 hi1 hinc hk0 hk1 hx hw hlt /=.
      have hA : forall ix iy k' w, ix = 4 * (P.`n %/ 8 + 4 + i{m}) + k{m} => iy = P.`n %/ 8 * k{m} + i{m} =>
        0 <= k' < 4 => 0 <= w < 25 =>
        BArray800.get64 (BArray800.set64 st{m} ix (Node4.get64 x{m} iy)) (4 * w + k') =
        if (k{m} < k' /\ P.`n %/ 8 + 4 <= w) \/ (k{m} = k' /\ P.`n %/ 8 + 4 + (i{m} + 1) <= w) then W64.zero
        else body_word c0 a0 pl k' w.
      + move=> ix iy k' w -> -> hk' hw'; rewrite get_set64_800 1:/#.
        case: (4 * (P.`n %/ 8 + 4 + i{m}) + k{m} = 4 * w + k') => he.
        + have [hw1 hk1'] : w = P.`n %/ 8 + 4 + i{m} /\ k' = k{m} by smt().
          by rewrite ifF 1:/# body_pl 1:/# /pl /= hx; congr; smt().
        by rewrite hw //; smt().
      by do !split; try (move=> k' w hk' hw'; apply (hA _ _ k' w _ _ hk' hw'); smt()); smt().
    wp; skip => &m [#] hk0 hk1 hx hw hlt /=; split.
    + by do !split; try (move=> k' w hk' hw'; rewrite hw //; smt()); smt().
    move=> i1 st1 hge [#] hi0 hi1 hinc _ _ _ hw1.
    by do !split; try (move=> k' w hk' hw'; rewrite hw1 //; smt(body_zero)); smt().
  wp; skip => &m [#] hx hw /=; split.
  + by do !split; try (move=> k w hk hw'; rewrite hw //; smt(body_head head_zero)); smt().
  move=> k1 st1 hge [#] hk0 hk1 _ hw1 k w hk hw'.
  by rewrite hw1 //; smt().
ecall (shake_x4_extract_n_h st); wp; ecall (keccakf1600_x4_h st).
ecall (shake_x4_pad_lanes_h st (2 * (P.`n %/ 8) + 4)).
skip => &m hw; split; first smt().
move=> _ s1 hs1 [s2 ms2] /= hs2 o ho k hk.
rewrite /F Thash.family_shake /=.
have h0 : forall w, 0 <= w < 25 => BArray800.get64 st{m} (4 * w + k) = body_word c0 a0 pl k w.
+ by move=> w hw'; apply hw.
have h3 : forall i, 0 <= i < P.`n %/ 8 => Node4.get64 o (P.`n %/ 8 * k + i) = (lane4w s2 k).[i].
+ by move=> i hi; apply ho.
apply (x4_close c0 a0 pl k _ st{m} s1 s2 o hk _ _ h0 (hs1 k hk) (hs2 k hk) h3).
+ exact (size_lane_n4 x0 k hk).
move=> i b hi hb; rewrite /pl /= Node4.get64d_byte 1:/# lane_nth 1..3:/#.
by rewrite Node4.get_to_list; congr; smt().
qed.

lemma thash_f_x4_ll : islossless M._thash_f_x4.
proof.
proc; call shake_x4_extract_n_ll; wp; call keccakf1600_x4_ll; call shake_x4_pad_lanes_ll.
while true (4 - k).
+ by move=> z; wp; while true (inc - i); auto => /#.
by wp; call shake_x4_seeded_head_ll; auto => /#.
qed.

lemma thash_f_x4_total (x0 : Node4.t) (c0 : Node.t) (a0 : BArray128.t) :
  phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      F P (Node.to_list c0) (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r.
proof. by conseq thash_f_x4_ll (thash_f_x4_h x0 c0 a0). qed.

(* ------------------------------------------------------------------ *)
(* T_len                                                              *)

(* Instance k absorbs PK.seed || ADRS_k || M_k, M_k being the len n bytes of
   lane k of in (len n / 8 = (2 n + 3) n / 8 words, at word k (2 n + 3) n / 8
   of in). tl_st k i is its sponge state once i words of M_k are absorbed. *)
op tl_pre (c0 : Node.t) (a0 : BArray128.t) (k : int) : W8.t list =
  Node.to_list c0 ++ lane 32 k (BArray128.to_list a0).

op tl_msg (m0 : TLenIn4.t) (k : int) : W8.t list = lane (len P * P.`n) k (TLenIn4.to_list m0).

op tl_word (m0 : TLenIn4.t) (i k : int) : W64.t = TLenIn4.get64 m0 (i + k * ((2 * P.`n + 3) * (P.`n %/ 8))).

op tl_st (c0 : Node.t) (a0 : BArray128.t) (m0 : TLenIn4.t) (k i : int) : state =
  abs_state 136 (tl_pre c0 a0 k ++ take (8 * i) (tl_msg m0 k)).

op xw (A : state) (p : int) (w : W64.t) : state = A.[p <- A.[p] `^` w].

lemma len_n : len P * P.`n = 8 * ((2 * P.`n + 3) * (P.`n %/ 8)).
proof. by rewrite /len Wots.len1_val Wots.len2_val; smt(n_val). qed.

lemma size_tl_msg (m0 : TLenIn4.t) (k : int) : 0 <= k < 4 => size (tl_msg m0 k) = len P * P.`n.
proof. by move=> hk; rewrite /tl_msg size_lane //; smt(n_val len_n TLenIn4.size_to_list). qed.

lemma size_tl (c0 : Node.t) (a0 : BArray128.t) (m0 : TLenIn4.t) (k i : int) :
  0 <= k < 4 => 0 <= i <= (2 * P.`n + 3) * (P.`n %/ 8) =>
  size (tl_pre c0 a0 k ++ take (8 * i) (tl_msg m0 k)) = P.`n + 32 + 8 * i.
proof.
move=> hk hi; have hs := size_tl_msg m0 k hk; have hl := len_n.
rewrite /tl_pre !size_cat Node.size_to_list size_adrs_lane // size_take 1:/#; smt(n_val).
qed.

lemma tl_word_bytes (m0 : TLenIn4.t) (i k : int) : 0 <= k < 4 => 0 <= i < (2 * P.`n + 3) * (P.`n %/ 8) =>
  forall b, 0 <= b < 8 => tl_word m0 i k \bits8 b = nth W8.zero (take 8 (drop (8 * i) (tl_msg m0 k))) b.
proof.
move=> hk hi b hb; have hs := size_tl_msg m0 k hk; have hl := len_n; have hn := n_val.
rewrite nth_take 1,2:/# nth_drop 1,2:/# /tl_msg lane_nth 1..3:/# TLenIn4.get_to_list.
by rewrite /tl_word TLenIn4.get64d_byte 1:/#; congr; smt().
qed.

lemma tl_step (c0 : Node.t) (a0 : BArray128.t) (m0 : TLenIn4.t) (k i : int) : 0 <= i =>
  tl_pre c0 a0 k ++ take (8 * (i + 1)) (tl_msg m0 k) =
  (tl_pre c0 a0 k ++ take (8 * i) (tl_msg m0 k)) ++ take 8 (drop (8 * i) (tl_msg m0 k)).
proof. by move=> hi; rewrite (_ : 8 * (i + 1) = 8 * i + 8) 1:/# takeD 1,2:/# catA. qed.

lemma tl_absorb_lt (c0 : Node.t) (a0 : BArray128.t) (m0 : TLenIn4.t) (k i p : int) :
  0 <= k < 4 => 0 <= i < (2 * P.`n + 3) * (P.`n %/ 8) => 0 <= p => p + 1 < 17 =>
  8 * p = (P.`n + 32 + 8 * i) %% 136 =>
  xw (tl_st c0 a0 m0 k i) p (tl_word m0 i k) = tl_st c0 a0 m0 k (i + 1).
proof.
move=> hk hi hp0 hp1 hpm; have hs := size_tl_msg m0 k hk; have hl := len_n.
rewrite /xw /tl_st tl_step 1:/#.
apply (absorb_w_lt _ _ _ p (tl_word m0 i k) hp0 hp1 _ _ _ _) => //.
+ by rewrite size_tl // 1:/#.
+ by apply Thash.size_word8; smt().
exact (tl_word_bytes m0 i k hk hi).
qed.

lemma tl_absorb_eq (c0 : Node.t) (a0 : BArray128.t) (m0 : TLenIn4.t) (k i p : int) :
  0 <= k < 4 => 0 <= i < (2 * P.`n + 3) * (P.`n %/ 8) => p + 1 = 17 =>
  8 * p = (P.`n + 32 + 8 * i) %% 136 =>
  keccak_f1600_op (xw (tl_st c0 a0 m0 k i) p (tl_word m0 i k)) = tl_st c0 a0 m0 k (i + 1).
proof.
move=> hk hi hp1 hpm; have hs := size_tl_msg m0 k hk; have hl := len_n.
rewrite /xw /tl_st tl_step 1:/#.
apply (absorb_w_eq _ _ _ p (tl_word m0 i k) hp1 _ _ _ _) => //.
+ by rewrite size_tl // 1:/#.
+ by apply Thash.size_word8; smt().
exact (tl_word_bytes m0 i k hk hi).
qed.

lemma lt_succ_ne (a b : int) : a <> b => (a < b + 1) = (a < b).
proof. by move=> h; smt(). qed.

lemma shl2 (x : W64.t) : to_uint x < 17 => to_uint (x `<<` W8.of_int 2) = 4 * to_uint x.
proof.
move=> h; have hb : 68 < W64.modulus by trivial.
rewrite W64.shl_shlw // W64.to_uint_shl // (_ : 2 ^ 2 = 4) // modz_small.
+ by move: h hb; pose M := W64.modulus; pose u := to_uint x; smt(W64.to_uint_cmp).
by ring.
qed.

lemma w64_add_small (x : W64.t) (c : int) : 0 <= c => to_uint x + c < W64.modulus =>
  to_uint (x + W64.of_int c) = to_uint x + c.
proof.
move=> h0 h1; have hc : to_uint (W64.of_int c) = c.
+ by rewrite W64.of_uintK modz_small //; move: h0 h1; pose M := W64.modulus; pose u := to_uint x; smt(W64.to_uint_cmp).
by rewrite W64.to_uintD_small hc //; move: h1; pose M := W64.modulus; pose u := to_uint x; smt().
qed.

lemma thash_t_len_x4_h (m0 : TLenIn4.t) (c0 : Node.t) (a0 : BArray128.t) :
  hoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      T_l P (Node.to_list c0) (lane 32 k (BArray128.to_list a0)) (lane (len P * P.`n) k (TLenIn4.to_list m0))].
proof.
have hn := n_val; have hl := len_n.
have hb : 1048576 < W64.modulus by trivial.
proc.
seq 4 : (in_0 = m0 /\
         forall k w, 0 <= k < 4 => 0 <= w < 25 => BArray800.get64 st (4 * w + k) = head_word c0 a0 k w).
+ by ecall (shake_x4_seeded_head_h c0 a0); auto.
seq 4 : (0 <= to_uint pos < 17 /\ 8 * to_uint pos = (P.`n + 32 + len P * P.`n) %% 136 /\
         forall k, 0 <= k < 4 => lane4w st k = tl_st c0 a0 m0 k ((2 * P.`n + 3) * (P.`n %/ 8))).
+ while (in_0 = m0 /\ 0 <= to_uint i <= (2 * P.`n + 3) * (P.`n %/ 8) /\
         (more <=> to_uint i < (2 * P.`n + 3) * (P.`n %/ 8)) /\ 0 <= to_uint pos < 17 /\
         8 * to_uint pos = (P.`n + 32 + 8 * to_uint i) %% 136 /\
         forall k, 0 <= k < 4 => lane4w st k = tl_st c0 a0 m0 k (to_uint i)).
  + wp.
    seq 3 : (#pre).
    + by wp; skip => &m h; rewrite Thash.clamp17 1:/#; exact h.
    seq 5 : (in_0 = m0 /\ 0 <= to_uint i < (2 * P.`n + 3) * (P.`n %/ 8) /\ 0 <= to_uint pos < 17 /\
             8 * to_uint pos = (P.`n + 32 + 8 * to_uint i) %% 136 /\
             forall k, 0 <= k < 4 =>
               lane4w st k = xw (tl_st c0 a0 m0 k (to_uint i)) (to_uint pos) (tl_word m0 (to_uint i) k)).
    + while (in_0 = m0 /\ 0 <= k <= 4 /\ 0 <= to_uint i < (2 * P.`n + 3) * (P.`n %/ 8) /\ 0 <= to_uint pos < 17 /\
             8 * to_uint pos = (P.`n + 32 + 8 * to_uint i) %% 136 /\
             to_uint lane = 4 * to_uint pos + k /\ to_uint o = to_uint i + k * ((2 * P.`n + 3) * (P.`n %/ 8)) /\
             forall k', 0 <= k' < 4 => lane4w st k' =
               if k' < k then xw (tl_st c0 a0 m0 k' (to_uint i)) (to_uint pos) (tl_word m0 (to_uint i) k')
               else tl_st c0 a0 m0 k' (to_uint i)).
      + wp; skip => &m [#] hm hk0 hk1 hi0 hi1 hp0 hp1 hpm hl0 ho hst hlt /=.
        have hA : forall ix k', ix = to_uint lane{m} => 0 <= k' < 4 =>
          lane4w (BArray800.set64 st{m} ix (BArray800.get64 st{m} ix `^` TLenIn4.get64 in_0{m} (to_uint o{m}))) k' =
          if k' < k{m} + 1 then xw (tl_st c0 a0 m0 k' (to_uint i{m})) (to_uint pos{m}) (tl_word m0 (to_uint i{m}) k')
          else tl_st c0 a0 m0 k' (to_uint i{m}).
        + move=> ix k' -> hk'; rewrite (lane4w_xor _ _ (to_uint pos{m}) k{m}) 1..4:/#.
          case: (k' = k{m}) => [-> | hne].
          + by rewrite hst 1:/# /= ifT 1:/# /xw /tl_word hm ho.
          by rewrite hst // (lt_succ_ne _ _ hne).
        have hl' : to_uint (lane{m} + W64.of_int 1) = to_uint lane{m} + 1.
        + by apply w64_add_small => //; move: hl0 hp1 hb; pose M := W64.modulus; smt().
        have ho' : forall c, c = (2 * P.`n + 3) * (P.`n %/ 8) => to_uint (o{m} + W64.of_int c) = to_uint o{m} + c.
        + by move=> c ->; apply w64_add_small; move: ho hi1 hk1 hb; pose M := W64.modulus; smt().
        by do !split; try (move=> k' hk'; apply (hA _ k' _ hk'); smt()); smt().
      wp; skip => &m [#] hm hi0 hi1 hmore hp0 hp1 hpm hst hc /=; split.
      + by do !split; try (move=> k' hk'; rewrite hst //; smt()); smt(shl2).
      move=> k1 l1 o1 s1 hge [#] _ hk0 hk1 _ _ _ _ _ _ _ hs1.
      by do !split; try (move=> k' hk'; rewrite hs1 //; smt()); smt().
    seq 2 : (in_0 = m0 /\ 0 <= to_uint i < (2 * P.`n + 3) * (P.`n %/ 8) /\ (full <=> to_uint pos = 17) /\
             0 < to_uint pos <= 17 /\ (8 * to_uint pos) %% 136 = (P.`n + 32 + 8 * (to_uint i + 1)) %% 136 /\
             forall k, 0 <= k < 4 =>
               (to_uint pos < 17 => lane4w st k = tl_st c0 a0 m0 k (to_uint i + 1)) /\
               (to_uint pos = 17 => keccak_f1600_op (lane4w st k) = tl_st c0 a0 m0 k (to_uint i + 1))).
    + wp; skip => &m [#] hm hi0 hi1 hp0 hp1 hpm hst /=.
      have hpos : to_uint (pos{m} + W64.of_int 1) = to_uint pos{m} + 1.
      + by apply w64_add_small => //; move: hp1 hb; pose M := W64.modulus; smt().
      have hfull := Thash.w64_inc17 pos{m} hp1.
      have hK : forall k, 0 <= k < 4 =>
        (to_uint pos{m} + 1 < 17 => lane4w st{m} k = tl_st c0 a0 m0 k (to_uint i{m} + 1)) /\
        (to_uint pos{m} + 1 = 17 => keccak_f1600_op (lane4w st{m} k) = tl_st c0 a0 m0 k (to_uint i{m} + 1)).
      + move=> k hk; rewrite hst //; split => h.
        + by apply tl_absorb_lt => //; smt().
        by apply tl_absorb_eq => //; smt().
      have hm' := Thash.mod_step _ _ hp0 hp1 hpm.
      rewrite hpos; do !split; try (move=> k hk; exact (hK k hk)); smt().
    if.
    + wp; ecall (keccakf1600_x4_h st); wp; skip => &m [#] hm hi0 hi1 hfull hp0 hp1 hpm hK hf [s2 ms2] /= hs2.
      have hp17 : to_uint pos{m} = 17 by rewrite -hfull.
      have hi' : to_uint (i{m} + W64.of_int 1) = to_uint i{m} + 1.
      + by apply w64_add_small => //; move: hi1 hb; pose M := W64.modulus; smt().
      have hS : forall k, 0 <= k < 4 => lane4w s2 k = tl_st c0 a0 m0 k (to_uint i{m} + 1).
      + by move=> k hk; rewrite hs2 //; have [_ h] := hK k hk; exact (h hp17).
      rewrite W64.ultE W64.of_uintK hi' hm /=.
      by do !split; try (exact hS); smt().
    wp; skip => &m [#] hm hi0 hi1 hfull hp0 hp1 hpm hK hf /=.
    have hp17 : to_uint pos{m} < 17 by smt().
    have hi' : to_uint (i{m} + W64.of_int 1) = to_uint i{m} + 1.
    + by apply w64_add_small => //; move: hi1 hb; pose M := W64.modulus; smt().
    have hS : forall k, 0 <= k < 4 => lane4w st{m} k = tl_st c0 a0 m0 k (to_uint i{m} + 1).
    + by move=> k hk; have [h _] := hK k hk; exact (h hp17).
    have hsm : 8 * to_uint pos{m} %% 136 = 8 * to_uint pos{m} by apply modz_small; smt().
    rewrite W64.ultE W64.of_uintK hi' hm /=.
    by do !split; try (exact hS); smt().
  wp; skip => &m [#] hm hw /=.
  have hH : forall k, 0 <= k < 4 => lane4w st{m} k = tl_st c0 a0 m0 k 0.
  + move=> k hk.
    have hB := body_absorbed c0 a0 (fun _ _ => W64.zero) k [] hk _ _.
    + smt().
    + by move=> i b hi hb' /=; rewrite W8u8.get_zero.
    rewrite /tl_st take0 /tl_pre -hB.
    apply Array25.tP => w hw'; rewrite lane4wE // Array25.initiE // hw //.
    case: (w < P.`n %/ 8 + 4) => h; first by rewrite body_head.
    by rewrite head_zero 1:/# /body_word ifF 1:/#; smt().
  split; first by do !split; try (exact hH); smt().
  move=> i1 x1 m1 p1 s1 hm1 [#] _ h1 h2 h3 h4 h5 h6 h7.
  have hiL : to_uint i1 = (2 * P.`n + 3) * (P.`n %/ 8) by smt().
  by do !split; try (move=> k hk; rewrite h7 // hiL); smt().
seq 6 : (0 <= to_uint pos < 17 /\ 8 * to_uint pos = (P.`n + 32 + len P * P.`n) %% 136 /\
         forall k, 0 <= k < 4 =>
           lane4w st k = pad_w (tl_st c0 a0 m0 k ((2 * P.`n + 3) * (P.`n %/ 8))) (to_uint pos)).
+ while (0 <= k <= 4 /\ to_uint lane = 4 * to_uint pos + k /\ v = W64.of_int 9223372036854775808 /\
         0 <= to_uint pos < 17 /\ 8 * to_uint pos = (P.`n + 32 + len P * P.`n) %% 136 /\
         (forall k', 0 <= k' < k =>
            lane4w st k' = pad_w (tl_st c0 a0 m0 k' ((2 * P.`n + 3) * (P.`n %/ 8))) (to_uint pos)) /\
         (forall k', k <= k' < 4 => lane4w st k' = tl_st c0 a0 m0 k' ((2 * P.`n + 3) * (P.`n %/ 8)))).
  + wp; skip => &m [#] hk0 hk1 hl0 hv hp0 hp1 hpm hlo hhi hlt /=.
    pose st1 := BArray800.set64 st{m} (to_uint lane{m})
                  (BArray800.get64 st{m} (to_uint lane{m}) `^` W64.of_int 31).
    have e1 : forall k', 0 <= k' < 4 => lane4w st1 k' =
      if k' = k{m}
      then (lane4w st{m} k{m}).[to_uint pos{m} <- (lane4w st{m} k{m}).[to_uint pos{m}] `^` W64.of_int 31]
      else lane4w st{m} k'.
    + by move=> k' hk'; rewrite /st1 (lane4w_xor _ _ (to_uint pos{m}) k{m}) 1..4:/#.
    have e2 : forall k', 0 <= k' < 4 =>
      lane4w (BArray800.set64 st1 (64 + k{m}) (BArray800.get64 st1 (64 + k{m}) `^` v{m})) k' =
      if k' = k{m} then (lane4w st1 k{m}).[16 <- (lane4w st1 k{m}).[16] `^` v{m}] else lane4w st1 k'.
    + by move=> k' hk'; rewrite (lane4w_xor _ _ 16 k{m}) 1..4:/#.
    have hA : forall k', 0 <= k' < k{m} + 1 =>
      lane4w (BArray800.set64 st1 (64 + k{m}) (BArray800.get64 st1 (64 + k{m}) `^` v{m})) k' =
      pad_w (tl_st c0 a0 m0 k' ((2 * P.`n + 3) * (P.`n %/ 8))) (to_uint pos{m}).
    + move=> k' hk'; rewrite e2 1:/# e1 1:/# e1 1:/#.
      case: (k' = k{m}) => [-> /= | hne]; first by rewrite hhi 1:/# /pad_w /= hv.
      by apply hlo; smt().
    have hB : forall k', k{m} + 1 <= k' < 4 =>
      lane4w (BArray800.set64 st1 (64 + k{m}) (BArray800.get64 st1 (64 + k{m}) `^` v{m})) k' =
      tl_st c0 a0 m0 k' ((2 * P.`n + 3) * (P.`n %/ 8)).
    + by move=> k' hk'; rewrite e2 1:/# ifF 1:/# e1 1:/# ifF 1:/#; apply hhi; smt().
    have hl' : to_uint (lane{m} + W64.of_int 1) = to_uint lane{m} + 1.
    + by apply w64_add_small => //; move: hl0 hp1 hb; pose M := W64.modulus; smt().
    by do !split; try (exact hA); try (exact hB); smt().
  wp; skip => &m [#] hp0 hp1 hpm hst /=; split.
  + by do !split; try (move=> k' hk'; apply hst; smt()); smt(shl2).
  move=> k1 l1 s1 hge [#] hk0 hk1 _ _ _ _ hlo _.
  by do !split; try (move=> k hk; apply hlo; smt()); smt().
ecall (shake_x4_extract_n_h st); wp; ecall (keccakf1600_x4_h st).
skip => &m [#] hp0 hp1 hpm hst [s2 ms2] /= hs2 o ho k hk.
rewrite /T_l Thash.family_shake /=.
have h3 : forall i, 0 <= i < P.`n %/ 8 => Node4.get64 o (P.`n %/ 8 * k + i) = (lane4w s2 k).[i].
+ by move=> i hi; apply ho.
have hfin : tl_pre c0 a0 k ++ take (8 * ((2 * P.`n + 3) * (P.`n %/ 8))) (tl_msg m0 k) =
            (Node.to_list c0 ++ lane 32 k (BArray128.to_list a0)) ++ lane (len P * P.`n) k (TLenIn4.to_list m0).
+ rewrite take_oversize; first by rewrite (size_tl_msg m0 k hk) hl.
  by rewrite /tl_pre /tl_msg.
apply (x4_final _ (to_uint pos{m}) k (tl_st c0 a0 m0 k ((2 * P.`n + 3) * (P.`n %/ 8))) st{m} s2 o hk _ _ _
         (hst k hk) (hs2 k hk) h3).
+ smt().
+ by rewrite -hfin size_tl //; smt().
by rewrite /tl_st hfin.
qed.

lemma thash_t_len_x4_ll : islossless M._thash_t_len_x4.
proof.
have hn := n_val; have hb : 1048576 < W64.modulus by trivial.
proc; call shake_x4_extract_n_ll; wp; call keccakf1600_x4_ll.
while true (4 - k).
+ by move=> z; auto => /#.
wp.
while (0 <= to_uint i <= (2 * P.`n + 3) * (P.`n %/ 8) /\ (more <=> to_uint i < (2 * P.`n + 3) * (P.`n %/ 8)))
      ((2 * P.`n + 3) * (P.`n %/ 8) - to_uint i).
+ move=> z.
  conseq (_ : (0 <= to_uint i <= (2 * P.`n + 3) * (P.`n %/ 8) /\
               (more <=> to_uint i < (2 * P.`n + 3) * (P.`n %/ 8))) /\ more /\
              (2 * P.`n + 3) * (P.`n %/ 8) - to_uint i = z ==> true : =1%r)
         (_ : (0 <= to_uint i <= (2 * P.`n + 3) * (P.`n %/ 8) /\
               (more <=> to_uint i < (2 * P.`n + 3) * (P.`n %/ 8))) /\ more /\
              (2 * P.`n + 3) * (P.`n %/ 8) - to_uint i = z ==>
              (0 <= to_uint i <= (2 * P.`n + 3) * (P.`n %/ 8) /\
               (more <=> to_uint i < (2 * P.`n + 3) * (P.`n %/ 8))) /\
              (2 * P.`n + 3) * (P.`n %/ 8) - to_uint i < z).
  + smt().
  + smt().
  + seq 8 : (0 <= to_uint i < (2 * P.`n + 3) * (P.`n %/ 8) /\ (2 * P.`n + 3) * (P.`n %/ 8) - to_uint i = z).
    + by wp; while (0 <= to_uint i < (2 * P.`n + 3) * (P.`n %/ 8) /\ (2 * P.`n + 3) * (P.`n %/ 8) - to_uint i = z);
        auto => /#.
    seq 2 : (#pre).
    + by auto.
    if.
    + wp; ecall (keccakf1600_x4_h st); wp; skip => &m [#] hi0 hi1 hz hf r _ /=.
      have hi' : to_uint (i{m} + W64.of_int 1) = to_uint i{m} + 1.
      + by apply w64_add_small => //; move: hi1 hb; pose M := W64.modulus; smt().
      by rewrite W64.ultE W64.of_uintK hi' /=; smt().
    wp; skip => &m [#] hi0 hi1 hz hf /=.
    have hi' : to_uint (i{m} + W64.of_int 1) = to_uint i{m} + 1.
    + by apply w64_add_small => //; move: hi1 hb; pose M := W64.modulus; smt().
    by rewrite W64.ultE W64.of_uintK hi' /=; smt().
  by unroll for ^while; sp; if; [wp; call keccakf1600_x4_ll; auto | auto].
by wp; call shake_x4_seeded_head_ll; auto => &m /=; smt().
qed.

lemma thash_t_len_x4_total (m0 : TLenIn4.t) (c0 : Node.t) (a0 : BArray128.t) :
  phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
    forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
      T_l P (Node.to_list c0) (lane 32 k (BArray128.to_list a0)) (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r.
proof. by conseq thash_t_len_x4_ll (thash_t_len_x4_h m0 c0 a0). qed.
