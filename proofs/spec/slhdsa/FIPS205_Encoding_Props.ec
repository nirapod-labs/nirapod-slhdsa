(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Encoding_Props.ec
 * =========================
 *
 * Closed forms of the step-by-step transcriptions of FIPS205_Encoding,
 * for the proofs that reason about whole digit strings (the WOTS+
 * encoding axioms of the security proof, and implementation proofs).
 *
 *     bounded_while_unfold   one step of a bounded while loop
 *     base_2b_state          the state of Algorithm 4 after o digits:
 *                            in = ceil(o b / 8), bits = 8 in - o b,
 *                            total = the integer of X[0:in]
 *     nth_base_2b            digit o of base_2b(X, b, out_len) is bits
 *                            o b .. (o + 1) b - 1 of X, most significant
 *                            first: the integer of X[0:in'] shifted right
 *                            by 8 in' - (o + 1) b and reduced mod 2^b,
 *                            with in' = ceil((o + 1) b / 8)
 *
 * The closed form needs X to hold the bytes it reads, the precondition of
 * Algorithm 4 ("X of length at least ceil(out_len b / 8)").
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding.

(* ------------------------------------------------------------------ *)
(* Bounded while loops                                                *)

lemma foldl_index_free ['a] (g : 'a -> int -> 'a) (s : 'a) (l1 l2 : int list) :
  (forall a i j, g a i = g a j) => size l1 = size l2 => foldl g s l1 = foldl g s l2.
proof.
move=> hg; elim: l1 l2 s => [|x l1 ih] [|y l2] s //=; first 2 smt(size_ge0).
by move=> hs; rewrite (hg s x y) (ih l2) /#.
qed.

lemma bounded_while_unfold ['a] (f : int) (c : 'a -> bool) (body : 'a -> 'a) (s : 'a) :
  0 < f =>
  bounded_while f c body s = bounded_while (f - 1) c body (if c s then body s else s).
proof.
move=> hf; rewrite /bounded_while /range /= (_: f = (f - 1) + 1) 1:/# iotaS 1:/# /=.
apply foldl_index_free => //; by rewrite !size_iota /#.
qed.

lemma bounded_while_stop ['a] (f : int) (c : 'a -> bool) (body : 'a -> 'a) (s : 'a) :
  !c s => bounded_while f c body s = s.
proof.
move=> hc; rewrite /bounded_while.
by elim: (range 0 f) => [//|x l ih /=]; rewrite hc /= ih.
qed.

(* ------------------------------------------------------------------ *)
(* Big-endian prefixes                                                *)

lemma be_int_rcons (l : bytes) (c : byte) : be_int (rcons l c) = 256 * be_int l + W8.to_uint c.
proof. by rewrite /be_int -cats1 foldl_cat. qed.

lemma be_int_take_succ (x : bytes) k :
  0 <= k < size x => be_int (take (k + 1) x) = 256 * be_int (take k x) + W8.to_uint (nth W8.zero x k).
proof. by move=> hk; rewrite (take_nth W8.zero) // be_int_rcons. qed.

lemma be_int_ge0 (l : bytes) : 0 <= be_int l.
proof.
elim/last_ind: l => [|l c ih]; first by rewrite /be_int.
by rewrite be_int_rcons; smt(W8.to_uint_cmp).
qed.

(* ------------------------------------------------------------------ *)
(* Algorithm 4                                                        *)

(* Lines 5 to 9 from a state with total = integer of X[0:in] and
   0 <= bits < 8: the loop reads exactly c = ceil((b - bits) / 8) bytes
   (none when bits >= b). *)
lemma base_2b_refill (x : bytes) (b inp bits : int) :
  0 < b => 0 <= bits < 8 => 0 <= inp =>
  inp + cdiv (b - bits) 8 <= size x =>
  bounded_while b (fun (s : int * int * int) => s.`2 < b) (base_2b_step x)
    (inp, bits, be_int (take inp x))
  = let c = max 0 (cdiv (b - bits) 8) in
    (inp + c, bits + 8 * c, be_int (take (inp + c) x)).
proof.
move=> hb hbits hinp hsz.
have gen : forall f i bt, 0 <= f => 0 <= bt => 0 <= i =>
  i + max 0 (cdiv (b - bt) 8) <= size x =>
  max 0 (cdiv (b - bt) 8) <= f =>
  bounded_while f (fun (s : int * int * int) => s.`2 < b) (base_2b_step x)
    (i, bt, be_int (take i x))
  = (i + max 0 (cdiv (b - bt) 8), bt + 8 * max 0 (cdiv (b - bt) 8),
     be_int (take (i + max 0 (cdiv (b - bt) 8)) x)).
+ elim/natind => [f hf0 i bt hf hbt hi hs hle | f hf ih i bt _ hbt hi hs hle].
  + have hz : max 0 (cdiv (b - bt) 8) = 0 by smt().
    rewrite hz /= bounded_while_stop //=; smt(cdivE).
  case: (bt < b) => hlt; last first.
  + have hz : max 0 (cdiv (b - bt) 8) = 0 by rewrite /cdiv; smt().
    by rewrite hz /= bounded_while_stop /#.
  rewrite bounded_while_unfold 1:/# /= hlt /=.
  have -> : base_2b_step x (i, bt, be_int (take i x)) = (i + 1, bt + 8, be_int (take (i + 1) x)).
  + by rewrite /base_2b_step /= be_int_take_succ 1:/#; ring.
  have hc : max 0 (cdiv (b - bt) 8) = 1 + max 0 (cdiv (b - (bt + 8)) 8) by rewrite /cdiv; smt().
  rewrite ih 1..5:/# /= hc; smt().
apply gen => //; smt().
qed.

(* After o digits Algorithm 4 has read in = ceil(o b / 8) bytes; the next
   digit needs ceil((o + 1) b / 8), and the refill reads the difference. *)
lemma cdiv_step o b : 0 < b => 0 <= o =>
  cdiv (o * b) 8 + max 0 (cdiv (b - (8 * cdiv (o * b) 8 - o * b)) 8) = cdiv ((o + 1) * b) 8.
proof.
move=> hb ho; rewrite /cdiv /=.
have -> : b - (8 * ((o * b + 7) %/ 8) - o * b) + 7
        = ((o + 1) * b + 7) + (- ((o * b + 7) %/ 8)) * 8 by ring.
rewrite divzMDr //.
have : (o * b + 7) %/ 8 <= ((o + 1) * b + 7) %/ 8 by apply leq_div2r => /#.
smt().
qed.

(* Digit j of base_2b(X, b, _): bits j b .. (j + 1) b - 1 of X. *)
op digit (x : bytes) (b j : int) : int =
  let i = cdiv ((j + 1) * b) 8 in
  (be_int (take i x) %/ 2 ^ (8 * i - (j + 1) * b)) %% 2 ^ b.

lemma base_2b_state (x : bytes) (b o : int) :
  0 < b => 0 <= o => cdiv (o * b) 8 <= size x =>
  foldl (fun (st : (int * int * int) * int list) (_ : int) => base_2b_out x b st)
        ((0, 0, 0), []) (range 0 o)
  = ((cdiv (o * b) 8, 8 * cdiv (o * b) 8 - o * b, be_int (take (cdiv (o * b) 8) x)),
     mkseq (digit x b) o).
proof.
move=> hb; elim/natind: o => [o ho0 ho _ | o ho ih _ hsz].
+ have -> : o = 0 by smt().
  by rewrite range_geq //= /cdiv /= mkseq0 /be_int take0.
have hmono : cdiv (o * b) 8 <= cdiv ((o + 1) * b) 8 by rewrite /cdiv; apply leq_div2r => /#.
rewrite rangeSr // -cats1 foldl_cat /= ih // 1:/#.
rewrite /base_2b_out /=.
have hbits : 0 <= 8 * cdiv (o * b) 8 - o * b < 8 by rewrite /cdiv; smt(divz_eq modz_ge0 ltz_pmod).
have hob : 0 <= o * b by apply mulr_ge0 => /#.
have hinp : 0 <= cdiv (o * b) 8 by move: hob; clear ih hsz hmono hbits; rewrite /cdiv; smt(divz_ge0).
have hrd : cdiv (o * b) 8 + cdiv (b - (8 * cdiv (o * b) 8 - o * b)) 8 <= size x.
+ by have := cdiv_step o b hb ho; move: hsz; smt().
rewrite (base_2b_refill x b _ _ hb hbits hinp hrd).
have hstep := cdiv_step o b hb ho.
have hexp : 8 * cdiv (o * b) 8 - o * b + 8 * max 0 (cdiv (b - (8 * cdiv (o * b) 8 - o * b)) 8) - b
          = 8 * cdiv ((o + 1) * b) 8 - (o + 1) * b by rewrite -hstep; ring.
rewrite /= hstep hexp mkseqS // /digit /=.
qed.

lemma nth_base_2b (x : bytes) (b out_len j : int) :
  0 < b => 0 <= j < out_len => cdiv (out_len * b) 8 <= size x =>
  nth 0 (base_2b x b out_len) j = digit x b j.
proof.
move=> hb hj hsz; rewrite /base_2b base_2b_state // 1:/# /=.
by rewrite nth_mkseq.
qed.
