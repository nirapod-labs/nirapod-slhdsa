(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Encoding.ec
 * ===========
 *
 * The n-byte moves of src/slhdsa/encoding.jinc: __node_copy returns its
 * source and __node_concat returns a || b (FIPS 205 section 4, byte
 * strings). n is a multiple of 8, so a move is n / 8 word copies; the
 * loop invariants say which bytes are already written.
 *
 * Model. CoreExtracted is the jasmin2ec model of one parameter set's
 * compilation unit (src/slhdsa/sets/<set>.jinc); this file is checked once
 * against the model of each set (proofs/Makefile, CORE_SETS). It names the
 * set only through SetModel: P is the FIPS 205 parameter record, whose
 * fields the lemmas n_val, a_val, ... give, and the buffers are the array
 * theories of their roles (Node, Node2, Digest, ForsIdx). The model writes
 * each parameter as its value; a proof step that needs one cites the
 * lemma, so no value is written in the proof text.
 *
 * Theorems:
 *     node_copy_correct    __node_copy returns src, total correctness;
 *     node_concat_correct  __node_concat returns the array whose bytes are
 *                          those of a then those of b, total correctness.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import SetModel CoreExtracted.

(* ------------------------------------------------------------------ *)
(* n / 8 words cover the n bytes                                      *)

lemma n_words : 0 < P.`n /\ 8 * (P.`n %/ 8) = P.`n by smt(n_val).

(* ------------------------------------------------------------------ *)
(* __node_copy                                                        *)

lemma node_copy_h (s0 : Node.t) :
  hoare [M.__node_copy : src = s0 ==> res = s0].
proof.
proc.
(* Invariant: the first 8 i bytes of dst are those of the source. *)
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ src = s0 /\
       forall j, 0 <= j < 8 * i => Node.get8 dst j = Node.get8 s0 j).
+ wp; skip => &m [#] h0 hi hinc hs hj hlt /=.
  do !(split; first smt()); move=> j [hj0 hj1].
  rewrite Node.get8_set64dE.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => hr.
  + have -> /= : 0 <= j && j < Node.size by smt(n_val).
    by rewrite hs Node.get64d_byte /#.
  by rewrite hs hj /#.
wp; skip => &m hs /=; split; first smt(n_val).
move=> dst0 i0 hn [#] h1 h2 h3 h4 h5; apply/Node.tP => j hj; rewrite h5 //; smt(n_val).
qed.

lemma node_copy_ll : islossless M.__node_copy.
proof. proc; while true (inc - i); auto; smt(). qed.

lemma node_copy_correct (s0 : Node.t) :
  phoare [M.__node_copy : src = s0 ==> res = s0] = 1%r.
proof. by conseq node_copy_ll (node_copy_h s0). qed.

(* ------------------------------------------------------------------ *)
(* __node_concat                                                      *)

lemma node_concat_h (a0 b0 : Node.t) :
  hoare [M.__node_concat : a = a0 /\ b = b0 ==>
         Node2.to_list res = Node.to_list a0 ++ Node.to_list b0].
proof.
proc.
(* Second loop: bytes n .. n + 8 i come from b; the first n stay a. *)
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ b = b0 /\
       (forall j, 0 <= j < P.`n => Node2.get8 dst j = Node.get8 a0 j) /\
       forall j, 0 <= j < 8 * i => Node2.get8 dst (P.`n + j) = Node.get8 b0 j).
+ wp; skip => &m [#] h0 hi hinc hb ha hj hlt /=.
  do 3!(split; first smt()).
  split => j [hj0 hj1]; rewrite Node2.get8_set64dE.
  + by rewrite ifF; [smt(n_val) | rewrite ha].
  (* The model's word offset is the literal n / 8 + i: n_val relates it to P.`n. *)
  case: (8 * i{m} <= j < 8 * i{m} + 8) => hr.
  + rewrite ifT; first smt(n_val).
    by rewrite hb Node.get64d_byte; [smt(n_val) | congr; smt(n_val)].
  by rewrite ifF; [smt(n_val) | rewrite hj /#].
wp.
(* First loop: bytes 0 .. 8 i come from a. *)
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ a = a0 /\ b = b0 /\
       forall j, 0 <= j < 8 * i => Node2.get8 dst j = Node.get8 a0 j).
+ wp; skip => &m [#] h0 hi hinc ha hb hj hlt /=.
  do !(split; first smt()); move=> j [hj0 hj1]; rewrite Node2.get8_set64dE.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => hr.
  + have -> /= : 0 <= j && j < Node2.size by smt(n_val).
    by rewrite ha Node.get64d_byte /#.
  by rewrite hj /#.
wp; skip => &m [ha hb] /=; split; first smt(n_val).
move=> dst0 i0 hn [#] h1 h2 h3 h4 h5 h6; split; first smt(n_val).
move=> dst1 i1 hn1 [#] g1 g2 g3 g4 g5 g6.
apply (eq_from_nth W8.zero).
+ by rewrite size_cat Node2.size_to_list !Node.size_to_list; smt(n_val).
move=> j; rewrite Node2.size_to_list => hj.
rewrite Node2.get_to_list nth_cat Node.size_to_list !Node.get_to_list.
case: (j < P.`n) => hjn.
+ by rewrite ifT; [smt(n_val) | rewrite g5 /#].
rewrite ifF; first smt(n_val).
have := g6 (j - P.`n) _; smt(n_val).
qed.

lemma node_concat_ll : islossless M.__node_concat.
proof.
proc; while true (inc - i); 1: by auto => /#.
wp; while true (inc - i); 1: by auto => /#.
by auto => /#.
qed.

lemma node_concat_correct (a0 b0 : Node.t) :
  phoare [M.__node_concat : a = a0 /\ b = b0 ==>
          Node2.to_list res = Node.to_list a0 ++ Node.to_list b0] = 1%r.
proof. by conseq node_concat_ll (node_concat_h a0 b0). qed.
