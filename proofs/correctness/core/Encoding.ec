(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Encoding.ec
 * ===========
 *
 * The n-byte moves of src/slhdsa/encoding.jinc: __node_copy returns its
 * source (FIPS 205 section 4, byte strings). n is a multiple of 8, so a
 * move is n / 8 word copies; the loop invariant says which bytes are
 * already written.
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
 *     node_copy_correct    __node_copy returns src, total correctness.
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
