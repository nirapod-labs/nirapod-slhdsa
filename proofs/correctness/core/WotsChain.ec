(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * WotsChain.ec
 * ============
 *
 * The chaining function of src/slhdsa/wots.jinc: _wots_chain computes
 * chain(X, i, s, PK.seed, ADRS) of FIPS 205 Algorithm 5 (chain of
 * FIPS205_WOTS), s applications of F with hash addresses i .. i + s - 1.
 *
 * The code passes one ADRS buffer along the chain and writes the hash
 * address into it before each F, as the standard does; the standard reads
 * ADRS only through setHashAddress, which keeps bytes 0 .. 27 and replaces
 * 28 .. 31. So chain depends on bytes 0 .. 27 of its address alone
 * (chain_irrel), and one more step is one more F (chainS). The returned
 * ADRS keeps bytes 0 .. 27 of the input, which is what a caller that
 * reuses the buffer for the next chain needs.
 *
 * Hash premise. The tweakable hash F is not proved here: the theorem takes
 * as a hypothesis that _thash_f, called with the caller's ctx c0, computes
 * F for some PK.seed pk. That is the shape of the per-family thash
 * theorems (Thash.thash_f_correct, with pk the bytes of ctx for SHAKE), so
 * the final theorems discharge it by instantiation.
 *
 * The ADRS setters are proved in correctness/slhdsa/ADRS.ec about the
 * set-free model; core_set_hash moves that theorem to this set's model,
 * whose copy of the procedure is the same code (proc; sim).
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel (P, Node).
 *
 * Theorem:
 *     wots_chain_correct   given the F premise, _wots_chain returns
 *                          chain(x, start, steps, pk, adrs) and an ADRS
 *                          with the same bytes 0 .. 27 when
 *                          start + steps < 2^32; total correctness.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Params FIPS205_Address FIPS205_Address_Props FIPS205_Hash FIPS205_WOTS.
require import BArray32 BArray128.
require import SetModel CoreExtracted.
require ADRS AddressExtracted.

(* ------------------------------------------------------------------ *)
(* The ADRS theorems, moved from the set-free model to this set's.    *)

lemma core_set_hash (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_hash : arg = (a0, i0) ==>
          BArray32.to_list res = setHashAddress (BArray32.to_list a0) (to_uint i0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_set_hash(adrs{m}, hash{m}) @ &m :
               BArray32.to_list res = setHashAddress (BArray32.to_list a0) (to_uint i0)] =
          Pr[AddressExtracted.M.__adrs_set_hash(a0, i0) @ &m :
               BArray32.to_list res = setHashAddress (BArray32.to_list a0) (to_uint i0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_hash_correct a0 i0).
qed.

(* ------------------------------------------------------------------ *)
(* chain (Alg. 5) reads the address only through setHashAddress, which *)
(* keeps bytes 0 .. 27.                                               *)

op chain_step (pk : bytes) (st : bytes * adrs) (j : int) : bytes * adrs =
  let a' = setHashAddress st.`2 j in (F P pk a' st.`1, a').

lemma chainE (x : bytes) i s pk (a : adrs) :
  chain P x i s pk a = (foldl (chain_step pk) (x, a) (range i (i + s))).`1.
proof. by rewrite /chain /chain_step. qed.

lemma sha_eq (a b : adrs) j : take 28 a = take 28 b => setHashAddress a j = setHashAddress b j.
proof. by rewrite /setHashAddress /slice !drop0 /= => ->. qed.

lemma sha_take (a : adrs) j : 28 <= size a =>
  size (setHashAddress a j) = 32 /\ take 28 (setHashAddress a j) = take 28 a.
proof.
move=> ha; rewrite /setHashAddress /slice drop0 /=.
have hs : size (take 28 a) = 28 by rewrite size_take //; smt().
split; first by rewrite size_cat hs size_toByte4.
by rewrite take_cat hs /= take0 cats0.
qed.

lemma fold_adrs (pk : bytes) (l : int list) (st : bytes * adrs) :
  28 <= size st.`2 =>
  28 <= size (foldl (chain_step pk) st l).`2 /\
  take 28 (foldl (chain_step pk) st l).`2 = take 28 st.`2.
proof.
elim: l st => //= j l ih st hs.
have [h1 h2] := sha_take st.`2 j hs.
have := ih (chain_step pk st j) _; first by rewrite /chain_step /= h1.
by rewrite /chain_step /= h2.
qed.

lemma fold_irrel (pk : bytes) (l : int list) (s1 s2 : bytes * adrs) :
  s1.`1 = s2.`1 => take 28 s1.`2 = take 28 s2.`2 =>
  (foldl (chain_step pk) s1 l).`1 = (foldl (chain_step pk) s2 l).`1.
proof.
elim: l s1 s2 => [|j l ih] s1 s2 h1 h2 //=; apply ih; rewrite /chain_step /=;
  by rewrite (sha_eq _ _ j h2) ?h1.
qed.

lemma chain_irrel (x : bytes) i s pk (a b : adrs) :
  take 28 a = take 28 b => chain P x i s pk a = chain P x i s pk b.
proof. by move=> h; rewrite !chainE; apply fold_irrel. qed.

lemma chain0 (x : bytes) i pk (a : adrs) : chain P x i 0 pk a = x.
proof. by rewrite chainE range_geq. qed.

lemma chainS (x : bytes) i s pk (a : adrs) : 0 <= s => 28 <= size a =>
  chain P x i (s + 1) pk a = F P pk (setHashAddress a (i + s)) (chain P x i s pk a).
proof.
move=> hs ha; rewrite !chainE (_ : i + (s + 1) = i + s + 1) 1:/# rangeSr 1:/# foldl_rcons.
rewrite {1}/chain_step /=; congr; apply sha_eq.
by have [_ ->] := fold_adrs pk (range i (i + s)) (x, a) ha.
qed.

(* ------------------------------------------------------------------ *)
(* _wots_chain                                                        *)

(* The premise: _thash_f with this ctx computes F for PK.seed = pk. For SHAKE
   sets pk is the bytes of ctx (Thash.thash_f_correct); for SHA2 sets ctx
   holds the chaining values of the PK.seed block. *)
lemma wots_chain_correct (pk : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  forall (x0 : Node.t) (i0 s0 : W32.t) (a0 : BArray32.t),
  phoare [M._wots_chain :
    x = x0 /\ start = i0 /\ steps = s0 /\ ctx = c0 /\ adrs = a0 /\
    to_uint i0 + to_uint s0 < W32.modulus ==>
    Node.to_list res.`1 =
      chain P (Node.to_list x0) (to_uint i0) (to_uint s0) pk (BArray32.to_list a0) /\
    take 28 (BArray32.to_list res.`2) = take 28 (BArray32.to_list a0)] = 1%r.
proof.
move=> thash_f_p x0 i0 s0 a0; proc; wp.
while (to_uint end_0 = to_uint i0 + to_uint s0 /\ to_uint i0 <= to_uint j <= to_uint end_0 /\
       more = (to_uint j < to_uint end_0) /\ ctx = c0 /\
       Node.to_list x = chain P (Node.to_list x0) (to_uint i0) (to_uint j - to_uint i0) pk (BArray32.to_list a0) /\
       take 28 (BArray32.to_list adrs) = take 28 (BArray32.to_list a0))
      (to_uint end_0 - to_uint j).
+ move=> z; wp; ecall (thash_f_p x adrs); ecall (core_set_hash adrs j); wp; skip.
  move=> &m [#] [#] he hj1 hj2 hmore hc hx ha hm hz /=.
  rewrite /protect_ptr /protect_32 /= => r hr; split => // _ r2 hr2.
  have hjj : to_uint (j{m} + W32.one) = to_uint j{m} + 1.
  + have h1 : to_uint W32.one = 1 by exact W32.to_uint1.
    have hlt' : to_uint j{m} < to_uint end_0{m} by rewrite -hmore.
    have hb := W32.to_uint_cmp end_0{m}.
    have hjm : to_uint j{m} + 1 < W32.modulus by move: hlt' hb => /#.
    by rewrite W32.to_uintD_small h1.
  have hx' : Node.to_list r2.`1 =
    chain P (Node.to_list x0) (to_uint i0) (to_uint j{m} + 1 - to_uint i0) pk (ADRS.bytes_of a0).
  + rewrite hr2 hr hx (sha_eq _ _ _ ha).
    rewrite (_ : to_uint j{m} + 1 - to_uint i0 = (to_uint j{m} - to_uint i0) + 1) 1:/#.
    by rewrite chainS 1:/# 1:ADRS.size_bytes_of //; congr; congr; smt().
  have ha' : take 28 (ADRS.bytes_of r) = take 28 (ADRS.bytes_of a0).
  + by rewrite hr; have [_ ->] := sha_take (ADRS.bytes_of adrs{m}) (to_uint j{m}) _;
      [rewrite ADRS.size_bytes_of | exact ha].
  rewrite hjj W32.ultE hjj /=; smt().
+ by move=> *.
wp; skip => &m /= [#] -> -> -> -> -> hlt /=.
have he : to_uint (i0 + s0) = to_uint i0 + to_uint s0.
+ by rewrite W32.to_uintD_small //; smt(W32.to_uint_cmp).
rewrite he; split.
+ by rewrite chain0 W32.ultE he /=; smt(W32.to_uint_cmp).
move=> a1 c1 e1 j1 m1 x1; split; first smt().
move=> hnm [#] he1 hj1 hj2 hm1 hc1 hx1 ha1; split => //.
have hs : to_uint s0 = to_uint j1 - to_uint i0.
+ clear hx1 ha1 hc1 hlt he; smt().
rewrite hs; exact hx1.
qed.
