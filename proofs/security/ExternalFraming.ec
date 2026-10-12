(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ExternalFraming.ec
 * ==================
 *
 * EUF-CMA of the external interfaces of FIPS 205 section 10 from EUF-CMA
 * of the internal functions of section 9.
 *
 * The external interfaces sign and verify a framed message M' in place of
 * the application's message (Algorithms 22 to 25). One key may serve both
 * pure and pre-hash signing, so the external message space here is the
 * disjoint union of the two kinds of request:
 *
 *     PureMsg ctx M         framed as 0 || |ctx| || ctx || M
 *     HashMsg ctx PH M      framed as 1 || |ctx| || ctx || OID(PH) || PH(M)
 *
 * and the external scheme rejects contexts longer than 255 bytes (signing
 * returns the empty string, standing for the error indication, and
 * verification returns false).
 *
 * Theorem (euf_cma_external). For every internal scheme I and every
 * EUF-CMA adversary A against External(I),
 *
 *     Pr[A forges against External(I)]
 *       <= Pr[B(A) forges against I]
 *        + Pr[A's forgery and a signed request are distinct pre-hash
 *             requests with equal context, function and digest]
 *
 * The second term is the probability that the run exhibits a collision of
 * the pre-hash function. It vanishes for pure requests, whose framing is
 * injective (Validate_Framing.pure_message_inj), and a pure framing never
 * equals a pre-hash framing (framing_separated). I is arbitrary: the
 * statement holds for hedged and deterministic signing alike, and
 * instantiating I with the SLH-DSA internal functions is separate work.
 *
 * Hypotheses: internal verification terminates (I_verify_ll), and A and I
 * do not read or write the games' own state (the section's module
 * restrictions). No other assumption is made; in particular nothing is
 * assumed about the pre-hash functions, whose collisions appear in the
 * bound instead.
 *)

require import AllCore List Distr.
require DigitalSignatures.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_External Validate_Framing.

(* ------------------------------------------------------------------ *)
(* External requests and their framing                                *)

type request = [
  | PureMsg of bytes & bytes
  | HashMsg of bytes & prehash & bytes
].

op ctx_of (x : request) : bytes =
  with x = PureMsg ctx m    => ctx
  with x = HashMsg ctx ph m => ctx.

op valid (x : request) : bool = size (ctx_of x) <= 255.

op frame (x : request) : bytes =
  with x = PureMsg ctx m    => pure_message ctx m
  with x = HashMsg ctx ph m => prehash_message ctx ph m.

(* Two distinct pre-hash requests that frame identically. *)
op ph_collision (x y : request) : bool =
  match x with
  | PureMsg _ _ => false
  | HashMsg ctx ph m =>
      match y with
      | PureMsg _ _ => false
      | HashMsg ctx' ph' m' =>
          ctx = ctx' /\ ph = ph' /\ m <> m' /\ ph_apply ph m = ph_apply ph m'
      end
  end.

lemma frame_inj x y :
  valid x => valid y => frame x = frame y => x = y \/ ph_collision x y.
proof.
case: x => [ctx m | ctx ph m].
+ case: y => [ctx' m' | ctx' ph' m']; rewrite /valid /=.
  + by move=> h h' /(pure_message_inj _ _ _ _ h h').
  by move=> _ _; apply framing_separated.
case: y => [ctx' m' | ctx' ph' m']; rewrite /valid /=.
+ by move=> _ _ /eq_sym; apply framing_separated.
move=> h h' /(prehash_message_inj _ _ _ _ _ _ h h') [<- [<- heq]].
by case: (m = m') => // ne; right.
qed.

(* ------------------------------------------------------------------ *)
(* The two signature notions                                          *)

clone import DigitalSignatures as DSI with
  type msg_t <- bytes, type sig_t <- bytes, type pk_t <- bytes, type sk_t <- bytes.

clone import DigitalSignatures as DSE with
  type msg_t <- request, type sig_t <- bytes, type pk_t <- bytes, type sk_t <- bytes.

(* Algorithms 22 to 25 over an internal scheme I. *)
module External (I : DSI.Stateless.Scheme) : DSE.Stateless.Scheme = {
  proc keygen() : bytes * bytes = {
    var k;
    k <@ I.keygen();
    return k;
  }

  proc sign(sk : bytes, x : request) : bytes = {
    var s;
    s <- [];
    if (valid x) {
      s <@ I.sign(sk, frame x);
    }
    return s;
  }

  proc verify(pk : bytes, x : request, s : bytes) : bool = {
    var b;
    b <- false;
    if (valid x) {
      b <@ I.verify(pk, frame x, s);
    }
    return b;
  }
}.

(* The reduction: run A, frame its signing requests, frame its forgery. *)
module B (A : DSE.Stateless.Adv_EUFCMA) (O : DSI.Stateless.SOracle_CMA) = {
  module O' = {
    proc sign(x : request) : bytes = {
      var s;
      s <- [];
      if (valid x) {
        s <@ O.sign(frame x);
      }
      return s;
    }
  }

  proc forge(pk : bytes) : bytes * bytes = {
    var x, s;
    (x, s) <@ A(O').forge(pk);
    return (frame x, s);
  }
}.

(* The external game with the forged request kept in a global, so that the
   collision event can be stated on the final memory. *)
module Rec = { var forged : request }.

module EUF_CMA_Rec (I : DSI.Stateless.Scheme) (A : DSE.Stateless.Adv_EUFCMA) = {
  proc main() : bool = {
    var pk, sk, x, s, is_valid, is_fresh;
    (pk, sk) <@ External(I).keygen();
    DSE.Stateless.O_CMA_Default(External(I)).init(sk);
    (x, s) <@ A(DSE.Stateless.O_CMA_Default(External(I))).forge(pk);
    Rec.forged <- x;
    is_valid <@ External(I).verify(pk, x, s);
    is_fresh <@ DSE.Stateless.O_CMA_Default(External(I)).fresh(x);
    return is_valid /\ is_fresh;
  }
}.

section Proof.

declare module I <: DSI.Stateless.Scheme
  {-DSI.Stateless.O_CMA_Default, -DSE.Stateless.O_CMA_Default, -Rec}.

declare module A <: DSE.Stateless.Adv_EUFCMA
  {-I, -DSI.Stateless.O_CMA_Default, -DSE.Stateless.O_CMA_Default, -Rec}.

(* Internal verification terminates. External verification of a request
   with an over-long context returns before calling it, and the reduction
   always calls it; termination is what makes the two runs comparable. The
   SLH-DSA internal verification is a total function. *)
declare axiom I_verify_ll : islossless I.verify.

lemma euf_cma_rec &m :
  Pr[DSE.Stateless.EUF_CMA(External(I), A, DSE.Stateless.O_CMA_Default).main() @ &m : res]
  = Pr[EUF_CMA_Rec(I, A).main() @ &m : res].
proof. by byequiv => //; proc; inline *; sim. qed.

(* The main bound. The two runs stay in step: the internal query list is
   always the framing of the valid external requests, so an external
   forgery is an internal forgery unless its framing equals that of a
   signed request, which by frame_inj means a pre-hash collision. *)
lemma euf_cma_external &m :
  Pr[DSE.Stateless.EUF_CMA(External(I), A, DSE.Stateless.O_CMA_Default).main() @ &m : res]
  <= Pr[DSI.Stateless.EUF_CMA(I, B(A), DSI.Stateless.O_CMA_Default).main() @ &m : res]
   + Pr[EUF_CMA_Rec(I, A).main() @ &m :
          exists y, y \in DSE.Stateless.O_CMA_Default.qs /\ ph_collision Rec.forged y].
proof.
rewrite euf_cma_rec Pr[mu_split (exists y, y \in DSE.Stateless.O_CMA_Default.qs /\
                                           ph_collision Rec.forged y)].
rewrite RField.addrC; apply StdOrder.RealOrder.ler_add; last by rewrite Pr[mu_sub].
byequiv (_: ={glob A, glob I} ==>
            (res{1} /\ ! exists y, y \in DSE.Stateless.O_CMA_Default.qs{1} /\
                                   ph_collision Rec.forged{1} y) => res{2}) => //.
proc; inline *.

(* Key generation and the adversary's run. Invariant: equal internal
   state and keys, and qs_internal = map frame (filter valid qs_external). *)
seq 6 6 : (={glob I, pk, x, s} /\
           DSI.Stateless.O_CMA_Default.qs{2}
             = map frame (filter valid DSE.Stateless.O_CMA_Default.qs{1})).
+ call (_: ={glob I} /\
           DSE.Stateless.O_CMA_Default.sk{1} = DSI.Stateless.O_CMA_Default.sk{2} /\
           DSI.Stateless.O_CMA_Default.qs{2}
             = map frame (filter valid DSE.Stateless.O_CMA_Default.qs{1})).
  + proc; inline *; sp.
    if => //.
    + wp; call (_: true); auto => /> &1 &2 hv.
      by rewrite filter_rcons hv /= map_rcons.
    by auto => /> &1 &2 hv; rewrite filter_rcons hv /=.
  by wp; call (_: true); auto.

(* Verification. A valid forged request whose framing was signed is either
   that request itself (not fresh) or a pre-hash collision (excluded). *)
sp; if{1}.
+ wp; call (_: true); auto => /> &1 &2 hv _ _ hfresh hnocoll.
  apply/negP => /mapP [y [/mem_filter [hy yin] hframe]].
  case: (frame_inj _ _ hv hy hframe) => [eqxy | hc].
  + by move: hfresh; rewrite eqxy yin.
  by apply hnocoll; exists y.
by wp; call{2} I_verify_ll; auto.
qed.

end section Proof.
