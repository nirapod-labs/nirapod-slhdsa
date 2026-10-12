(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validate_Framing.ec
 * ===================
 *
 * The message framing of FIPS 205 section 10.2 (Algorithms 22 to 25).
 *
 * Besides small evaluations, this theory proves the three properties the
 * external interfaces need from M' for the security argument (see
 * proofs/security):
 *
 *     pure_message_inj      (ctx, M) is recoverable from the pure M' when
 *                           |ctx| <= 255;
 *     prehash_message_inj   (ctx, PH, PH(M)) is recoverable from the
 *                           pre-hash M' when |ctx| <= 255;
 *     framing_separated     no pure M' equals a pre-hash M' (first byte 0
 *                           against 1), the domain separation section
 *                           10.2.1 describes.
 *
 * The pre-hash case can only recover PH(M), not M: two messages with the
 * same digest frame identically, which is the collision caveat of
 * section 10.2.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Encoding FIPS205_External Validate_Encoding.

(* ------------------------------------------------------------------ *)
(* One-byte encodings                                                 *)

lemma toByte1 x : toByte x 1 = [W8.of_int x].
proof.
rewrite /toByte /zeros /range -mkseq_nseq /mkseq -!iotaredE /= /put /=.
by rewrite -(W8.of_int_mod x).
qed.

lemma of_int_byte_inj x y : 0 <= x < 256 => 0 <= y < 256 => W8.of_int x = W8.of_int y => x = y.
proof.
move=> hx hy /(congr1 W8.to_uint); rewrite !W8.of_uintK.
by rewrite !modz_small //; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Evaluations                                                        *)

lemma pure_message_empty_ctx m : pure_message [] m = W8.zero :: W8.zero :: m.
proof. by rewrite /pure_message !toByte1. qed.

lemma ph_oid_sha256 : ph_oid PH_SHA2_256 =
  map W8.of_int [0x06; 0x09; 0x60; 0x86; 0x48; 0x01; 0x65; 0x03; 0x04; 0x02; 0x01].
proof. by rewrite /= /toByte /zeros /range -mkseq_nseq /mkseq -!iotaredE /=. qed.

(* ------------------------------------------------------------------ *)
(* The OID table                                                      *)

(* The last OID byte: the arc 2.16.840.1.101.3.4.2.x of each function. *)
op ph_arc (ph : prehash) : int =
  with ph = PH_SHA2_224     => 4
  with ph = PH_SHA2_256     => 1
  with ph = PH_SHA2_384     => 2
  with ph = PH_SHA2_512     => 3
  with ph = PH_SHA2_512_224 => 5
  with ph = PH_SHA2_512_256 => 6
  with ph = PH_SHA3_224     => 7
  with ph = PH_SHA3_256     => 8
  with ph = PH_SHA3_384     => 9
  with ph = PH_SHA3_512     => 10
  with ph = PH_SHAKE128     => 11
  with ph = PH_SHAKE256     => 12.

op oid_prefix : bytes = map W8.of_int [0x06; 0x09; 0x60; 0x86; 0x48; 0x01; 0x65; 0x03; 0x04; 0x02].

lemma ph_oidE ph : ph_oid ph = oid_prefix ++ [W8.of_int (ph_arc ph)].
proof.
by case: ph => /=; rewrite /oid_prefix /toByte /zeros /range
                     -mkseq_nseq /mkseq -!iotaredE /=.
qed.

lemma ph_arc_inj ph1 ph2 : ph_arc ph1 = ph_arc ph2 => ph1 = ph2.
proof. by case: ph1; case: ph2. qed.

lemma ph_arc_range ph : 0 <= ph_arc ph < 256.
proof. by case: ph. qed.

lemma size_ph_oid ph : size (ph_oid ph) = 11.
proof. by rewrite ph_oidE size_cat /oid_prefix. qed.

lemma ph_oid_inj ph1 ph2 : ph_oid ph1 = ph_oid ph2 => ph1 = ph2.
proof.
rewrite !ph_oidE /oid_prefix /= => h.
by apply ph_arc_inj; apply of_int_byte_inj => //; apply ph_arc_range.
qed.

(* ------------------------------------------------------------------ *)
(* Injectivity and domain separation                                  *)

lemma pure_message_inj ctx1 ctx2 m1 m2 :
  size ctx1 <= 255 => size ctx2 <= 255 =>
  pure_message ctx1 m1 = pure_message ctx2 m2 =>
  ctx1 = ctx2 /\ m1 = m2.
proof.
move=> h1 h2; rewrite /pure_message !toByte1 /= => -[hs].
have eqs : size ctx1 = size ctx2.
+ by apply of_int_byte_inj => //; smt(size_ge0).
by rewrite -?catA => /(eqseq_cat _ _ _ _ eqs).
qed.

lemma prehash_message_inj ctx1 ctx2 ph1 ph2 m1 m2 :
  size ctx1 <= 255 => size ctx2 <= 255 =>
  prehash_message ctx1 ph1 m1 = prehash_message ctx2 ph2 m2 =>
  ctx1 = ctx2 /\ ph1 = ph2 /\ ph_apply ph1 m1 = ph_apply ph2 m2.
proof.
move=> h1 h2; rewrite /prehash_message !toByte1 /= => -[hs].
have eqs : size ctx1 = size ctx2.
+ by apply of_int_byte_inj => //; smt(size_ge0).
rewrite -?catA => /(eqseq_cat _ _ _ _ eqs) [-> h].
have hz : size (ph_oid ph1) = size (ph_oid ph2) by rewrite !size_ph_oid.
by move: h => /(eqseq_cat _ _ _ _ hz) [/ph_oid_inj -> ->].
qed.

lemma framing_separated ctx1 ctx2 ph m1 m2 :
  pure_message ctx1 m1 <> prehash_message ctx2 ph m2.
proof.
rewrite /pure_message /prehash_message !toByte1 /=.
by apply/negP => -[] /(congr1 W8.to_uint); rewrite !W8.of_uintK.
qed.
