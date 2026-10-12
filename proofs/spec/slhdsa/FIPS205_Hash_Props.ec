(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Hash_Props.ec
 * =====================
 *
 * Output lengths of the FIPS 205 hash functions (section 11), for every
 * parameter set with n in {16, 24, 32}: PRF_msg, PRF, F, H and T_l return
 * n bytes, as their signatures in section 4.1 state. The lengths follow
 * from those of SHA-256 (32 bytes), SHA-512 (64 bytes), HMAC (the length
 * of its hash) and SHAKE256 (the requested length).
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS180_SHA2 FIPS198_HMAC RFC8017_MGF1 FIPS202_Bytes.
require import FIPS205_Params FIPS205_Address FIPS205_Hash.

lemma size_sha256 (m : bytes) : size (SHA256.sha256 m) = 32.
proof.
have hc : forall hv w, size hv = 8 => size (SHA256.compress hv w) = 8.
+ move=> hv w hs; rewrite /SHA256.compress /= size_map size_zip.
  by case: (foldl _ _ _) => a b c d e f g h /=; rewrite hs.
have hh : forall l hv, size hv = 8 => size (foldl SHA256.compress hv l) = 8.
+ by elim => [|x l ih] hv hs //=; apply ih; apply hc.
rewrite /SHA256.sha256 (size_flatten_ctt 4).
+ by move=> x /mapP [y [_ ->]]; rewrite /w32_be size_rev W4u8.size_to_list.
by rewrite size_map /SHA256.hash hh.
qed.

lemma size_sha512 (m : bytes) : size (SHA512.sha512 m) = 64.
proof.
have hc : forall hv w, size hv = 8 => size (SHA512.compress hv w) = 8.
+ move=> hv w hs; rewrite /SHA512.compress /= size_map size_zip.
  by case: (foldl _ _ _) => a b c d e f g h /=; rewrite hs.
have hh : forall l hv, size hv = 8 => size (foldl SHA512.compress hv l) = 8.
+ by elim => [|x l ih] hv hs //=; apply ih; apply hc.
rewrite /SHA512.sha512 /SHA512.digest (size_flatten_ctt 8).
+ by move=> x /mapP [y [_ ->]]; rewrite /w64_be size_rev W8u8.size_to_list.
by rewrite size_map /SHA512.hash hh.
qed.

lemma size_hmac_sha256 (k t : bytes) : size (hmac_sha256 k t) = 32.
proof. by rewrite /hmac_sha256 /hmac /= size_sha256. qed.

lemma size_hmac_sha512 (k t : bytes) : size (hmac_sha512 k t) = 64.
proof. by rewrite /hmac_sha512 /hmac /= size_sha512. qed.

(* The digest lengths n of Table 2. *)
pred n_ok (p : params) = p.`n = 16 \/ p.`n = 24 \/ p.`n = 32.

lemma size_PRF_msg p (sk_prf opt_rand msg : bytes) :
  n_ok p => size (PRF_msg p sk_prf opt_rand msg) = p.`n.
proof.
move=> hn; rewrite /PRF_msg.
case: (p.`family = SHAKE) => _; first by rewrite size_shake256 /#.
by case: (p.`n = 16) => h16; rewrite size_trunc // ?size_hmac_sha256 ?size_hmac_sha512 /#.
qed.

lemma size_PRF p (pk_seed sk_seed : bytes) (a : adrs) :
  n_ok p => size (PRF p pk_seed sk_seed a) = p.`n.
proof.
move=> hn; rewrite /PRF.
case: (p.`family = SHAKE) => _; first by rewrite size_shake256 /#.
by rewrite size_trunc // size_sha256 /#.
qed.

lemma size_F p (pk_seed : bytes) (a : adrs) (m : bytes) :
  n_ok p => size (F p pk_seed a m) = p.`n.
proof.
move=> hn; rewrite /F.
case: (p.`family = SHAKE) => _; first by rewrite size_shake256 /#.
by rewrite size_trunc // size_sha256 /#.
qed.

lemma size_H p (pk_seed : bytes) (a : adrs) (m : bytes) :
  n_ok p => size (H p pk_seed a m) = p.`n.
proof.
move=> hn; rewrite /H.
case: (p.`family = SHAKE) => _; first by rewrite size_shake256 /#.
by case: (p.`n = 16) => h16; rewrite size_trunc // ?size_sha256 ?size_sha512 /#.
qed.

lemma size_T_l p (pk_seed : bytes) (a : adrs) (m : bytes) :
  n_ok p => size (T_l p pk_seed a m) = p.`n.
proof.
move=> hn; rewrite /T_l.
case: (p.`family = SHAKE) => _; first by rewrite size_shake256 /#.
by case: (p.`n = 16) => h16; rewrite size_trunc // ?size_sha256 ?size_sha512 /#.
qed.

lemma size_mgf1 (hash : bytes -> bytes) (hlen : int) (seed : bytes) (masklen : int) :
  0 < hlen => 0 <= masklen => (forall x, size (hash x) = hlen) =>
  size (mgf1 hash hlen seed masklen) = masklen.
proof.
move=> hh hm hs; rewrite /mgf1 size_take // (size_flatten_ctt hlen).
+ by move=> x /mapP [c [_ ->]]; rewrite hs.
rewrite size_map size_range /cdiv.
have h1 : masklen <= hlen * ((masklen + hlen - 1) %/ hlen).
+ by have := divz_eq (masklen + hlen - 1) hlen; smt(modz_ge0 ltz_pmod).
have h0 : 0 <= (masklen + hlen - 1) %/ hlen by apply divz_ge0 => /#.
by smt().
qed.

lemma size_H_msg p (r pk_seed pk_root msg : bytes) :
  n_ok p => 0 <= p.`m => size (H_msg p r pk_seed pk_root msg) = p.`m.
proof.
move=> hn hm; rewrite /H_msg.
case: (p.`family = SHAKE) => _; first by rewrite size_shake256.
case: (p.`n = 16) => _.
+ by rewrite /mgf1_sha256 size_mgf1 // => x; rewrite size_sha256.
by rewrite /mgf1_sha512 size_mgf1 // => x; rewrite size_sha512.
qed.
