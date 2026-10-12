(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Hash.ec
 * ===============
 *
 * The six keyed and tweakable functions of FIPS 205 section 4.1, PRF_msg,
 * H_msg, PRF, T_l, H and F, as instantiated in section 11:
 *
 *     SHAKE sets                      section 11.1, SHAKE256 throughout
 *     SHA2 sets with n = 16           section 11.2.1, SHA-256 throughout
 *     SHA2 sets with n = 24 or 32     section 11.2.2, SHA-512 for H_msg,
 *                                     PRF_msg, H and T_l; SHA-256 for PRF
 *                                     and F
 *
 * Section 11 selects 11.2.1 or 11.2.2 by n ("if n = 16", "if n = 24 or
 * n = 32"), not by the security category, and so does this file.
 *
 * Output lengths. SHAKE256(X, 8n) and Trunc_n give n bytes; H_msg gives m
 * bytes. The hash functions themselves are specified in spec/hash against
 * FIPS 202, FIPS 180-4, FIPS 198-1 and RFC 8017.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS180_SHA2 FIPS198_HMAC RFC8017_MGF1 FIPS202_Bytes.
require import FIPS205_Encoding FIPS205_Params FIPS205_Address.

(* PRF_msg(SK.prf, opt_rand, M), B^n x B^n x B^* -> B^n. *)
op PRF_msg (p : params) (sk_prf opt_rand msg : bytes) : bytes =
  if p.`family = SHAKE then shake256 (sk_prf ++ opt_rand ++ msg) (8 * p.`n)
  else if p.`n = 16 then trunc p.`n (hmac_sha256 sk_prf (opt_rand ++ msg))
  else trunc p.`n (hmac_sha512 sk_prf (opt_rand ++ msg)).

(* H_msg(R, PK.seed, PK.root, M), B^n x B^n x B^n x B^* -> B^m. *)
op H_msg (p : params) (r pk_seed pk_root msg : bytes) : bytes =
  if p.`family = SHAKE then shake256 (r ++ pk_seed ++ pk_root ++ msg) (8 * p.`m)
  else if p.`n = 16 then
    mgf1_sha256 (r ++ pk_seed ++ SHA256.sha256 (r ++ pk_seed ++ pk_root ++ msg)) p.`m
  else
    mgf1_sha512 (r ++ pk_seed ++ SHA512.sha512 (r ++ pk_seed ++ pk_root ++ msg)) p.`m.

(* PRF(PK.seed, SK.seed, ADRS), B^n x B^n x B^32 -> B^n. SHA-256 for every
   SHA2 set. The zero block pads PK.seed to one SHA-256 input block. *)
op PRF (p : params) (pk_seed sk_seed : bytes) (a : adrs) : bytes =
  if p.`family = SHAKE then shake256 (pk_seed ++ a ++ sk_seed) (8 * p.`n)
  else trunc p.`n (SHA256.sha256 (pk_seed ++ toByte 0 (64 - p.`n) ++ compress a ++ sk_seed)).

(* F(PK.seed, ADRS, M1), B^n x B^32 x B^n -> B^n. SHA-256 for every SHA2 set. *)
op F (p : params) (pk_seed : bytes) (a : adrs) (m1 : bytes) : bytes =
  if p.`family = SHAKE then shake256 (pk_seed ++ a ++ m1) (8 * p.`n)
  else trunc p.`n (SHA256.sha256 (pk_seed ++ toByte 0 (64 - p.`n) ++ compress a ++ m1)).

(* H(PK.seed, ADRS, M2), B^n x B^32 x B^2n -> B^n. For n = 24 and 32 the
   SHA-512 input is padded to a 128-byte block. *)
op H (p : params) (pk_seed : bytes) (a : adrs) (m2 : bytes) : bytes =
  if p.`family = SHAKE then shake256 (pk_seed ++ a ++ m2) (8 * p.`n)
  else if p.`n = 16 then
    trunc p.`n (SHA256.sha256 (pk_seed ++ toByte 0 (64 - p.`n) ++ compress a ++ m2))
  else
    trunc p.`n (SHA512.sha512 (pk_seed ++ toByte 0 (128 - p.`n) ++ compress a ++ m2)).

(* T_l(PK.seed, ADRS, M_l), B^n x B^32 x B^ln -> B^n. Same instantiation as
   H; section 4.1 calls H the special case l = 2. *)
op T_l (p : params) (pk_seed : bytes) (a : adrs) (ml : bytes) : bytes =
  if p.`family = SHAKE then shake256 (pk_seed ++ a ++ ml) (8 * p.`n)
  else if p.`n = 16 then
    trunc p.`n (SHA256.sha256 (pk_seed ++ toByte 0 (64 - p.`n) ++ compress a ++ ml))
  else
    trunc p.`n (SHA512.sha512 (pk_seed ++ toByte 0 (128 - p.`n) ++ compress a ++ ml)).
