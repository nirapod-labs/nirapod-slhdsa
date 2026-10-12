(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_External.ec
 * ===================
 *
 * The SLH-DSA external functions of FIPS 205 section 10: Algorithms 21
 * (slh_keygen), 22 (slh_sign), 23 (hash_slh_sign), 24 (slh_verify) and
 * 25 (hash_slh_verify), with the pre-hash functions of section 10.2.2.
 *
 * Message framing. Pure SLH-DSA signs
 *
 *     M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M,
 *
 * HashSLH-DSA signs
 *
 *     M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M),
 *
 * where OID is the DER encoding (tag, length, value) of the pre-hash
 * function's object identifier. Contexts longer than 255 bytes are
 * rejected: signing returns None (the standard's error indication) and
 * verification returns false.
 *
 * Pre-hash functions. Algorithm 23 lists SHA-256, SHA-512, SHAKE128 and
 * SHAKE256 and allows "other approved hash functions or XOFs". This
 * specification covers the twelve functions of the NIST hashAlgs arc
 * 2.16.840.1.101.3.4.2.{1..12}: SHA-224/256/384/512, SHA-512/224,
 * SHA-512/256, SHA3-224/256/384/512, SHAKE128 with 256 output bits and
 * SHAKE256 with 512 output bits (the lengths of Algorithm 23 lines 17
 * and 20). These are the pre-hash functions of the NIST ACVP SLH-DSA
 * test specification.
 *
 * Randomness. The deterministic operators take the random values as
 * arguments: an RBG failure (Algorithm 21 lines 4-6, Algorithm 22 lines
 * 5-7) is the caller's error path and has no counterpart here. The module
 * SLH_DSA samples them uniformly and is the probabilistic scheme the
 * security theorems are about.
 *)

require import AllCore List IntDiv Distr DList.
from Jasmin require import JWord.
require import Bytes FIPS180_SHA2 FIPS202_Bytes.
require import FIPS205_Encoding FIPS205_Params FIPS205_Internal.

type prehash = [
  | PH_SHA2_224 | PH_SHA2_256 | PH_SHA2_384 | PH_SHA2_512
  | PH_SHA2_512_224 | PH_SHA2_512_256
  | PH_SHA3_224 | PH_SHA3_256 | PH_SHA3_384 | PH_SHA3_512
  | PH_SHAKE128 | PH_SHAKE256
].

(* DER encodings 06 09 60 86 48 01 65 03 04 02 xx of 2.16.840.1.101.3.4.2.xx
   (Algorithm 23 lines 10, 13, 16 and 19 for xx = 01, 03, 0B and 0C). *)
op ph_oid (ph : prehash) : bytes =
  with ph = PH_SHA2_224     => toByte 0x0609608648016503040204 11
  with ph = PH_SHA2_256     => toByte 0x0609608648016503040201 11
  with ph = PH_SHA2_384     => toByte 0x0609608648016503040202 11
  with ph = PH_SHA2_512     => toByte 0x0609608648016503040203 11
  with ph = PH_SHA2_512_224 => toByte 0x0609608648016503040205 11
  with ph = PH_SHA2_512_256 => toByte 0x0609608648016503040206 11
  with ph = PH_SHA3_224     => toByte 0x0609608648016503040207 11
  with ph = PH_SHA3_256     => toByte 0x0609608648016503040208 11
  with ph = PH_SHA3_384     => toByte 0x0609608648016503040209 11
  with ph = PH_SHA3_512     => toByte 0x060960864801650304020A 11
  with ph = PH_SHAKE128     => toByte 0x060960864801650304020B 11
  with ph = PH_SHAKE256     => toByte 0x060960864801650304020C 11.

(* PH_M (Algorithm 23 lines 11, 14, 17 and 20, and their analogues). *)
op ph_apply (ph : prehash) (msg : bytes) : bytes =
  with ph = PH_SHA2_224     => SHA256.sha224 msg
  with ph = PH_SHA2_256     => SHA256.sha256 msg
  with ph = PH_SHA2_384     => SHA512.sha384 msg
  with ph = PH_SHA2_512     => SHA512.sha512 msg
  with ph = PH_SHA2_512_224 => SHA512.sha512_224 msg
  with ph = PH_SHA2_512_256 => SHA512.sha512_256 msg
  with ph = PH_SHA3_224     => sha3_224 msg
  with ph = PH_SHA3_256     => sha3_256 msg
  with ph = PH_SHA3_384     => sha3_384 msg
  with ph = PH_SHA3_512     => sha3_512 msg
  with ph = PH_SHAKE128     => shake128 msg 256
  with ph = PH_SHAKE256     => shake256 msg 512.

(* Algorithm 22 line 8 and Algorithm 24 line 4. *)
op pure_message (ctx msg : bytes) : bytes =
  toByte 0 1 ++ toByte (size ctx) 1 ++ ctx ++ msg.

(* Algorithm 23 line 24 and Algorithm 25 line 20. *)
op prehash_message (ctx : bytes) (ph : prehash) (msg : bytes) : bytes =
  toByte 1 1 ++ toByte (size ctx) 1 ++ ctx ++ ph_oid ph ++ ph_apply ph msg.

(* Algorithm 21 line 7, from the three n-byte values of lines 1 to 3. *)
op slh_keygen (p : params) (sk_seed sk_prf pk_seed : bytes) : bytes * bytes =
  slh_keygen_internal p sk_seed sk_prf pk_seed.

(* Algorithm 22, slh_sign(M, ctx, SK); addrnd = None is the deterministic
   variant. *)
op slh_sign (p : params) (msg ctx sk : bytes) (addrnd : bytes option) : bytes option =
  if 255 < size ctx then None                                                          (* 1-3 *)
  else Some (slh_sign_internal p (pure_message ctx msg) sk addrnd).                    (* 8-10 *)

(* Algorithm 23, hash_slh_sign(M, ctx, PH, SK). *)
op hash_slh_sign (p : params) (msg ctx : bytes) (ph : prehash) (sk : bytes) (addrnd : bytes option) : bytes option =
  if 255 < size ctx then None                                                          (* 1-3 *)
  else Some (slh_sign_internal p (prehash_message ctx ph msg) sk addrnd).              (* 8-26 *)

(* Algorithm 24, slh_verify(M, SIG, ctx, PK). *)
op slh_verify (p : params) (msg sig ctx pk : bytes) : bool =
  if 255 < size ctx then false                                                         (* 1-3 *)
  else slh_verify_internal p (pure_message ctx msg) sig pk.                            (* 4-5 *)

(* Algorithm 25, hash_slh_verify(M, SIG, ctx, PH, PK). *)
op hash_slh_verify (p : params) (msg sig ctx : bytes) (ph : prehash) (pk : bytes) : bool =
  if 255 < size ctx then false                                                         (* 1-3 *)
  else slh_verify_internal p (prehash_message ctx ph msg) sig pk.                      (* 4-21 *)

(* ------------------------------------------------------------------ *)
(* The probabilistic external interface                               *)

(* B^n with the uniform distribution (the "<-$ B^n" of section 2.3). *)
op dbytes (n : int) : bytes distr = dlist W8.dword n.

module SLH_DSA = {
  (* Algorithm 21. *)
  proc keygen(p : params) : bytes * bytes = {
    var sk_seed, sk_prf, pk_seed;
    sk_seed <$ dbytes p.`n;
    sk_prf  <$ dbytes p.`n;
    pk_seed <$ dbytes p.`n;
    return slh_keygen p sk_seed sk_prf pk_seed;
  }

  (* Algorithm 22, hedged. *)
  proc sign(p : params, msg : bytes, ctx : bytes, sk : bytes) : bytes option = {
    var addrnd, sig;
    sig <- None;
    if (size ctx <= 255) {
      addrnd <$ dbytes p.`n;
      sig <- slh_sign p msg ctx sk (Some addrnd);
    }
    return sig;
  }

  (* Algorithm 23, hedged. *)
  proc hash_sign(p : params, msg : bytes, ctx : bytes, ph : prehash, sk : bytes) : bytes option = {
    var addrnd, sig;
    sig <- None;
    if (size ctx <= 255) {
      addrnd <$ dbytes p.`n;
      sig <- hash_slh_sign p msg ctx ph sk (Some addrnd);
    }
    return sig;
  }

  proc verify(p : params, msg : bytes, sig : bytes, ctx : bytes, pk : bytes) : bool = {
    return slh_verify p msg sig ctx pk;
  }

  proc hash_verify(p : params, msg : bytes, sig : bytes, ctx : bytes, ph : prehash, pk : bytes) : bool = {
    return hash_slh_verify p msg sig ctx ph pk;
  }
}.
