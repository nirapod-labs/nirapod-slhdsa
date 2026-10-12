(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS202_Bytes.ec
 * ================
 *
 * The SHA-3 hash functions and SHAKE extendable-output functions of
 * FIPS 202 (August 2015) on byte strings, as FIPS 205 uses them.
 *
 * FIPS 202 defines these functions on bit strings. The bit-level
 * specification is imported from formosa-crypto/crypto-specs
 * (third_party/crypto-specs): FIPS202_SHA3 transcribes sections 4 to 6 as
 * procedures, and FIPS202_SHA3_Spec states the same functions as operators
 * and proves each procedure computes its operator (sha3_224_ph to
 * shake256_ph there). This file only fixes the byte
 * interface: a byte string is the bit string whose 8i-th to (8i+7)-th bits
 * are the bits of byte i, least significant first, which is the convention
 * of FIPS 202 Appendix B.1 (h2b/b2h). An output length d is in bits, as in
 * FIPS 202; FIPS 205 always passes a multiple of 8.
 *
 * Each function is also stated equal to the byte-oriented sponge of
 * crypto-specs (Keccak1600_Spec), which is the form implementation proofs
 * work with.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes.
require JWordList FIPS202_SHA3_Spec Keccak1600_Spec.

op bytes2bits (m : bytes) : bool list = JWordList.Bytes2Bits.bytes_to_bits m.
op bits2bytes (z : bool list) : bytes = JWordList.Bytes2Bits.bytes_from_bits z.

(* Section 6.1: SHA3-224, SHA3-256, SHA3-384, SHA3-512. *)
op sha3_224 (m : bytes) : bytes = bits2bytes (FIPS202_SHA3_Spec.sha3_224_op (bytes2bits m)).
op sha3_256 (m : bytes) : bytes = bits2bytes (FIPS202_SHA3_Spec.sha3_256_op (bytes2bits m)).
op sha3_384 (m : bytes) : bytes = bits2bytes (FIPS202_SHA3_Spec.sha3_384_op (bytes2bits m)).
op sha3_512 (m : bytes) : bytes = bits2bytes (FIPS202_SHA3_Spec.sha3_512_op (bytes2bits m)).

(* Section 6.2: SHAKE128(M, d) and SHAKE256(M, d), d in bits. *)
op shake128 (m : bytes) (d : int) : bytes = bits2bytes (FIPS202_SHA3_Spec.shake128_op (bytes2bits m) d).
op shake256 (m : bytes) (d : int) : bytes = bits2bytes (FIPS202_SHA3_Spec.shake256_op (bytes2bits m) d).

(* ------------------------------------------------------------------ *)
(* Agreement with the byte-oriented sponge                            *)

lemma bits2bytesK (m : bytes) : bits2bytes (bytes2bits m) = m.
proof. by rewrite /bits2bytes /bytes2bits JWordList.Bytes2Bits.bytes_to_bitsK. qed.

lemma shake128E (m : bytes) (l : int) :
  shake128 m (8 * l) = Keccak1600_Spec.SHAKE128 m l.
proof. by rewrite /shake128 (Keccak1600_Spec.shake128_opE _ _ l) // -/(bytes2bits _) bits2bytesK. qed.

lemma shake256E (m : bytes) (l : int) :
  shake256 m (8 * l) = Keccak1600_Spec.SHAKE256 m l.
proof. by rewrite /shake256 (Keccak1600_Spec.shake256_opE _ _ l) // -/(bytes2bits _) bits2bytesK. qed.

lemma sha3_224E (m : bytes) : sha3_224 m = Keccak1600_Spec.SHA3_224 m.
proof. by rewrite /sha3_224 Keccak1600_Spec.sha3_224_opE -/(bytes2bits _) bits2bytesK. qed.

lemma sha3_256E (m : bytes) : sha3_256 m = Keccak1600_Spec.SHA3_256 m.
proof. by rewrite /sha3_256 Keccak1600_Spec.sha3_256_opE -/(bytes2bits _) bits2bytesK. qed.

lemma sha3_384E (m : bytes) : sha3_384 m = Keccak1600_Spec.SHA3_384 m.
proof. by rewrite /sha3_384 Keccak1600_Spec.sha3_384_opE -/(bytes2bits _) bits2bytesK. qed.

lemma sha3_512E (m : bytes) : sha3_512 m = Keccak1600_Spec.SHA3_512 m.
proof. by rewrite /sha3_512 Keccak1600_Spec.sha3_512_opE -/(bytes2bits _) bits2bytesK. qed.

lemma size_shake128 (m : bytes) (l : int) : 0 <= l => size (shake128 m (8 * l)) = l.
proof. by move=> ge0_l; rewrite shake128E Keccak1600_Spec.size_SHAKE128. qed.

lemma size_shake256 (m : bytes) (l : int) : 0 <= l => size (shake256 m (8 * l)) = l.
proof. by move=> ge0_l; rewrite shake256E Keccak1600_Spec.size_SHAKE256. qed.
