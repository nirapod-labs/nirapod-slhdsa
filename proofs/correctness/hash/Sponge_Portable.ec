(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sponge_Portable.ec
 * ==================
 *
 * The sponge, SHA-3 and SHAKE theorems on the pairs that build the
 * portable Keccak-f[1600] kernel (src/hash/keccak/keccakf1600.jinc), with
 * no premise left.
 *
 * Sponge.ec, SpongeSqueeze.ec and SHA3_SHAKE.ec prove the sponge for any
 * permutation model that meets the section hypotheses kf_h (_keccakf1600
 * computes keccak_f1600_op on the lanes of its state) and kf_ll (it
 * terminates), which become the first two premises of their theorems.
 * Keccakf1600_Portable.ec proves both for this kernel, as
 * keccakf1600_correct and keccakf1600_ll, so each theorem below is the
 * theorem of the same name there applied to them.
 *
 * Theorems (total correctness):
 *     keccak_absorb_mem_total, keccak_finalize_total,
 *     keccak_squeeze_mem_total             the sponge (Sponge.ec,
 *                                          SpongeSqueeze.ec)
 *     sha3_absorb_all_total, sha3_224_mem_total ... sha3_512_mem_total,
 *     shake_mem_total, shake128_mem_total,
 *     shake256_mem_total                   the one-shot functions
 *                                          (SHA3_SHAKE.ec)
 *)

require import AllCore List.
from Jasmin require import JWord JMemory.
require import BArray28 BArray32 BArray48 BArray64 KeccakState.
require import Keccakf1600_Spec Keccak1600_Spec JWordList.
require import HashExtracted ShakeSponge Sponge SpongeSqueeze SHA3_SHAKE.
require Keccakf1600_Portable.

(* ------------------------------------------------------------------ *)
(* The sponge                                                          *)

lemma keccak_absorb_mem_total (r8 : int) (m0 : W8.t list) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._keccak_absorb_mem :
    Glob.mem = mem0 /\ absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 < 200
    /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0
    /\ absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint l0)) res.`1 res.`2] = 1%r.
proof. exact (Sponge.keccak_absorb_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma keccak_finalize_total (r8 : int) (m0 : W8.t list) (trail : W8.t) :
  phoare [M._keccak_finalize :
    absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200 /\ truncateu8 ds = trail
    ==> lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 m0)] = 1%r.
proof. exact (Sponge.keccak_finalize_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma keccak_squeeze_mem_total (r8 : int) (s : state) (t0 : int) (mem0 : global_mem_t) (o0 l0 : W64.t) :
  phoare [M._keccak_squeeze_mem :
    Glob.mem = mem0 /\ squeezing r8 s t0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200
    /\ out = o0 /\ outlen = l0 /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0) (drop t0 (SQUEEZE1600 r8 (t0 + to_uint l0) s))
    /\ squeezing r8 s (t0 + to_uint l0) res.`1 res.`2] = 1%r.
proof. exact (SpongeSqueeze.keccak_squeeze_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

(* ------------------------------------------------------------------ *)
(* The one-shot functions                                              *)

lemma sha3_absorb_all_total (r8 : int) (trail : W8.t) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M.__sha3_absorb_all :
    Glob.mem = mem0 /\ to_uint rate = r8 /\ 0 < r8 < 200 /\ truncateu8 ds = trail
    /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0
    /\ lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 (memread mem0 (to_uint p0) (to_uint l0)))] = 1%r.
proof. exact (SHA3_SHAKE.sha3_absorb_all_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma sha3_224_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_224_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray28.to_list res.`1 = SHA3_224 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof. exact (SHA3_SHAKE.sha3_224_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma sha3_256_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_256_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray32.to_list res.`1 = SHA3_256 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof. exact (SHA3_SHAKE.sha3_256_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma sha3_384_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_384_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray48.to_list res.`1 = SHA3_384 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof. exact (SHA3_SHAKE.sha3_384_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma sha3_512_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_512_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray64.to_list res.`1 = SHA3_512 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof. exact (SHA3_SHAKE.sha3_512_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma shake_mem_total (r8 : int) (mem0 : global_mem_t) (o0 l0 p0 n0 : W64.t) :
  phoare [M.__shake_mem :
    Glob.mem = mem0 /\ to_uint rate = r8 /\ 0 < r8 < 200 /\ out = o0 /\ outlen = l0
    /\ in_0 = p0 /\ inlen = n0 /\ to_uint p0 + to_uint n0 <= W64.modulus
    /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0)
          (KECCAK1600 r8 (memread mem0 (to_uint p0) (to_uint n0)) SHAKE_DS_BYTE (to_uint l0))] = 1%r.
proof. exact (SHA3_SHAKE.shake_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma shake128_mem_total (mem0 : global_mem_t) (o0 l0 p0 n0 : W64.t) :
  phoare [M._shake128_mem :
    Glob.mem = mem0 /\ out = o0 /\ outlen = l0 /\ in_0 = p0 /\ inlen = n0
    /\ to_uint p0 + to_uint n0 <= W64.modulus /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0) (SHAKE128 (memread mem0 (to_uint p0) (to_uint n0)) (to_uint l0))] = 1%r.
proof. exact (SHA3_SHAKE.shake128_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.

lemma shake256_mem_total (mem0 : global_mem_t) (o0 l0 p0 n0 : W64.t) :
  phoare [M._shake256_mem :
    Glob.mem = mem0 /\ out = o0 /\ outlen = l0 /\ in_0 = p0 /\ inlen = n0
    /\ to_uint p0 + to_uint n0 <= W64.modulus /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0) (SHAKE256 (memread mem0 (to_uint p0) (to_uint n0)) (to_uint l0))] = 1%r.
proof. exact (SHA3_SHAKE.shake256_mem_total Keccakf1600_Portable.keccakf1600_correct Keccakf1600_Portable.keccakf1600_ll). qed.
