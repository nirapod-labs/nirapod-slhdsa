(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Keccakf1600_Pair.ec (x86_64/portable)
 * =====================================
 *
 * The Keccak-f[1600] theorems of this pair's kernel under one theory
 * name, so that a proof checked against every pair (the per-set proofs
 * of correctness/core/) can use them without naming the kernel. This
 * pair builds the shared scalar kernel (src/hash/keccak/keccakf1600.jinc),
 * proven in Keccakf1600_Portable.ec.
 *
 * Theorems (each the theorem of the same name in Keccakf1600_Portable):
 *     keccakf1600_correct   _keccakf1600 computes keccak_f1600_op on the
 *                           lanes of st (partial correctness);
 *     keccakf1600_ll        it terminates;
 *     keccakf1600_total     both together.
 *)

require import AllCore.
require import BArray200 HashExtracted KeccakState Keccakf1600_Spec.
require Keccakf1600_Portable.

lemma keccakf1600_correct (s0 : BArray200.t) :
  hoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)].
proof. exact (Keccakf1600_Portable.keccakf1600_correct s0). qed.

lemma keccakf1600_ll : islossless M._keccakf1600.
proof. exact Keccakf1600_Portable.keccakf1600_ll. qed.

lemma keccakf1600_total (s0 : BArray200.t) :
  phoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)] = 1%r.
proof. exact (Keccakf1600_Portable.keccakf1600_total s0). qed.
