(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * HashKernels.ec (SHA2 sets)
 * ==========================
 *
 * The compression functions of a SHA2 set's model, and the tweakable
 * hashes of Thash.ec with their premises discharged.
 *
 * The model of a parameter set (CoreExtracted) is the whole compilation
 * unit, so it carries its own copy of every hash kernel it calls. That
 * copy is extracted from the same source, under the same kernel roots, as
 * the pair's hash model (HashExtracted), on which SHA256_Compress.ec and
 * SHA512_Compress.ec prove the compression functions. Each theorem is
 * moved to the set's copy by an equivalence of the two procedures
 * (proc; sim: the bodies are the same program). Every pair whose model
 * the per-set proofs are checked against builds the portable SHA-2
 * kernels (proofs/Makefile, Sha2Kernel = sha2).
 *
 * Thash.ec proves F, PRF, H and the context initialisation under the
 * premises that the set's _sha256_compress and _sha512_compress compute
 * the FIPS 180-4 compression functions; each theorem below is the theorem
 * of the same name there applied to sha256_compress_total and
 * sha512_compress_total, and has no premise.
 *
 * Theorems (total correctness, every input):
 *     sha256_compress_total, sha512_compress_total
 *                               the compression functions of the set's
 *                               model;
 *     thash_ctx_init_total      _thash_ctx_init establishes ctx_ok;
 *     thash_f_total, thash_prf_total, thash_h_total
 *                               F, PRF and H for a context ctx_ok for
 *                               PK.seed.
 *)

require import AllCore List.
from Jasmin require import JWord.
require import Bytes FIPS180_SHA2 FIPS205_Params FIPS205_Hash.
require import BArray32 BArray64 BArray96 BArray128 SetModel CoreExtracted.
require import Thash.
require HashExtracted SHA256_Compress SHA512_Compress.

import BitEncoding.BitChunking.

(* ------------------------------------------------------------------ *)
(* The compression functions of the set's model                       *)

lemma sha256_compress_total (h0 : W32.t list) (blk : BArray64.t) :
  phoare [M._sha256_compress : hw256 h = h0 /\ block = blk ==>
          hw256 res.`1 = SHA256.compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha256_compress(h{m}, block{m}, ms{m}) @ &m :
               hw256 res.`1 = SHA256.compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))] =
          Pr[HashExtracted.M._sha256_compress(h{m}, block{m}, ms{m}) @ &m :
               hw256 res.`1 = SHA256.compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
byphoare (_ : SHA256_Compress.hwords h = h0 /\ block = blk ==>
              hw256 res.`1 = SHA256.compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))) => //.
by conseq (SHA256_Compress.sha256_compress_total h0 blk).
qed.

lemma sha512_compress_total (h0 : W64.t list) (blk : BArray128.t) :
  phoare [M._sha512_compress : hw512 h = h0 /\ block = blk ==>
          hw512 res.`1 = SHA512.compress h0 (map be64 (chunk 8 (BArray128.to_list blk)))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha512_compress(h{m}, block{m}, ms{m}) @ &m :
               hw512 res.`1 = SHA512.compress h0 (map be64 (chunk 8 (BArray128.to_list blk)))] =
          Pr[HashExtracted.M._sha512_compress(h{m}, block{m}, ms{m}) @ &m :
               hw512 res.`1 = SHA512.compress h0 (map be64 (chunk 8 (BArray128.to_list blk)))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
byphoare (_ : SHA512_Compress.hwords h = h0 /\ block = blk ==>
              hw512 res.`1 = SHA512.compress h0 (map be64 (chunk 8 (BArray128.to_list blk)))) => //.
by conseq (SHA512_Compress.sha512_compress_total h0 blk).
qed.

(* ------------------------------------------------------------------ *)
(* The context and the tweakable hashes, no premise left              *)

lemma thash_ctx_init_total (s0 : Node.t) :
  phoare [M._thash_ctx_init : pk_seed = s0 ==> ctx_ok (Node.to_list s0) res.`1] = 1%r.
proof. exact (thash_ctx_init_correct sha256_compress_total sha512_compress_total s0). qed.

lemma thash_f_total (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : Node.t) :
  phoare [M._thash_f :
    x = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = F P pk (BArray32.to_list a0) (Node.to_list x0)] = 1%r.
proof. exact (thash_f_correct sha256_compress_total sha512_compress_total pk c0 a0 x0). qed.

lemma thash_prf_total (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : Node.t) :
  phoare [M._thash_prf :
    sk_seed = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = PRF P pk (Node.to_list x0) (BArray32.to_list a0)] = 1%r.
proof. exact (thash_prf_correct sha256_compress_total sha512_compress_total pk c0 a0 x0). qed.

lemma thash_h_total (pk : bytes) (c0 : BArray96.t) (a0 : BArray32.t) (x0 : Node2.t) :
  phoare [M._thash_h :
    in_0 = x0 /\ ctx = c0 /\ adrs = a0 /\ size pk = P.`n /\ ctx_ok pk c0 ==>
    Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r.
proof. exact (thash_h_correct sha256_compress_total sha512_compress_total pk c0 a0 x0). qed.
