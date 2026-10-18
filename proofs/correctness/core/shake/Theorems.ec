(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Theorems.ec (SHAKE sets)
 * ========================
 *
 * The internal functions of a SHAKE set (Internal.ec) with the hash
 * premises that the hash proofs discharge.
 *
 * Internal.ec proves _slh_sign, _slh_verify and _slh_keygen for any
 * context relation ok and under premises on the tweakable and message
 * hashes. For the SHAKE sets the context is PK.seed itself
 * (HashKernels.thash_ctx_init_correct), so ok is the equality of the
 * context with PK.seed, and the premises are discharged by
 * HashKernels.ec (F, T_len, H, T_k: Thash.ec with the Keccak-f[1600]
 * theorem of the pair's kernel) and MsgHash.ec (PRF_msg, H_msg).
 *
 * The four-way hashes _thash_prf_x4, _thash_f_x4 and _thash_t_len_x4,
 * which signing and key generation call through the WOTS+ leaf
 * computation, have no proof yet: they remain the premises of
 * slh_sign_total and slh_keygen_total, stated for a context equal to
 * PK.seed. Verification calls no four-way hash, and slh_verify_total has
 * no premise.
 *
 * Theorems (total correctness):
 *     slh_verify_total    _slh_verify returns 0 when slh_verify_internal
 *                         (Algorithm 20) accepts and all ones otherwise;
 *     slh_sign_total      _slh_sign returns slh_sign_internal (Algorithm
 *                         19), given the four-way hashes;
 *     slh_keygen_total    _slh_keygen returns slh_keygen_internal
 *                         (Algorithm 18), given the four-way hashes.
 *)

require import AllCore List.
from Jasmin require import JMemory JWord.
require import Bytes FIPS205_Params FIPS205_Hash FIPS205_Internal.
require import BArray32 BArray128 SetModel CoreExtracted WotsLeaf Internal HashKernels MsgHash.

lemma slh_verify_total :
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (p0 : PK.t) (mem0 : global_mem_t),
  phoare [M._slh_verify :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ pk = p0 /\
    Glob.mem = mem0 /\ msg_ok pl m ml ==>
    res.`1 = if slh_verify_internal P (slh_msg mem0 x0 pl m ml) (Sig.to_list s0) (PK.to_list p0)
             then W64.zero else W64.of_int (-1)] = 1%r.
proof.
apply (slh_verify_correct (fun pk (c : Ctx.t) => Node.to_list c = pk)).
+ by move=> p0 /=; exact (thash_ctx_init_correct p0).
+ by move=> pk c0 /= <- x0 a0; exact (thash_f_total x0 c0 a0).
+ by move=> pk c0 /= <- x0 a0; exact (thash_t_len_total x0 c0 a0).
+ by move=> pk c0 /= <- x0 a0; exact (thash_h_total x0 c0 a0).
+ by move=> pk c0 /= <- x0 a0; exact (thash_t_k_total x0 c0 a0).
exact h_msg_correct.
qed.

lemma slh_sign_total :
  (forall pk c0, Node.to_list c0 = pk => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, Node.to_list c0 = pk => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, Node.to_list c0 = pk => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (k0 : SK.t) (o0 : Node.t)
         (mem0 : global_mem_t),
  phoare [M._slh_sign :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
    opt_rand = o0 /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Sig.to_list res.`1 =
      slh_sign_internal P (slh_msg mem0 x0 pl m ml) (SK.to_list k0) (Some (Node.to_list o0))] = 1%r.
proof.
move=> hprf hf htl.
apply (slh_sign_correct (fun pk (c : Ctx.t) => Node.to_list c = pk)) => //.
+ by move=> p0 /=; exact (thash_ctx_init_correct p0).
+ by move=> pk c0 /= <- x0 a0; exact (thash_h_total x0 c0 a0).
+ by move=> pk c0 /= <- x0 a0; exact (thash_t_k_total x0 c0 a0).
+ exact prf_msg_correct.
exact h_msg_correct.
qed.

lemma slh_keygen_total :
  (forall pk c0, Node.to_list c0 = pk => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, Node.to_list c0 = pk => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, Node.to_list c0 = pk => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  forall (e0 : Seeds.t),
  phoare [M._slh_keygen : seeds = e0 ==>
    (SK.to_list res.`2, PK.to_list res.`1) =
      slh_keygen_internal P (slice (Seeds.to_list e0) 0 P.`n)
        (slice (Seeds.to_list e0) P.`n (2 * P.`n)) (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n))] = 1%r.
proof.
move=> hprf hf htl.
apply (slh_keygen_correct (fun pk (c : Ctx.t) => Node.to_list c = pk)) => //.
+ by move=> p0 /=; exact (thash_ctx_init_correct p0).
by move=> pk c0 /= <- x0 a0; exact (thash_h_total x0 c0 a0).
qed.
