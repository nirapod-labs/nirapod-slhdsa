(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Theorems.ec (SHA2 sets)
 * =======================
 *
 * The internal functions of a SHA2 set (Internal.ec) with the hash
 * premises that the hash proofs discharge.
 *
 * Internal.ec proves _slh_sign, _slh_verify and _slh_keygen for any
 * context relation ok and under premises on the tweakable and message
 * hashes. For the SHA2 sets the context holds the chaining values after
 * the PK.seed block (Thash.ctx_ok), so ok is ctx_ok together with the
 * length of PK.seed, and the premises are discharged by HashKernels.ec
 * (context, F, H), ThashT.ec (T_len, T_k), MsgHash.ec (PRF_msg),
 * HMsg.ec (H_msg) and ThashX4.ec (the four-way PRF, F and T_len).
 *
 * The four-way hashes _thash_prf_x4, _thash_f_x4 and _thash_t_len_x4,
 * which signing and key generation call through the WOTS+ leaf
 * computation, run the scalar hash once per lane and are proved in
 * ThashX4.ec. No theorem below has a hash premise.
 *
 * The exports of External.ec take the internal theorems as premises,
 * and sign and verify also the pre-hash theorems of PreHash.ec; with
 * those discharged, the exports are proved with no hash premise. Their
 * only conditions are on the caller's input: M in msg_dom (Internal.ec)
 * and, for sign and verify, in ph_dom (External.ec).
 *
 * Theorems (total correctness, no premise):
 *     slh_verify_total    _slh_verify returns 0 when slh_verify_internal
 *                         (Algorithm 20) accepts and all ones otherwise;
 *     slh_sign_total      _slh_sign returns slh_sign_internal (Algorithm
 *                         19);
 *     slh_keygen_total    _slh_keygen returns slh_keygen_internal
 *                         (Algorithm 18);
 *     sign_total          sign returns slh_sign or hash_slh_sign
 *                         (Algorithms 22, 23), and all ones for a
 *                         selector above 12;
 *     verify_total        verify returns 0 when slh_verify or
 *                         hash_slh_verify (Algorithms 24, 25) accepts and
 *                         all ones otherwise;
 *     keygen_total        keygen returns slh_keygen (Algorithm 21 from
 *                         line 4) for the caller's seeds;
 *     sign_internal_total, verify_internal_total
 *                         the section 9 exports on M.
 *)

require import AllCore List.
from Jasmin require import JMemory JWord.
require import Bytes FIPS205_Params FIPS205_Hash FIPS205_Internal FIPS205_External.
require import BArray32 BArray96 BArray128 BArray257 SetModel CoreExtracted WotsLeaf Internal External PreHash.
require import Thash HashKernels
  MsgHash HMsg ThashT ThashX4.

lemma slh_verify_total :
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (p0 : PK.t) (mem0 : global_mem_t),
  phoare [M._slh_verify :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ pk = p0 /\
    Glob.mem = mem0 /\ msg_ok pl m ml ==>
    res.`1 = if slh_verify_internal P (slh_msg mem0 x0 pl m ml) (Sig.to_list s0) (PK.to_list p0)
             then W64.zero else W64.of_int (-1)] = 1%r.
proof.
apply (slh_verify_correct (fun pk (c : Ctx.t) => size pk = P.`n /\ ctx_ok pk c)).
+ by move=> p0 /=; conseq (thash_ctx_init_total p0) => //; smt(Node.size_to_list n_val).
+ by move=> pk c0 /= [hs hc] x0 a0; conseq (thash_f_total pk c0 a0 x0) => /#.
+ by move=> pk c0 /= [hs hc] x0 a0; conseq (thash_t_len_total pk c0 a0 x0) => /#.
+ by move=> pk c0 /= [hs hc] x0 a0; conseq (thash_h_total pk c0 a0 x0) => /#.
+ by move=> pk c0 /= [hs hc] x0 a0; conseq (thash_t_k_total pk c0 a0 x0) => /#.
exact h_msg_correct.
qed.

lemma slh_sign_total :
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (k0 : SK.t) (o0 : Node.t)
         (mem0 : global_mem_t),
  phoare [M._slh_sign :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
    opt_rand = o0 /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Sig.to_list res.`1 =
      slh_sign_internal P (slh_msg mem0 x0 pl m ml) (SK.to_list k0) (Some (Node.to_list o0))] = 1%r.
proof.
have hprf : forall pk c0, size pk = P.`n /\ ctx_ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r.
+ by move=> pk c0 [hs hc] k0 a0; conseq (thash_prf_x4_total pk c0 k0 a0) => /#.
have hf : forall pk c0, size pk = P.`n /\ ctx_ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r.
+ by move=> pk c0 [hs hc] x0 a0; conseq (thash_f_x4_total pk c0 x0 a0) => /#.
have htl : forall pk c0, size pk = P.`n /\ ctx_ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r.
+ by move=> pk c0 [hs hc] m0 a0; conseq (thash_t_len_x4_total pk c0 m0 a0) => /#.
apply (slh_sign_correct (fun pk (c : Ctx.t) => size pk = P.`n /\ ctx_ok pk c)) => //.
+ by move=> p0 /=; conseq (thash_ctx_init_total p0) => //; smt(Node.size_to_list n_val).
+ by move=> pk c0 /= [hs hc] x0 a0; conseq (thash_h_total pk c0 a0 x0) => /#.
+ by move=> pk c0 /= [hs hc] x0 a0; conseq (thash_t_k_total pk c0 a0 x0) => /#.
+ exact prf_msg_correct.
exact h_msg_correct.
qed.

lemma slh_keygen_total :
  forall (e0 : Seeds.t),
  phoare [M._slh_keygen : seeds = e0 ==>
    (SK.to_list res.`2, PK.to_list res.`1) =
      slh_keygen_internal P (slice (Seeds.to_list e0) 0 P.`n)
        (slice (Seeds.to_list e0) P.`n (2 * P.`n)) (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n))] = 1%r.
proof.
have hprf : forall pk c0, size pk = P.`n /\ ctx_ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r.
+ by move=> pk c0 [hs hc] k0 a0; conseq (thash_prf_x4_total pk c0 k0 a0) => /#.
have hf : forall pk c0, size pk = P.`n /\ ctx_ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r.
+ by move=> pk c0 [hs hc] x0 a0; conseq (thash_f_x4_total pk c0 x0 a0) => /#.
have htl : forall pk c0, size pk = P.`n /\ ctx_ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r.
+ by move=> pk c0 [hs hc] m0 a0; conseq (thash_t_len_x4_total pk c0 m0 a0) => /#.
apply (slh_keygen_correct (fun pk (c : Ctx.t) => size pk = P.`n /\ ctx_ok pk c)) => //.
+ by move=> p0 /=; conseq (thash_ctx_init_total p0) => //; smt(Node.size_to_list n_val).
by move=> pk c0 /= [hs hc] x0 a0; conseq (thash_h_total pk c0 a0 x0) => /#.
qed.

(* ------------------------------------------------------------------ *)
(* The exports (External.ec) with the pre-hash proofs (PreHash.ec)    *)

lemma sign_total :
  forall (s0 : Sig.t) (m ml : W64.t) (d0 : BArray257.t) (k0 : SK.t) (o0 : Node.t)
         (mem0 : global_mem_t),
  phoare [M.sign :
    sig = s0 /\ msg = m /\ msg_len = ml /\ domain = d0 /\ sk = k0 /\ opt_rand = o0 /\
    Glob.mem = mem0 /\ msg_dom (W64.of_int Prefix.size) m ml /\ ph_dom (dsel d0) m ml ==>
    if dsel d0 <= 12
    then res.`2 = W64.zero /\
         ext_sign d0 (m_of mem0 m ml) (SK.to_list k0) (Some (Node.to_list o0)) = Some (Sig.to_list res.`1)
    else res.`2 = W64.of_int (-1) /\ res.`1 = s0 /\
         ext_sign d0 (m_of mem0 m ml) (SK.to_list k0) (Some (Node.to_list o0)) = None] = 1%r.
proof. exact (sign_correct prehash_ll prehash_h slh_sign_total). qed.

lemma verify_total :
  forall (s0 : Sig.t) (m ml : W64.t) (d0 : BArray257.t) (p0 : PK.t) (mem0 : global_mem_t),
  phoare [M.verify :
    sig = s0 /\ msg = m /\ msg_len = ml /\ domain = d0 /\ pk = p0 /\ Glob.mem = mem0 /\
    msg_dom (W64.of_int Prefix.size) m ml /\ ph_dom (dsel d0) m ml ==>
    res = if ext_verify d0 (m_of mem0 m ml) (Sig.to_list s0) (PK.to_list p0)
          then W64.zero else W64.of_int (-1)] = 1%r.
proof. exact (verify_correct prehash_ll prehash_h slh_verify_total). qed.

lemma keygen_total :
  forall (e0 : Seeds.t),
  phoare [M.keygen : seeds = e0 ==>
    (SK.to_list res.`2, PK.to_list res.`1) =
      slh_keygen P (slice (Seeds.to_list e0) 0 P.`n)
        (slice (Seeds.to_list e0) P.`n (2 * P.`n)) (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n))] = 1%r.
proof. exact (keygen_correct slh_keygen_total). qed.

lemma sign_internal_total :
  forall (s0 : Sig.t) (m ml : W64.t) (k0 : SK.t) (o0 : Node.t) (mem0 : global_mem_t),
  phoare [M.sign_internal :
    sig = s0 /\ msg = m /\ msg_len = ml /\ sk = k0 /\ opt_rand = o0 /\ Glob.mem = mem0 /\
    msg_dom W64.zero m ml ==>
    Sig.to_list res = slh_sign_internal P (m_of mem0 m ml) (SK.to_list k0) (Some (Node.to_list o0))] = 1%r.
proof. exact (sign_internal_correct slh_sign_total). qed.

lemma verify_internal_total :
  forall (s0 : Sig.t) (m ml : W64.t) (p0 : PK.t) (mem0 : global_mem_t),
  phoare [M.verify_internal :
    sig = s0 /\ msg = m /\ msg_len = ml /\ pk = p0 /\ Glob.mem = mem0 /\
    msg_dom W64.zero m ml ==>
    res = if slh_verify_internal P (m_of mem0 m ml) (Sig.to_list s0) (PK.to_list p0)
          then W64.zero else W64.of_int (-1)] = 1%r.
proof. exact (verify_internal_correct slh_verify_total). qed.
