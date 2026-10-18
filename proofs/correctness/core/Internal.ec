(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal.ec
 * ===========
 *
 * The internal functions of src/slhdsa/internal.jinc against FIPS 205
 * section 9: _slh_sign computes slh_sign_internal (Algorithm 19),
 * _slh_verify computes slh_verify_internal (Algorithm 20) and _slh_keygen
 * computes slh_keygen_internal (Algorithm 18).
 *
 * Message. The code receives M in two pieces, prefix[0 : prefix_len] in a
 * stack buffer and msg_len bytes at address msg; slh_msg names their
 * concatenation as the specification sees it. msg_ok is what the message
 * hashes need of the two lengths: the prefix fits its buffer and the
 * message does not wrap the address space.
 *
 * Context. Every tweakable hash is called with the context that
 * _thash_ctx_init derives from PK.seed. Its contents differ between the
 * SHAKE and SHA2 families, so the theorems take the relation as a
 * parameter, ok: _thash_ctx_init returns a context ok for PK.seed (the
 * premise hctx), and the hash premises are those of the FORS and
 * hypertree theorems for every context ok for PK.seed. The proofs fix the
 * context right after its initialisation and use those theorems at it.
 *
 * Signing. Algorithm 19 in the order of the code: R = PRF_msg(SK.prf,
 * opt_rand, M) is copied into the first n bytes of the signature, the
 * digest H_msg(R, PK.seed, PK.root, M) is split by __fors_indices and
 * __digest_tree_leaf (DigestIndices.ec), the address is the spec's
 * address of line 11-13 (zero, tree, type FORS_TREE, key pair), and
 * _fors_sign (ForsSign.ec) and _ht_sign (Hypertree.ec) write SIG_FORS and
 * SIG_HT after R. _ht_sign keeps the first (1 + k (1 + a)) n bytes, which
 * are then exactly R || SIG_FORS. The code takes opt_rand from its caller;
 * Some opt_rand is the hedged variant of the specification, and opt_rand =
 * PK.seed the deterministic one (sign_deterministic).
 *
 * Verification. Algorithm 20 in the order of the code: the digest
 * H_msg(R, PK.seed, PK.root, M) of the signature's R, the same indices and
 * address as signing, PK_FORS from SIG_FORS (ForsPk.ec) and the verdict of
 * _ht_verify (Hypertree.ec) on SIG_HT. The length check of line 1 is the
 * type of sig: Sig.size = sig_length.
 *
 * Key generation. Algorithm 18: seeds = SK.seed || SK.prf || PK.seed is
 * copied into sk[0 : 3n], PK.root is the treehash root of layer d - 1, tree
 * 0 (Xmss.ec), with no target leaf and a zero digit vector, and is copied
 * into sk[3n : 4n] and pk[n : 2n], PK.seed into pk[0 : n].
 *
 * Message hash premises. PRF_msg and H_msg are premises in the shape of
 * the other hash premises: the procedure returns the specification's
 * value on the message slh_msg of the memory it runs in.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorems, all total correctness:
 *     slh_sign_correct     _slh_sign returns slh_sign_internal(M, SK,
 *                          opt_rand).
 *     slh_verify_correct   _slh_verify returns 0 when
 *                          slh_verify_internal(M, SIG, PK) accepts and
 *                          all ones otherwise.
 *     slh_keygen_correct   _slh_keygen returns the SK and PK of
 *                          slh_keygen_internal(SK.seed, SK.prf, PK.seed).
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JMemory JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_WOTS FIPS205_XMSS FIPS205_Hypertree FIPS205_FORS.
require import FIPS205_Internal.
require import MerkleTrees_FIPS205 FIPS205_TreeForms.
require import BArray32 BArray128.
require import SetModel CoreExtracted Encoding WotsPk WotsLeaf TreeFold DigestIndices Hypertree ForsSign.
require Wots XmssPk Xmss ForsPk JWordList.

(* ------------------------------------------------------------------ *)
(* The message and the key fields                                     *)

(* M = prefix[0 : prefix_len] || mem[msg : msg + msg_len]. *)
op slh_msg (mem : global_mem_t) (x : Prefix.t) (pl m ml : W64.t) : bytes =
  take (to_uint pl) (Prefix.to_list x) ++ JWordList.memread mem (to_uint m) (to_uint ml).

op msg_ok (pl m ml : W64.t) : bool =
  to_uint pl <= Prefix.size /\ to_uint m + to_uint ml <= W64.modulus.

lemma sk_size : SK.size = 4 * P.`n by rewrite n_val.
lemma pk_size : PK.size = 2 * P.`n by rewrite n_val.

lemma skn_sub (k : SK.t) o : 0 <= o => o + P.`n <= 4 * P.`n =>
  Node.to_list (SkNode.get_sub k o) = slice (SK.to_list k) o (o + P.`n).
proof.
move=> h0 h1; apply (eq_from_nth W8.zero).
+ rewrite Node.size_to_list /slice size_take 1:/# size_drop // SK.size_to_list; smt(n_val).
rewrite Node.size_to_list => j hj.
rewrite Node.get_to_list SkNode.get8_get_sub ifT // /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite SK.get_to_list.
qed.

lemma skp_sub (k : SK.t) o : 0 <= o => o + 2 * P.`n <= 4 * P.`n =>
  PK.to_list (SkPk.get_sub k o) = slice (SK.to_list k) o (o + 2 * P.`n).
proof.
move=> h0 h1; apply (eq_from_nth W8.zero).
+ rewrite PK.size_to_list /slice size_take 1:/# size_drop // SK.size_to_list; smt(n_val).
rewrite PK.size_to_list => j hj.
rewrite PK.get_to_list SkPk.get8_get_sub ifT // /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite SK.get_to_list.
qed.

lemma sk_seedE (k : SK.t) : Node.to_list (SkNode.get_sub k 0) = sk_seed_of P (SK.to_list k).
proof. have h := skn_sub k 0 _ _; 1,2: smt(n_val). by rewrite h. qed.

lemma sk_prfE (k : SK.t) : Node.to_list (SkNode.get_sub k P.`n) = sk_prf_of P (SK.to_list k).
proof. have h := skn_sub k P.`n _ _; 1,2: smt(n_val). by rewrite h /sk_prf_of; congr; ring. qed.

lemma sk_pkseedE (k : SK.t) : Node.to_list (SkNode.get_sub k (2 * P.`n)) = pk_seed_of P (SK.to_list k).
proof. have h := skn_sub k (2 * P.`n) _ _; 1,2: smt(n_val). by rewrite h /pk_seed_of; congr; ring. qed.

lemma sk_pkE (k : SK.t) : PK.to_list (SkPk.get_sub k (2 * P.`n)) = slice (SK.to_list k) (2 * P.`n) (4 * P.`n).
proof. have h := skp_sub k (2 * P.`n) _ _; 1,2: smt(n_val). by rewrite h; congr; ring. qed.


lemma pk_halves (k : SK.t) :
  slice (PK.to_list (SkPk.get_sub k (2 * P.`n))) 0 P.`n = pk_seed_of P (SK.to_list k) /\
  slice (PK.to_list (SkPk.get_sub k (2 * P.`n))) P.`n (2 * P.`n) = pk_root_of P (SK.to_list k).
proof.
have hn := n_val; rewrite sk_pkE /pk_seed_of /pk_root_of; split.
+ by rewrite ForsPk.slice_slice 1..3:/#; congr; smt().
by rewrite ForsPk.slice_slice 1..3:/#; congr; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Hoare forms of the component theorems, premises in the pre         *)

lemma kp_h (a0 : BArray32.t) (i0 : W32.t) : hoare [M.__adrs_set_keypair : arg = (a0, i0) ==>
  BArray32.to_list res = setKeyPairAddress (BArray32.to_list a0) (to_uint i0)].
proof. by conseq (core_set_keypair a0 i0). qed.

op adrs_ok (a : adrs) : bool = exists l tr y kp w1 w0, a = mk_adrs l tr y kp w1 w0 /\ 0 <= kp < 2 ^ 32.

lemma fors_sign_hh (pk_seed : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk_seed (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk_seed (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk_seed (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  forall (s0 : Sig.t) (i0 : ForsIdx.t) (k0 : Node.t) (a0 : BArray32.t) (md : bytes),
  hoare [M._fors_sign :
    sig = s0 /\ indices = i0 /\ sk_seed = k0 /\ ctx = c0 /\ adrs = a0 /\
    (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i0 j) = nth 0 (base_2b md P.`a P.`k) j) /\
    adrs_ok (BArray32.to_list a0) ==>
    Sig.to_list res.`1 =
      take P.`n (Sig.to_list s0) ++ fors_sign P md (Node.to_list k0) pk_seed (BArray32.to_list a0) ++
      drop (P.`n + P.`k * ((P.`a + 1) * P.`n)) (Sig.to_list s0) /\
    Node.to_list res.`2 =
      fors_pkFromSig P (fors_sign P md (Node.to_list k0) pk_seed (BArray32.to_list a0)) md pk_seed
                     (BArray32.to_list a0)].
proof.
move=> hprf hf hh htk s0 i0 k0 a0 md.
have [hA | hA] : adrs_ok (BArray32.to_list a0) \/ !adrs_ok (BArray32.to_list a0) by rewrite orbN.
+ case: hA => l tr y kp w1 w0 [hA hkp].
  by conseq (fors_sign_correct pk_seed c0 hprf hf hh htk s0 i0 k0 a0 md l tr y kp w1 w0 hA hkp).
by conseq (_ : false ==> _) => // &hr [#] *; apply hA.
qed.

lemma ht_sign_hh (pk : bytes) c0 :
  (forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  forall (s0 : Sig.t) (m0 k0 : Node.t) (it0 : W64.t) (il0 : W32.t),
  hoare [M._ht_sign :
    sig = s0 /\ msg = m0 /\ sk_seed = k0 /\ ctx = c0 /\ idx_tree = it0 /\ idx_leaf = il0 /\
    to_uint il0 < 2 ^ P.`hp ==>
    Sig.to_list res.`1 =
      take ht_off (Sig.to_list s0) ++
      ht_sign P (Node.to_list m0) (Node.to_list k0) pk (to_uint it0) (to_uint il0) /\
    Node.to_list res.`2 =
      xmss_node P (Node.to_list k0) 0 P.`hp pk
        (mk_adrs (P.`d - 1) (ht_tree P (to_uint it0) (P.`d - 1)) 0 0 0 0)].
proof.
move=> hprf hf htl hh s0 m0 k0 it0 il0.
have [hl | hl] : to_uint il0 < 2 ^ P.`hp \/ !(to_uint il0 < 2 ^ P.`hp) by rewrite orbN.
+ by conseq (ht_sign_correct pk c0 hprf hf htl hh s0 m0 k0 it0 il0 hl).
by conseq (_ : false ==> _) => // &hr [#] *; apply hl.
qed.

(* ------------------------------------------------------------------ *)
(* _slh_sign (Algorithm 19)                                           *)

(* The randomizer copy: the first n bytes of the signature are R. *)
lemma take_r (s : Sig.t) (r : Node.t) :
  (forall j, 0 <= j < P.`n => Sig.get8 s j = Node.get8 r j) =>
  take P.`n (Sig.to_list s) = Node.to_list r.
proof.
move=> h; apply (eq_from_nth W8.zero).
+ by rewrite size_take ?Node.size_to_list ?Sig.size_to_list; smt(n_val k_val a_val d_val hp_val).
rewrite size_take; first smt(n_val). rewrite Sig.size_to_list => j hj.
have hj' : 0 <= j < P.`n by smt(n_val k_val a_val d_val hp_val).
by rewrite nth_take 1,2:/# Sig.get_to_list Node.get_to_list h.
qed.

lemma idx_leaf_lt (d : bytes) : (split_digest P d).`3 < 2 ^ P.`hp.
proof.
rewrite /split_digest /= -hp_def; apply ltz_pmod.
by apply StdOrder.IntOrder.expr_gt0.
qed.

lemma sign_adrs (it il : int) : 0 <= il < 2 ^ 32 =>
  adrs_ok (setKeyPairAddress (setTypeAndClear (setTreeAddress (toByte 0 32) it) FORS_TREE) il).
proof.
move=> hil; exists 0 it FORS_TREE il 0 0.
by rewrite mk_adrs0 setTreeAddressE setTypeAndClearE setKeyPairAddressE.
qed.

hint simplify ForsPk.fprotpE, ForsPk.fprot64E, ForsPk.fprot32E.

(* The FORS address of Algorithm 19 lines 11-13. *)
op sA (it il : int) : adrs =
  setKeyPairAddress (setTypeAndClear (setTreeAddress (toByte 0 32) it) FORS_TREE) il.

lemma sA_mk it il : sA it il = mk_adrs 0 it FORS_TREE il 0 0.
proof. by rewrite /sA mk_adrs0 setTreeAddressE setTypeAndClearE setKeyPairAddressE. qed.

lemma sign_internalE (M sk o : bytes) :
  slh_sign_internal P M sk (Some o) =
   let r = PRF_msg P (sk_prf_of P sk) o M in
   let sd = split_digest P (H_msg P r (pk_seed_of P sk) (pk_root_of P sk) M) in
   let fs = fors_sign P sd.`1 (sk_seed_of P sk) (pk_seed_of P sk) (sA sd.`2 sd.`3) in
   r ++ fs ++
   ht_sign P (fors_pkFromSig P fs sd.`1 (pk_seed_of P sk) (sA sd.`2 sd.`3))
     (sk_seed_of P sk) (pk_seed_of P sk) sd.`2 sd.`3.
proof. by rewrite /slh_sign_internal /= /sA; case: (split_digest _ _). qed.

lemma slh_sign_h (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  (forall (k0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prf_msg :
       sk_prf = k0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Node.to_list res.`1 = PRF_msg P (Node.to_list k0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)]
     = 1%r) =>
  (forall (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._h_msg :
       r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Digest.to_list res.`1 =
         H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
           (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r) =>
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (k0 : SK.t) (o0 : Node.t)
         (mem0 : global_mem_t),
  hoare [M._slh_sign :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
    opt_rand = o0 /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Sig.to_list res.`1 =
      slh_sign_internal P (slh_msg mem0 x0 pl m ml) (SK.to_list k0) (Some (Node.to_list o0))].
proof.
move=> hctx hprf hf htl hh htk hpm hhm s0 x0 pl m ml k0 o0 mem0.
proc.
seq 7 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
         opt_rand = o0 /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
         ok (pk_seed_of P (SK.to_list k0)) ctx).
+ call (_ : pk_seed = SkNode.get_sub k0 (2 * P.`n) ==>
             ok (Node.to_list (SkNode.get_sub k0 (2 * P.`n))) res.`1).
  + by conseq (hctx (SkNode.get_sub k0 (2 * P.`n))).
  by auto => /> hmo _ _ c; rewrite sk_pkseedE.
exlim ctx => c0.
have [hok | hok] : ok (pk_seed_of P (SK.to_list k0)) c0 \/ !ok (pk_seed_of P (SK.to_list k0)) c0
  by rewrite orbN.
have hprf' := hprf _ _ hok; have hf' := hf _ _ hok; have htl' := htl _ _ hok.
have hh' := hh _ _ hok; have htk' := htk _ _ hok.
(* R = PRF_msg(SK.prf, opt_rand, M) *)
seq 5 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
         Glob.mem = mem0 /\ msg_ok pl m ml /\ ctx = c0 /\
         Node.to_list r = PRF_msg P (sk_prf_of P (SK.to_list k0)) (Node.to_list o0)
                            (slh_msg mem0 x0 pl m ml)).
+ call (_ : sk_prf = SkNode.get_sub k0 P.`n /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\
            msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
            Node.to_list res.`1 = PRF_msg P (Node.to_list (SkNode.get_sub k0 P.`n)) (Node.to_list o0)
                                    (slh_msg mem0 x0 pl m ml)).
  + by conseq (hpm (SkNode.get_sub k0 P.`n) o0 x0 pl m ml mem0).
  by auto => /> _ _ _ _ r0 ->; rewrite sk_prfE.
(* sig[0 : n] = R *)
seq 6 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
         Glob.mem = mem0 /\ msg_ok pl m ml /\ ctx = c0 /\
         Node.to_list r = PRF_msg P (sk_prf_of P (SK.to_list k0)) (Node.to_list o0)
                            (slh_msg mem0 x0 pl m ml) /\
         take P.`n (Sig.to_list sig) = Node.to_list r).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\
         prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
         Glob.mem = mem0 /\ msg_ok pl m ml /\ ctx = c0 /\
         Node.to_list r = PRF_msg P (sk_prf_of P (SK.to_list k0)) (Node.to_list o0)
                            (slh_msg mem0 x0 pl m ml) /\
         forall j, 0 <= j < 8 * i => Sig.get8 sig j = Node.get8 r j).
  + wp; skip => &m [#] h0 hi hinc 6!-> hmo -> hr hj hlt /=.
    do !(split; first smt()); move=> j [hj0 hj1].
    rewrite Sig.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => hb.
    + have -> /= : 0 <= j && j < Sig.size by smt(n_val k_val a_val d_val hp_val).
      by rewrite Node.get64d_byte /#.
    by rewrite hj /#.
  wp; skip => &m [#] 6!-> hmo -> hr /=; split; first smt(n_val).
  move=> i0 s1 hn [#] h1 h2 h3 h4 _ hj.
  split; [exact h4 | split; [exact hr | ]].
  apply take_r => j hj'; apply hj; have [_ h8] := n_words; smt().
(* digest, indices, idx_tree, idx_leaf *)
exlim r => r1.
seq 5 : (sk = k0 /\ ctx = c0 /\ r = r1 /\
         Node.to_list r1 = PRF_msg P (sk_prf_of P (SK.to_list k0)) (Node.to_list o0)
                             (slh_msg mem0 x0 pl m ml) /\
         take P.`n (Sig.to_list sig) = Node.to_list r1 /\
         Digest.to_list digest = H_msg P (Node.to_list r1) (pk_seed_of P (SK.to_list k0))
                                   (pk_root_of P (SK.to_list k0)) (slh_msg mem0 x0 pl m ml) /\
         (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 indices j) =
            nth 0 (base_2b (split_digest P (Digest.to_list digest)).`1 P.`a P.`k) j) /\
         to_uint idx_tree = (split_digest P (Digest.to_list digest)).`2 /\
         to_uint idx_leaf = (split_digest P (Digest.to_list digest)).`3).
+ ecall (digest_tree_leaf_h digest).
  ecall (fors_indices_h digest).
  wp.
  call (_ : r = r1 /\ pk = SkPk.get_sub k0 (2 * P.`n) /\ prefix = x0 /\ prefix_len = pl /\
            msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
            Digest.to_list res.`1 =
              H_msg P (Node.to_list r1) (slice (PK.to_list (SkPk.get_sub k0 (2 * P.`n))) 0 P.`n)
                (slice (PK.to_list (SkPk.get_sub k0 (2 * P.`n))) P.`n (2 * P.`n))
                (slh_msg mem0 x0 pl m ml)).
  + by conseq (hhm r1 (SkPk.get_sub k0 (2 * P.`n)) x0 pl m ml mem0).
  auto => /> &hr _ _ _ _ _ d0 hd _ _ _ _ _.
  by have [h1 h2] := pk_halves k0; rewrite hd h1 h2.
(* the FORS address *)
seq 6 : (sk = k0 /\ ctx = c0 /\
         take P.`n (Sig.to_list sig) = PRF_msg P (sk_prf_of P (SK.to_list k0)) (Node.to_list o0)
                                        (slh_msg mem0 x0 pl m ml) /\
         Digest.to_list digest =
           H_msg P (PRF_msg P (sk_prf_of P (SK.to_list k0)) (Node.to_list o0) (slh_msg mem0 x0 pl m ml))
             (pk_seed_of P (SK.to_list k0)) (pk_root_of P (SK.to_list k0)) (slh_msg mem0 x0 pl m ml) /\
         (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 indices j) =
            nth 0 (base_2b (split_digest P (Digest.to_list digest)).`1 P.`a P.`k) j) /\
         to_uint idx_tree = (split_digest P (Digest.to_list digest)).`2 /\
         to_uint idx_leaf = (split_digest P (Digest.to_list digest)).`3 /\
         BArray32.to_list adrs = sA (to_uint idx_tree) (to_uint idx_leaf)).
+ ecall (kp_h adrs idx_leaf).
  ecall (tc3_h adrs).
  ecall (tree_h adrs idx_tree).
  ecall (zero_h adrs).
  auto => /> &hr hr1 hs hd hi ht hl a0 -> a1 -> a2 -> a3 ->.
  by rewrite /sA hs hd hr1.
(* SIG_FORS, PK_FORS, SIG_HT *)
ecall (ht_sign_hh (pk_seed_of P (SK.to_list k0)) c0 hprf' hf' htl' hh' sig pk_fors
                  (SkNode.get_sub sk 0) idx_tree idx_leaf).
wp.
inline M.__hook_fors_pk.
wp.
ecall (fors_sign_hh (pk_seed_of P (SK.to_list k0)) c0 hprf' hf' hh' htk' sig indices
                    (SkNode.get_sub sk 0) adrs (split_digest P (Digest.to_list digest)).`1).
skip => &hr [#] -> -> hR hD hI hT hL hA /=.
split.
+ split; first exact hI.
  rewrite hA sA_mk; exists 0 (to_uint idx_tree{hr}) FORS_TREE (to_uint idx_leaf{hr}) 0 0 => /=.
  exact W32.to_uint_cmp.
move=> _ s2 [hs2 hp2]; split.
+ by rewrite hL; apply idx_leaf_lt.
move=> _ s3 [hs3 _].
rewrite hs3 hp2 hs2 sign_internalE /= -hD -hT -hL -hA sk_seedE.
rewrite take_size_cat; last by rewrite hR.
rewrite size_cat size_take; first smt(n_val).
rewrite Sig.size_to_list hA sA_mk size_fsig; first exact W32.to_uint_cmp.
rewrite /ht_off; smt(n_val k_val a_val d_val hp_val).
by conseq (_ : false ==> _) => // &hr [#] *; apply hok; smt().
qed.

(* _slh_sign terminates: every callee does, and the R copy loop runs
   n / 8 times. *)
lemma slh_sign_ll (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  (forall (k0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prf_msg :
       sk_prf = k0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Node.to_list res.`1 = PRF_msg P (Node.to_list k0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)]
     = 1%r) =>
  (forall (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._h_msg :
       r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Digest.to_list res.`1 =
         H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
           (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r) =>
  phoare [M._slh_sign : msg_ok prefix_len msg msg_len ==> true] = 1%r.
proof.
move=> hctx hprf hf htl hh htk hpm hhm.
have hpml : phoare [M._prf_msg : msg_ok prefix_len msg msg_len ==> true] = 1%r.
+ proc*; exlim sk_prf, opt_rand, prefix, prefix_len, msg, msg_len, Glob.mem =>
    k1 o1 x1 pl1 m1 ml1 mem1.
  by call (hpm k1 o1 x1 pl1 m1 ml1 mem1); auto.
have hhml : phoare [M._h_msg : msg_ok prefix_len msg msg_len ==> true] = 1%r.
+ proc*; exlim r, pk, prefix, prefix_len, msg, msg_len, Glob.mem => r1 p1 x1 pl1 m1 ml1 mem1.
  by call (hhm r1 p1 x1 pl1 m1 ml1 mem1); auto.
proc; exlim sk => k0.
seq 7 : (sk = k0 /\ msg_ok prefix_len msg msg_len /\ ok (pk_seed_of P (SK.to_list k0)) ctx)
        1%r 1%r 0%r _ => //.
+ call (_ : pk_seed = SkNode.get_sub k0 (2 * P.`n) ==>
             ok (Node.to_list (SkNode.get_sub k0 (2 * P.`n))) res.`1).
  + by conseq (hctx (SkNode.get_sub k0 (2 * P.`n))).
  by auto => />; rewrite sk_pkseedE.
+ exlim ctx => c0.
  have [hok | hok] : ok (pk_seed_of P (SK.to_list k0)) c0 \/ !ok (pk_seed_of P (SK.to_list k0)) c0
    by rewrite orbN.
  + have hprf' := hprf _ _ hok; have hf' := hf _ _ hok; have htl' := htl _ _ hok.
    have hh' := hh _ _ hok; have htk' := htk _ _ hok.
    have hprfl : phoare [M._thash_prf_x4 : ctx = c0 ==> true] = 1%r.
    + by proc*; exlim sk_seed, adrs => k1 a1; call (hprf' k1 a1); auto.
    have hfl : phoare [M._thash_f_x4 : ctx = c0 ==> true] = 1%r.
    + by proc*; exlim x, adrs => x1 a1; call (hf' x1 a1); auto.
    have hhl : phoare [M._thash_h : ctx = c0 ==> true] = 1%r.
    + by proc*; exlim in_0, adrs => x1 a1; call (hh' x1 a1); auto.
    have htkl : phoare [M._thash_t_k : ctx = c0 ==> true] = 1%r.
    + by proc*; exlim in_0, adrs => x1 a1; call (htk' x1 a1); auto.
    have hxl := Xmss.xmss_treehash_ll _ c0 hprf' hf' htl' hh'.
    call (ht_sign_ll c0 hxl); wp.
    inline M.__hook_fors_pk; wp.
    call (fors_sign_ll c0 hprfl hfl hhl htkl).
    call set_keypair_ll; call set_tc_ll; call set_tree_ll; call adrs_zero_ll; wp.
    call digest_tree_leaf_ll; call fors_indices_ll; wp.
    call hhml; wp.
    while (true) (inc - i); first by auto => /#.
    wp; call hpml; auto => /> /#.
  by exfalso; smt().
hoare; call (_ : pk_seed = SkNode.get_sub k0 (2 * P.`n) ==>
                 ok (Node.to_list (SkNode.get_sub k0 (2 * P.`n))) res.`1).
+ by conseq (hctx (SkNode.get_sub k0 (2 * P.`n))).
by auto => />; rewrite sk_pkseedE.
qed.

(* Total correctness of _slh_sign: slh_sign_ll and slh_sign_h. *)
lemma slh_sign_correct (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  (forall (k0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prf_msg :
       sk_prf = k0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Node.to_list res.`1 = PRF_msg P (Node.to_list k0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)]
     = 1%r) =>
  (forall (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._h_msg :
       r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Digest.to_list res.`1 =
         H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
           (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r) =>
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (k0 : SK.t) (o0 : Node.t)
         (mem0 : global_mem_t),
  phoare [M._slh_sign :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ sk = k0 /\
    opt_rand = o0 /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Sig.to_list res.`1 =
      slh_sign_internal P (slh_msg mem0 x0 pl m ml) (SK.to_list k0) (Some (Node.to_list o0))] = 1%r.
proof.
move=> hctx hprf hf htl hh htk hpm hhm s0 x0 pl m ml k0 o0 mem0.
conseq (slh_sign_ll ok hctx hprf hf htl hh htk hpm hhm)
       (slh_sign_h ok hctx hprf hf htl hh htk hpm hhm s0 x0 pl m ml k0 o0 mem0) => /#.
qed.

(* The deterministic variant (Algorithm 19 line 2) is the hedged one with
   opt_rand = PK.seed: the caller passes sk[2n : 3n] as opt_rand. *)
lemma sign_deterministic (M sk : bytes) :
  slh_sign_internal P M sk None = slh_sign_internal P M sk (Some (pk_seed_of P sk)).
proof. by rewrite /slh_sign_internal. qed.

(* ------------------------------------------------------------------ *)
(* _slh_verify (Algorithm 20)                                         *)

lemma sig_len : Sig.size = sig_length P.
proof. by rewrite /sig_length /len Wots.len1_val Wots.len2_val n_val k_val a_val d_val h_val. qed.

lemma ht_offE : P.`n + P.`k * (P.`a + 1) * P.`n = ht_off by rewrite /ht_off; ring.

(* The fields of a signature and of a public key. *)
lemma sigr_sub (s : Sig.t) : Node.to_list (SigR.get_sub s 0) = slice (Sig.to_list s) 0 P.`n.
proof.
have hn := n_val; have hs := sig_size; have hx := xsl_b; have hd := d_ge1.
have ho : P.`n <= ht_off by rewrite /ht_off k_val a_val n_val.
apply (eq_from_nth W8.zero).
+ rewrite Node.size_to_list /slice size_take 1:/# size_drop // Sig.size_to_list; smt().
rewrite Node.size_to_list => j hj.
rewrite Node.get_to_list SigR.get8_get_sub ifT // /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite Sig.get_to_list.
qed.

lemma sigf_sub (s : Sig.t) :
  ForsSig.to_list (SigFors.get_sub s P.`n) = slice (Sig.to_list s) P.`n ht_off.
proof.
have hn := n_val; have hs := sig_size; have hx := xsl_b; have hd := d_ge1.
have ho : ht_off = P.`n + ForsSig.size by rewrite ForsPk.fsig_size /ht_off; ring.
have hf : 0 < ForsSig.size by rewrite ForsPk.fsig_size k_val a_val n_val.
apply (eq_from_nth W8.zero).
+ rewrite ForsSig.size_to_list /slice size_take 1:/# size_drop 1:/# Sig.size_to_list; smt().
rewrite ForsSig.size_to_list => j hj.
rewrite ForsSig.get_to_list SigFors.get8_get_sub ifT // /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite Sig.get_to_list.
qed.

lemma sigh_sub (s : Sig.t) :
  HtSig.to_list (SigHt.get_sub s ht_off) = slice (Sig.to_list s) ht_off (sig_length P).
proof.
have hn := n_val; have hs := sig_size; have hx := xsl_b; have hd := d_ge1.
have hh := htsig_size; have hl := sig_len.
have ho : 0 <= ht_off by rewrite /ht_off k_val a_val n_val.
apply (eq_from_nth W8.zero).
+ rewrite HtSig.size_to_list /slice size_take 1:/# size_drop 1:/# Sig.size_to_list; smt().
rewrite HtSig.size_to_list => j hj.
rewrite HtSig.get_to_list SigHt.get8_get_sub ifT // /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite Sig.get_to_list.
qed.

lemma pkn_sub (p : PK.t) o : 0 <= o => o + P.`n <= 2 * P.`n =>
  Node.to_list (PkNode.get_sub p o) = slice (PK.to_list p) o (o + P.`n).
proof.
move=> h0 h1; apply (eq_from_nth W8.zero).
+ rewrite Node.size_to_list /slice size_take 1:/# size_drop // PK.size_to_list; smt(n_val).
rewrite Node.size_to_list => j hj.
rewrite Node.get_to_list PkNode.get8_get_sub ifT // /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite PK.get_to_list.
qed.

lemma pk_seedE (p : PK.t) : Node.to_list (PkNode.get_sub p 0) = slice (PK.to_list p) 0 P.`n.
proof. by have h := pkn_sub p 0 _ _; 1,2: smt(n_val). qed.

lemma pk_rootE (p : PK.t) :
  Node.to_list (PkNode.get_sub p P.`n) = slice (PK.to_list p) P.`n (2 * P.`n).
proof. have h := pkn_sub p P.`n _ _; 1,2: smt(n_val). by rewrite h; congr; ring. qed.

lemma verify_internalE (M s pk : bytes) : size s = sig_length P =>
  slh_verify_internal P M s pk =
   let sd = split_digest P (H_msg P (slice s 0 P.`n) (slice pk 0 P.`n) (slice pk P.`n (2 * P.`n)) M) in
   ht_verify P (fors_pkFromSig P (slice s P.`n ht_off) sd.`1 (slice pk 0 P.`n) (sA sd.`2 sd.`3))
     (slice s ht_off (sig_length P)) (slice pk 0 P.`n) sd.`2 sd.`3 (slice pk P.`n (2 * P.`n)).
proof. by move=> hs; rewrite /slh_verify_internal hs /= /sA /ht_off; case: (split_digest _ _). qed.

lemma slh_verify_h (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_len : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list m0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  (forall (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._h_msg :
       r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Digest.to_list res.`1 =
         H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
           (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r) =>
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (p0 : PK.t) (mem0 : global_mem_t),
  hoare [M._slh_verify :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ pk = p0 /\
    Glob.mem = mem0 /\ msg_ok pl m ml ==>
    res.`1 = if slh_verify_internal P (slh_msg mem0 x0 pl m ml) (Sig.to_list s0) (PK.to_list p0)
             then W64.zero else W64.of_int (-1)].
proof.
move=> hctx hf htl hh htk hhm s0 x0 pl m ml p0 mem0.
proc.
seq 6 : (sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ pk = p0 /\
         Glob.mem = mem0 /\ msg_ok pl m ml /\ ok (slice (PK.to_list p0) 0 P.`n) ctx).
+ call (_ : pk_seed = PkNode.get_sub p0 0 ==> ok (Node.to_list (PkNode.get_sub p0 0)) res.`1).
  + by conseq (hctx (PkNode.get_sub p0 0)).
  by auto => />; rewrite pk_seedE.
exlim ctx => c0.
have [hok | hok] : ok (slice (PK.to_list p0) 0 P.`n) c0 \/ !ok (slice (PK.to_list p0) 0 P.`n) c0
  by rewrite orbN.
+ have hf' := hf _ _ hok; have htl' := htl _ _ hok; have hh' := hh _ _ hok; have htk' := htk _ _ hok.
  have hfp : forall (s1 : ForsSig.t) (i1 : ForsIdx.t) (a1 : BArray32.t) (md : bytes),
    hoare [M._fors_pk_from_sig :
      sig = s1 /\ indices = i1 /\ ctx = c0 /\ adrs = a1 /\
      (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 i1 j) = nth 0 (base_2b md P.`a P.`k) j) ==>
      Node.to_list res.`1 =
        fors_pkFromSig P (ForsSig.to_list s1) md (slice (PK.to_list p0) 0 P.`n)
          (BArray32.to_list a1)].
  + by move=> s1 i1 a1 md; conseq (ForsPk.fors_pk_from_sig_correct _ c0 hf' hh' htk' s1 i1 a1 md).
  have hhv : forall (s1 : HtSig.t) (m1 r1 : Node.t) (it1 : W64.t) (il1 : W32.t),
    hoare [M._ht_verify :
      sig = s1 /\ msg = m1 /\ pk_root = r1 /\ ctx = c0 /\ idx_tree = it1 /\ idx_leaf = il1 ==>
      res.`1 = if ht_verify P (Node.to_list m1) (HtSig.to_list s1) (slice (PK.to_list p0) 0 P.`n)
                            (to_uint it1) (to_uint il1) (Node.to_list r1)
               then W64.zero else W64.of_int (-1)].
  + by move=> s1 m1 r1 it1 il1; conseq (ht_verify_correct _ c0 hf' htl' hh' s1 m1 r1 it1 il1).
  (* digest = H_msg(R, PK.seed, PK.root, M) *)
  seq 6 : (sig = s0 /\ pk = p0 /\ ctx = c0 /\
           Digest.to_list digest =
             H_msg P (slice (Sig.to_list s0) 0 P.`n) (slice (PK.to_list p0) 0 P.`n)
               (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)).
  + wp; call (_ : r = SigR.get_sub s0 0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\
                  msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
                  Digest.to_list res.`1 =
                    H_msg P (Node.to_list (SigR.get_sub s0 0)) (slice (PK.to_list p0) 0 P.`n)
                      (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)).
    + by conseq (hhm (SigR.get_sub s0 0) p0 x0 pl m ml mem0).
    by auto => />; rewrite sigr_sub.
  (* indices, idx_tree, idx_leaf and the FORS address *)
  seq 8 : (sig = s0 /\ pk = p0 /\ ctx = c0 /\
           Digest.to_list digest =
             H_msg P (slice (Sig.to_list s0) 0 P.`n) (slice (PK.to_list p0) 0 P.`n)
               (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml) /\
           (forall j, 0 <= j < P.`k => to_uint (ForsIdx.get32 indices j) =
              nth 0 (base_2b (split_digest P (Digest.to_list digest)).`1 P.`a P.`k) j) /\
           to_uint idx_tree = (split_digest P (Digest.to_list digest)).`2 /\
           to_uint idx_leaf = (split_digest P (Digest.to_list digest)).`3 /\
           BArray32.to_list adrs = sA (to_uint idx_tree) (to_uint idx_leaf)).
  + ecall (kp_h adrs idx_leaf).
    ecall (tc3_h adrs).
    ecall (tree_h adrs idx_tree).
    ecall (zero_h adrs).
    wp.
    ecall (digest_tree_leaf_h digest).
    ecall (fors_indices_h digest).
    auto => /> &hr hd i hi t ht hl a0 -> a1 -> a2 -> a3 ->.
    by rewrite /sA.
  (* PK_FORS, then the hypertree verdict *)
  ecall (hhv (SigHt.get_sub sig (P.`n + P.`k * (P.`a + 1) * P.`n)) pk_fors
             (PkNode.get_sub pk P.`n) idx_tree idx_leaf).
  wp.
  ecall (hfp (SigFors.get_sub sig P.`n) indices adrs (split_digest P (Digest.to_list digest)).`1).
  skip => &hr [#] -> -> -> hD hI hT hL hA /=.
  split; first by split; [rewrite n_val | exact hI].
  move=> _ pf hpf; split; first by rewrite n_val k_val a_val.
  move=> _ v ->.
  rewrite verify_internalE; first by rewrite Sig.size_to_list; exact sig_len.
  by rewrite /= ht_offE sigh_sub pk_rootE hpf sigf_sub hA -hD -hT -hL.
by conseq (_ : false ==> _) => // &hr [#] *; apply hok; smt().
qed.

(* _slh_verify terminates. *)
lemma slh_verify_ll (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_len : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list m0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  (forall (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._h_msg :
       r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Digest.to_list res.`1 =
         H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
           (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r) =>
  phoare [M._slh_verify : msg_ok prefix_len msg msg_len ==> true] = 1%r.
proof.
move=> hctx hf htl hh htk hhm.
have hhml : phoare [M._h_msg : msg_ok prefix_len msg msg_len ==> true] = 1%r.
+ proc*; exlim r, pk, prefix, prefix_len, msg, msg_len, Glob.mem => r1 p1 x1 pl1 m1 ml1 mem1.
  by call (hhm r1 p1 x1 pl1 m1 ml1 mem1); auto.
proc; exlim pk => p0.
seq 6 : (pk = p0 /\ msg_ok prefix_len msg msg_len /\ ok (slice (PK.to_list p0) 0 P.`n) ctx)
        1%r 1%r 0%r _ => //.
+ call (_ : pk_seed = PkNode.get_sub p0 0 ==> ok (Node.to_list (PkNode.get_sub p0 0)) res.`1).
  + by conseq (hctx (PkNode.get_sub p0 0)).
  by auto => />; rewrite pk_seedE.
+ exlim ctx => c0.
  have [hok | hok] : ok (slice (PK.to_list p0) 0 P.`n) c0 \/ !ok (slice (PK.to_list p0) 0 P.`n) c0
    by rewrite orbN.
  + have hf' := hf _ _ hok; have htl' := htl _ _ hok; have hh' := hh _ _ hok.
    have htk' := htk _ _ hok.
    have hpl := XmssPk.xmss_pk_from_sig_ll _ c0 hf' htl' hh'.
    call (ht_verify_ll c0 hpl); wp.
    call (ForsPk.fors_pk_from_sig_ll _ c0 hf' hh' htk').
    call set_keypair_ll; call set_tc_ll; call set_tree_ll; call adrs_zero_ll; wp.
    call digest_tree_leaf_ll; call fors_indices_ll; wp.
    by call hhml; auto => /> /#.
  by exfalso; smt().
hoare; call (_ : pk_seed = PkNode.get_sub p0 0 ==> ok (Node.to_list (PkNode.get_sub p0 0)) res.`1).
+ by conseq (hctx (PkNode.get_sub p0 0)).
by auto => />; rewrite pk_seedE.
qed.

(* Total correctness of _slh_verify: slh_verify_ll and slh_verify_h. *)
lemma slh_verify_correct (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_len : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TLenIn.to_list m0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TKIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_k : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk (BArray32.to_list a0) (TKIn.to_list m0)] = 1%r) =>
  (forall (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._h_msg :
       r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
       msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
       Digest.to_list res.`1 =
         H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
           (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r) =>
  forall (s0 : Sig.t) (x0 : Prefix.t) (pl m ml : W64.t) (p0 : PK.t) (mem0 : global_mem_t),
  phoare [M._slh_verify :
    sig = s0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ pk = p0 /\
    Glob.mem = mem0 /\ msg_ok pl m ml ==>
    res.`1 = if slh_verify_internal P (slh_msg mem0 x0 pl m ml) (Sig.to_list s0) (PK.to_list p0)
             then W64.zero else W64.of_int (-1)] = 1%r.
proof.
move=> hctx hf htl hh htk hhm s0 x0 pl m ml p0 mem0.
conseq (slh_verify_ll ok hctx hf htl hh htk hhm)
       (slh_verify_h ok hctx hf htl hh htk hhm s0 x0 pl m ml p0 mem0) => /#.
qed.

(* ------------------------------------------------------------------ *)
(* _slh_keygen (Algorithm 18)                                         *)

(* After the seed copy, sk[0 : 3n] = seeds. *)
op seeds_in (k : SK.t) (e : Seeds.t) : bool =
  forall j, 0 <= j < 3 * P.`n => SK.get8 k j = Seeds.get8 e j.

lemma seeds_sub (k : SK.t) (e : Seeds.t) o : seeds_in k e => 0 <= o => o + P.`n <= 3 * P.`n =>
  Node.to_list (SkNode.get_sub k o) = slice (Seeds.to_list e) o (o + P.`n).
proof.
move=> he h0 h1; apply (eq_from_nth W8.zero).
+ rewrite Node.size_to_list /slice size_take 1:/# size_drop // Seeds.size_to_list; smt(n_val).
rewrite Node.size_to_list => j hj.
rewrite Node.get_to_list SkNode.get8_get_sub ifT // he 1:/# /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite Seeds.get_to_list.
qed.

lemma seeds_take (k : SK.t) (e : Seeds.t) : seeds_in k e =>
  take (3 * P.`n) (SK.to_list k) = Seeds.to_list e.
proof.
move=> he; have hn := n_val; apply (eq_from_nth W8.zero).
+ by rewrite size_take 1:/# SK.size_to_list Seeds.size_to_list /#.
rewrite size_take 1:/# SK.size_to_list => j hj.
have hj' : 0 <= j < 3 * P.`n by smt().
by rewrite nth_take 1,2:/# SK.get_to_list Seeds.get_to_list he.
qed.

lemma sk_set_root (k : SK.t) (v : Node.t) :
  SK.to_list (SkNode.set_sub k (3 * P.`n) v) = take (3 * P.`n) (SK.to_list k) ++ Node.to_list v.
proof.
have hn := n_val; have hs : size (take (3 * P.`n) (SK.to_list k)) = 3 * P.`n.
+ by rewrite size_take 1:/# SK.size_to_list /#.
apply (eq_from_nth W8.zero).
+ by rewrite size_cat hs SK.size_to_list Node.size_to_list /#.
rewrite SK.size_to_list => j hj.
rewrite SK.get_to_list SkNode.get8_set_sub nth_cat hs.
case: (j < 3 * P.`n) => hj3.
+ by rewrite ifF 1:/# nth_take 1,2:/# SK.get_to_list.
by rewrite ifT 1:/# Node.get_to_list.
qed.

lemma pk_set (p : PK.t) (a b : Node.t) :
  PK.to_list (PkNode.set_sub (PkNode.set_sub p 0 a) P.`n b) = Node.to_list a ++ Node.to_list b.
proof.
have hn := n_val; apply (eq_from_nth W8.zero).
+ by rewrite size_cat PK.size_to_list !Node.size_to_list /#.
rewrite PK.size_to_list => j hj.
rewrite PK.get_to_list PkNode.get8_set_sub nth_cat Node.size_to_list.
case: (j < P.`n) => hjn.
+ by rewrite ifF 1:/# PkNode.get8_set_sub ifT 1:/# ifT 1:/# Node.get_to_list.
by rewrite ifT 1:/# ifF 1:/# Node.get_to_list /#.
qed.

lemma keygen_internalE (e : bytes) : size e = 3 * P.`n =>
  slh_keygen_internal P (slice e 0 P.`n) (slice e P.`n (2 * P.`n)) (slice e (2 * P.`n) (3 * P.`n)) =
  let r = xmss_node P (slice e 0 P.`n) 0 P.`hp (slice e (2 * P.`n) (3 * P.`n))
            (setLayerAddress (toByte 0 32) (P.`d - 1)) in
  (e ++ r, slice e (2 * P.`n) (3 * P.`n) ++ r).
proof.
move=> he; have hn := n_val.
have h3 : (slice e 0 P.`n ++ slice e P.`n (2 * P.`n)) ++ slice e (2 * P.`n) (3 * P.`n) = e.
+ rewrite ForsPk.slice_cat2 1,2:/# ForsPk.slice_cat2 1,2:/#.
  by rewrite -he slice_whole.
by rewrite /slh_keygen_internal /= h3.
qed.

lemma slh_keygen_h (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  forall (e0 : Seeds.t),
  hoare [M._slh_keygen : seeds = e0 ==>
    (SK.to_list res.`2, PK.to_list res.`1) =
      slh_keygen_internal P (slice (Seeds.to_list e0) 0 P.`n)
        (slice (Seeds.to_list e0) P.`n (2 * P.`n)) (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n))].
proof.
move=> hctx hprf hf htl hh e0.
have hn := n_val; have [_ hws] := Wots.wots_sizes.
have hlen : len P = 2 * P.`n + 3 by rewrite /len Wots.len1_val Wots.len2_val.
proc.
(* sk[0 : 3n] = seeds *)
seq 8 : (seeds = e0 /\ seeds_in sk e0).
+ while (0 <= i <= inc /\ inc = 3 * P.`n %/ 8 /\ seeds = e0 /\
         forall j, 0 <= j < 8 * i => SK.get8 sk j = Seeds.get8 e0 j).
  + wp; skip => &m [#] h0 hi hinc he hj hlt /=.
    do !(split; first smt()); move=> j [hj0 hj1].
    rewrite SK.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => hb.
    + have -> /= : 0 <= j && j < SK.size by smt().
      by rewrite he Seeds.get64d_byte /#.
    by rewrite hj /#.
  wp; skip => &m -> /=; split; first smt().
  by move=> i0 s1 hn0 [#] h1 h2 h3 hj; rewrite /seeds_in => j hj'; apply hj; smt().
(* no_steps = 0 *)
seq 4 : (seeds = e0 /\ seeds_in sk e0 /\
         forall j, 0 <= j < len P => WotsDigits.get8 no_steps j = W8.zero).
+ while (0 <= i <= inc /\ inc = len P /\ t = W64.of_int 0 /\ seeds = e0 /\ seeds_in sk e0 /\
         forall j, 0 <= j < i => WotsDigits.get8 no_steps j = W8.zero).
  + wp; skip => &m [#] h0 hi hinc ht he hs hz hlt /=.
    do !(split; first smt()); move=> j [hj0 hj1].
    rewrite WotsDigits.get_setE; first smt(Wots.len1_val Wots.len2_val).
    case: (j = i{m}) => hji; first by rewrite ht /truncateu8.
    by apply hz; smt().
  wp; skip => &m [#] -> he /=; split; first by rewrite /len Wots.len1_val Wots.len2_val /#.
  by move=> i0 s1 hn0 [#] h1 h2 h3 hs hz; split => // j hj; apply hz; smt().
(* ctx *)
exlim sk => k1.
seq 1 : (seeds = e0 /\ sk = k1 /\ seeds_in k1 e0 /\
         (forall j, 0 <= j < len P => WotsDigits.get8 no_steps j = W8.zero) /\
         ok (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n)) ctx).
+ call (_ : pk_seed = SkNode.get_sub k1 (2 * P.`n) ==>
             ok (Node.to_list (SkNode.get_sub k1 (2 * P.`n))) res.`1).
  + by conseq (hctx (SkNode.get_sub k1 (2 * P.`n))).
  auto => /> &hr he hz c.
  by have -> := seeds_sub k1 e0 (2 * P.`n) he _ _; 1,2: smt().
exlim ctx => c0.
have [hok | hok] : ok (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n)) c0 \/
                   !ok (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n)) c0 by rewrite orbN.
+ have hprf' := hprf _ _ hok; have hf' := hf _ _ hok; have htl' := htl _ _ hok.
  have hh' := hh _ _ hok.
  have hx : forall (r1 : Node.t) (s1 : XmssSig.t) (k2 : Node.t) (a1 : BArray32.t) (tg1 : W32.t)
                   (st1 : WotsDigits.t),
    hoare [M._xmss_treehash :
      root = r1 /\ sig = s1 /\ sk_seed = k2 /\ ctx = c0 /\ adrs = a1 /\ target = tg1 /\
      steps = st1 /\
      (forall i, 0 <= i < len P => nth 0 (map W8.to_uint (WotsDigits.to_list st1)) i < 16) ==>
      Node.to_list res.`1 =
        xmss_node P (Node.to_list k2) 0 P.`hp (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n))
          (BArray32.to_list a1) /\
      (2 ^ P.`hp <= to_uint tg1 => res.`2 = s1)].
  + by move=> r1 s1 k2 a1 tg1 st1; conseq (Xmss.xmss_node_correct _ c0 hprf' hf' htl' hh' r1 s1 k2 a1 tg1 st1).
  wp; ecall (node_copy_h root).
  wp; ecall (node_copy_h (SkNode.get_sub sk (2 * P.`n))).
  wp; ecall (node_copy_h root).
  wp; ecall (hx root no_sig (SkNode.get_sub sk 0) adrs target no_steps).
  wp; ecall (layer_h adrs layer).
  wp; ecall (zero_h adrs).
  wp; skip => &hr [#] hc0 _ -> he hz hc /=.
  move=> a0 ha0 a1 ha1; split.
  + split; first by rewrite hc0.
    move=> i hi; rewrite (nth_map W8.zero); first by rewrite WotsDigits.size_to_list /max /=; smt().
    by rewrite WotsDigits.get_to_list hz.
  move=> _ rt [hrt _] c1 ->; split; first by rewrite n_val.
  move=> _ c2 -> c3 ->.
  have h1 := sk_set_root k1 rt.`1.
  have h2 := skn_sub (SkNode.set_sub k1 (3 * P.`n) rt.`1) (2 * P.`n) _ _; 1,2: smt().
  have h3 := pk_set pk{hr} (SkNode.get_sub (SkNode.set_sub k1 (3 * P.`n) rt.`1) (2 * P.`n)) rt.`1.
  have h4 := seeds_take _ _ he.
  have h5 := seeds_sub _ _ 0 he _ _; 1,2: smt().
  have h6 := keygen_internalE (Seeds.to_list e0) _; first by rewrite Seeds.size_to_list /#.
  move: h1 h2 h3 h4 h5 h6 hrt ha1 ha0; rewrite n_val d_val /= => h1 h2 h3 h4 h5 h6 hrt ha1 ha0.
  rewrite h3 h2 h1 h4 slice_cat_l; first by rewrite Seeds.size_to_list /max.
  by rewrite h6 hrt ha1 ha0 h5.
by conseq (_ : false ==> _) => // &hr [#] *; apply hok; smt().
qed.

(* _slh_keygen terminates. *)
lemma slh_keygen_ll (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  phoare [M._slh_keygen : true ==> true] = 1%r.
proof.
move=> hctx hprf hf htl hh.
proc.
seq 12 : true 1%r 1%r 0%r _ => //.
+ while (true) (inc - i); first by auto => /#.
  wp; while (true) (inc - i); first by auto => /#.
  by auto => /#.
exlim sk => k1.
seq 1 : (sk = k1 /\ ok (Node.to_list (SkNode.get_sub k1 (2 * P.`n))) ctx) 1%r 1%r 0%r _ => //.
+ call (_ : pk_seed = SkNode.get_sub k1 (2 * P.`n) ==>
             ok (Node.to_list (SkNode.get_sub k1 (2 * P.`n))) res.`1).
  + by conseq (hctx (SkNode.get_sub k1 (2 * P.`n))).
  by auto.
+ exlim ctx => c0.
  have [hok | hok] : ok (Node.to_list (SkNode.get_sub k1 (2 * P.`n))) c0 \/
                     !ok (Node.to_list (SkNode.get_sub k1 (2 * P.`n))) c0 by rewrite orbN.
  + have hprf' := hprf _ _ hok; have hf' := hf _ _ hok; have htl' := htl _ _ hok.
    have hh' := hh _ _ hok.
    have hxl := Xmss.xmss_treehash_ll _ c0 hprf' hf' htl' hh'.
    wp; call node_copy_ll; wp; call node_copy_ll; wp; call node_copy_ll; wp.
    call hxl; wp; call set_layer_ll; wp; call adrs_zero_ll.
    by auto => /#.
  by exfalso; smt().
hoare; call (_ : pk_seed = SkNode.get_sub k1 (2 * P.`n) ==>
                 ok (Node.to_list (SkNode.get_sub k1 (2 * P.`n))) res.`1).
+ by conseq (hctx (SkNode.get_sub k1 (2 * P.`n))).
by auto.
qed.

(* Total correctness of _slh_keygen: slh_keygen_ll and slh_keygen_h. *)
lemma slh_keygen_correct (ok : bytes -> Ctx.t -> bool) :
  (forall (p0 : Node.t),
     phoare [M._thash_ctx_init : pk_seed = p0 ==> ok (Node.to_list p0) res.`1] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (k0 : Node.t) (a0 : BArray128.t),
     phoare [M._thash_prf_x4 : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         PRF P pk (Node.to_list k0) (lane 32 k (BArray128.to_list a0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node4.t) (a0 : BArray128.t),
     phoare [M._thash_f_x4 : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         F P pk (lane 32 k (BArray128.to_list a0)) (lane P.`n k (Node4.to_list x0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (m0 : TLenIn4.t) (a0 : BArray128.t),
     phoare [M._thash_t_len_x4 : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       forall k, 0 <= k < 4 => lane P.`n k (Node4.to_list res.`1) =
         T_l P pk (lane 32 k (BArray128.to_list a0))
             (lane (len P * P.`n) k (TLenIn4.to_list m0))] = 1%r) =>
  (forall pk c0, ok pk c0 => forall (x0 : Node2.t) (a0 : BArray32.t),
     phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = H P pk (BArray32.to_list a0) (Node2.to_list x0)] = 1%r) =>
  forall (e0 : Seeds.t),
  phoare [M._slh_keygen : seeds = e0 ==>
    (SK.to_list res.`2, PK.to_list res.`1) =
      slh_keygen_internal P (slice (Seeds.to_list e0) 0 P.`n)
        (slice (Seeds.to_list e0) P.`n (2 * P.`n)) (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n))] = 1%r.
proof.
move=> hctx hprf hf htl hh e0.
by conseq (slh_keygen_ll ok hctx hprf hf htl hh) (slh_keygen_h ok hctx hprf hf htl hh e0).
qed.
