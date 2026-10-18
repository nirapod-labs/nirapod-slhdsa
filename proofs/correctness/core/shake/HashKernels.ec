(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * HashKernels.ec (SHAKE sets)
 * ===========================
 *
 * The hash kernels of a SHAKE set's model, and the tweakable hashes of
 * Thash.ec with their premise discharged.
 *
 * The model of a parameter set (CoreExtracted) is the whole compilation
 * unit, so it carries its own copy of every hash kernel it calls. That
 * copy is extracted from the same source, under the same kernel roots, as
 * the pair's hash model (HashExtracted), on which correctness/hash/ proves
 * the kernels. Each kernel theorem is moved to the set's copy by an
 * equivalence of the two procedures (proc; sim: the bodies are the same
 * program) and the theorem of the pair's kernel: Keccakf1600_Pair for
 * Keccak-f[1600], and Sponge.ec, applied to it, for the absorbing of a
 * message from memory.
 *
 * Thash.ec proves F, PRF, H, T_len, T_k, the prefix absorb and the SHAKE
 * finalisation under the premise that the set's _keccakf1600 computes
 * keccak_f1600_op; each theorem below is the theorem of the same name
 * there applied to keccakf1600_total, and has no premise.
 *
 * Context. _thash_ctx_init of the SHAKE sets copies PK.seed into the
 * context: the context of every tweakable hash is PK.seed itself
 * (thash_ctx_init_correct).
 *
 * Theorems (total correctness, every input):
 *     keccakf1600_total         _keccakf1600 computes keccak_f1600_op;
 *     keccak_absorb_mem_total   _keccak_absorb_mem absorbs the bytes it
 *                               reads from memory (the absorbing state of
 *                               ShakeSponge.ec);
 *     thash_ctx_init_correct    _thash_ctx_init returns PK.seed;
 *     thash_f_total, thash_prf_total, thash_h_total, thash_t_len_total,
 *     thash_t_k_total           F, PRF, H, T_len and T_k (Thash.ec);
 *     shake_absorb_prefix_total, keccak_finalize_total
 *                               the prefix absorb and the finalisation
 *                               of the message hashes (Thash.ec).
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JMemory.
require import Bytes FIPS205_Params FIPS205_Hash FIPS202_Bytes.
require import BArray32 BArray200 BArray332 KeccakState Keccakf1600_Spec Keccak1600_Spec.
require import JWordList ShakeSponge SetModel CoreExtracted.
require HashExtracted Keccakf1600_Pair Sponge Thash.

(* ------------------------------------------------------------------ *)
(* The kernels of the set's model                                     *)

lemma keccakf1600_total (s0 : BArray200.t) :
  phoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._keccakf1600(st{m}, ms{m}) @ &m : lanes res.`1 = keccak_f1600_op (lanes s0)] =
          Pr[HashExtracted.M._keccakf1600(s0, ms{m}) @ &m : lanes res.`1 = keccak_f1600_op (lanes s0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (Keccakf1600_Pair.keccakf1600_total s0).
qed.

lemma keccak_absorb_mem_total (r8 : int) (m0 : W8.t list) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._keccak_absorb_mem :
    Glob.mem = mem0 /\ absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 < 200
    /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0
    /\ absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint l0)) res.`1 res.`2] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._keccak_absorb_mem(st{m}, pos{m}, rate{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               Glob.mem = mem0 /\ absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint l0)) res.`1 res.`2] =
          Pr[HashExtracted.M._keccak_absorb_mem(st{m}, pos{m}, rate{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               Glob.mem = mem0 /\ absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint l0)) res.`1 res.`2].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
byphoare (Sponge.keccak_absorb_mem_total Keccakf1600_Pair.keccakf1600_correct Keccakf1600_Pair.keccakf1600_ll
            r8 m0 mem0 p0 l0) => //.
qed.

lemma keccakf1600_ll : islossless M._keccakf1600.
proof. by proc*; exlim st => s0; call (keccakf1600_total s0); auto. qed.

lemma keccak_absorb_mem_ll :
  phoare [M._keccak_absorb_mem : to_uint pos < to_uint rate ==> true] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._keccak_absorb_mem(st{m}, pos{m}, rate{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._keccak_absorb_mem(st{m}, pos{m}, rate{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (Sponge.keccak_absorb_mem_ll Keccakf1600_Pair.keccakf1600_correct Keccakf1600_Pair.keccakf1600_ll).
qed.

lemma keccak_finalize_ll : islossless M._keccak_finalize.
proof. by proc; call keccakf1600_ll; auto. qed.

(* The prefix absorb keeps the sponge position inside the block. *)
lemma shake_absorb_prefix_pos :
  phoare [M._shake_absorb_prefix : to_uint pos < 136 ==> to_uint res.`2 < 136] = 1%r.
proof.
proc; wp.
while (to_uint pos < 136 /\ (more <=> to_uint i < to_uint len) /\ to_uint i <= to_uint len)
      (to_uint len - to_uint i).
+ move=> z.
  sp; if.
  + wp; call keccakf1600_ll; wp; skip => &m [] [p0 s0 m0] [#] _ _ _ _ _ _ hp hmore h1 hm hz hf r /=.
    have hlt : to_uint i{m} < to_uint len{m} by rewrite -hmore.
    have hi := Thash.w64_inc_bound i{m} (to_uint len{m}) hlt _; first by case: (W64.to_uint_cmp len{m}).
    rewrite /protect_64 /= W64.ultE hi.
    by move: hlt hz; pose u := to_uint i{m}; pose v := to_uint len{m}; smt().
  wp; skip => &m [] [p0 s0 m0] [#] e1 e2 e3 e4 e5 e6 hp hmore h1 hm hz hf /=.
  have hlt : to_uint i{m} < to_uint len{m} by rewrite -hmore.
  have hi := Thash.w64_inc_bound i{m} (to_uint len{m}) hlt _; first by case: (W64.to_uint_cmp len{m}).
  rewrite W64.ultE hi.
  have hq : to_uint pos{m} < 136.
  + have hp1 := Thash.w64_inc_bound p0 136 hp _; first done.
    have h136 : to_uint (W64.of_int 136) = 136 by rewrite W64.of_uintK.
    by smt(W64.to_uint_eq).
  by move: hlt hz; pose u := to_uint i{m}; pose v := to_uint len{m}; smt().
wp; skip => &m /= hp; split.
+ by rewrite hp W64.ultE /=; case: (W64.to_uint_cmp len{m}).
by move=> i1 l1 m1 p1; pose u := to_uint i1; pose v := to_uint l1; smt().
qed.

(* ------------------------------------------------------------------ *)
(* The context                                                        *)

lemma thash_ctx_init_h (p0 : Node.t) :
  hoare [M._thash_ctx_init : pk_seed = p0 ==> Node.to_list res.`1 = Node.to_list p0].
proof.
proc; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ pk_seed = p0 /\
             forall j, 0 <= j < 8 * i => nth W8.zero (Node.to_list ctx) j = nth W8.zero (Node.to_list p0) j).
+ wp; skip => &m [#] h0 h1 hinc hp hj hlt; do !(split; first smt()); move=> j hj'.
  rewrite Node.get_to_list Node.get8_set64dE; have hn := n_val.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
  + by rewrite ifT 1:/# hp Node.get64d_byte 1:/# -Node.get_to_list; congr; smt().
  by rewrite ifF 1:/# -Node.get_to_list hj 1:/#.
wp; skip => /> &m; split; first smt(n_val).
move=> c0 i0 h0 h1 h2 h3 h4; apply (eq_from_nth W8.zero); first by rewrite !Node.size_to_list.
by rewrite Node.size_to_list => j hj; rewrite !Node.get_to_list; apply h4; smt(n_val).
qed.

lemma thash_ctx_init_ll : islossless M._thash_ctx_init.
proof. by proc; while true (inc - i); auto => /#. qed.

lemma thash_ctx_init_correct (p0 : Node.t) :
  phoare [M._thash_ctx_init : pk_seed = p0 ==> Node.to_list res.`1 = Node.to_list p0] = 1%r.
proof. by conseq thash_ctx_init_ll (thash_ctx_init_h p0). qed.

(* ------------------------------------------------------------------ *)
(* The tweakable hashes and the message absorb, no premise left       *)

lemma thash_f_total (x0 c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = F P (Node.to_list c0) (BArray32.to_list a0) (Node.to_list x0)] = 1%r.
proof. exact (Thash.thash_f_correct keccakf1600_total x0 c0 a0). qed.

lemma thash_prf_total (k0 c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_prf : sk_seed = k0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = PRF P (Node.to_list c0) (Node.to_list k0) (BArray32.to_list a0)] = 1%r.
proof. exact (Thash.thash_prf_correct keccakf1600_total k0 c0 a0). qed.

lemma thash_h_total (x0 : Node2.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_h : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = H P (Node.to_list c0) (BArray32.to_list a0) (Node2.to_list x0)] = 1%r.
proof. exact (Thash.thash_h_correct keccakf1600_total x0 c0 a0). qed.

lemma thash_t_len_total (x0 : TLenIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_t_len : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TLenIn.to_list x0)] = 1%r.
proof. exact (Thash.thash_t_len_correct keccakf1600_total x0 c0 a0). qed.

lemma thash_t_k_total (x0 : TKIn.t) (c0 : Node.t) (a0 : BArray32.t) :
  phoare [M._thash_t_k : in_0 = x0 /\ ctx = c0 /\ adrs = a0 ==>
    Node.to_list res.`1 = T_l P (Node.to_list c0) (BArray32.to_list a0) (TKIn.to_list x0)] = 1%r.
proof. exact (Thash.thash_t_k_correct keccakf1600_total x0 c0 a0). qed.

lemma shake_absorb_prefix_total (s0 : BArray200.t) (p0 l0 : W64.t) (x0 : BArray332.t) (m : W8.t list) :
  phoare [M._shake_absorb_prefix :
    st = s0 /\ pos = p0 /\ prefix = x0 /\ len = l0 /\ to_uint l0 <= 332 /\
    to_uint p0 = size m %% 136 /\ lanes s0 = abs_state 136 m ==>
    to_uint res.`2 < 136 /\
    to_uint res.`2 = size (m ++ take (to_uint l0) (BArray332.to_list x0)) %% 136 /\
    lanes res.`1 = abs_state 136 (m ++ take (to_uint l0) (BArray332.to_list x0))] = 1%r.
proof. exact (Thash.shake_absorb_prefix_correct keccakf1600_total s0 p0 l0 x0 m). qed.

lemma keccak_finalize_total (s0 : BArray200.t) (p0 : W64.t) (m : W8.t list) :
  phoare [M._keccak_finalize :
    st = s0 /\ pos = p0 /\ rate = W64.of_int 136 /\ ds = W64.of_int 31 /\
    to_uint p0 = size m %% 136 /\ lanes s0 = abs_state 136 m ==>
    lanes res.`1 = keccak_f1600_op (ABSORB1600 SHAKE_DS_BYTE 136 m)] = 1%r.
proof. exact (Thash.keccak_finalize_correct keccakf1600_total s0 p0 m). qed.
