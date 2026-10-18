(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * MsgHash.ec (SHAKE sets)
 * =======================
 *
 * The message hashes of the SHAKE parameter sets (FIPS 205 section
 * 11.1): _prf_msg computes PRF_msg and _h_msg computes H_msg, on the
 * message M = prefix[0 : prefix_len] || mem[msg : msg + msg_len] of
 * Internal.ec (slh_msg).
 *
 * Both write a short head into a zeroed state, lane by lane: SK.prf ||
 * opt_rand (2n bytes) for PRF_msg, R || PK.seed || PK.root (3n bytes) for
 * H_msg. The head is shorter than one SHAKE256 block, so the state holds
 * the sponge state of ShakeSponge.ec for it (abs_short), at position
 * |head|. __shake_absorb_message then absorbs the prefix byte by byte
 * (_shake_absorb_prefix), the message from memory (_keccak_absorb_mem)
 * and pads and permutes (_keccak_finalize); each step keeps the sponge
 * state of the bytes absorbed so far (HashKernels.ec), so the state is
 * the permuted ABSORB1600 state of head || M. The output, n or m bytes,
 * is at most one block: it is the first bytes of that state
 * (shake256_one), read lane by lane (PRF_msg) or byte by byte (H_msg).
 *
 * Model. As Thash.ec: checked against the model of each SHAKE set.
 *
 * Theorems (total correctness, every input with msg_ok):
 *     prf_msg_correct   _prf_msg returns PRF_msg(SK.prf, opt_rand, M);
 *     h_msg_correct     _h_msg returns H_msg(R, PK.seed, PK.root, M).
 * Their statements are the PRF_msg and H_msg premises of Internal.ec.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils JMemory Jslh.
from JazzEC require import WArray200.
require import Bytes FIPS205_Params FIPS205_Hash FIPS202_Bytes.
require import BArray32 BArray200 BArray332 KeccakState Keccakf1600_Spec Keccak1600_Spec.
require import JWordList ShakeSponge SetModel CoreExtracted.
require import Internal HashKernels.
require Thash Sponge.

(* ------------------------------------------------------------------ *)
(* Helpers                                                            *)

(* The first len bytes of the permuted ABSORB1600 state are SHAKE256. *)
lemma shake_out (msg out : W8.t list) (sc : BArray200.t) (len : int) :
  0 < len <= 136 => size out = len =>
  lanes sc = keccak_f1600_op (ABSORB1600 SHAKE_DS_BYTE 136 msg) =>
  (forall j, 0 <= j < len => nth W8.zero out j = sc.[j]) =>
  out = shake256 msg (8 * len).
proof.
move=> hl hs hsc hr; rewrite shake256E shake256_one 1:/# -hsc.
apply (eq_from_nth W8.zero); first by rewrite size_take 1:/# size_state2bytes /#.
move=> j hj; rewrite nth_take 1,2:/# state2bytesE stbytes_lanes 1:/# hr /#.
qed.

(* A head of fewer than 136 bytes in a zeroed state is its sponge state. *)
lemma head_state (st : BArray200.t) (h : W8.t list) :
  size h < 136 => (forall j, 0 <= j < 200 => st.[j] = nth W8.zero h j) =>
  lanes st = abs_state 136 h.
proof.
move=> hs hj; apply stbytes_inj; apply WArray200.tP => j hjr.
by rewrite stbytes_lanes // abs_short // hj.
qed.

lemma prefix_size : Prefix.size = 332 by [].

lemma kinit_p : phoare [M.__keccak_init : true ==> forall j, 0 <= j < 200 => res.[j] = W8.zero] = 1%r.
proof. by conseq Thash.keccak_init_ll Thash.keccak_init_h. qed.

lemma extract_n_p (s0 : BArray200.t) :
  phoare [M.__shake_extract_n : st = s0 ==>
    forall j, 0 <= j < P.`n => nth W8.zero (Node.to_list res) j = s0.[j]] = 1%r.
proof. by conseq Thash.extract_n_ll (Thash.extract_n_h s0). qed.

(* ------------------------------------------------------------------ *)
(* __shake_absorb_message                                             *)

lemma absorb_message_p (s0 : BArray200.t) (h0 : W8.t list) (x0 : Prefix.t) (pl m ml : W64.t)
  (mem0 : global_mem_t) :
  phoare [M.__shake_absorb_message :
    st = s0 /\ head = size h0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\
    Glob.mem = mem0 /\ msg_ok pl m ml /\ size h0 < 136 /\ lanes s0 = abs_state 136 h0 ==>
    Glob.mem = mem0 /\
    lanes res.`1 = keccak_f1600_op (ABSORB1600 SHAKE_DS_BYTE 136 (h0 ++ slh_msg mem0 x0 pl m ml))] = 1%r.
proof.
proc.
seq 3 : (to_uint pos = size (h0 ++ take (to_uint pl) (Prefix.to_list x0)) %% 136 /\
         lanes st = abs_state 136 (h0 ++ take (to_uint pl) (Prefix.to_list x0)) /\
         msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ to_uint m + to_uint ml <= W64.modulus)
        1%r 1%r 0%r _ => //.
+ call (shake_absorb_prefix_total s0 (W64.of_int (size h0)) pl x0 h0); wp; skip.
  move=> &hr [#] -> -> -> -> -> -> -> [hpl hm] hs hst; rewrite /protect_64 /= -prefix_size hpl hst /=.
  have hs0 := size_ge0 h0; split; first by rewrite W64.to_uint_small 1:/# modz_small //; smt().
  by move=> _ r [#] _ -> -> /=; exact hm.
+ seq 4 : (Glob.mem = mem0 /\ absorbing 136 (h0 ++ take (to_uint pl) (Prefix.to_list x0) ++
                                    memread mem0 (to_uint m) (to_uint ml)) st pos) 1%r 1%r 0%r _ => //.
  + call (keccak_absorb_mem_total 136 (h0 ++ take (to_uint pl) (Prefix.to_list x0)) mem0 m ml); wp; skip.
    by move=> &hr [#] hp hs -> -> -> hm /=; rewrite /protect_64 /absorbing /= hp hs /=.
  + exlim st, pos => s2 p2.
    call (keccak_finalize_total s2 p2 (h0 ++ take (to_uint pl) (Prefix.to_list x0) ++
                                       memread mem0 (to_uint m) (to_uint ml))); wp; skip.
    move=> &hr [[<- <-] [-> ha]] /=; move: ha; rewrite /absorbing => -[hp hs]; split; first by rewrite hp hs.
    by move=> _ r -> /=; rewrite /slh_msg !catA.
  hoare; call (_ : Glob.mem = mem0 /\ absorbing 136 (h0 ++ take (to_uint pl) (Prefix.to_list x0)) st pos /\
                   to_uint rate = 136 /\ in_0 = m /\ inlen = ml /\ to_uint m + to_uint ml <= W64.modulus ==>
                   Glob.mem = mem0 /\ absorbing 136 (h0 ++ take (to_uint pl) (Prefix.to_list x0) ++
                                    memread mem0 (to_uint m) (to_uint ml)) res.`1 res.`2).
  + by conseq (keccak_absorb_mem_total 136 (h0 ++ take (to_uint pl) (Prefix.to_list x0)) mem0 m ml).
  wp; skip; by move=> &hr [#] hp hs -> -> -> hm /=; rewrite /protect_64 /absorbing /= hp hs /=.
hoare; call (_ : st = s0 /\ pos = W64.of_int (size h0) /\ prefix = x0 /\ len = pl /\ to_uint pl <= 332 /\
                 to_uint (W64.of_int (size h0)) = size h0 %% 136 /\ lanes s0 = abs_state 136 h0 ==>
                 to_uint res.`2 < 136 /\
                 to_uint res.`2 = size (h0 ++ take (to_uint pl) (BArray332.to_list x0)) %% 136 /\
                 lanes res.`1 = abs_state 136 (h0 ++ take (to_uint pl) (BArray332.to_list x0))).
+ by conseq (shake_absorb_prefix_total s0 (W64.of_int (size h0)) pl x0 h0).
wp; skip => &hr [#] -> -> -> -> -> -> -> [hpl hm] hs hst; rewrite /protect_64 /= -prefix_size hpl hst /=.
have hs0 := size_ge0 h0; split; first by rewrite W64.to_uint_small 1:/# modz_small //; smt().
by move=> _ r [#] _ -> -> /=; exact hm.
qed.

lemma absorb_message_h (s0 : BArray200.t) (h0 : W8.t list) (x0 : Prefix.t) (pl m ml : W64.t)
  (mem0 : global_mem_t) :
  hoare [M.__shake_absorb_message :
    st = s0 /\ head = size h0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\
    Glob.mem = mem0 /\ msg_ok pl m ml /\ size h0 < 136 /\ lanes s0 = abs_state 136 h0 ==>
    Glob.mem = mem0 /\
    lanes res.`1 = keccak_f1600_op (ABSORB1600 SHAKE_DS_BYTE 136 (h0 ++ slh_msg mem0 x0 pl m ml))].
proof. by conseq (absorb_message_p s0 h0 x0 pl m ml mem0). qed.

lemma absorb_message_ll : phoare [M.__shake_absorb_message : 0 <= head < 136 ==> true] = 1%r.
proof.
proc; call keccak_finalize_ll; wp; call keccak_absorb_mem_ll; wp; call shake_absorb_prefix_pos.
wp; skip => &hr h /=; have h136 : to_uint (W64.of_int 136) = 136 by rewrite W64.of_uintK.
by rewrite W64.to_uint_small 1:/#; smt().
qed.

(* ------------------------------------------------------------------ *)
(* PRF_msg                                                            *)

lemma prf_msg_h (k0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  hoare [M._prf_msg :
    sk_prf = k0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Node.to_list res.`1 = PRF_msg P (Node.to_list k0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)].
proof.
proc.
ecall (Thash.extract_n_h st); wp.
ecall (absorb_message_h st (Node.to_list k0 ++ Node.to_list o0) x0 pl m ml mem0); wp.
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ sk_prf = k0 /\ opt_rand = o0 /\
       forall j, 0 <= j < 200 => st.[j] =
         if j < 8 * i then nth W8.zero (Node.to_list k0) j
         else if P.`n <= j < P.`n + 8 * i then nth W8.zero (Node.to_list o0) (j - P.`n)
         else W8.zero).
+ wp; skip => &m [#] h0 h1 hinc hk ho hj hlt.
  rewrite hk ho /=; do 4?(split; first smt()).
  move=> j hjr; have hn := n_val.
  rewrite BArray200.get8_set64dE.
  case: (8 * (P.`n %/ 8 + i{m}) <= j < 8 * (P.`n %/ 8 + i{m}) + 8) => h.
  + by rewrite ifT 1:/# ifF 1:/# ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
  rewrite ifF 1:/# BArray200.get8_set64dE.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => h'.
  + by rewrite ifT 1:/# ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
  by rewrite ifF 1:/# hj // /#.
wp; call Thash.keccak_init_h; wp; skip => &m [#] -> -> -> -> -> -> -> hok /= z hz; split.
+ split; first smt(n_val).
  by move=> j hj; rewrite hz //; smt().
move=> i0 st0 hlt [#] h0 h1 h2 hj; have hn := n_val.
have hi8 : 8 * i0 = P.`n by smt().
have hk : size (Node.to_list k0) = P.`n by rewrite Node.size_to_list /max /#.
have hsz : size (Node.to_list k0 ++ Node.to_list o0) = 2 * P.`n.
+ by rewrite size_cat hk Node.size_to_list /max /#.
have hc : forall j, 0 <= j < 200 => st0.[j] = nth W8.zero (Node.to_list k0 ++ Node.to_list o0) j.
+ move=> j hjr; rewrite hj // hi8.
  case: (2 * P.`n <= j) => hb; first by rewrite ifF 1:/# ifF 1:/# nth_default 1:/#.
  rewrite nth_cat hk; case: (j < P.`n) => h; first by simplify.
  by rewrite ifT 1:/#.
have hhd : lanes st0 = abs_state 136 (Node.to_list k0 ++ Node.to_list o0) by apply head_state; smt().
split; first smt().
move=> _ [s1 ms1] /= hs1 r1 hr1.
rewrite /PRF_msg (_ : P.`family = SHAKE) 1:/P //=.
apply (shake_out _ _ s1 P.`n); 1,2: smt(Node.size_to_list).
+ by rewrite hs1.
by move=> j hjj /=; apply hr1.
qed.

lemma prf_msg_ll : islossless M._prf_msg.
proof.
proc; call Thash.extract_n_ll; wp; call absorb_message_ll; wp.
while true (inc - i); first by auto => /#.
by wp; call Thash.keccak_init_ll; auto => /#.
qed.

lemma prf_msg_correct (k0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  phoare [M._prf_msg :
    sk_prf = k0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Node.to_list res.`1 = PRF_msg P (Node.to_list k0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)] = 1%r.
proof. by conseq prf_msg_ll (prf_msg_h k0 o0 x0 pl m ml mem0). qed.

(* ------------------------------------------------------------------ *)
(* H_msg                                                              *)

lemma pk_halves (p0 : PK.t) :
  slice (PK.to_list p0) 0 P.`n ++ slice (PK.to_list p0) P.`n (2 * P.`n) = PK.to_list p0.
proof.
have hn := n_val.
by rewrite ForsPk.slice_cat2 1,2:/# /slice drop0 take_oversize // PK.size_to_list /max /#.
qed.

lemma h_msg_h (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  hoare [M._h_msg :
    r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Digest.to_list res.`1 =
      H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
        (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)].
proof.
proc.
while (0 <= i <= P.`m /\ forall j, 0 <= j < i => nth W8.zero (Digest.to_list digest) j = st.[j]).
+ wp; skip => &m [#] h0 h1 hj hlt; have hm := m_val; split; first smt().
  move=> j hjr; rewrite Digest.get_to_list Digest.get_setE 1:/#.
  case: (j = i{m}) => h; first by rewrite h /= Sponge.trunc_zext8.
  by rewrite -Digest.get_to_list hj /#.
wp; ecall (absorb_message_h st (Node.to_list r0 ++ PK.to_list p0) x0 pl m ml mem0); wp.
while (0 <= i <= inc /\ inc = 2 * (P.`n %/ 8) /\ pk = p0 /\
       forall j, 0 <= j < 200 => st.[j] =
         if j < P.`n then nth W8.zero (Node.to_list r0) j
         else if j < P.`n + 8 * i then nth W8.zero (PK.to_list p0) (j - P.`n) else W8.zero).
+ wp; skip => &m [#] h0 h1 hinc hp hj hlt; rewrite hp /=; do 4?(split; first smt()).
  move=> j hjr; have hn := n_val; rewrite BArray200.get8_set64dE.
  case: (8 * (P.`n %/ 8 + i{m}) <= j < 8 * (P.`n %/ 8 + i{m}) + 8) => h.
  + by rewrite ifT 1:/# ifF 1:/# ifT 1:/# PK.get64d_byte 1:/#; congr; smt().
  by rewrite ifF 1:/# hj // /#.
wp.
while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ r = r0 /\
       forall j, 0 <= j < 200 => st.[j] = if j < 8 * i then nth W8.zero (Node.to_list r0) j else W8.zero).
+ wp; skip => &m [#] h0 h1 hinc hr hj hlt; rewrite hr /=; do 4?(split; first smt()).
  move=> j hjr; have hn := n_val; rewrite BArray200.get8_set64dE.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
  + by rewrite ifT 1:/# ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
  by rewrite ifF 1:/# hj // /#.
wp; call Thash.keccak_init_h; wp; skip => &m [#] -> -> -> -> -> -> -> hok /= z hz; have hn := n_val.
split; first by split; [smt() | move=> j hj; rewrite hz //; smt()].
move=> i0 st0 hlt [#] h0 h1 h2 hj; split.
+ split; first smt().
  move=> j hjr; rewrite hj //; smt().
move=> i1 st1 hlt1 [#] g0 g1 g2 gj.
have hk : size (Node.to_list r0) = P.`n by rewrite Node.size_to_list /max /#.
have hsz : size (Node.to_list r0 ++ PK.to_list p0) = 3 * P.`n.
+ by rewrite size_cat hk PK.size_to_list /max /#.
have hc : forall j, 0 <= j < 200 => st1.[j] = nth W8.zero (Node.to_list r0 ++ PK.to_list p0) j.
+ move=> j hjr; rewrite gj //.
  case: (3 * P.`n <= j) => hb; first by rewrite ifF 1:/# ifF 1:/# nth_default 1:/#.
  rewrite nth_cat hk; case: (j < P.`n) => h; first by simplify.
  by rewrite ifT 1:/#.
have hhd : lanes st1 = abs_state 136 (Node.to_list r0 ++ PK.to_list p0) by apply head_state; smt().
split; first smt().
move=> _ [s1 ms1] /= hs1; split; first smt(m_val).
move=> d2 i2 hlt2 [#] k0 k1 hd.
rewrite /H_msg (_ : P.`family = SHAKE) 1:/P //=.
have hcat : forall (a b c d : W8.t list), a ++ b ++ c ++ d = a ++ (b ++ c) ++ d by move=> a b c d; rewrite !catA.
rewrite hcat pk_halves.
apply (shake_out _ _ s1 P.`m); 1: smt(m_val).
+ by rewrite Digest.size_to_list /max; smt(m_val).
+ by rewrite hs1.
by move=> j hjj /=; rewrite hd /#.
qed.

lemma h_msg_ll : islossless M._h_msg.
proof.
proc; while true (P.`m - i); first by auto => /#.
wp; call absorb_message_ll; wp.
while true (inc - i); first by auto => /#.
wp; while true (inc - i); first by auto => /#.
by wp; call Thash.keccak_init_ll; auto; smt(n_val m_val).
qed.

lemma h_msg_correct (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  phoare [M._h_msg :
    r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Digest.to_list res.`1 =
      H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
        (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r.
proof. by conseq h_msg_ll (h_msg_h r0 p0 x0 pl m ml mem0). qed.
