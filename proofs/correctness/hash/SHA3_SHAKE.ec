(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * SHA3_SHAKE.ec
 * =============
 *
 * Functional correctness of the one-shot SHA-3 and SHAKE functions of
 * src/hash/keccak/fips202.jinc against FIPS 202 sections 6.1 and 6.2
 * (Keccak1600_Spec SHA3_224 ... SHAKE256), for a message read from memory
 * at in.
 *
 * Each function zeroes a state, absorbs the message from position 0,
 * finalizes with the SHA-3 (0x06) or SHAKE (0x1f) suffix byte, and then
 * either copies the digest out of the first state lanes (SHA-3, digest
 * length below the rate) or squeezes outlen bytes to memory at out
 * (SHAKE). The proofs compose Sponge.ec and SpongeSqueeze.ec; the
 * permutation's correctness is again the section hypothesis kf_h (with
 * kf_ll), a premise of every theorem once the section is closed, which
 * Sponge_Portable.ec and Sponge_KernelSpec.ec discharge.
 *
 * The SHAKE functions read the whole message before they write any
 * output, so the statements hold when the two regions overlap.
 *
 * Theorems (total correctness, under kf_h and kf_ll), for the message
 * m = memread mem0 in inlen:
 *     sha3_224_mem_total ... sha3_512_mem_total   out holds SHA3_d m
 *     shake128_mem_total, shake256_mem_total      memory at out holds
 *                                                 SHAKEd m outlen
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils JMemory.
from JazzEC require import Array25 WArray200.
require import BArray200 BArray28 BArray32 BArray48 BArray64 KeccakState.
require import Keccakf1600_Spec Keccak1600_Spec JWordList Keccak1600_arrays.
require import HashExtracted ArchWord ShakeSponge Sponge SpongeSqueeze.
require BitEncoding.
import BitEncoding.BitChunking.

(* ------------------------------------------------------------------ *)
(* The empty sponge                                                    *)

lemma absorbing_nil r8 (st : BArray200.t) : 0 < r8 => lanes st = st0 => absorbing r8 [] st W64.zero.
proof.
move=> hr hl; have hc : chunkremains<:W8.t> r8 [] = [] by apply chunkremains_nil => //; exact dvdz0.
by rewrite /absorbing /abs_state W64.to_uint0 /= chunk_nil hc /stateabsorb_iblocks /= /stateabsorb bytes2state0 addstate_st0 hl.
qed.

lemma keccak_init_total : phoare [M.__keccak_init : true ==> lanes res = st0] = 1%r.
proof.
proc; while (0 <= i <= 25 /\ z = W64.zero /\ forall j, 0 <= j < i => BArray200.get64 st j = W64.zero) (25 - i).
+ move=> k; auto => /> &hr h0 _ hj hlt; split; last smt().
  split; first smt().
  by move=> j hj'; rewrite BArray200.get_set64E 1,2:/#; smt().
auto => /> &hr; split; first smt().
move=> i0 st1; split; first smt().
move=> hn h0 h1 hb; apply Array25.tP => j hj.
by rewrite lanesE // /st0 /init_25_64 Array25.initiE //=; apply hb; smt().
qed.

(* ------------------------------------------------------------------ *)
(* The one-shot functions, under the permutation's correctness        *)

section.

declare axiom kf_h (s0 : BArray200.t) :
  hoare [M._keccakf1600 : st = s0 ==> lanes res.`1 = keccak_f1600_op (lanes s0)].
declare axiom kf_ll : islossless M._keccakf1600.

lemma sha3_absorb_all_total (r8 : int) (trail : W8.t) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M.__sha3_absorb_all :
    Glob.mem = mem0 /\ to_uint rate = r8 /\ 0 < r8 < 200 /\ truncateu8 ds = trail
    /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0
    /\ lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 (memread mem0 (to_uint p0) (to_uint l0)))] = 1%r.
proof.
proc.
call (keccak_finalize_total kf_h kf_ll r8 (memread mem0 (to_uint p0) (to_uint l0)) trail).
wp; call (keccak_absorb_mem_total kf_h kf_ll r8 [] mem0 p0 l0).
wp; call keccak_init_total.
auto => /> &hr hr0 hr1 hpl st1 hst1; split.
+ by have := absorbing_nil (to_uint rate{hr}) st1 hr0 hst1; rewrite /absorbing => -[].
by move=> _ r _ _; smt().
qed.

lemma sha3_224_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_224_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray28.to_list res.`1 = SHA3_224 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof.
proc; wp.
while (0 <= i <= 3 /\ Glob.mem = mem0 /\
    lanes st = keccak_f1600_op (ABSORB1600 SHA3_DS_BYTE 144 (memread mem0 (to_uint p0) (to_uint l0))) /\
    forall j, 0 <= j < 8 * i => out.[j] = st.[j]) (3 - i).
+ move=> z; auto => /> &hr h0 _ hst hj hlt; split; last smt().
  split; first smt().
  move=> j hj' hj2; rewrite BArray28.get8_set64dE; case: (j < 8 * i{hr}) => hlt'.
  + by rewrite ifF 1:/#; apply hj => /#.
  by rewrite ifT 1:/# BArray200.get64d_byte 1:/#; congr; ring.
wp; call (sha3_absorb_all_total 144 SHA3_DS_BYTE mem0 p0 l0).
auto => /> &hr hpl _ r hl; split; first smt().
move=> i0 out1; split; first smt().
move=> hn h0 h1 hb; have hi : i0 = 3 by smt().
apply (eq_from_nth W8.zero); first by rewrite BArray28.size_to_list /SHA3_224 /KECCAK1600 /c448_r8 size_SQUEEZE1600.
move=> j; rewrite BArray28.size_to_list /= => hj.
rewrite /SHA3_224 /KECCAK1600 /c448_r8 squeeze_one // -hl nth_take 1,2:/#.
rewrite state2bytesE stbytes_lanes 1:/# BArray28.get8_set32dE.
case: (j < 24) => hj24.
+ by rewrite ifF 1:/#; apply hb; smt().
by rewrite ifT 1:/# BArray200.get32d_byte 1:/#; congr; ring.
qed.

lemma sha3_256_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_256_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray32.to_list res.`1 = SHA3_256 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof.
proc.
while (0 <= i <= 4 /\ Glob.mem = mem0 /\
    lanes st = keccak_f1600_op (ABSORB1600 SHA3_DS_BYTE 136 (memread mem0 (to_uint p0) (to_uint l0))) /\
    forall j, 0 <= j < 8 * i => out.[j] = st.[j]) (4 - i).
+ move=> z; auto => /> &hr h0 _ hst hj hlt; split; last smt().
  split; first smt().
  move=> j hj' hj2; rewrite BArray32.get8_set64dE; case: (j < 8 * i{hr}) => hlt'.
  + by rewrite ifF 1:/#; apply hj => /#.
  by rewrite ifT 1:/# BArray200.get64d_byte 1:/#; congr; ring.
wp; call (sha3_absorb_all_total 136 SHA3_DS_BYTE mem0 p0 l0).
auto => /> &hr hpl _ r hl; split; first smt().
move=> i0 out1; split; first smt().
move=> hn h0 h1 hb; have hi : i0 = 4 by smt().
apply (eq_from_nth W8.zero); first by rewrite BArray32.size_to_list /SHA3_256 /KECCAK1600 /c512_r8 size_SQUEEZE1600.
move=> j; rewrite BArray32.size_to_list /= => hj.
rewrite /SHA3_256 /KECCAK1600 /c512_r8 squeeze_one // -hl nth_take 1,2:/#.
by rewrite state2bytesE stbytes_lanes 1:/#; apply hb; smt().
qed.

lemma sha3_384_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_384_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray48.to_list res.`1 = SHA3_384 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof.
proc.
while (0 <= i <= 6 /\ Glob.mem = mem0 /\
    lanes st = keccak_f1600_op (ABSORB1600 SHA3_DS_BYTE 104 (memread mem0 (to_uint p0) (to_uint l0))) /\
    forall j, 0 <= j < 8 * i => out.[j] = st.[j]) (6 - i).
+ move=> z; auto => /> &hr h0 _ hst hj hlt; split; last smt().
  split; first smt().
  move=> j hj' hj2; rewrite BArray48.get8_set64dE; case: (j < 8 * i{hr}) => hlt'.
  + by rewrite ifF 1:/#; apply hj => /#.
  by rewrite ifT 1:/# BArray200.get64d_byte 1:/#; congr; ring.
wp; call (sha3_absorb_all_total 104 SHA3_DS_BYTE mem0 p0 l0).
auto => /> &hr hpl _ r hl; split; first smt().
move=> i0 out1; split; first smt().
move=> hn h0 h1 hb; have hi : i0 = 6 by smt().
apply (eq_from_nth W8.zero); first by rewrite BArray48.size_to_list /SHA3_384 /KECCAK1600 /c768_r8 size_SQUEEZE1600.
move=> j; rewrite BArray48.size_to_list /= => hj.
rewrite /SHA3_384 /KECCAK1600 /c768_r8 squeeze_one // -hl nth_take 1,2:/#.
by rewrite state2bytesE stbytes_lanes 1:/#; apply hb; smt().
qed.

lemma sha3_512_mem_total (mem0 : global_mem_t) (p0 l0 : W64.t) :
  phoare [M._sha3_512_mem :
    Glob.mem = mem0 /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0 /\ BArray64.to_list res.`1 = SHA3_512 (memread mem0 (to_uint p0) (to_uint l0))] = 1%r.
proof.
proc.
while (0 <= i <= 8 /\ Glob.mem = mem0 /\
    lanes st = keccak_f1600_op (ABSORB1600 SHA3_DS_BYTE 72 (memread mem0 (to_uint p0) (to_uint l0))) /\
    forall j, 0 <= j < 8 * i => out.[j] = st.[j]) (8 - i).
+ move=> z; auto => /> &hr h0 _ hst hj hlt; split; last smt().
  split; first smt().
  move=> j hj' hj2; rewrite BArray64.get8_set64dE; case: (j < 8 * i{hr}) => hlt'.
  + by rewrite ifF 1:/#; apply hj => /#.
  by rewrite ifT 1:/# BArray200.get64d_byte 1:/#; congr; ring.
wp; call (sha3_absorb_all_total 72 SHA3_DS_BYTE mem0 p0 l0).
auto => /> &hr hpl _ r hl; split; first smt().
move=> i0 out1; split; first smt().
move=> hn h0 h1 hb; have hi : i0 = 8 by smt().
apply (eq_from_nth W8.zero); first by rewrite BArray64.size_to_list /SHA3_512 /KECCAK1600 /c1024_r8 size_SQUEEZE1600.
move=> j; rewrite BArray64.size_to_list /= => hj.
rewrite /SHA3_512 /KECCAK1600 /c1024_r8 squeeze_one // -hl nth_take 1,2:/#.
by rewrite state2bytesE stbytes_lanes 1:/#; apply hb; smt().
qed.

lemma shake_mem_total (r8 : int) (mem0 : global_mem_t) (o0 l0 p0 n0 : W64.t) :
  phoare [M.__shake_mem :
    Glob.mem = mem0 /\ to_uint rate = r8 /\ 0 < r8 < 200 /\ out = o0 /\ outlen = l0
    /\ in_0 = p0 /\ inlen = n0 /\ to_uint p0 + to_uint n0 <= W64.modulus
    /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0)
          (KECCAK1600 r8 (memread mem0 (to_uint p0) (to_uint n0)) SHAKE_DS_BYTE (to_uint l0))] = 1%r.
proof.
proc.
call (keccak_squeeze_mem_total kf_h kf_ll r8 (ABSORB1600 SHAKE_DS_BYTE r8 (memread mem0 (to_uint p0) (to_uint n0))) 0 mem0 o0 l0).
wp; call (sha3_absorb_all_total r8 SHAKE_DS_BYTE mem0 p0 n0).
auto => /> &hr hr0 hr1 hpi hpo _ r hl; split.
+ by rewrite /FIPS202_SHA3_Spec.st_i iter1 hl; smt().
by move=> *; rewrite drop0 /KECCAK1600.
qed.

lemma shake128_mem_total (mem0 : global_mem_t) (o0 l0 p0 n0 : W64.t) :
  phoare [M._shake128_mem :
    Glob.mem = mem0 /\ out = o0 /\ outlen = l0 /\ in_0 = p0 /\ inlen = n0
    /\ to_uint p0 + to_uint n0 <= W64.modulus /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0) (SHAKE128 (memread mem0 (to_uint p0) (to_uint n0)) (to_uint l0))] = 1%r.
proof. by proc; call (shake_mem_total 168 mem0 o0 l0 p0 n0); auto => />. qed.

lemma shake256_mem_total (mem0 : global_mem_t) (o0 l0 p0 n0 : W64.t) :
  phoare [M._shake256_mem :
    Glob.mem = mem0 /\ out = o0 /\ outlen = l0 /\ in_0 = p0 /\ inlen = n0
    /\ to_uint p0 + to_uint n0 <= W64.modulus /\ to_uint o0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = stores mem0 (to_uint o0) (SHAKE256 (memread mem0 (to_uint p0) (to_uint n0)) (to_uint l0))] = 1%r.
proof. by proc; call (shake_mem_total 136 mem0 o0 l0 p0 n0); auto => />. qed.

end section.
