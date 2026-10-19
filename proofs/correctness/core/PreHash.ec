(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * PreHash.ec
 * ==========
 *
 * The pre-hash _prehash of src/slhdsa/external.jinc, which computes PH(M)
 * for HashSLH-DSA (FIPS 205 section 10.2.2) from the message in memory:
 * selector s in 1 .. 12 picks SHA-256, SHA-384, SHA-512, SHA-224,
 * SHA-512/224, SHA-512/256 (the SHA-2 one-shots of the hash layer) or
 * SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 (256 bits), SHAKE256
 * (512 bits) (_ph_keccak: absorb, pad, then copy the first outlen state
 * bytes, outlen at most the rate), and the 64-byte digest buffer is
 * copied out with its length.
 *
 * Each kernel is the set's copy of the hash layer's procedure: its
 * theorem is moved over by an equivalence of the two bodies (proc; sim),
 * as in HashKernels.ec. The SHA-2 one-shots are proved for M under 2^61
 * bytes in a buffer that ends below 2^64; External.ph_dom states that
 * domain for the SHA-2 selectors and is a precondition of prehash_h. The
 * SHA-3 and SHAKE kernels need only that the buffer fits the address
 * space. The rate, padding byte and output length of each Keccak
 * selector are those of FIPS 202 (Keccak1600_Spec: SHA3_224 .. SHAKE256).
 *
 * Theorems:
 *     prehash_ll       _prehash terminates on every input;
 *     prehash_h        on a selector 1 .. 12 and M in ph_dom, the first
 *                      len bytes of the result are ph_apply (ph_of s) M
 *                      (the premises of External.ec on _prehash);
 *     prehash_total    both together.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils JMemory Jslh.
from JazzEC require import Array25 WArray200.
require import Bytes FIPS180_SHA2 FIPS202_Bytes FIPS205_External.
require import BArray32 BArray64 BArray200 SBArray64_32 KeccakState Keccakf1600_Spec Keccak1600_Spec.
require import ShakeSponge JWordList SetModel CoreExtracted External.
require HashExtracted Keccakf1600_Pair Sponge SHA3_SHAKE SHA256_Stream SHA512_Stream.

(* ------------------------------------------------------------------ *)
(* The set's copies of the hash-layer kernels                         *)

lemma ph_sha256_total (p0 l0 : W64.t) :
  phoare [M._sha256_mem : in_0 = p0 /\ inlen = l0 /\
    to_uint p0 + to_uint l0 < W64.modulus /\ to_uint l0 < 2^61 ==>
    BArray32.to_list res.`1 = SHA256.sha256 (memread Glob.mem (to_uint p0) (to_uint l0))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               BArray32.to_list res.`1 = SHA256.sha256 (memread Glob.mem (to_uint p0) (to_uint l0))] =
          Pr[HashExtracted.M._sha256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               BArray32.to_list res.`1 = SHA256.sha256 (memread Glob.mem (to_uint p0) (to_uint l0))].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA256_Stream.sha256_mem_total p0 l0) => //.
qed.

lemma ph_sha256_ll : islossless M._sha256_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA256_Stream.sha256_mem_ll.
qed.

lemma ph_sha256_h (p0 l0 : W64.t) :
  to_uint p0 + to_uint l0 < W64.modulus => to_uint l0 < 2^61 =>
  hoare [M._sha256_mem : in_0 = p0 /\ inlen = l0 ==>
    BArray32.to_list res.`1 = SHA256.sha256 (memread Glob.mem (to_uint p0) (to_uint l0))].
proof. by move=> h1 h2; conseq (ph_sha256_total p0 l0) => &hr [-> ->] /=; split. qed.

lemma ph_sha224_total (p0 l0 : W64.t) :
  phoare [M._sha224_mem : in_0 = p0 /\ inlen = l0 /\
    to_uint p0 + to_uint l0 < W64.modulus /\ to_uint l0 < 2^61 ==>
    take 28 (BArray32.to_list res.`1) = SHA256.sha224 (memread Glob.mem (to_uint p0) (to_uint l0))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 28 (BArray32.to_list res.`1) = SHA256.sha224 (memread Glob.mem (to_uint p0) (to_uint l0))] =
          Pr[HashExtracted.M._sha224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 28 (BArray32.to_list res.`1) = SHA256.sha224 (memread Glob.mem (to_uint p0) (to_uint l0))].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA256_Stream.sha224_mem_total p0 l0) => //.
qed.

lemma ph_sha224_ll : islossless M._sha224_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA256_Stream.sha224_mem_ll.
qed.

lemma ph_sha224_h (p0 l0 : W64.t) :
  to_uint p0 + to_uint l0 < W64.modulus => to_uint l0 < 2^61 =>
  hoare [M._sha224_mem : in_0 = p0 /\ inlen = l0 ==>
    take 28 (BArray32.to_list res.`1) = SHA256.sha224 (memread Glob.mem (to_uint p0) (to_uint l0))].
proof. by move=> h1 h2; conseq (ph_sha224_total p0 l0) => &hr [-> ->] /=; split. qed.

lemma ph_sha384_total (p0 l0 : W64.t) :
  phoare [M._sha384_mem : in_0 = p0 /\ inlen = l0 /\
    to_uint p0 + to_uint l0 < W64.modulus /\ to_uint l0 < 2^61 ==>
    take 48 (BArray64.to_list res.`1) = SHA512.sha384 (memread Glob.mem (to_uint p0) (to_uint l0))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha384_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 48 (BArray64.to_list res.`1) = SHA512.sha384 (memread Glob.mem (to_uint p0) (to_uint l0))] =
          Pr[HashExtracted.M._sha384_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 48 (BArray64.to_list res.`1) = SHA512.sha384 (memread Glob.mem (to_uint p0) (to_uint l0))].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA512_Stream.sha384_mem_total p0 l0) => //.
qed.

lemma ph_sha384_ll : islossless M._sha384_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha384_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha384_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA512_Stream.sha384_mem_ll.
qed.

lemma ph_sha384_h (p0 l0 : W64.t) :
  to_uint p0 + to_uint l0 < W64.modulus => to_uint l0 < 2^61 =>
  hoare [M._sha384_mem : in_0 = p0 /\ inlen = l0 ==>
    take 48 (BArray64.to_list res.`1) = SHA512.sha384 (memread Glob.mem (to_uint p0) (to_uint l0))].
proof. by move=> h1 h2; conseq (ph_sha384_total p0 l0) => &hr [-> ->] /=; split. qed.

lemma ph_sha512_total (p0 l0 : W64.t) :
  phoare [M._sha512_mem : in_0 = p0 /\ inlen = l0 /\
    to_uint p0 + to_uint l0 < W64.modulus /\ to_uint l0 < 2^61 ==>
    BArray64.to_list res.`1 = SHA512.sha512 (memread Glob.mem (to_uint p0) (to_uint l0))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha512_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               BArray64.to_list res.`1 = SHA512.sha512 (memread Glob.mem (to_uint p0) (to_uint l0))] =
          Pr[HashExtracted.M._sha512_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               BArray64.to_list res.`1 = SHA512.sha512 (memread Glob.mem (to_uint p0) (to_uint l0))].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA512_Stream.sha512_mem_total p0 l0) => //.
qed.

lemma ph_sha512_ll : islossless M._sha512_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha512_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha512_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA512_Stream.sha512_mem_ll.
qed.

lemma ph_sha512_h (p0 l0 : W64.t) :
  to_uint p0 + to_uint l0 < W64.modulus => to_uint l0 < 2^61 =>
  hoare [M._sha512_mem : in_0 = p0 /\ inlen = l0 ==>
    BArray64.to_list res.`1 = SHA512.sha512 (memread Glob.mem (to_uint p0) (to_uint l0))].
proof. by move=> h1 h2; conseq (ph_sha512_total p0 l0) => &hr [-> ->] /=; split. qed.

lemma ph_sha512_224_total (p0 l0 : W64.t) :
  phoare [M._sha512_224_mem : in_0 = p0 /\ inlen = l0 /\
    to_uint p0 + to_uint l0 < W64.modulus /\ to_uint l0 < 2^61 ==>
    take 28 (BArray64.to_list res.`1) = SHA512.sha512_224 (memread Glob.mem (to_uint p0) (to_uint l0))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha512_224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 28 (BArray64.to_list res.`1) = SHA512.sha512_224 (memread Glob.mem (to_uint p0) (to_uint l0))] =
          Pr[HashExtracted.M._sha512_224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 28 (BArray64.to_list res.`1) = SHA512.sha512_224 (memread Glob.mem (to_uint p0) (to_uint l0))].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA512_Stream.sha512_224_mem_total p0 l0) => //.
qed.

lemma ph_sha512_224_ll : islossless M._sha512_224_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha512_224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha512_224_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA512_Stream.sha512_224_mem_ll.
qed.

lemma ph_sha512_224_h (p0 l0 : W64.t) :
  to_uint p0 + to_uint l0 < W64.modulus => to_uint l0 < 2^61 =>
  hoare [M._sha512_224_mem : in_0 = p0 /\ inlen = l0 ==>
    take 28 (BArray64.to_list res.`1) = SHA512.sha512_224 (memread Glob.mem (to_uint p0) (to_uint l0))].
proof. by move=> h1 h2; conseq (ph_sha512_224_total p0 l0) => &hr [-> ->] /=; split. qed.

lemma ph_sha512_256_total (p0 l0 : W64.t) :
  phoare [M._sha512_256_mem : in_0 = p0 /\ inlen = l0 /\
    to_uint p0 + to_uint l0 < W64.modulus /\ to_uint l0 < 2^61 ==>
    take 32 (BArray64.to_list res.`1) = SHA512.sha512_256 (memread Glob.mem (to_uint p0) (to_uint l0))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha512_256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 32 (BArray64.to_list res.`1) = SHA512.sha512_256 (memread Glob.mem (to_uint p0) (to_uint l0))] =
          Pr[HashExtracted.M._sha512_256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               take 32 (BArray64.to_list res.`1) = SHA512.sha512_256 (memread Glob.mem (to_uint p0) (to_uint l0))].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA512_Stream.sha512_256_mem_total p0 l0) => //.
qed.

lemma ph_sha512_256_ll : islossless M._sha512_256_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha512_256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha512_256_mem(out{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA512_Stream.sha512_256_mem_ll.
qed.

lemma ph_sha512_256_h (p0 l0 : W64.t) :
  to_uint p0 + to_uint l0 < W64.modulus => to_uint l0 < 2^61 =>
  hoare [M._sha512_256_mem : in_0 = p0 /\ inlen = l0 ==>
    take 32 (BArray64.to_list res.`1) = SHA512.sha512_256 (memread Glob.mem (to_uint p0) (to_uint l0))].
proof. by move=> h1 h2; conseq (ph_sha512_256_total p0 l0) => &hr [-> ->] /=; split. qed.


lemma ph_keccak_init_total : phoare [M.__keccak_init : true ==> lanes res = st0] = 1%r.
proof.
bypr => &m _.
have -> : Pr[M.__keccak_init(st{m}) @ &m : lanes res = st0] =
          Pr[HashExtracted.M.__keccak_init(st{m}) @ &m : lanes res = st0].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare SHA3_SHAKE.keccak_init_total.
qed.

lemma ph_absorb_mem_total (r8 : int) (m0 : W8.t list) (mem0 : global_mem_t) (p0 l0 : W64.t) :
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

lemma ph_finalize_total (r8 : int) (m0 : W8.t list) (trail : W8.t) :
  phoare [M._keccak_finalize :
    absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200 /\ truncateu8 ds = trail
    ==> lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 m0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._keccak_finalize(st{m}, pos{m}, rate{m}, ds{m}, ms{m}) @ &m :
               lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 m0)] =
          Pr[HashExtracted.M._keccak_finalize(st{m}, pos{m}, rate{m}, ds{m}, ms{m}) @ &m :
               lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 m0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
byphoare (Sponge.keccak_finalize_total Keccakf1600_Pair.keccakf1600_correct Keccakf1600_Pair.keccakf1600_ll
            r8 m0 trail) => //.
qed.

(* ------------------------------------------------------------------ *)
(* _ph_keccak                                                         *)

lemma ph_keccak_init_h : hoare [M.__keccak_init : true ==> lanes res = st0].
proof. by conseq ph_keccak_init_total. qed.

lemma ph_absorb_mem_h (r8 : int) (m0 : W8.t list) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  hoare [M._keccak_absorb_mem :
    Glob.mem = mem0 /\ absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 < 200
    /\ in_0 = p0 /\ inlen = l0 /\ to_uint p0 + to_uint l0 <= W64.modulus
    ==> Glob.mem = mem0
    /\ absorbing r8 (m0 ++ memread mem0 (to_uint p0) (to_uint l0)) res.`1 res.`2].
proof. by conseq (ph_absorb_mem_total r8 m0 mem0 p0 l0). qed.

lemma ph_finalize_h (r8 : int) (m0 : W8.t list) (trail : W8.t) :
  hoare [M._keccak_finalize :
    absorbing r8 m0 st pos /\ to_uint rate = r8 /\ 0 < r8 <= 200 /\ truncateu8 ds = trail
    ==> lanes res.`1 = keccak_f1600_op (ABSORB1600 trail r8 m0)].
proof. by conseq (ph_finalize_total r8 m0 trail). qed.

lemma take_bound (j ol : int) : ol <= 64 => 0 <= j < (if ol < max 0 64 then ol else max 0 64) => 0 <= j < ol.
proof. by rewrite /max /=; smt(). qed.

lemma ph_keccak_h (r8 ol : int) (trail : W8.t) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  hoare [M._ph_keccak :
    Glob.mem = mem0 /\ msg = p0 /\ msg_len = l0 /\ to_uint rate = r8 /\ 0 < r8 < 200 /\
    truncateu8 ds_byte = trail /\ to_uint outlen = ol /\ 0 < ol <= r8 /\ ol <= 64 /\
    to_uint p0 + to_uint l0 <= W64.modulus ==>
    take ol (BArray64.to_list res.`1) = KECCAK1600 r8 (memread mem0 (to_uint p0) (to_uint l0)) trail ol].
proof.
proc; wp.
while (0 <= to_uint i <= ol /\ to_uint outlen = ol /\ 0 < ol <= r8 /\ ol <= 64 /\ (more <=> to_uint i < ol) /\
       lanes st = keccak_f1600_op (ABSORB1600 trail r8 (memread mem0 (to_uint p0) (to_uint l0))) /\
       forall j, 0 <= j < to_uint i => BArray64.get8 out j = BArray200.get8 st j).
+ wp; skip => &m [#] hi0 hi1 ho hol0 hol1 hol64 hmore hst hj hc /=.
  have hlt : to_uint i{m} < ol by rewrite -hmore.
  have hi' := Sponge.inc1 i{m} _; first smt().
  have hJ : forall j, 0 <= j < to_uint i{m} + 1 =>
    BArray64.get8 (BArray64.set8 out{m} (to_uint i{m})
      (truncateu8 (zeroextu64 (BArray200.get8 st{m} (to_uint i{m}))))) j = BArray200.get8 st{m} j.
  + move=> j hj'; rewrite BArray64.get_setE 1:/#.
    case: (j = to_uint i{m}) => [-> /= | hne]; first by rewrite Sponge.trunc_zext8.
    by apply hj; smt().
  rewrite W64.ultE hi' ho.
  by do !split; try (exact hJ); smt().
wp; ecall (ph_finalize_h r8 (memread mem0 (to_uint p0) (to_uint l0)) trail); wp.
ecall (ph_absorb_mem_h r8 [] mem0 p0 l0); wp; ecall (ph_keccak_init_h); wp.
skip => &m [#] hm hp hl hr hr0 hr1 ht ho hol0 hol1 hol64 hpl st1 hst1 /=.
have ha := SHA3_SHAKE.absorbing_nil r8 st1 _ hst1; first smt().
have hmod : W64.modulus = 18446744073709551616 by trivial.
split; first by do !split; try (exact ha); smt().
move=> _ r1 [hm1 hab]; split; first by do !split; try (exact hab); smt().
move=> _ r2 hr2.
have hz : (W64.zero \ult outlen{m} <=> 0 < ol) by rewrite W64.ultE W64.to_uint0 ho.
split; first by do !split; try (exact hz); try (exact hr2); smt().
move=> i0 more0 out0 hmore [#] h0 h1 _ _ _ _ hmo hl0 hJ.
have hi : to_uint i0 = ol by smt().
rewrite /KECCAK1600 squeeze_one 1:/# -hl0.
apply (eq_from_nth W8.zero).
+ by rewrite !size_take 1,2:/# BArray64.size_to_list size_state2bytes /#.
move=> j; rewrite size_take 1:/# BArray64.size_to_list => hj.
have hj' := take_bound j ol hol64 hj.
rewrite !nth_take 1..4:/# BArray64.get_to_list state2bytesE stbytes_lanes 1:/#.
by apply hJ; smt().
qed.

lemma ph_keccak_c (r8 ol t : int) (mem0 : global_mem_t) (p0 l0 : W64.t) :
  to_uint p0 + to_uint l0 <= W64.modulus =>
  0 < r8 < 200 /\ 0 < ol <= r8 /\ ol <= 64 /\ 0 <= t < 256 =>
  hoare [M._ph_keccak :
    Glob.mem = mem0 /\ msg = p0 /\ msg_len = l0 /\ rate = W64.of_int r8 /\
    ds_byte = W64.of_int t /\ outlen = W64.of_int ol ==>
    take ol (BArray64.to_list res.`1) = KECCAK1600 r8 (memread mem0 (to_uint p0) (to_uint l0)) (W8.of_int t) ol].
proof.
move=> hb [#] hr0 hr1 ho0 ho1 ho64 ht0 ht1.
have hm : W64.modulus = 18446744073709551616 by trivial.
conseq (ph_keccak_h r8 ol (W8.of_int t) mem0 p0 l0) => &hr [#] hg -> -> -> -> ->.
have h1 : to_uint (W64.of_int r8) = r8 by rewrite W64.to_uint_small /#.
have h2 : to_uint (W64.of_int ol) = ol by rewrite W64.to_uint_small /#.
have h3 := SHA256_Stream.trunc_const t _; first smt().
by rewrite h1 h2 h3 /=; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Termination                                                        *)

lemma ph_keccak_init_ll : islossless M.__keccak_init.
proof. by proc*; call ph_keccak_init_total; auto. qed.

lemma ph_absorb_ll : phoare [M._keccak_absorb_mem : to_uint pos < to_uint rate ==> true] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._keccak_absorb_mem(st{m}, pos{m}, rate{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._keccak_absorb_mem(st{m}, pos{m}, rate{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
byphoare (Sponge.keccak_absorb_mem_ll Keccakf1600_Pair.keccakf1600_correct Keccakf1600_Pair.keccakf1600_ll) => //.
qed.

lemma ph_finalize_ll : islossless M._keccak_finalize.
proof.
bypr => &m _.
have -> : Pr[M._keccak_finalize(st{m}, pos{m}, rate{m}, ds{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._keccak_finalize(st{m}, pos{m}, rate{m}, ds{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact (Sponge.keccak_finalize_ll Keccakf1600_Pair.keccakf1600_correct Keccakf1600_Pair.keccakf1600_ll).
qed.

lemma ph_keccak_ll :
  phoare [M._ph_keccak : 0 < to_uint rate < 200 /\ to_uint outlen <= 64 ==> true] = 1%r.
proof.
proc; wp.
while (to_uint i <= to_uint outlen /\ to_uint outlen <= 64 /\ more = (i \ult outlen))
      (to_uint outlen - to_uint i).
+ move=> z; wp; skip => &hr [#] h1 h2 hm hc hz.
  have hlt : i{hr} \ult outlen{hr} by rewrite -hm.
  move: hlt; rewrite W64.ultE => hlt.
  have hi := Sponge.inc1 i{hr} _; first smt().
  by rewrite /= hi; smt().
wp; call ph_finalize_ll; wp; call ph_absorb_ll; wp; call ph_keccak_init_ll.
auto => &hr [h0 h1]; rewrite /Jslh.SLH64.protect_64 /=.
split; first smt().
move=> r0; split; first smt(W64.to_uint_cmp).
by move=> i1 more0 [#] hi hl -> hv; rewrite W64.ultE; smt().
qed.

lemma prehash_ll : islossless M._prehash.
proof.
proc.
while (true) (inc - i); first by move=> z; auto => /#.
wp; sp; if; first by wp; call ph_sha256_ll; auto => /#.
sp; if; first by wp; call ph_sha384_ll; auto => /#.
sp; if; first by wp; call ph_sha512_ll; auto => /#.
sp; if; first by wp; call ph_sha224_ll; auto => /#.
sp; if; first by wp; call ph_sha512_224_ll; auto => /#.
sp; if; first by wp; call ph_sha512_256_ll; auto => /#.
sp; if; first by wp; call ph_keccak_ll; auto => /#.
sp; if; first by wp; call ph_keccak_ll; auto => /#.
sp; if; first by wp; call ph_keccak_ll; auto => /#.
sp; if; first by wp; call ph_keccak_ll; auto => /#.
sp; if; first by wp; call ph_keccak_ll; auto => /#.
by wp; call ph_keccak_ll; auto => /#.
qed.

(* ------------------------------------------------------------------ *)
(* _prehash                                                           *)

lemma sel_eq (s : W64.t) (k : int) : 0 <= k < 256 => (s = W64.of_int k) <=> (to_uint s = k).
proof.
move=> hk; have hm : W64.modulus = 18446744073709551616 by trivial.
by rewrite W64.to_uint_eq W64.of_uintK; smt(pmod_small).
qed.

(* The SHA-256 and SHA-224 states are written to the low half of d. *)
lemma take_set_sub (d : BArray64.t) (a : BArray32.t) (n : int) : 0 <= n <= 32 =>
  take n (BArray64.to_list (SBArray64_32.set_sub d 0 a)) = take n (BArray32.to_list a).
proof.
move=> hn; apply (eq_from_nth W8.zero).
+ by rewrite !size_take 1,2:/# BArray64.size_to_list BArray32.size_to_list /#.
move=> j; rewrite size_take 1:/# BArray64.size_to_list => hj.
rewrite !nth_take 1..4:/# BArray64.get_to_list BArray32.get_to_list SBArray64_32.get8_set_sub /#.
qed.

lemma take64 (d : BArray64.t) : take 64 (BArray64.to_list d) = BArray64.to_list d.
proof. by rewrite take_oversize // BArray64.size_to_list. qed.

lemma take32 (a : BArray32.t) : take 32 (BArray32.to_list a) = BArray32.to_list a.
proof. by rewrite take_oversize // BArray32.size_to_list. qed.

(* The function of each selector (ph_of), in the form the kernels compute. *)
lemma ph1 M : ph_apply (ph_of 1) M = SHA256.sha256 M.          proof. by rewrite /ph_of /=. qed.
lemma ph2 M : ph_apply (ph_of 2) M = SHA512.sha384 M.          proof. by rewrite /ph_of /=. qed.
lemma ph3 M : ph_apply (ph_of 3) M = SHA512.sha512 M.          proof. by rewrite /ph_of /=. qed.
lemma ph4 M : ph_apply (ph_of 4) M = SHA256.sha224 M.          proof. by rewrite /ph_of /=. qed.
lemma ph5 M : ph_apply (ph_of 5) M = SHA512.sha512_224 M.      proof. by rewrite /ph_of /=. qed.
lemma ph6 M : ph_apply (ph_of 6) M = SHA512.sha512_256 M.      proof. by rewrite /ph_of /=. qed.
lemma ph7 M : ph_apply (ph_of 7) M = KECCAK1600 144 M (W8.of_int 6) 28.
proof. by rewrite /ph_of /= sha3_224E /SHA3_224 /c448_r8 /SHA3_DS_BYTE. qed.
lemma ph8 M : ph_apply (ph_of 8) M = KECCAK1600 136 M (W8.of_int 6) 32.
proof. by rewrite /ph_of /= sha3_256E /SHA3_256 /c512_r8 /SHA3_DS_BYTE. qed.
lemma ph9 M : ph_apply (ph_of 9) M = KECCAK1600 104 M (W8.of_int 6) 48.
proof. by rewrite /ph_of /= sha3_384E /SHA3_384 /c768_r8 /SHA3_DS_BYTE. qed.
lemma ph10 M : ph_apply (ph_of 10) M = KECCAK1600 72 M (W8.of_int 6) 64.
proof. by rewrite /ph_of /= sha3_512E /SHA3_512 /c1024_r8 /SHA3_DS_BYTE. qed.
lemma ph11 M : ph_apply (ph_of 11) M = KECCAK1600 168 M (W8.of_int 31) 32.
proof. by rewrite /ph_of /= (_ : 256 = 8 * 32) // shake128E /SHAKE128 /c256_r8 /SHAKE_DS_BYTE. qed.
lemma ph12 M : ph_apply (ph_of 12) M = KECCAK1600 136 M (W8.of_int 31) 64.
proof. by rewrite /ph_of /= (_ : 512 = 8 * 64) // shake256E /SHAKE256 /c512_r8 /SHAKE_DS_BYTE. qed.

lemma prehash_h (s p0 l0 : W64.t) (mem0 : global_mem_t) :
  hoare [M._prehash :
    sel = s /\ msg = p0 /\ msg_len = l0 /\ Glob.mem = mem0 /\
    1 <= to_uint s <= 12 /\ to_uint p0 + to_uint l0 <= W64.modulus /\ ph_dom (to_uint s) p0 l0 ==>
    take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 p0 l0)].
proof.
case: (1 <= to_uint s <= 12 /\ to_uint p0 + to_uint l0 <= W64.modulus /\ ph_dom (to_uint s) p0 l0);
  last by move=> hn; conseq (_ : false ==> _) => // &hr [#] *; smt().
move=> [#] hr0 hr1 hb hd.
have hsha : to_uint s <= 6 => to_uint p0 + to_uint l0 < W64.modulus /\ to_uint l0 < 2 ^ 61.
+ by move=> h6; apply hd => /#.
proc.
(* the 8-word copy d -> ph *)
seq 3 : (take (to_uint len) (BArray64.to_list d) = ph_apply (ph_of (to_uint s)) (m_of mem0 p0 l0) /\
         to_uint len <= 64); last first.
+ wp; while (inc = 8 /\ 0 <= i <= 8 /\ forall x, 0 <= x < i => BArray64.get64 ph x = BArray64.get64 d x).
  + wp; skip => &hr [#] hi hi0 hi1 hx hlt.
    split; first smt(). split; first smt().
    move=> j hj.
    rewrite BArray64.get_set64E 1,2:/#.
    by case: (i{hr} = j) => // hne; apply hx => /#.
  wp; skip => &hr [#] htk hl /=; split; first smt().
  move=> i1 ph1' hni [#] hi0 hi1 hx.
  have -> // : ph1' = d{hr}.
  by apply BArray64.ext_eq64 => x hx0; apply hx => /#.
conseq (_ : sel = s /\ msg = p0 /\ msg_len = l0 /\ Glob.mem = mem0 ==> _) => //.
have : to_uint s = 1 \/ to_uint s = 2 \/ to_uint s = 3 \/ to_uint s = 4 \/ to_uint s = 5 \/ to_uint s = 6 \/
       to_uint s = 7 \/ to_uint s = 8 \/ to_uint s = 9 \/ to_uint s = 10 \/ to_uint s = 11 \/ to_uint s = 12.
+ smt().
case=> [hs|[hs|[hs|[hs|[hs|[hs|[hs|[hs|[hs|[hs|[hs|hs]]]]]]]]]]].
+ rcondt 3; first by auto => />; rewrite sel_eq // hs.
  have [hb1 hb2] := hsha _; first by rewrite hs.
  wp; call (ph_sha256_h p0 l0 hb1 hb2); auto => /> r hq.
  by rewrite take_set_sub // take32 hq hs ph1 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondt 5; first by auto => />; rewrite sel_eq // hs.
  have [hb1 hb2] := hsha _; first by rewrite hs.
  wp; call (ph_sha384_h p0 l0 hb1 hb2); auto => /> r hq.
  by rewrite hq hs ph2 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondt 7; first by auto => />; rewrite sel_eq // hs.
  have [hb1 hb2] := hsha _; first by rewrite hs.
  wp; call (ph_sha512_h p0 l0 hb1 hb2); auto => /> r hq.
  by rewrite take64 hq hs ph3 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondt 9; first by auto => />; rewrite sel_eq // hs.
  have [hb1 hb2] := hsha _; first by rewrite hs.
  wp; call (ph_sha224_h p0 l0 hb1 hb2); auto => /> r hq.
  by rewrite take_set_sub // hq hs ph4 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondf 9; first by auto => />; rewrite sel_eq // hs.
  rcondt 11; first by auto => />; rewrite sel_eq // hs.
  have [hb1 hb2] := hsha _; first by rewrite hs.
  wp; call (ph_sha512_224_h p0 l0 hb1 hb2); auto => /> r hq.
  by rewrite hq hs ph5 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondf 9; first by auto => />; rewrite sel_eq // hs.
  rcondf 11; first by auto => />; rewrite sel_eq // hs.
  rcondt 13; first by auto => />; rewrite sel_eq // hs.
  have [hb1 hb2] := hsha _; first by rewrite hs.
  wp; call (ph_sha512_256_h p0 l0 hb1 hb2); auto => /> r hq.
  by rewrite hq hs ph6 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondf 9; first by auto => />; rewrite sel_eq // hs.
  rcondf 11; first by auto => />; rewrite sel_eq // hs.
  rcondf 13; first by auto => />; rewrite sel_eq // hs.
  rcondt 15; first by auto => />; rewrite sel_eq // hs.
  have hk := ph_keccak_c 144 28 6 mem0 p0 l0 hb _; first by [].
  wp; call hk; auto => /> r hq.
  by rewrite hq hs ph7 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondf 9; first by auto => />; rewrite sel_eq // hs.
  rcondf 11; first by auto => />; rewrite sel_eq // hs.
  rcondf 13; first by auto => />; rewrite sel_eq // hs.
  rcondf 15; first by auto => />; rewrite sel_eq // hs.
  rcondt 17; first by auto => />; rewrite sel_eq // hs.
  have hk := ph_keccak_c 136 32 6 mem0 p0 l0 hb _; first by [].
  wp; call hk; auto => /> r hq.
  by rewrite hq hs ph8 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondf 9; first by auto => />; rewrite sel_eq // hs.
  rcondf 11; first by auto => />; rewrite sel_eq // hs.
  rcondf 13; first by auto => />; rewrite sel_eq // hs.
  rcondf 15; first by auto => />; rewrite sel_eq // hs.
  rcondf 17; first by auto => />; rewrite sel_eq // hs.
  rcondt 19; first by auto => />; rewrite sel_eq // hs.
  have hk := ph_keccak_c 104 48 6 mem0 p0 l0 hb _; first by [].
  wp; call hk; auto => /> r hq.
  by rewrite hq hs ph9 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondf 9; first by auto => />; rewrite sel_eq // hs.
  rcondf 11; first by auto => />; rewrite sel_eq // hs.
  rcondf 13; first by auto => />; rewrite sel_eq // hs.
  rcondf 15; first by auto => />; rewrite sel_eq // hs.
  rcondf 17; first by auto => />; rewrite sel_eq // hs.
  rcondf 19; first by auto => />; rewrite sel_eq // hs.
  rcondt 21; first by auto => />; rewrite sel_eq // hs.
  have hk := ph_keccak_c 72 64 6 mem0 p0 l0 hb _; first by [].
  wp; call hk; auto => /> r hq.
  by rewrite hq hs ph10 /m_of.
+ rcondf 3; first by auto => />; rewrite sel_eq // hs.
  rcondf 5; first by auto => />; rewrite sel_eq // hs.
  rcondf 7; first by auto => />; rewrite sel_eq // hs.
  rcondf 9; first by auto => />; rewrite sel_eq // hs.
  rcondf 11; first by auto => />; rewrite sel_eq // hs.
  rcondf 13; first by auto => />; rewrite sel_eq // hs.
  rcondf 15; first by auto => />; rewrite sel_eq // hs.
  rcondf 17; first by auto => />; rewrite sel_eq // hs.
  rcondf 19; first by auto => />; rewrite sel_eq // hs.
  rcondf 21; first by auto => />; rewrite sel_eq // hs.
  rcondt 23; first by auto => />; rewrite sel_eq // hs.
  have hk := ph_keccak_c 168 32 31 mem0 p0 l0 hb _; first by [].
  wp; call hk; auto => /> r hq.
  by rewrite hq hs ph11 /m_of.
rcondf 3; first by auto => />; rewrite sel_eq // hs.
rcondf 5; first by auto => />; rewrite sel_eq // hs.
rcondf 7; first by auto => />; rewrite sel_eq // hs.
rcondf 9; first by auto => />; rewrite sel_eq // hs.
rcondf 11; first by auto => />; rewrite sel_eq // hs.
rcondf 13; first by auto => />; rewrite sel_eq // hs.
rcondf 15; first by auto => />; rewrite sel_eq // hs.
rcondf 17; first by auto => />; rewrite sel_eq // hs.
rcondf 19; first by auto => />; rewrite sel_eq // hs.
rcondf 21; first by auto => />; rewrite sel_eq // hs.
rcondf 23; first by auto => />; rewrite sel_eq // hs.
have hk := ph_keccak_c 136 64 31 mem0 p0 l0 hb _; first by [].
wp; call hk; auto => /> r hq.
by rewrite hq hs ph12 /m_of.
qed.

lemma prehash_total (s p0 l0 : W64.t) (mem0 : global_mem_t) :
  phoare [M._prehash :
    sel = s /\ msg = p0 /\ msg_len = l0 /\ Glob.mem = mem0 /\
    1 <= to_uint s <= 12 /\ to_uint p0 + to_uint l0 <= W64.modulus /\ ph_dom (to_uint s) p0 l0 ==>
    take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 p0 l0)] = 1%r.
proof. by conseq prehash_ll (prehash_h s p0 l0 mem0). qed.
