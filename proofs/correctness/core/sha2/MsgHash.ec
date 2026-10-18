(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * MsgHash.ec (SHA2 sets)
 * ======================
 *
 * PRF_msg of the SHA2 parameter sets (FIPS 205 section 11.2): _prf_msg
 * computes PRF_msg on the message M = prefix[0 : prefix_len] ||
 * mem[msg : msg + msg_len] of Internal.ec (slh_msg).
 *
 * The message hashes stream their input through the SHA-256 or SHA-512
 * state (h, buf, total) of the hash layer: buf holds the total mod b
 * bytes after the last complete block (SHA256_Stream.ec,
 * SHA512_Stream.ec). A short head goes into the empty buffer first;
 * __sha*_absorb_prefix then appends the prefix byte by byte, compressing
 * each full block, and _sha*_absorb_mem the message from memory, so the
 * state is the stream state of head || M (absorb_message*_h). For
 * PRF_msg the inner message of HMAC is K0 xor ipad || opt_rand || M, K0
 * the key SK.prf padded with zeros to one block (FIPS 198-1 section 4,
 * step 3): __hmac_sha*_init compresses its first block, opt_rand is the
 * head, and __hmac_sha*_finalize returns HMAC(SK.prf, opt_rand || M); R
 * is its first n bytes.
 *
 * Hash layer. The model of a set carries its own copy of the hash layer
 * procedures; the theorems of the pair's hash model (HashExtracted) on
 * the streaming, HMAC and initialisation procedures are moved to that
 * copy by an equivalence of the two procedures (proc; sim), as in
 * HashKernels.ec.
 *
 * Domain. The SHA-2 theorems hold for inputs of fewer than 2^61 bytes
 * whose memory part ends below 2^64: the SHA2 part of msg_ok
 * (Internal.sha2_msg_ok).
 *
 * Model. As Thash.ec: checked against the model of each SHA2 set. The
 * branch of _prf_msg on SHA2_WIDE is a literal in each model, so only
 * one branch is reachable; prf_msg_narrow_h (n = 16, SHA-256) and
 * prf_msg_wide_h (n = 24 and 32, SHA-512) prove both branches on every
 * set, the dead one from the contradiction between its condition on n
 * and n_val.
 *
 * Theorems (total correctness):
 *     absorb_prefix256_h, absorb_prefix512_h
 *                       __sha*_absorb_prefix appends the prefix to the
 *                       stream (Hoare; termination: *_ll);
 *     absorb_message256_h, absorb_message512_h
 *                       the prefix, then the message from memory;
 *     prf_msg_correct   _prf_msg returns PRF_msg(SK.prf, opt_rand, M),
 *                       every input with msg_ok. Its statement is the
 *                       PRF_msg premise of Internal.ec.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils JMemory Jslh.
require import Bytes FIPS180_SHA2 FIPS180_SHA2_Blocks FIPS198_HMAC FIPS205_Params FIPS205_Hash.
require import BArray32 BArray64 BArray128 SetModel CoreExtracted.
require import JWordList Internal Thash HashKernels.
require import SBArray128_64.
require HashExtracted SHA256_Compress SHA512_Compress SHA256_Stream SHA512_Stream.
require HMAC_SHA256 HMAC_SHA512.

(* ------------------------------------------------------------------ *)
(* The hash layer procedures of the set's model                       *)

lemma sha256_init_total : phoare [M.__sha256_init : true ==> hw256 res = SHA256.H0_256] = 1%r.
proof.
bypr => &m _.
have -> : Pr[M.__sha256_init(h{m}) @ &m : hw256 res = SHA256.H0_256] =
          Pr[HashExtracted.M.__sha256_init(h{m}) @ &m : hw256 res = SHA256.H0_256].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
byphoare (_ : true ==> hw256 res = SHA256.H0_256) => //.
by conseq SHA256_Stream.sha256_init_ll SHA256_Stream.sha256_init_correct.
qed.

lemma sha512_init_total : phoare [M.__sha512_init : true ==> hw512 res = SHA512.H0_512] = 1%r.
proof.
bypr => &m _.
have -> : Pr[M.__sha512_init(h{m}) @ &m : hw512 res = SHA512.H0_512] =
          Pr[HashExtracted.M.__sha512_init(h{m}) @ &m : hw512 res = SHA512.H0_512].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
byphoare (_ : true ==> hw512 res = SHA512.H0_512) => //.
by conseq SHA512_Stream.sha512_init_ll SHA512_Stream.sha512_init_correct.
qed.

lemma sha256_absorb_mem_total (h0 : W32.t list) (m : bytes) (p0 l0 : W64.t) :
  phoare [M._sha256_absorb_mem :
           SHA256_Stream.stream256 h0 m h buf total /\ in_0 = p0 /\ inlen = l0 /\
           to_uint p0 + to_uint l0 < W64.modulus /\ size m + to_uint l0 < W64.modulus ==>
           SHA256_Stream.stream256 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
             res.`1 res.`2 res.`3] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha256_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               SHA256_Stream.stream256 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
                 res.`1 res.`2 res.`3] =
          Pr[HashExtracted.M._sha256_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               SHA256_Stream.stream256 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
                 res.`1 res.`2 res.`3].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA256_Stream.sha256_absorb_mem_total h0 m p0 l0).
qed.

lemma sha512_absorb_mem_total (h0 : W64.t list) (m : bytes) (p0 l0 : W64.t) :
  phoare [M._sha512_absorb_mem :
           SHA512_Stream.stream512 h0 m h buf total /\ in_0 = p0 /\ inlen = l0 /\
           to_uint p0 + to_uint l0 < W64.modulus /\ size m + to_uint l0 < W64.modulus ==>
           SHA512_Stream.stream512 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
             res.`1 res.`2 res.`3] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha512_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               SHA512_Stream.stream512 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
                 res.`1 res.`2 res.`3] =
          Pr[HashExtracted.M._sha512_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m :
               SHA512_Stream.stream512 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
                 res.`1 res.`2 res.`3].
+ by byequiv (_ : ={arg, Glob.mem} ==> ={res, Glob.mem}) => //; proc; sim.
by byphoare (SHA512_Stream.sha512_absorb_mem_total h0 m p0 l0).
qed.

lemma sha256_finalize_total (h0 : W32.t list) (m : bytes) :
  phoare [M._sha256_finalize :
           SHA256_Stream.stream256 h0 m h buf total /\ size m < 2^61 ==>
           BArray32.to_list res.`1 = flatten (map w32_be (SHA256.hash h0 m))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha256_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m :
               BArray32.to_list res.`1 = flatten (map w32_be (SHA256.hash h0 m))] =
          Pr[HashExtracted.M._sha256_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m :
               BArray32.to_list res.`1 = flatten (map w32_be (SHA256.hash h0 m))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (SHA256_Stream.sha256_finalize_total h0 m).
qed.

lemma sha512_finalize_total (h0 : W64.t list) (m : bytes) :
  phoare [M._sha512_finalize :
           SHA512_Stream.stream512 h0 m h buf total /\ size m < 2^61 ==>
           BArray64.to_list res.`1 = flatten (map w64_be (SHA512.hash h0 m))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M._sha512_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m :
               BArray64.to_list res.`1 = flatten (map w64_be (SHA512.hash h0 m))] =
          Pr[HashExtracted.M._sha512_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m :
               BArray64.to_list res.`1 = flatten (map w64_be (SHA512.hash h0 m))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (SHA512_Stream.sha512_finalize_total h0 m).
qed.

lemma hmac_sha256_init_total (K : BArray64.t) :
  phoare [M.__hmac_sha256_init :
           k0 = K ==>
           hw256 res.`1 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (ipad 64))) /\
           hw256 res.`2 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (opad 64)))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__hmac_sha256_init(inner{m}, outer{m}, k0{m}, ms{m}) @ &m :
           hw256 res.`1 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (ipad 64))) /\
           hw256 res.`2 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (opad 64)))] =
          Pr[HashExtracted.M.__hmac_sha256_init(inner{m}, outer{m}, k0{m}, ms{m}) @ &m :
           hw256 res.`1 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (ipad 64))) /\
           hw256 res.`2 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (opad 64)))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (HMAC_SHA256.hmac_sha256_init_total K).
qed.

lemma hmac_sha512_init_total (K : BArray128.t) :
  phoare [M.__hmac_sha512_init :
           k0 = K ==>
           hw512 res.`1 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (ipad 128))) /\
           hw512 res.`2 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (opad 128)))] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__hmac_sha512_init(inner{m}, outer{m}, k0{m}, ms{m}) @ &m :
           hw512 res.`1 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (ipad 128))) /\
           hw512 res.`2 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (opad 128)))] =
          Pr[HashExtracted.M.__hmac_sha512_init(inner{m}, outer{m}, k0{m}, ms{m}) @ &m :
           hw512 res.`1 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (ipad 128))) /\
           hw512 res.`2 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (opad 128)))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (HMAC_SHA512.hmac_sha512_init_total K).
qed.

lemma hmac_sha256_finalize_total (ib ob text : bytes) : size ob = 64 =>
  phoare [M.__hmac_sha256_finalize :
           SHA256_Stream.stream256 SHA256.H0_256 (ib ++ text) inner buf total /\
           hw256 outer = SHA256.compress SHA256.H0_256 (words256 ob) /\ size (ib ++ text) < 2^61 ==>
           BArray32.to_list res.`1 = SHA256.sha256 (ob ++ SHA256.sha256 (ib ++ text))] = 1%r.
proof.
move=> hob; bypr => &m h.
have -> : Pr[M.__hmac_sha256_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m :
               BArray32.to_list res.`1 = SHA256.sha256 (ob ++ SHA256.sha256 (ib ++ text))] =
          Pr[HashExtracted.M.__hmac_sha256_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m :
               BArray32.to_list res.`1 = SHA256.sha256 (ob ++ SHA256.sha256 (ib ++ text))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (HMAC_SHA256.hmac_sha256_finalize_total ib ob text hob).
qed.

lemma hmac_sha512_finalize_total (ib ob text : bytes) : size ob = 128 =>
  phoare [M.__hmac_sha512_finalize :
           SHA512_Stream.stream512 SHA512.H0_512 (ib ++ text) inner buf total /\
           hw512 outer = SHA512.compress SHA512.H0_512 (words512 ob) /\ size (ib ++ text) < 2^61 ==>
           BArray64.to_list res.`1 = SHA512.sha512 (ob ++ SHA512.sha512 (ib ++ text))] = 1%r.
proof.
move=> hob; bypr => &m h.
have -> : Pr[M.__hmac_sha512_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m :
               BArray64.to_list res.`1 = SHA512.sha512 (ob ++ SHA512.sha512 (ib ++ text))] =
          Pr[HashExtracted.M.__hmac_sha512_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m :
               BArray64.to_list res.`1 = SHA512.sha512 (ob ++ SHA512.sha512 (ib ++ text))].
+ by byequiv (_ : ={arg} ==> ={res}) => //; proc; sim.
by byphoare (HMAC_SHA512.hmac_sha512_finalize_total ib ob text hob).
qed.

lemma compress256_h (h0 : W32.t list) (blk : BArray64.t) :
  hoare [M._sha256_compress : hw256 h = h0 /\ block = blk ==>
         hw256 res.`1 = SHA256.compress h0 (map be32 (chunk 4 (BArray64.to_list blk)))].
proof. by conseq (sha256_compress_total h0 blk). qed.

lemma compress512_h (h0 : W64.t list) (blk : BArray128.t) :
  hoare [M._sha512_compress : hw512 h = h0 /\ block = blk ==>
         hw512 res.`1 = SHA512.compress h0 (map be64 (chunk 8 (BArray128.to_list blk)))].
proof. by conseq (sha512_compress_total h0 blk). qed.

lemma set_compress256_ll : islossless M._sha256_compress.
proof. by proc*; ecall (sha256_compress_total (hw256 h) block); auto. qed.

lemma set_compress512_ll : islossless M._sha512_compress.
proof. by proc*; ecall (sha512_compress_total (hw512 h) block); auto. qed.

(* ------------------------------------------------------------------ *)
(* The prefix, byte by byte                                           *)

lemma prefix_size : Prefix.size = 332 by [].

lemma inc_small (i : W64.t) : to_uint i + 1 < W64.modulus => to_uint (i + W64.one) = to_uint i + 1.
proof. by move=> h; rewrite W64.to_uintD_small W64.to_uint1. qed.

lemma c63 : to_uint (W64.of_int 63) = 63 by rewrite W64.of_uintK.
lemma c127 : to_uint (W64.of_int 127) = 127 by rewrite W64.of_uintK.

(* One prefix byte b after the stream of y: the block closes when y ends
   one byte short of it, otherwise b joins the pending bytes. *)
lemma step_full256 h0 (y : bytes) b (buf : BArray64.t) (hv : W32.t list) :
  hv = foldl SHA256.compress h0 (SHA256.parse y) =>
  SHA256_Stream.pending buf (rcons (SHA256_Stream.tail256 y) b) =>
  size y %% 64 = 63 =>
  SHA256.compress hv (map be32 (chunk 4 (BArray64.to_list buf)))
  = foldl SHA256.compress h0 (SHA256.parse (y ++ [b])) /\
  SHA256_Stream.tail256 (y ++ [b]) = [].
proof.
move=> -> hp h63.
have hbl : BArray64.to_list buf = SHA256_Stream.tail256 y ++ [b].
+ apply SHA256_Stream.pending_full; first by rewrite cats1.
  by rewrite size_cat SHA256_Stream.size_tail256 /= h63.
exact (SHA256_Stream.close_block h0 y [b] buf hbl).
qed.

lemma step_short256 h0 (y : bytes) b (buf : BArray64.t) :
  size y %% 64 <> 63 =>
  SHA256_Stream.pending buf (rcons (SHA256_Stream.tail256 y) b) =>
  foldl SHA256.compress h0 (SHA256.parse (y ++ [b])) = foldl SHA256.compress h0 (SHA256.parse y) /\
  SHA256_Stream.pending buf (SHA256_Stream.tail256 (y ++ [b])).
proof.
move=> h63 hp.
have hs : size (SHA256_Stream.tail256 y ++ [b]) < 64.
+ by rewrite size_cat SHA256_Stream.size_tail256 /=; smt(modz_cmp).
have [-> ->] := SHA256_Stream.short_ext y [b] hs.
by rewrite cats1.
qed.

lemma step_full512 h0 (y : bytes) b (buf : BArray128.t) (hv : W64.t list) :
  hv = foldl SHA512.compress h0 (SHA512.parse y) =>
  SHA512_Stream.pending buf (rcons (SHA512_Stream.tail512 y) b) =>
  size y %% 128 = 127 =>
  SHA512.compress hv (map be64 (chunk 8 (BArray128.to_list buf)))
  = foldl SHA512.compress h0 (SHA512.parse (y ++ [b])) /\
  SHA512_Stream.tail512 (y ++ [b]) = [].
proof.
move=> -> hp h127.
have hbl : BArray128.to_list buf = SHA512_Stream.tail512 y ++ [b].
+ apply SHA512_Stream.pending_full; first by rewrite cats1.
  by rewrite size_cat SHA512_Stream.size_tail512 /= h127.
exact (SHA512_Stream.close_block h0 y [b] buf hbl).
qed.

lemma step_short512 h0 (y : bytes) b (buf : BArray128.t) :
  size y %% 128 <> 127 =>
  SHA512_Stream.pending buf (rcons (SHA512_Stream.tail512 y) b) =>
  foldl SHA512.compress h0 (SHA512.parse (y ++ [b])) = foldl SHA512.compress h0 (SHA512.parse y) /\
  SHA512_Stream.pending buf (SHA512_Stream.tail512 (y ++ [b])).
proof.
move=> h127 hp.
have hs : size (SHA512_Stream.tail512 y ++ [b]) < 128.
+ by rewrite size_cat SHA512_Stream.size_tail512 /=; smt(modz_cmp).
have [-> ->] := SHA512_Stream.short_ext y [b] hs.
by rewrite cats1.
qed.

lemma take_step (x : Prefix.t) (m0 : bytes) (i0 i : W64.t) :
  to_uint i = to_uint i0 + 1 => to_uint i0 < Prefix.size =>
  m0 ++ take (to_uint i) (Prefix.to_list x)
  = (m0 ++ take (to_uint i0) (Prefix.to_list x)) ++ [nth W8.zero (Prefix.to_list x) (to_uint i0)].
proof.
move=> hi hl; rewrite hi (take_nth W8.zero); first smt(W64.to_uint_cmp Prefix.size_to_list).
by rewrite -cats1 catA.
qed.

lemma absorb_prefix256_h (h0 : W32.t list) (m0 : bytes) (x0 : Prefix.t) (l0 : W64.t) :
  hoare [M.__sha256_absorb_prefix :
    SHA256_Stream.stream256 h0 m0 h buf total /\ prefix = x0 /\ len = l0 /\
    to_uint l0 <= Prefix.size /\ size m0 + Prefix.size < W64.modulus ==>
    SHA256_Stream.stream256 h0 (m0 ++ take (to_uint l0) (Prefix.to_list x0)) res.`1 res.`2 res.`3].
proof.
proc; wp.
while (SHA256_Stream.stream256 h0 (m0 ++ take (to_uint i) (Prefix.to_list x0)) h buf total /\
       prefix = x0 /\ len = l0 /\ to_uint i <= to_uint l0 /\ to_uint l0 <= Prefix.size /\
       size m0 + Prefix.size < W64.modulus /\ (more <=> to_uint i < to_uint l0)).
+ exlim i => i0.
  seq 8 : (prefix = x0 /\ len = l0 /\ to_uint l0 <= Prefix.size /\ size m0 + Prefix.size < W64.modulus /\
           to_uint i0 < to_uint l0 /\ to_uint i = to_uint i0 + 1 /\
           to_uint total = size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) + 1 /\
           hw256 h = foldl SHA256.compress h0 (SHA256.parse (m0 ++ take (to_uint i0) (Prefix.to_list x0))) /\
           SHA256_Stream.pending buf (rcons (SHA256_Stream.tail256 (m0 ++ take (to_uint i0) (Prefix.to_list x0)))
                                             (nth W8.zero (Prefix.to_list x0) (to_uint i0))) /\
           (full <=> size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) %% 64 = 63)).
  + wp; skip => &m; rewrite /SHA256_Stream.stream256 => [#] -> ht hh hp -> -> hil hl hs hmore hm0 /=.
    have hlt : to_uint i{m} < to_uint l0 by rewrite -hmore.
    have hsz : size (m0 ++ take (to_uint i{m}) (Prefix.to_list x0)) = size m0 + to_uint i{m}.
    + rewrite size_cat size_take; smt(W64.to_uint_cmp Prefix.size_to_list).
    have hf : to_uint (total{m} `&` W64.of_int 63) = size (m0 ++ take (to_uint i{m}) (Prefix.to_list x0)) %% 64.
    + by rewrite SHA256_Stream.and63 ht.
    have [_ hlm] := W64.to_uint_cmp l0.
    split; first exact hl. split; first exact hs. split; first exact hlt.
    split; first by apply inc_small; move: hlt hlm; pose M := W64.modulus; pose u := to_uint i{m}; smt().
    split.
    + rewrite inc_small ht //; move: hlt hl hs; rewrite hsz prefix_size.
      by pose M := W64.modulus; pose u := to_uint i{m}; smt().
    split; first exact hh.
    split.
    + rewrite SHA256_Stream.trunc_zext hf -SHA256_Stream.size_tail256.
      by apply SHA256_Stream.pending_rcons => //; rewrite SHA256_Stream.size_tail256; smt().
    rewrite -hf; split => h; first by rewrite h c63.
    by apply W64.to_uint_eq; rewrite h c63.
  if.
  + wp; ecall (compress256_h (hw256 h) buf); wp.
    skip => &m [#] -> -> hl hs hil hi ht hh hp hfull hc /= r hr; rewrite /SLH64.protect_ptr /SLH64.protect_64 /=.
    have hfl : size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) %% 64 = 63 by rewrite -hfull.
    have [hc1 htl] := step_full256 h0 _ _ _ _ hh hp hfl; move: hc1 htl => /= hc1 htl.
    rewrite (take_step x0 m0 i0 i{m} hi _); 1: smt().
    split; last by split; [smt() | split; [exact hl | split; [exact hs | by rewrite W64.ultE]]].
    rewrite /SHA256_Stream.stream256 /=; split; first by rewrite size_cat ht.
    split; first by rewrite -hc1 -hr.
    by rewrite htl; exact SHA256_Stream.pending_nil.
  wp; skip => &m [#] -> -> hl hs hil hi ht hh hp hfull hc /=.
  have hfl : size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) %% 64 <> 63 by rewrite -hfull.
  have [hc1 hp1] := step_short256 h0 _ _ _ hfl hp; move: hc1 hp1 => /= hc1 hp1.
  rewrite (take_step x0 m0 i0 i{m} hi _); 1: smt().
  split; last by split; [smt() | split; [exact hl | split; [exact hs | by rewrite W64.ultE]]].
  rewrite /SHA256_Stream.stream256 /=; split; first by rewrite size_cat ht.
  by rewrite hc1 -hh hp1.
wp; skip => &m [#] hst -> -> hl hs; move: hst => /= hst; split.
+ rewrite take0 cats0 hst /=; split; first smt(W64.to_uint_cmp).
  split; first exact hl. split; first exact hs. by rewrite W64.ultE.
move=> b1 h1 i1 l1 mo1 p1 t1 hmo [#] hst1 _ _ hil1 _ _ hiff.
have hil : to_uint i1 = to_uint l0 by smt().
by rewrite -hil.
qed.

lemma absorb_prefix512_h (h0 : W64.t list) (m0 : bytes) (x0 : Prefix.t) (l0 : W64.t) :
  hoare [M.__sha512_absorb_prefix :
    SHA512_Stream.stream512 h0 m0 h buf total /\ prefix = x0 /\ len = l0 /\
    to_uint l0 <= Prefix.size /\ size m0 + Prefix.size < W64.modulus ==>
    SHA512_Stream.stream512 h0 (m0 ++ take (to_uint l0) (Prefix.to_list x0)) res.`1 res.`2 res.`3].
proof.
proc; wp.
while (SHA512_Stream.stream512 h0 (m0 ++ take (to_uint i) (Prefix.to_list x0)) h buf total /\
       prefix = x0 /\ len = l0 /\ to_uint i <= to_uint l0 /\ to_uint l0 <= Prefix.size /\
       size m0 + Prefix.size < W64.modulus /\ (more <=> to_uint i < to_uint l0)).
+ exlim i => i0.
  seq 8 : (prefix = x0 /\ len = l0 /\ to_uint l0 <= Prefix.size /\ size m0 + Prefix.size < W64.modulus /\
           to_uint i0 < to_uint l0 /\ to_uint i = to_uint i0 + 1 /\
           to_uint total = size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) + 1 /\
           hw512 h = foldl SHA512.compress h0 (SHA512.parse (m0 ++ take (to_uint i0) (Prefix.to_list x0))) /\
           SHA512_Stream.pending buf (rcons (SHA512_Stream.tail512 (m0 ++ take (to_uint i0) (Prefix.to_list x0)))
                                             (nth W8.zero (Prefix.to_list x0) (to_uint i0))) /\
           (full <=> size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) %% 128 = 127)).
  + wp; skip => &m; rewrite /SHA512_Stream.stream512 => [#] -> ht hh hp -> -> hil hl hs hmore hm0 /=.
    have hlt : to_uint i{m} < to_uint l0 by rewrite -hmore.
    have hsz : size (m0 ++ take (to_uint i{m}) (Prefix.to_list x0)) = size m0 + to_uint i{m}.
    + rewrite size_cat size_take; smt(W64.to_uint_cmp Prefix.size_to_list).
    have hf : to_uint (total{m} `&` W64.of_int 127) = size (m0 ++ take (to_uint i{m}) (Prefix.to_list x0)) %% 128.
    + by rewrite SHA512_Stream.and127 ht.
    have [_ hlm] := W64.to_uint_cmp l0.
    split; first exact hl. split; first exact hs. split; first exact hlt.
    split; first by apply inc_small; move: hlt hlm; pose M := W64.modulus; pose u := to_uint i{m}; smt().
    split.
    + rewrite inc_small ht //; move: hlt hl hs; rewrite hsz prefix_size.
      by pose M := W64.modulus; pose u := to_uint i{m}; smt().
    split; first exact hh.
    split.
    + rewrite SHA512_Stream.trunc_zext hf -SHA512_Stream.size_tail512.
      by apply SHA512_Stream.pending_rcons => //; rewrite SHA512_Stream.size_tail512; smt().
    rewrite -hf; split => h; first by rewrite h c127.
    by apply W64.to_uint_eq; rewrite h c127.
  if.
  + wp; ecall (compress512_h (hw512 h) buf); wp.
    skip => &m [#] -> -> hl hs hil hi ht hh hp hfull hc /= r hr; rewrite /SLH64.protect_ptr /SLH64.protect_64 /=.
    have hfl : size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) %% 128 = 127 by rewrite -hfull.
    have [hc1 htl] := step_full512 h0 _ _ _ _ hh hp hfl; move: hc1 htl => /= hc1 htl.
    rewrite (take_step x0 m0 i0 i{m} hi _); 1: smt().
    split; last by split; [smt() | split; [exact hl | split; [exact hs | by rewrite W64.ultE]]].
    rewrite /SHA512_Stream.stream512 /=; split; first by rewrite size_cat ht.
    split; first by rewrite -hc1 -hr.
    by rewrite htl; exact SHA512_Stream.pending_nil.
  wp; skip => &m [#] -> -> hl hs hil hi ht hh hp hfull hc /=.
  have hfl : size (m0 ++ take (to_uint i0) (Prefix.to_list x0)) %% 128 <> 127 by rewrite -hfull.
  have [hc1 hp1] := step_short512 h0 _ _ _ hfl hp; move: hc1 hp1 => /= hc1 hp1.
  rewrite (take_step x0 m0 i0 i{m} hi _); 1: smt().
  split; last by split; [smt() | split; [exact hl | split; [exact hs | by rewrite W64.ultE]]].
  rewrite /SHA512_Stream.stream512 /=; split; first by rewrite size_cat ht.
  by rewrite hc1 -hh hp1.
wp; skip => &m [#] hst -> -> hl hs; move: hst => /= hst; split.
+ rewrite take0 cats0 hst /=; split; first smt(W64.to_uint_cmp).
  split; first exact hl. split; first exact hs. by rewrite W64.ultE.
move=> b1 h1 i1 l1 mo1 p1 t1 hmo [#] hst1 _ _ hil1 _ _ hiff.
have hil : to_uint i1 = to_uint l0 by smt().
by rewrite -hil.
qed.

(* ------------------------------------------------------------------ *)
(* The message after a head                                           *)

lemma absorb_mem256_h (h0 : W32.t list) (m : bytes) (p0 l0 : W64.t) :
  hoare [M._sha256_absorb_mem :
           SHA256_Stream.stream256 h0 m h buf total /\ in_0 = p0 /\ inlen = l0 /\
           to_uint p0 + to_uint l0 < W64.modulus /\ size m + to_uint l0 < W64.modulus ==>
           SHA256_Stream.stream256 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
             res.`1 res.`2 res.`3].
proof. by conseq (sha256_absorb_mem_total h0 m p0 l0). qed.

lemma absorb_mem512_h (h0 : W64.t list) (m : bytes) (p0 l0 : W64.t) :
  hoare [M._sha512_absorb_mem :
           SHA512_Stream.stream512 h0 m h buf total /\ in_0 = p0 /\ inlen = l0 /\
           to_uint p0 + to_uint l0 < W64.modulus /\ size m + to_uint l0 < W64.modulus ==>
           SHA512_Stream.stream512 h0 (m ++ memread Glob.mem (to_uint p0) (to_uint l0))
             res.`1 res.`2 res.`3].
proof. by conseq (sha512_absorb_mem_total h0 m p0 l0). qed.

lemma absorb_message256_h (h0 : W32.t list) (m0 : bytes) (x0 : Prefix.t) (pl m ml : W64.t)
  (mem0 : global_mem_t) :
  hoare [M.__sha256_absorb_message :
    SHA256_Stream.stream256 h0 m0 h buf total /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ to_uint pl <= Prefix.size /\
    to_uint m + to_uint ml < W64.modulus /\ size m0 + Prefix.size + to_uint ml < W64.modulus ==>
    Glob.mem = mem0 /\ SHA256_Stream.stream256 h0 (m0 ++ slh_msg mem0 x0 pl m ml) res.`1 res.`2 res.`3].
proof.
proc.
ecall (absorb_mem256_h h0 (m0 ++ take (to_uint pl) (Prefix.to_list x0)) m ml).
wp; ecall (absorb_prefix256_h h0 m0 x0 pl).
wp; skip => &m [#] hst -> -> -> -> -> hpl hm hs; move: hst hm hs => /= hst hm hs; rewrite /SLH64.protect_64 /=.
have [hml0 hml] := W64.to_uint_cmp ml; move: hml => /= hml.
split; first by split; [exact hst | split; [exact hpl | smt()]].
move=> _ r1 hr1; split.
+ split; first exact hr1.
  split; first exact hm.
  have h1 : size (take (to_uint pl) (Prefix.to_list x0)) <= Prefix.size.
  + rewrite size_take; first smt(W64.to_uint_cmp).
    by rewrite Prefix.size_to_list; smt().
  rewrite size_cat; move: hs h1; pose u := size m0; pose v := size (take (to_uint pl) (Prefix.to_list x0)).
  by pose w := to_uint ml; smt().
by move=> _ r2; rewrite /slh_msg catA.
qed.

lemma absorb_message512_h (h0 : W64.t list) (m0 : bytes) (x0 : Prefix.t) (pl m ml : W64.t)
  (mem0 : global_mem_t) :
  hoare [M.__sha512_absorb_message :
    SHA512_Stream.stream512 h0 m0 h buf total /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ to_uint pl <= Prefix.size /\
    to_uint m + to_uint ml < W64.modulus /\ size m0 + Prefix.size + to_uint ml < W64.modulus ==>
    Glob.mem = mem0 /\ SHA512_Stream.stream512 h0 (m0 ++ slh_msg mem0 x0 pl m ml) res.`1 res.`2 res.`3].
proof.
proc.
ecall (absorb_mem512_h h0 (m0 ++ take (to_uint pl) (Prefix.to_list x0)) m ml).
wp; ecall (absorb_prefix512_h h0 m0 x0 pl).
wp; skip => &m [#] hst -> -> -> -> -> hpl hm hs; move: hst hm hs => /= hst hm hs; rewrite /SLH64.protect_64 /=.
have [hml0 hml] := W64.to_uint_cmp ml; move: hml => /= hml.
split; first by split; [exact hst | split; [exact hpl | smt()]].
move=> _ r1 hr1; split.
+ split; first exact hr1.
  split; first exact hm.
  have h1 : size (take (to_uint pl) (Prefix.to_list x0)) <= Prefix.size.
  + rewrite size_take; first smt(W64.to_uint_cmp).
    by rewrite Prefix.size_to_list; smt().
  rewrite size_cat; move: hs h1; pose u := size m0; pose v := size (take (to_uint pl) (Prefix.to_list x0)).
  by pose w := to_uint ml; smt().
by move=> _ r2; rewrite /slh_msg catA.
qed.

(* A head of one compressed block and a short tail in the buffer. *)
lemma head_stream256 (ib o : bytes) (inner : BArray32.t) (buf : BArray64.t) (total : W64.t) :
  size ib = 64 => size o < 64 =>
  hw256 inner = SHA256.compress SHA256.H0_256 (words256 ib) =>
  to_uint total = 64 + size o => SHA256_Stream.pending buf o =>
  SHA256_Stream.stream256 SHA256.H0_256 (ib ++ o) inner buf total.
proof.
move=> hib ho hh ht hp.
have htl : SHA256_Stream.tail256 ib = [] by rewrite -size_eq0 SHA256_Stream.size_tail256 hib.
rewrite /SHA256_Stream.stream256 size_cat hib ht /=.
rewrite SHA256_Stream.parse_cat htl /= (SHA256_Stream.parse_short o) // cats0.
rewrite (SHA256_Stream.parse_block ib hib) /= SHA256_Stream.tail_cat htl /= SHA256_Stream.tail_short //.
qed.

lemma head_stream512 (ib o : bytes) (inner : BArray64.t) (buf : BArray128.t) (total : W64.t) :
  size ib = 128 => size o < 128 =>
  hw512 inner = SHA512.compress SHA512.H0_512 (words512 ib) =>
  to_uint total = 128 + size o => SHA512_Stream.pending buf o =>
  SHA512_Stream.stream512 SHA512.H0_512 (ib ++ o) inner buf total.
proof.
move=> hib ho hh ht hp.
have htl : SHA512_Stream.tail512 ib = [] by rewrite -size_eq0 SHA512_Stream.size_tail512 hib.
rewrite /SHA512_Stream.stream512 size_cat hib ht /=.
rewrite SHA512_Stream.parse_cat htl /= (SHA512_Stream.parse_short o) // cats0.
rewrite (SHA512_Stream.parse_block ib hib) /= SHA512_Stream.tail_cat htl /= SHA512_Stream.tail_short //.
qed.

(* ------------------------------------------------------------------ *)
(* PRF_msg                                                            *)

(* The key block K0 of FIPS 198-1 for a key shorter than the block. *)
op kb256 (s : bytes) : bytes = s ++ zeros (64 - size s).
op kb512 (s : bytes) : bytes = s ++ zeros (128 - size s).

lemma size_node (x : Node.t) : size (Node.to_list x) = P.`n.
proof. by rewrite Node.size_to_list; smt(n_val). qed.

lemma size_kb256 (s : bytes) : size s <= 64 => size (kb256 s) = 64.
proof. by move=> hs; rewrite /kb256 size_cat /zeros size_nseq /#. qed.

lemma size_kb512 (s : bytes) : size s <= 128 => size (kb512 s) = 128.
proof. by move=> hs; rewrite /kb512 size_cat /zeros size_nseq /#. qed.

lemma size_pad256 (s : Node.t) (c : W8.t) :
  size (xorb (kb256 (Node.to_list s)) (nseq 64 c)) = 64.
proof.
have hk := size_kb256 (Node.to_list s) _; first by rewrite size_node; smt(n_val).
by rewrite HMAC_SHA256.size_xorb hk // size_nseq.
qed.

lemma size_pad512 (s : Node.t) (c : W8.t) :
  size (xorb (kb512 (Node.to_list s)) (nseq 128 c)) = 128.
proof.
have hk := size_kb512 (Node.to_list s) _; first by rewrite size_node; smt(n_val).
by rewrite HMAC_SHA512.size_xorb hk // size_nseq.
qed.

lemma hmac256_kb (s text : bytes) : size s <= 64 =>
  hmac_sha256 s text
  = SHA256.sha256 (xorb (kb256 s) (opad 64) ++ SHA256.sha256 (xorb (kb256 s) (ipad 64) ++ text)).
proof. by move=> hs; rewrite HMAC_SHA256.hmac_sha256_blocks. qed.

lemma hmac512_kb (s text : bytes) : size s <= 128 =>
  hmac_sha512 s text
  = SHA512.sha512 (xorb (kb512 s) (opad 128) ++ SHA512.sha512 (xorb (kb512 s) (ipad 128) ++ text)).
proof. by move=> hs; rewrite HMAC_SHA512.hmac_sha512_blocks. qed.

(* k0 holds SK.prf and zeros: its first 64 bytes, and all 128, are K0. *)
lemma kblock256 (k : BArray128.t) (s0 : Node.t) :
  (forall j, 0 <= j < 128 => k.[j] = if j < P.`n then Node.get8 s0 j else W8.zero) =>
  BArray64.to_list (SBArray128_64.get_sub k 0) = kb256 (Node.to_list s0).
proof.
move=> hk; have hn := n_val; apply (eq_from_nth W8.zero).
+ have := size_kb256 (Node.to_list s0) _; first by rewrite size_node /#.
  by move=> ->; rewrite BArray64.size_to_list.
move=> j; rewrite BArray64.size_to_list => hj.
rewrite BArray64.get_to_list SBArray128_64.get8_get_sub ifT 1:/# /= hk 1:/# /kb256 nth_cat size_node.
case: (j < P.`n) => h; first by rewrite Node.get_to_list.
by rewrite /zeros nth_nseq /#.
qed.

lemma kblock512 (k : BArray128.t) (s0 : Node.t) :
  (forall j, 0 <= j < 128 => k.[j] = if j < P.`n then Node.get8 s0 j else W8.zero) =>
  BArray128.to_list k = kb512 (Node.to_list s0).
proof.
move=> hk; have hn := n_val; apply (eq_from_nth W8.zero).
+ have := size_kb512 (Node.to_list s0) _; first by rewrite size_node /#.
  by move=> ->; rewrite BArray128.size_to_list.
move=> j; rewrite BArray128.size_to_list => hj.
rewrite BArray128.get_to_list hk 1:/# /kb512 nth_cat size_node.
case: (j < P.`n) => h; first by rewrite Node.get_to_list.
by rewrite /zeros nth_nseq /#.
qed.

lemma hmac256_init_h (K : BArray64.t) :
  hoare [M.__hmac_sha256_init :
           k0 = K ==>
           hw256 res.`1 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (ipad 64))) /\
           hw256 res.`2 = SHA256.compress SHA256.H0_256 (words256 (xorb (BArray64.to_list K) (opad 64)))].
proof. by conseq (hmac_sha256_init_total K). qed.

lemma hmac512_init_h (K : BArray128.t) :
  hoare [M.__hmac_sha512_init :
           k0 = K ==>
           hw512 res.`1 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (ipad 128))) /\
           hw512 res.`2 = SHA512.compress SHA512.H0_512 (words512 (xorb (BArray128.to_list K) (opad 128)))].
proof. by conseq (hmac_sha512_init_total K). qed.

lemma hmac256_fin_h (ib ob text : bytes) : size ob = 64 =>
  hoare [M.__hmac_sha256_finalize :
           SHA256_Stream.stream256 SHA256.H0_256 (ib ++ text) inner buf total /\
           hw256 outer = SHA256.compress SHA256.H0_256 (words256 ob) /\ size (ib ++ text) < 2^61 ==>
           BArray32.to_list res.`1 = SHA256.sha256 (ob ++ SHA256.sha256 (ib ++ text))].
proof. by move=> hob; conseq (hmac_sha256_finalize_total ib ob text hob). qed.

lemma hmac512_fin_h (ib ob text : bytes) : size ob = 128 =>
  hoare [M.__hmac_sha512_finalize :
           SHA512_Stream.stream512 SHA512.H0_512 (ib ++ text) inner buf total /\
           hw512 outer = SHA512.compress SHA512.H0_512 (words512 ob) /\ size (ib ++ text) < 2^61 ==>
           BArray64.to_list res.`1 = SHA512.sha512 (ob ++ SHA512.sha512 (ib ++ text))].
proof. by move=> hob; conseq (hmac_sha512_finalize_total ib ob text hob). qed.

(* The bytes the SHA2 domain bounds. *)
lemma msg_sha2 (pl m ml : W64.t) : msg_ok pl m ml =>
  to_uint pl <= Prefix.size /\ to_uint m + to_uint ml < W64.modulus /\
  to_uint pl + to_uint ml < sha2_msg_max.
proof. by rewrite /msg_ok msg_domE family_sha2 /= /sha2_msg_ok. qed.

lemma size_slh_msg (mem : global_mem_t) (x : Prefix.t) (pl m ml : W64.t) : to_uint pl <= Prefix.size =>
  size (slh_msg mem x pl m ml) <= to_uint pl + to_uint ml.
proof.
move=> hpl; rewrite /slh_msg size_cat JWordList.size_memread; first smt(W64.to_uint_cmp).
rewrite size_take; first smt(W64.to_uint_cmp).
by rewrite Prefix.size_to_list; smt().
qed.

lemma prf_msg_narrow_h (s0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  P.`n = 16 =>
  hoare [M._prf_msg :
    sk_prf = s0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Node.to_list res.`1 = PRF_msg P (Node.to_list s0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)].
proof.
move=> hn16; have hn := n_val.
proc.
seq 15 : (opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
          msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
          forall j, 0 <= j < 128 => k0.[j] = if j < P.`n then Node.get8 s0 j else W8.zero).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ sk_prf = s0 /\
         forall j, 0 <= j < 128 => k0.[j] = if j < 8 * i then Node.get8 s0 j else W8.zero).
  + wp; skip => &m [#] h0 h1 hinc hs hj hlt; rewrite hs /=; do 3?(split; first smt()).
    move=> j hjr; rewrite BArray128.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj // /#.
  wp; while (0 <= i <= 16 /\ z = W64.zero /\ forall j, 0 <= j < 8 * i => k0.[j] = W8.zero).
  + wp; skip => &m [#] h0 h1 hz hj hlt; rewrite hz /=; do 2?(split; first smt()).
    move=> j hjr; rewrite BArray128.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h; first by rewrite ifT 1:/# W8u8.get_zero.
    by rewrite ifF 1:/# hj /#.
  wp; skip => &m [#] -> -> -> -> -> -> -> hok /=; split; first smt().
  move=> i0 k1 hlt [h0 hj]; split.
  + split; first smt().
    by move=> j hj'; rewrite ifF 1:/#; apply hj; smt().
  move=> i1 k2 hlt2 [#] g0 g1 _ gj; split; first exact hok.
  by move=> j hj'; rewrite gj //; smt().
if; last by conseq (_ : false ==> _) => //; smt().
(* the inner and outer chaining values of HMAC *)
seq 1 : (opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\
        Glob.mem = mem0 /\ msg_ok pl m ml /\
        hw256 inner = SHA256.compress SHA256.H0_256 (words256 (xorb (kb256 (Node.to_list s0)) (ipad 64))) /\
        hw256 outer = SHA256.compress SHA256.H0_256 (words256 (xorb (kb256 (Node.to_list s0)) (opad 64)))).
+ ecall (hmac256_init_h (SBArray128_64.get_sub k0 0)).
  skip => &m [#] -> -> -> -> -> -> hok hk _ /= r [h1 h2].
  by rewrite -(kblock256 k0{m} s0 hk) h1 h2.
(* opt_rand opens the inner message *)
seq 5 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
        SHA256_Stream.stream256 SHA256.H0_256
           (xorb (kb256 (Node.to_list s0)) (ipad 64) ++ Node.to_list o0) inner buf total /\
        hw256 outer = SHA256.compress SHA256.H0_256 (words256 (xorb (kb256 (Node.to_list s0)) (opad 64)))).
+ wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ opt_rand = o0 /\
            forall j, 0 <= j < 8 * i => buf.[j] = Node.get8 o0 j).
  + wp; skip => &m [#] h0 h1 hinc ho hj hlt; rewrite ho /=; do 3?(split; first smt()).
    move=> j hjr; rewrite BArray64.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj /#.
  wp; skip => &m [#] -> -> -> -> -> -> hok hi ho /=; rewrite /SLH64.protect_ptr /=; split; first smt().
  move=> b1 i1 hlt [#] g0 g1 _ gj; split; first exact hok.
  split; last exact ho.
  apply head_stream256.
  + exact (size_pad256 s0 (W8.of_int 0x36)).
  + by rewrite size_node /#.
  + exact hi.
  + by rewrite W64.of_uintK size_node /#.
  by move=> j hj; rewrite gj; [smt(size_node) | rewrite Node.get_to_list].
(* the prefix and the message *)
seq 2 : (Glob.mem = mem0 /\ msg_ok pl m ml /\
        SHA256_Stream.stream256 SHA256.H0_256
           ((xorb (kb256 (Node.to_list s0)) (ipad 64) ++ Node.to_list o0) ++ slh_msg mem0 x0 pl m ml)
           inner buf total /\
        hw256 outer = SHA256.compress SHA256.H0_256 (words256 (xorb (kb256 (Node.to_list s0)) (opad 64)))).
+ ecall (absorb_message256_h SHA256.H0_256 (xorb (kb256 (Node.to_list s0)) (ipad 64) ++ Node.to_list o0)
           x0 pl m ml mem0).
  wp; skip => &m [#] -> -> -> -> -> hok hst ho; rewrite /SLH64.protect_ptr /=.
  have [hpl [hm hml]] := msg_sha2 _ _ _ hok.
  move: hm => /= hm.
  have hsz : size (xorb (kb256 (Node.to_list s0)) (ipad 64) ++ Node.to_list o0) = 64 + P.`n.
  + by rewrite size_cat /ipad size_pad256 size_node.
  have [hml0 _] := W64.to_uint_cmp ml; have [hpl0 _] := W64.to_uint_cmp pl.
  split.
  + split; first exact hst. split; first exact hpl. split; first exact hm.
    rewrite hsz prefix_size; move: hml; rewrite /sha2_msg_max; smt(n_val).
  by move=> _ r hr; split; [exact hok | split].
(* the inner digest and the outer hash *)
seq 1 : (BArray32.to_list tag =
           SHA256.sha256 (xorb (kb256 (Node.to_list s0)) (opad 64) ++
             SHA256.sha256 (xorb (kb256 (Node.to_list s0)) (ipad 64) ++
               (Node.to_list o0 ++ slh_msg mem0 x0 pl m ml)))).
+ ecall (hmac256_fin_h (xorb (kb256 (Node.to_list s0)) (ipad 64)) (xorb (kb256 (Node.to_list s0)) (opad 64))
           (Node.to_list o0 ++ slh_msg mem0 x0 pl m ml) (size_pad256 s0 (W8.of_int 0x5c))).
  skip => &m [#] _ hok hst ho /=.
  have [hpl [hm hml]] := msg_sha2 _ _ _ hok.
  have hs := size_slh_msg mem0 x0 pl m ml hpl.
  split; first by rewrite catA.
  split; first exact ho.
  rewrite size_cat size_cat /ipad size_pad256 size_node; move: hml hs; rewrite /sha2_msg_max.
  by pose u := size (slh_msg mem0 x0 pl m ml); smt(n_val).
(* R = the first n bytes of the tag *)
wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\
           BArray32.to_list tag =
             SHA256.sha256 (xorb (kb256 (Node.to_list s0)) (opad 64) ++
               SHA256.sha256 (xorb (kb256 (Node.to_list s0)) (ipad 64) ++
                 (Node.to_list o0 ++ slh_msg mem0 x0 pl m ml))) /\
           forall j, 0 <= j < 8 * i => Node.get8 r j = tag.[j]).
+ wp; skip => &m [#] h0 h1 hinc ht hj hlt /=; do 4?(split; first smt()).
  move=> j hjr; rewrite Node.get8_set64dE.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
  + by rewrite ifT 1:/# BArray32.get64d_byte 1:/#; congr; smt().
  by rewrite ifF 1:/# hj /#.
wp; skip => &m htag /=; split; first smt().
move=> i1 r1 hlt [#] g0 g1 _ gt gj.
rewrite /PRF_msg family_sha2 /= hn16 /= hmac256_kb; first by rewrite size_node /#.
apply (eq_from_nth W8.zero).
+ by rewrite size_node /trunc size_take // -gt BArray32.size_to_list /#.
move=> j; rewrite size_node => hj.
by rewrite /trunc nth_take 1,2:/# -gt BArray32.get_to_list Node.get_to_list gj /#.
qed.

lemma prf_msg_wide_h (s0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  P.`n <> 16 =>
  hoare [M._prf_msg :
    sk_prf = s0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Node.to_list res.`1 = PRF_msg P (Node.to_list s0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)].
proof.
move=> hn16; have hn := n_val.
proc.
seq 15 : (opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
          msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
          forall j, 0 <= j < 128 => k0.[j] = if j < P.`n then Node.get8 s0 j else W8.zero).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ sk_prf = s0 /\
         forall j, 0 <= j < 128 => k0.[j] = if j < 8 * i then Node.get8 s0 j else W8.zero).
  + wp; skip => &m [#] h0 h1 hinc hs hj hlt; rewrite hs /=; do 3?(split; first smt()).
    move=> j hjr; rewrite BArray128.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj // /#.
  wp; while (0 <= i <= 16 /\ z = W64.zero /\ forall j, 0 <= j < 8 * i => k0.[j] = W8.zero).
  + wp; skip => &m [#] h0 h1 hz hj hlt; rewrite hz /=; do 2?(split; first smt()).
    move=> j hjr; rewrite BArray128.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h; first by rewrite ifT 1:/# W8u8.get_zero.
    by rewrite ifF 1:/# hj /#.
  wp; skip => &m [#] -> -> -> -> -> -> -> hok /=; split; first smt().
  move=> i0 k1 hlt [h0 hj]; split.
  + split; first smt().
    by move=> j hj'; rewrite ifF 1:/#; apply hj; smt().
  move=> i1 k2 hlt2 [#] g0 g1 _ gj; split; first exact hok.
  by move=> j hj'; rewrite gj //; smt().
if; first by conseq (_ : false ==> _) => //; smt().
(* the inner and outer chaining values of HMAC *)
seq 1 : (opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\
        Glob.mem = mem0 /\ msg_ok pl m ml /\
        hw512 inner512 = SHA512.compress SHA512.H0_512 (words512 (xorb (kb512 (Node.to_list s0)) (ipad 128))) /\
        hw512 outer512 = SHA512.compress SHA512.H0_512 (words512 (xorb (kb512 (Node.to_list s0)) (opad 128)))).
+ ecall (hmac512_init_h k0).
  skip => &m [#] -> -> -> -> -> -> hok hk _ /= r [h1 h2].
  by rewrite -(kblock512 k0{m} s0 hk) h1 h2.
(* opt_rand opens the inner message *)
seq 5 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
        SHA512_Stream.stream512 SHA512.H0_512
           (xorb (kb512 (Node.to_list s0)) (ipad 128) ++ Node.to_list o0) inner512 buf512 total /\
        hw512 outer512 = SHA512.compress SHA512.H0_512 (words512 (xorb (kb512 (Node.to_list s0)) (opad 128)))).
+ wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ opt_rand = o0 /\
            forall j, 0 <= j < 8 * i => buf512.[j] = Node.get8 o0 j).
  + wp; skip => &m [#] h0 h1 hinc ho hj hlt; rewrite ho /=; do 3?(split; first smt()).
    move=> j hjr; rewrite BArray128.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj /#.
  wp; skip => &m [#] -> -> -> -> -> -> hok hi ho /=; rewrite /SLH64.protect_ptr /=; split; first smt().
  move=> b1 i1 hlt [#] g0 g1 _ gj; split; first exact hok.
  split; last exact ho.
  apply head_stream512.
  + exact (size_pad512 s0 (W8.of_int 0x36)).
  + by rewrite size_node /#.
  + exact hi.
  + by rewrite W64.of_uintK size_node /#.
  by move=> j hj; rewrite gj; [smt(size_node) | rewrite Node.get_to_list].
(* the prefix and the message *)
seq 2 : (Glob.mem = mem0 /\ msg_ok pl m ml /\
        SHA512_Stream.stream512 SHA512.H0_512
           ((xorb (kb512 (Node.to_list s0)) (ipad 128) ++ Node.to_list o0) ++ slh_msg mem0 x0 pl m ml)
           inner512 buf512 total /\
        hw512 outer512 = SHA512.compress SHA512.H0_512 (words512 (xorb (kb512 (Node.to_list s0)) (opad 128)))).
+ ecall (absorb_message512_h SHA512.H0_512 (xorb (kb512 (Node.to_list s0)) (ipad 128) ++ Node.to_list o0)
           x0 pl m ml mem0).
  wp; skip => &m [#] -> -> -> -> -> hok hst ho; rewrite /SLH64.protect_ptr /=.
  have [hpl [hm hml]] := msg_sha2 _ _ _ hok.
  move: hm => /= hm.
  have hsz : size (xorb (kb512 (Node.to_list s0)) (ipad 128) ++ Node.to_list o0) = 128 + P.`n.
  + by rewrite size_cat /ipad size_pad512 size_node.
  have [hml0 _] := W64.to_uint_cmp ml; have [hpl0 _] := W64.to_uint_cmp pl.
  split.
  + split; first exact hst. split; first exact hpl. split; first exact hm.
    rewrite hsz prefix_size; move: hml; rewrite /sha2_msg_max; smt(n_val).
  by move=> _ r hr; split; [exact hok | split].
(* the inner digest and the outer hash *)
seq 1 : (BArray64.to_list tag512 =
           SHA512.sha512 (xorb (kb512 (Node.to_list s0)) (opad 128) ++
             SHA512.sha512 (xorb (kb512 (Node.to_list s0)) (ipad 128) ++
               (Node.to_list o0 ++ slh_msg mem0 x0 pl m ml)))).
+ ecall (hmac512_fin_h (xorb (kb512 (Node.to_list s0)) (ipad 128)) (xorb (kb512 (Node.to_list s0)) (opad 128))
           (Node.to_list o0 ++ slh_msg mem0 x0 pl m ml) (size_pad512 s0 (W8.of_int 0x5c))).
  skip => &m [#] _ hok hst ho /=.
  have [hpl [hm hml]] := msg_sha2 _ _ _ hok.
  have hs := size_slh_msg mem0 x0 pl m ml hpl.
  split; first by rewrite catA.
  split; first exact ho.
  rewrite size_cat size_cat /ipad size_pad512 size_node; move: hml hs; rewrite /sha2_msg_max.
  by pose u := size (slh_msg mem0 x0 pl m ml); smt(n_val).
(* R = the first n bytes of the tag *)
wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\
           BArray64.to_list tag512 =
             SHA512.sha512 (xorb (kb512 (Node.to_list s0)) (opad 128) ++
               SHA512.sha512 (xorb (kb512 (Node.to_list s0)) (ipad 128) ++
                 (Node.to_list o0 ++ slh_msg mem0 x0 pl m ml))) /\
           forall j, 0 <= j < 8 * i => Node.get8 r j = tag512.[j]).
+ wp; skip => &m [#] h0 h1 hinc ht hj hlt /=; do 4?(split; first smt()).
  move=> j hjr; rewrite Node.get8_set64dE.
  case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
  + by rewrite ifT 1:/# BArray64.get64d_byte 1:/#; congr; smt().
  by rewrite ifF 1:/# hj /#.
wp; skip => &m htag /=; split; first smt().
move=> i1 r1 hlt [#] g0 g1 _ gt gj.
rewrite /PRF_msg family_sha2 /= hn16 /= hmac512_kb; first by rewrite size_node /#.
apply (eq_from_nth W8.zero).
+ by rewrite size_node /trunc size_take // -gt BArray64.size_to_list /#.
move=> j; rewrite size_node => hj.
by rewrite /trunc nth_take 1,2:/# -gt BArray64.get_to_list Node.get_to_list gj /#.
qed.

lemma prf_msg_h (s0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  hoare [M._prf_msg :
    sk_prf = s0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Node.to_list res.`1 = PRF_msg P (Node.to_list s0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)].
proof.
case: (P.`n = 16) => h16; first exact (prf_msg_narrow_h s0 o0 x0 pl m ml mem0 h16).
exact (prf_msg_wide_h s0 o0 x0 pl m ml mem0 h16).
qed.

(* ------------------------------------------------------------------ *)
(* Termination                                                        *)

lemma hmac256_init_ll : islossless M.__hmac_sha256_init.
proof. by proc*; ecall (hmac_sha256_init_total k0); auto. qed.

lemma hmac512_init_ll : islossless M.__hmac_sha512_init.
proof. by proc*; ecall (hmac_sha512_init_total k0); auto. qed.

lemma hmac256_fin_ll : islossless M.__hmac_sha256_finalize.
proof.
bypr => &m _.
have -> : Pr[M.__hmac_sha256_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M.__hmac_sha256_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact HMAC_SHA256.hmac_sha256_finalize_ll.
qed.

lemma hmac512_fin_ll : islossless M.__hmac_sha512_finalize.
proof.
bypr => &m _.
have -> : Pr[M.__hmac_sha512_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M.__hmac_sha512_finalize(out{m}, inner{m}, buf{m}, total{m}, outer{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact HMAC_SHA512.hmac_sha512_finalize_ll.
qed.

lemma absorb_mem256_ll : islossless M._sha256_absorb_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha256_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha256_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA256_Stream.sha256_absorb_mem_ll.
qed.

lemma absorb_mem512_ll : islossless M._sha512_absorb_mem.
proof.
bypr => &m _.
have -> : Pr[M._sha512_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha512_absorb_mem(h{m}, buf{m}, total{m}, in_0{m}, inlen{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg, Glob.mem} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA512_Stream.sha512_absorb_mem_ll.
qed.

lemma absorb_prefix256_ll : islossless M.__sha256_absorb_prefix.
proof.
proc; wp.
while ((more <=> to_uint i < to_uint len)) (to_uint len - to_uint i).
+ move=> z; sp; if.
  + wp; call set_compress256_ll; wp; skip => &m [[i0 t0 b0 ms0] [#] _ _ _ _ _ -> _ hmore hm0 <-] _ /=.
    rewrite /SLH64.protect_64 /=.
    have hlt : to_uint i0 < to_uint len{m} by rewrite -hmore.
    have hi := inc_small i0 _; first by move: hlt; have := W64.to_uint_cmp len{m}; pose M := W64.modulus; smt().
    by rewrite W64.ultE hi /#.
  wp; skip => &m [[i0 t0 b0 ms0] [#] _ _ _ _ _ -> _ hmore hm0 <-] _ /=.
  have hlt : to_uint i0 < to_uint len{m} by rewrite -hmore.
  have hi := inc_small i0 _; first by move: hlt; have := W64.to_uint_cmp len{m}; pose M := W64.modulus; smt().
  by rewrite W64.ultE hi /#.
by wp; skip => &m /=; split; [by rewrite W64.ultE | smt()].
qed.

lemma absorb_prefix512_ll : islossless M.__sha512_absorb_prefix.
proof.
proc; wp.
while ((more <=> to_uint i < to_uint len)) (to_uint len - to_uint i).
+ move=> z; sp; if.
  + wp; call set_compress512_ll; wp; skip => &m [[i0 t0 b0 ms0] [#] _ _ _ _ _ -> _ hmore hm0 <-] _ /=.
    rewrite /SLH64.protect_64 /=.
    have hlt : to_uint i0 < to_uint len{m} by rewrite -hmore.
    have hi := inc_small i0 _; first by move: hlt; have := W64.to_uint_cmp len{m}; pose M := W64.modulus; smt().
    by rewrite W64.ultE hi /#.
  wp; skip => &m [[i0 t0 b0 ms0] [#] _ _ _ _ _ -> _ hmore hm0 <-] _ /=.
  have hlt : to_uint i0 < to_uint len{m} by rewrite -hmore.
  have hi := inc_small i0 _; first by move: hlt; have := W64.to_uint_cmp len{m}; pose M := W64.modulus; smt().
  by rewrite W64.ultE hi /#.
by wp; skip => &m /=; split; [by rewrite W64.ultE | smt()].
qed.

lemma absorb_message256_ll : islossless M.__sha256_absorb_message.
proof. by proc; call absorb_mem256_ll; wp; call absorb_prefix256_ll; auto. qed.

lemma absorb_message512_ll : islossless M.__sha512_absorb_message.
proof. by proc; call absorb_mem512_ll; wp; call absorb_prefix512_ll; auto. qed.

lemma prf_msg_ll : islossless M._prf_msg.
proof.
proc.
seq 15 : true 1%r 1%r 0%r _ => //.
+ while (true) (inc - i); first by auto => /#.
  wp; while (true) (16 - i); first by auto => /#.
  by auto => /#.
if.
+ while (true) (inc - i); first by auto => /#.
  wp; call hmac256_fin_ll; call absorb_message256_ll; wp.
  while (true) (inc - i); first by auto => /#.
  by wp; call hmac256_init_ll; auto => /#.
while (true) (inc - i); first by auto => /#.
wp; call hmac512_fin_ll; call absorb_message512_ll; wp.
while (true) (inc - i); first by auto => /#.
by wp; call hmac512_init_ll; auto => /#.
qed.

lemma prf_msg_correct (s0 o0 : Node.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  phoare [M._prf_msg :
    sk_prf = s0 /\ opt_rand = o0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Node.to_list res.`1 = PRF_msg P (Node.to_list s0) (Node.to_list o0) (slh_msg mem0 x0 pl m ml)] = 1%r.
proof. by conseq prf_msg_ll (prf_msg_h s0 o0 x0 pl m ml mem0). qed.
