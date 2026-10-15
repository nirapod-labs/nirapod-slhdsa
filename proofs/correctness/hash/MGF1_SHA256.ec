(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * MGF1_SHA256.ec
 * ==============
 *
 * Functional correctness of MGF1 with SHA-256 (_mgf1_sha256 of
 * src/hash/sha2/mgf1.jinc) against RFC 8017 appendix B.2.1
 * (spec/hash/RFC8017_MGF1.ec), for the two instances that H_msg of the
 * SHA2 parameter sets with n = 16 uses (FIPS 205 section 11.2.1): a 64-byte
 * seed R || PK.seed || SHA-256(R || PK.seed || PK.root || M) and 30 bytes of
 * output (128s) or 34 (128f). proofs/extracted/hash.jazz instantiates them
 * as the namespaces Mgf64_30 and Mgf64_34; their _mgf1_sha512 is not used
 * by any parameter set and is not covered.
 *
 * The code lays out the padded message of FIPS 180-4 section 5.1.1 once,
 * in the first 128 bytes of its buffer m:
 *
 *     m[0, 64)     seed
 *     m[64, 68)    counter c, big-endian (rewritten for each c)
 *     m[68]        0x80
 *     m[69, 120)   zero
 *     m[120, 128)  8 * 68 = 544, big-endian
 *
 * so that m[0, 128) is pad (seed ++ I2OSP(c, 4)), two blocks. For each c it
 * compresses them from the initial value and writes bytes 32c .. 32c + 31
 * of the output (fewer in the last round) from the big-endian chaining
 * words, which is block c of T in RFC 8017.
 *
 * Theorems (total correctness):
 *     mgf64_30_sha256_total   to_list out = mgf1_sha256 seed 30
 *     mgf64_34_sha256_total   to_list out = mgf1_sha256 seed 34
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils.
require import BArray30 BArray32 BArray34 BArray64 BArray192 SBArray192_64.
require import HashExtracted ArchWord.
require import Bytes FIPS180_SHA2 RFC8017_MGF1 SHA256_Compress SHA256_Stream.
import SHA256.

(* ------------------------------------------------------------------ *)
(* The specification side                                             *)

(* m[0, 128) outside the counter bytes, as the layout writes it. *)
op lay (s : bytes) (k : int) : W8.t =
  if k < 64 then nth W8.zero s k
  else if k = 68 then W8.of_int 128
  else if 120 <= k then W8.of_int (544 %/ 256 ^ (127 - k))
  else W8.zero.

lemma pad68 (x : bytes) : size x = 68 =>
  pad x = x ++ ([W8.of_int 128] ++ (zeros 51 ++ be_bytes 8 544)).
proof. by move=> hx; rewrite /pad hx /= -!catA. qed.

lemma nth_pad68 (s : bytes) (c k : int) : size s = 64 => 0 <= k < 128 =>
  nth W8.zero (pad (s ++ be_bytes 4 c)) k =
  if 64 <= k < 68 then nth W8.zero (be_bytes 4 c) (k - 64) else lay s k.
proof.
move=> hs hk; have hx : size (s ++ be_bytes 4 c) = 68 by rewrite size_cat size_be_bytes hs.
rewrite pad68 // nth_cat hx /lay.
case: (k < 68) => h68 /=.
+ by rewrite nth_cat hs; smt().
rewrite (_ : !(k < 64)) 1:/# /=.
case: (k = 68) => h1 /=; first by rewrite h1.
have hz : size (zeros 51) = 51 by rewrite size_zeros.
rewrite (_ : k - 68 <> 0) 1:/# /= nth_cat hz.
case: (k < 120) => h2.
+ by rewrite (_ : k - 69 < 51) 1:/# /= (_ : !(120 <= k)) 1:/# /= nth_nseq 1:/#.
rewrite (_ : !(k - 69 < 51)) 1:/# (_ : 120 <= k) 1:/# /= /be_bytes nth_mkseq 1:/# /=.
smt().
qed.

lemma size_pad68 (x : bytes) : size x = 68 => size (pad x) = 128.
proof. by move=> hx; rewrite pad68 // !size_cat size_zeros size_be_bytes hx. qed.

(* parse of the 128-byte padded message: its two 64-byte blocks. *)
lemma size_parse128 (p : bytes) : size p = 128 => size (parse p) = 2.
proof. by move=> hp; rewrite /parse size_map size_chunk // hp. qed.

lemma nth_parse128 (p : bytes) (b : int) : size p = 128 => 0 <= b < 2 =>
  nth [] (parse p) b = map be32 (chunk 4 (take 64 (drop (64 * b) p))).
proof.
move=> hp hb; rewrite /parse (nth_map []) 1:size_chunk // 1:hp 1:/#.
have hc : nth [] (chunk 64 p) b = take 64 (drop (64 * b) p).
+ by rewrite /chunk nth_mkseq /= 1:hp 1:/#.
by rewrite hc.
qed.

lemma sub_block (m : BArray192.t) (p : bytes) (b : int) : size p = 128 => 0 <= b < 2 =>
  (forall k, 0 <= k < 128 => BArray192.get8 m k = nth W8.zero p k) =>
  BArray64.to_list (SBArray192_64.get_sub m (64 * b)) = take 64 (drop (64 * b) p).
proof.
move=> hp hb hm; apply (eq_from_nth W8.zero).
+ by rewrite BArray64.size_to_list size_take // size_drop 1:/# hp /#.
move=> j; rewrite BArray64.size_to_list => hj.
rewrite BArray64.get_to_list SBArray192_64.get8_get_sub hj /= hm 1:/#.
by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
qed.

(* The digest of block c of T, and the output bytes. *)
lemma size_hash256 (m : bytes) : size (hash H0_256 m) = 8.
proof.
have hh : forall l hv, size hv = 8 => size (foldl compress hv l) = 8.
+ by elim => [|x l ih] hv hs //=; apply ih; apply size_compress.
by rewrite /hash hh // /H0_256 size_map.
qed.

lemma size_sha256 (m : bytes) : size (sha256 m) = 32.
proof.
rewrite /sha256 (size_flatten_ctt 4).
+ by move=> x /mapP [y [_ ->]]; rewrite /w32_be size_rev W4u8.size_to_list.
by rewrite size_map size_hash256.
qed.

lemma size_mgf1_256 (s : bytes) (l : int) : 0 <= l => size (mgf1_sha256 s l) = l.
proof.
move=> hl; rewrite /mgf1_sha256 /mgf1 size_take // (size_flatten_ctt 32).
+ by move=> x /mapP [y [_ ->]]; rewrite size_sha256.
rewrite size_map size_range /cdiv; smt().
qed.

lemma nth_mgf1_256 (s : bytes) (l j : int) : 0 <= j < l =>
  nth W8.zero (mgf1_sha256 s l) j = nth W8.zero (sha256 (s ++ be_bytes 4 (j %/ 32))) (j %% 32).
proof.
move=> hj; rewrite /mgf1_sha256 /mgf1 nth_take 1,2:/# (nth_flatten W8.zero 32).
+ by rewrite allP => x /mapP [y [_ ->]] /=; rewrite size_sha256.
rewrite (nth_map 0) 1:size_range /cdiv 1:/# nth_range /cdiv 1:/# //.
qed.

lemma nth_sha256 (m : bytes) (i : int) : 0 <= i < 32 =>
  nth W8.zero (sha256 m) i = nth W8.zero (w32_be (nth W32.zero (hash H0_256 m) (i %/ 4))) (i %% 4).
proof.
move=> hi; rewrite /sha256 (nth_flatten W8.zero 4).
+ by rewrite allP => x /mapP [y [_ ->]] /=; rewrite /w32_be size_rev W4u8.size_to_list.
by rewrite (nth_map W32.zero) // size_hash256 /#.
qed.

lemma idx4 (i : int) : 0 <= i < 32 => 0 <= i %/ 4 < 8.
proof. smt(). qed.

lemma nth_hwords (h : BArray32.t) (i : int) : 0 <= i < 32 =>
  nth W32.zero (hwords h) (i %/ 4) = BArray32.get32 h (i %/ 4).
proof.
move=> hi; have hq := idx4 i hi.
by rewrite /hwords (nth_map 0) 1:size_iota 1:/# /= nth_iota.
qed.

(* Byte i of the big-endian encoding of x, as the code extracts it. *)
lemma byte_be32 (x : W32.t) (i : int) : 0 <= i < 4 =>
  truncateu8 (zeroextu64 (x `>>` W8.of_int (8 * (3 - i)))) = nth W8.zero (w32_be x) i.
proof.
move=> hi; rewrite /w32_be nth_rev W4u8.size_to_list // W4u8.nth_to_list W4u8.bits8_div 1:/#.
apply W8.to_uint_eq; rewrite to_uint_truncateu8 to_uint_zeroextu64 W32.shr_div.
rewrite W8.of_uintK (pmod_small (8 * (3 - i))) 1:/#.
by rewrite (_ : 4 - (i + 1) = 3 - i) 1:/# ?W8.of_uintK.
qed.

(* Code-side helpers. *)
lemma trunc64 (a : int) : truncateu8 (W64.of_int a) = W8.of_int a.
proof.
apply W8.to_uint_eq; rewrite to_uint_truncateu8 W64.of_uintK !W8.of_uintK.
by rewrite modz_dvd //.
qed.

lemma shr8_div (t : W64.t) : to_uint (t `>>` W8.of_int 8) = to_uint t %/ 256.
proof. by rewrite W64.shr_div. qed.

lemma trunc_u (t : W64.t) (a : int) : to_uint t = a => truncateu8 t = W8.of_int a.
proof. by move=> h; apply W8.to_uint_eq; rewrite to_uint_truncateu8 !W8.of_uintK h. qed.

lemma be4_byte (c i : int) : 0 <= c < 256 => 0 <= i < 4 =>
  truncateu8 ((W64.of_int c) `>>` (W8.of_int (8 * (3 - i)))) = nth W8.zero (be_bytes 4 c) i.
proof.
move=> hc hi; rewrite /be_bytes nth_mkseq //=.
apply W8.to_uint_eq; rewrite to_uint_truncateu8 W64.shr_div W64.of_uintK W8.of_uintK.
rewrite W8.of_uintK (pmod_small (8 * (3 - i))) 1:/# (pmod_small c) 1:/# (_ : 4 - 1 - i = 3 - i) 1:/#.
by rewrite exprM.
qed.

(* The padded message for counter c, block by block. *)
lemma step_block (m : BArray192.t) (x : bytes) (b : int) : size x = 68 => 0 <= b < 2 =>
  (forall k, 0 <= k < 128 => BArray192.get8 m k = nth W8.zero (pad x) k) =>
  compress (foldl compress H0_256 (take b (parse (pad x))))
           (map be32 (chunk 4 (BArray64.to_list (SBArray192_64.get_sub m (64 * b)))))
  = foldl compress H0_256 (take (b + 1) (parse (pad x))).
proof.
move=> hx hb hm; have hp := size_pad68 x hx; have hq := size_parse128 _ hp.
rewrite (take_nth []) 1:hq 1:/# foldl_rcons nth_parse128 //.
by rewrite (sub_block m (pad x) b).
qed.

lemma out_step (l c i j : int) : 0 <= c => 32 * c < l =>
  !(i < if l - 32 * c < 32 then l - 32 * c else 32) =>
  j < l => j < 32 * (c + 1) => j < 32 * c + i.
proof. smt(). qed.

lemma idx_out (l c i : int) : 0 <= c => 0 <= i =>
  i < (if l - 32 * c < 32 then l - 32 * c else 32) =>
  (0 <= 32 * c + i < l) /\ (0 <= i < 32).
proof. smt(). qed.

(* ------------------------------------------------------------------ *)
(* Mgf64_30: 30 bytes of output                                         *)

lemma mgf64_30_layout_correct (s : BArray64.t) :
  hoare [M.mgf64_30____mgf1_layout : seed = s /\ padded = 128 ==>
    forall k, 0 <= k < 128 => !(64 <= k < 68) =>
      BArray192.get8 res k = lay (BArray64.to_list s) k].
proof.
proc.
while (0 <= i <= 8 /\ padded = 128 /\ seed = s /\ to_uint t = 544 %/ 256 ^ i /\
       forall k, 0 <= k < 128 => !(64 <= k < 68) =>
         BArray192.get8 m k = if 128 - i <= k then lay (BArray64.to_list s) k
                              else if k < 64 then BArray64.get8 s k
                              else if k = 68 then W8.of_int 128 else W8.zero).
+ auto => /> &hr hi0 _ ht hm hi8; split; first smt().
  split.
  + by rewrite shr8_div ht exprSr 1:/# divz_mul //; apply expr_ge0.
  move=> k hk hk'; rewrite BArray192.get_setE 1:/#.
  case: (k = 127 - i{hr}) => [->|hne] /=.
  + rewrite (trunc_u _ _ ht) /lay (_ : !(127 - i{hr} < 64)) 1:/# (_ : 127 - i{hr} <> 68) 1:/#.
    by rewrite (_ : 120 <= 127 - i{hr}) 1:/# (_ : 127 - (127 - i{hr}) = i{hr}) 1:/# /#.
  by move=> hk2; rewrite hm //; smt().
wp; while (0 <= i <= 64 /\ padded = 128 /\ seed = s /\
           forall k, 0 <= k < 128 => BArray192.get8 m k = if k < i then BArray64.get8 s k else W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk; rewrite BArray192.get_setE 1:/# trunc_zext; smt().
wp; while (0 <= i <= inc /\ inc = 128 /\ padded = 128 /\ seed = s /\ z = W64.of_int 0 /\
           forall k, 0 <= k < i => BArray192.get8 m k = W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk hk'; rewrite BArray192.get_setE 1:/# trunc64; smt().
auto => /> &hr; split; first smt().
move=> m1 i1 hi1 _ hm1 hi1'; split; first smt().
move=> m2 i2 hi2 _ hm2 hi2'; split.
+ move=> k hk hk'; rewrite BArray192.get_setE 1:/# trunc64 /=; smt().
move=> i3 m3 t3 hi3 hi3a hi3b ht3 hm3 k hk0 hk1 hk'; rewrite hm3 1:/# //.
rewrite (_ : i3 = 8) 1:/# /lay /=.
by case: (k < 64) => h64 /=; smt().
qed.

lemma mgf64_30_layout_ll : islossless M.mgf64_30____mgf1_layout.
proof.
proc; while (true) (8 - i); first by auto => /#.
wp; while (true) (64 - i); first by auto => /#.
by wp; while (true) (inc - i); auto => /#.
qed.

lemma mgf64_30_set_counter_correct (m0 : BArray192.t) (c0 : int) :
  hoare [M.mgf64_30____mgf1_set_counter : m = m0 /\ c = c0 /\ 0 <= c0 < 256 ==>
    forall k, 0 <= k < 192 => BArray192.get8 res k =
      if 64 <= k < 68 then nth W8.zero (be_bytes 4 c0) (k - 64) else BArray192.get8 m0 k].
proof.
proc.
while (0 <= i <= 4 /\ c = c0 /\ 0 <= c0 < 256 /\
       forall k, 0 <= k < 192 => BArray192.get8 m k =
         if 64 <= k < 64 + i then nth W8.zero (be_bytes 4 c0) (k - 64) else BArray192.get8 m0 k).
+ auto => /> &hr hi0 _ hc0 hc1 hm hi; split; first smt().
  move=> k hk; rewrite BArray192.get_setE 1:/#.
  case: (k = 64 + i{hr}) => [->|hne] /=.
  + move=> _; rewrite (_ : 64 <= 64 + i{hr} < i{hr} + 65) 1:/# /=.
    by rewrite be4_byte; smt().
  by move=> hk2; smt().
by auto => />; smt().
qed.

lemma mgf64_30_set_counter_ll : islossless M.mgf64_30____mgf1_set_counter.
proof. by proc; while (true) (4 - i); auto => /#. qed.

lemma mgf64_30_sha256_correct (s : BArray64.t) :
  hoare [M.mgf64_30___mgf1_sha256 : seed = s ==>
           BArray30.to_list res.`1 = mgf1_sha256 (BArray64.to_list s) 30].
proof.
proc.
while (0 <= c <= inc /\ inc = (30 + 31) %/ 32 /\
       (forall k, 0 <= k < 128 => !(64 <= k < 68) =>
          BArray192.get8 m k = lay (BArray64.to_list s) k) /\
       forall j, 0 <= j < 30 => j < 32 * c =>
         BArray30.get8 out j = nth W8.zero (mgf1_sha256 (BArray64.to_list s) 30) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if 30 - 32 * c < 32 then 30 - 32 * c else 32) /\
         0 <= c < inc /\ inc = (30 + 31) %/ 32 /\
         hwords h = hash H0_256 (BArray64.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < 128 => !(64 <= k < 68) =>
            BArray192.get8 m k = lay (BArray64.to_list s) k) /\
         forall j, 0 <= j < 30 => j < 32 * c + i =>
           BArray30.get8 out j = nth W8.zero (mgf1_sha256 (BArray64.to_list s) 30) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi32] := idx_out 30 c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite BArray30.get_setE; first exact hidx.
    case: (j = 32 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite byte_be32 1:/# nth_mgf1_256 1:/#.
    have -> : (32 * c{hr} + i{hr}) %/ 32 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (32 * c{hr} + i{hr}) %% 32 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite nth_sha256 1:/# -hh nth_hwords.
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = 2 /\ 0 <= c < inc /\ inc = (30 + 31) %/ 32 /\
         hwords h = foldl compress H0_256 (take b (parse (pad (BArray64.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < 128 =>
            BArray192.get8 m k = nth W8.zero (pad (BArray64.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < 128 => !(64 <= k < 68) =>
            BArray192.get8 m k = lay (BArray64.to_list s) k) /\
         forall j, 0 <= j < 30 => j < 32 * c =>
           BArray30.get8 out j = nth W8.zero (mgf1_sha256 (BArray64.to_list s) 30) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (sha256_compress_correct (hwords h0) (SBArray192_64.get_sub m0 (64 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hp hm hout hb h1 hh1.
    split; first smt().
    split; first by rewrite hh1 hh step_block // size_cat size_be_bytes BArray64.size_to_list.
    smt().
  wp; call sha256_init_correct; exlim m, c => m0 c0.
  call (mgf64_30_set_counter_correct m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> ? m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad68 1:BArray64.size_to_list 1,2:/#.
      by case: (64 <= k < 68) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = 2) 1:/# take_oversize //.
    by rewrite size_parse128 // size_pad68 // size_cat size_be_bytes BArray64.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (out_step 30 c0 i3 j) => //; smt().
wp; call (mgf64_30_layout_correct s).
auto => /> &hr m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite BArray30.size_to_list size_mgf1_256.
by move=> j; rewrite BArray30.size_to_list => hj; rewrite BArray30.get_to_list hout2 // /#.
qed.

lemma mgf64_30_sha256_ll : islossless M.mgf64_30___mgf1_sha256.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call sha256_compress_ll; auto => /#.
  by wp; call sha256_init_ll; call mgf64_30_set_counter_ll; auto => /#.
by wp; call mgf64_30_layout_ll; auto => /#.
qed.

lemma mgf64_30_sha256_total (s : BArray64.t) :
  phoare [M.mgf64_30___mgf1_sha256 : seed = s ==>
           BArray30.to_list res.`1 = mgf1_sha256 (BArray64.to_list s) 30] = 1%r.
proof. by conseq mgf64_30_sha256_ll (mgf64_30_sha256_correct s). qed.

(* ------------------------------------------------------------------ *)
(* Mgf64_34: 34 bytes of output                                         *)

lemma mgf64_34_layout_correct (s : BArray64.t) :
  hoare [M.mgf64_34____mgf1_layout : seed = s /\ padded = 128 ==>
    forall k, 0 <= k < 128 => !(64 <= k < 68) =>
      BArray192.get8 res k = lay (BArray64.to_list s) k].
proof.
proc.
while (0 <= i <= 8 /\ padded = 128 /\ seed = s /\ to_uint t = 544 %/ 256 ^ i /\
       forall k, 0 <= k < 128 => !(64 <= k < 68) =>
         BArray192.get8 m k = if 128 - i <= k then lay (BArray64.to_list s) k
                              else if k < 64 then BArray64.get8 s k
                              else if k = 68 then W8.of_int 128 else W8.zero).
+ auto => /> &hr hi0 _ ht hm hi8; split; first smt().
  split.
  + by rewrite shr8_div ht exprSr 1:/# divz_mul //; apply expr_ge0.
  move=> k hk hk'; rewrite BArray192.get_setE 1:/#.
  case: (k = 127 - i{hr}) => [->|hne] /=.
  + rewrite (trunc_u _ _ ht) /lay (_ : !(127 - i{hr} < 64)) 1:/# (_ : 127 - i{hr} <> 68) 1:/#.
    by rewrite (_ : 120 <= 127 - i{hr}) 1:/# (_ : 127 - (127 - i{hr}) = i{hr}) 1:/# /#.
  by move=> hk2; rewrite hm //; smt().
wp; while (0 <= i <= 64 /\ padded = 128 /\ seed = s /\
           forall k, 0 <= k < 128 => BArray192.get8 m k = if k < i then BArray64.get8 s k else W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk; rewrite BArray192.get_setE 1:/# trunc_zext; smt().
wp; while (0 <= i <= inc /\ inc = 128 /\ padded = 128 /\ seed = s /\ z = W64.of_int 0 /\
           forall k, 0 <= k < i => BArray192.get8 m k = W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk hk'; rewrite BArray192.get_setE 1:/# trunc64; smt().
auto => /> &hr; split; first smt().
move=> m1 i1 hi1 _ hm1 hi1'; split; first smt().
move=> m2 i2 hi2 _ hm2 hi2'; split.
+ move=> k hk hk'; rewrite BArray192.get_setE 1:/# trunc64 /=; smt().
move=> i3 m3 t3 hi3 hi3a hi3b ht3 hm3 k hk0 hk1 hk'; rewrite hm3 1:/# //.
rewrite (_ : i3 = 8) 1:/# /lay /=.
by case: (k < 64) => h64 /=; smt().
qed.

lemma mgf64_34_layout_ll : islossless M.mgf64_34____mgf1_layout.
proof.
proc; while (true) (8 - i); first by auto => /#.
wp; while (true) (64 - i); first by auto => /#.
by wp; while (true) (inc - i); auto => /#.
qed.

lemma mgf64_34_set_counter_correct (m0 : BArray192.t) (c0 : int) :
  hoare [M.mgf64_34____mgf1_set_counter : m = m0 /\ c = c0 /\ 0 <= c0 < 256 ==>
    forall k, 0 <= k < 192 => BArray192.get8 res k =
      if 64 <= k < 68 then nth W8.zero (be_bytes 4 c0) (k - 64) else BArray192.get8 m0 k].
proof.
proc.
while (0 <= i <= 4 /\ c = c0 /\ 0 <= c0 < 256 /\
       forall k, 0 <= k < 192 => BArray192.get8 m k =
         if 64 <= k < 64 + i then nth W8.zero (be_bytes 4 c0) (k - 64) else BArray192.get8 m0 k).
+ auto => /> &hr hi0 _ hc0 hc1 hm hi; split; first smt().
  move=> k hk; rewrite BArray192.get_setE 1:/#.
  case: (k = 64 + i{hr}) => [->|hne] /=.
  + move=> _; rewrite (_ : 64 <= 64 + i{hr} < i{hr} + 65) 1:/# /=.
    by rewrite be4_byte; smt().
  by move=> hk2; smt().
by auto => />; smt().
qed.

lemma mgf64_34_set_counter_ll : islossless M.mgf64_34____mgf1_set_counter.
proof. by proc; while (true) (4 - i); auto => /#. qed.

lemma mgf64_34_sha256_correct (s : BArray64.t) :
  hoare [M.mgf64_34___mgf1_sha256 : seed = s ==>
           BArray34.to_list res.`1 = mgf1_sha256 (BArray64.to_list s) 34].
proof.
proc.
while (0 <= c <= inc /\ inc = (34 + 31) %/ 32 /\
       (forall k, 0 <= k < 128 => !(64 <= k < 68) =>
          BArray192.get8 m k = lay (BArray64.to_list s) k) /\
       forall j, 0 <= j < 34 => j < 32 * c =>
         BArray34.get8 out j = nth W8.zero (mgf1_sha256 (BArray64.to_list s) 34) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if 34 - 32 * c < 32 then 34 - 32 * c else 32) /\
         0 <= c < inc /\ inc = (34 + 31) %/ 32 /\
         hwords h = hash H0_256 (BArray64.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < 128 => !(64 <= k < 68) =>
            BArray192.get8 m k = lay (BArray64.to_list s) k) /\
         forall j, 0 <= j < 34 => j < 32 * c + i =>
           BArray34.get8 out j = nth W8.zero (mgf1_sha256 (BArray64.to_list s) 34) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi32] := idx_out 34 c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite BArray34.get_setE; first exact hidx.
    case: (j = 32 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite byte_be32 1:/# nth_mgf1_256 1:/#.
    have -> : (32 * c{hr} + i{hr}) %/ 32 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (32 * c{hr} + i{hr}) %% 32 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite nth_sha256 1:/# -hh nth_hwords.
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = 2 /\ 0 <= c < inc /\ inc = (34 + 31) %/ 32 /\
         hwords h = foldl compress H0_256 (take b (parse (pad (BArray64.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < 128 =>
            BArray192.get8 m k = nth W8.zero (pad (BArray64.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < 128 => !(64 <= k < 68) =>
            BArray192.get8 m k = lay (BArray64.to_list s) k) /\
         forall j, 0 <= j < 34 => j < 32 * c =>
           BArray34.get8 out j = nth W8.zero (mgf1_sha256 (BArray64.to_list s) 34) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (sha256_compress_correct (hwords h0) (SBArray192_64.get_sub m0 (64 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hp hm hout hb h1 hh1.
    split; first smt().
    split; first by rewrite hh1 hh step_block // size_cat size_be_bytes BArray64.size_to_list.
    smt().
  wp; call sha256_init_correct; exlim m, c => m0 c0.
  call (mgf64_34_set_counter_correct m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> ? m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad68 1:BArray64.size_to_list 1,2:/#.
      by case: (64 <= k < 68) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = 2) 1:/# take_oversize //.
    by rewrite size_parse128 // size_pad68 // size_cat size_be_bytes BArray64.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (out_step 34 c0 i3 j) => //; smt().
wp; call (mgf64_34_layout_correct s).
auto => /> &hr m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite BArray34.size_to_list size_mgf1_256.
by move=> j; rewrite BArray34.size_to_list => hj; rewrite BArray34.get_to_list hout2 // /#.
qed.

lemma mgf64_34_sha256_ll : islossless M.mgf64_34___mgf1_sha256.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call sha256_compress_ll; auto => /#.
  by wp; call sha256_init_ll; call mgf64_34_set_counter_ll; auto => /#.
by wp; call mgf64_34_layout_ll; auto => /#.
qed.

lemma mgf64_34_sha256_total (s : BArray64.t) :
  phoare [M.mgf64_34___mgf1_sha256 : seed = s ==>
           BArray34.to_list res.`1 = mgf1_sha256 (BArray64.to_list s) 34] = 1%r.
proof. by conseq mgf64_34_sha256_ll (mgf64_34_sha256_correct s). qed.
