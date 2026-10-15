(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * MGF1_SHA512.ec
 * ==============
 *
 * Functional correctness of MGF1 with SHA-512 (_mgf1_sha512 of
 * src/hash/sha2/mgf1.jinc) against RFC 8017 appendix B.2.1
 * (spec/hash/RFC8017_MGF1.ec), for the four instances that H_msg of the
 * SHA2 parameter sets with n = 24 and n = 32 uses (FIPS 205 section
 * 11.2.2): a seed R || PK.seed || SHA-512(R || PK.seed || PK.root || M) of
 * 2n + 64 bytes, that is 112 bytes (n = 24) or 128 (n = 32), and 39, 42,
 * 47 or 49 bytes of output. proofs/extracted/hash.jazz instantiates them as
 * the namespaces Mgf112_39, Mgf112_42, Mgf128_47 and Mgf128_49; their
 * _mgf1_sha256 is not used by any parameter set and is not covered.
 *
 * For a seed of S bytes the code lays out the padded message of FIPS 180-4
 * section 5.1.2 once, in the first 256 bytes of its buffer m:
 *
 *     m[0, S)          seed
 *     m[S, S + 4)      counter c, big-endian (rewritten for each c)
 *     m[S + 4]         0x80
 *     m[S + 5, 240)    zero
 *     m[240, 256)      8 (S + 4), as a 128-bit big-endian integer; its
 *                      upper eight bytes are zero and the code leaves them
 *                      from the zero fill
 *
 * so that m[0, 256) is pad (seed ++ I2OSP(c, 4)), two blocks. Every
 * output length here is at most 64, so the loop over c runs once and the
 * output is the first bytes of SHA-512(seed || I2OSP(0, 4)); the proof
 * keeps the general loop invariant all the same.
 *
 * Theorems (total correctness):
 *     mgf112_39_sha512_total   to_list out = mgf1_sha512 seed 39
 *     mgf112_42_sha512_total   to_list out = mgf1_sha512 seed 42
 *     mgf128_47_sha512_total   to_list out = mgf1_sha512 seed 47
 *     mgf128_49_sha512_total   to_list out = mgf1_sha512 seed 49
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils.
require import BArray39 BArray42 BArray47 BArray49 BArray64 BArray112 BArray128.
require import BArray320 SBArray320_128.
require import HashExtracted ArchWord.
require import Bytes FIPS180_SHA2 RFC8017_MGF1 SHA512_Compress SHA512_Stream.
import SHA512.

(* ------------------------------------------------------------------ *)
(* The specification side                                             *)

lemma size_hash512 (m : bytes) : size (hash H0_512 m) = 8.
proof.
have hh : forall l hv, size hv = 8 => size (foldl compress hv l) = 8.
+ by elim => [|x l ih] hv hs //=; apply ih; apply size_compress.
by rewrite /hash hh // /H0_512 size_map.
qed.

lemma size_sha512 (m : bytes) : size (sha512 m) = 64.
proof.
rewrite /sha512 /digest (size_flatten_ctt 8).
+ by move=> x /mapP [y [_ ->]]; rewrite /w64_be size_rev W8u8.size_to_list.
by rewrite size_map size_hash512.
qed.

lemma size_mgf1_512 (s : bytes) (l : int) : 0 <= l => size (mgf1_sha512 s l) = l.
proof.
move=> hl; rewrite /mgf1_sha512 /mgf1 size_take // (size_flatten_ctt 64).
+ by move=> x /mapP [y [_ ->]]; rewrite size_sha512.
rewrite size_map size_range /cdiv; smt().
qed.

lemma nth_mgf1_512 (s : bytes) (l j : int) : 0 <= j < l =>
  nth W8.zero (mgf1_sha512 s l) j = nth W8.zero (sha512 (s ++ be_bytes 4 (j %/ 64))) (j %% 64).
proof.
move=> hj; rewrite /mgf1_sha512 /mgf1 nth_take 1,2:/# (nth_flatten W8.zero 64).
+ by rewrite allP => x /mapP [y [_ ->]] /=; rewrite size_sha512.
rewrite (nth_map 0) 1:size_range /cdiv 1:/# nth_range /cdiv 1:/# //.
qed.

lemma nth_sha512 (m : bytes) (i : int) : 0 <= i < 64 =>
  nth W8.zero (sha512 m) i = nth W8.zero (w64_be (nth W64.zero (hash H0_512 m) (i %/ 8))) (i %% 8).
proof.
move=> hi; rewrite /sha512 /digest (nth_flatten W8.zero 8).
+ by rewrite allP => x /mapP [y [_ ->]] /=; rewrite /w64_be size_rev W8u8.size_to_list.
by rewrite (nth_map W64.zero) // size_hash512 /#.
qed.

lemma idx8 (i : int) : 0 <= i < 64 => 0 <= i %/ 8 < 8.
proof. smt(). qed.

(* The high bytes of the length field: the bit length is below 2^16. *)
lemma hi_zero (l e : int) : 0 <= l < 65536 => 8 <= e => l %/ 256 ^ e = 0.
proof.
move=> hl he; apply divz_small.
have h0 : 0 < 256 ^ e by apply expr_gt0.
have h2 : 256 ^ 2 <= 256 ^ e by apply ler_weexpn2l => /#.
have h3 : 256 ^ 2 = 65536 by rewrite expr2.
by rewrite ger0_norm 1:/#; smt().
qed.

(* parse of the 256-byte padded message: its two 128-byte blocks. *)
lemma size_parse256 (p : bytes) : size p = 256 => size (parse p) = 2.
proof. by move=> hp; rewrite /parse size_map size_chunk // hp. qed.

lemma nth_parse256 (p : bytes) (b : int) : size p = 256 => 0 <= b < 2 =>
  nth [] (parse p) b = map be64 (chunk 8 (take 128 (drop (128 * b) p))).
proof.
move=> hp hb; rewrite /parse (nth_map []) 1:size_chunk // 1:hp 1:/#.
have hc : nth [] (chunk 128 p) b = take 128 (drop (128 * b) p).
+ by rewrite /chunk nth_mkseq /= 1:hp 1:/#.
by rewrite hc.
qed.

lemma sub_block (m : BArray320.t) (p : bytes) (b : int) : size p = 256 => 0 <= b < 2 =>
  (forall k, 0 <= k < 256 => BArray320.get8 m k = nth W8.zero p k) =>
  BArray128.to_list (SBArray320_128.get_sub m (128 * b)) = take 128 (drop (128 * b) p).
proof.
move=> hp hb hm; apply (eq_from_nth W8.zero).
+ by rewrite BArray128.size_to_list size_take // size_drop 1:/# hp /#.
move=> j; rewrite BArray128.size_to_list => hj.
rewrite BArray128.get_to_list SBArray320_128.get8_get_sub hj /= hm 1:/#.
by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
qed.

(* Byte i of the big-endian encoding of x, as the code extracts it. *)
lemma byte_be64 (x : W64.t) (i : int) : 0 <= i < 8 =>
  truncateu8 (x `>>` W8.of_int (8 * (7 - i))) = nth W8.zero (w64_be x) i.
proof.
move=> hi; rewrite /w64_be nth_rev W8u8.size_to_list // W8u8.nth_to_list W8u8.bits8_div 1:/#.
apply W8.to_uint_eq; rewrite to_uint_truncateu8 W64.shr_div.
rewrite W8.of_uintK (pmod_small (8 * (7 - i))) 1:/#.
by rewrite (_ : 8 - (i + 1) = 7 - i) 1:/# ?W8.of_uintK.
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

lemma idx_out (l c i : int) : 0 <= c => 0 <= i =>
  i < (if l - 64 * c < 64 then l - 64 * c else 64) =>
  (0 <= 64 * c + i < l) /\ (0 <= i < 64).
proof. smt(). qed.

lemma out_step (l c i j : int) : 0 <= c => 64 * c < l =>
  !(i < if l - 64 * c < 64 then l - 64 * c else 64) =>
  j < l => j < 64 * (c + 1) => j < 64 * c + i.
proof. smt(). qed.

(* ------------------------------------------------------------------ *)
(* Seeds of 112 bytes: the layout                                      *)

(* m[0, 256) outside the counter bytes, as the layout writes it. *)
op lay112 (s : bytes) (k : int) : W8.t =
  if k < 112 then nth W8.zero s k
  else if k = 116 then W8.of_int 128
  else if 240 <= k then W8.of_int (928 %/ 256 ^ (255 - k))
  else W8.zero.

lemma lay112_zero (s : bytes) (k : int) : 240 <= k < 248 => lay112 s k = W8.zero.
proof.
move=> hk; rewrite /lay112 (_ : !(k < 112)) 1:/# (_ : k <> 116) 1:/# (_ : 240 <= k) 1:/# /=.
have -> : 928 %/ 256 ^ (255 - k) = 0 by apply hi_zero => /#.
done.
qed.

lemma pad116 (x : bytes) : size x = 116 =>
  pad x = x ++ ([W8.of_int 128] ++ (zeros 123 ++ be_bytes 16 928)).
proof. by move=> hx; rewrite /pad hx /= -!catA. qed.

lemma size_pad116 (x : bytes) : size x = 116 => size (pad x) = 256.
proof. by move=> hx; rewrite pad116 // !size_cat size_zeros size_be_bytes hx. qed.

lemma nth_pad116 (s : bytes) (c k : int) : size s = 112 => 0 <= k < 256 =>
  nth W8.zero (pad (s ++ be_bytes 4 c)) k =
  if 112 <= k < 116 then nth W8.zero (be_bytes 4 c) (k - 112) else lay112 s k.
proof.
move=> hs hk; have hx : size (s ++ be_bytes 4 c) = 116 by rewrite size_cat size_be_bytes hs.
rewrite pad116 // nth_cat hx /lay112.
case: (k < 116) => h68 /=.
+ by rewrite nth_cat hs; smt().
rewrite (_ : !(k < 112)) 1:/# /=.
case: (k = 116) => h1 /=; first by rewrite h1.
have hz : size (zeros 123) = 123 by rewrite size_zeros.
rewrite (_ : k - 116 <> 0) 1:/# /= nth_cat hz.
case: (k < 240) => h2.
+ by rewrite (_ : k - 117 < 123) 1:/# /= (_ : !(240 <= k)) 1:/# /= nth_nseq 1:/#.
rewrite (_ : !(k - 117 < 123)) 1:/# (_ : 240 <= k) 1:/# /= /be_bytes nth_mkseq 1:/# /=.
smt().
qed.

(* The padded message for counter c, block by block. *)
lemma step_block112 (m : BArray320.t) (x : bytes) (b : int) : size x = 116 => 0 <= b < 2 =>
  (forall k, 0 <= k < 256 => BArray320.get8 m k = nth W8.zero (pad x) k) =>
  compress (foldl compress H0_512 (take b (parse (pad x))))
           (map be64 (chunk 8 (BArray128.to_list (SBArray320_128.get_sub m (128 * b)))))
  = foldl compress H0_512 (take (b + 1) (parse (pad x))).
proof.
move=> hx hb hm; have hp := size_pad116 x hx; have hq := size_parse256 _ hp.
rewrite (take_nth []) 1:hq 1:/# foldl_rcons nth_parse256 //.
by rewrite (sub_block m (pad x) b).
qed.

(* ------------------------------------------------------------------ *)
(* Seeds of 128 bytes: the layout                                      *)

(* m[0, 256) outside the counter bytes, as the layout writes it. *)
op lay128 (s : bytes) (k : int) : W8.t =
  if k < 128 then nth W8.zero s k
  else if k = 132 then W8.of_int 128
  else if 240 <= k then W8.of_int (1056 %/ 256 ^ (255 - k))
  else W8.zero.

lemma lay128_zero (s : bytes) (k : int) : 240 <= k < 248 => lay128 s k = W8.zero.
proof.
move=> hk; rewrite /lay128 (_ : !(k < 128)) 1:/# (_ : k <> 132) 1:/# (_ : 240 <= k) 1:/# /=.
have -> : 1056 %/ 256 ^ (255 - k) = 0 by apply hi_zero => /#.
done.
qed.

lemma pad132 (x : bytes) : size x = 132 =>
  pad x = x ++ ([W8.of_int 128] ++ (zeros 107 ++ be_bytes 16 1056)).
proof. by move=> hx; rewrite /pad hx /= -!catA. qed.

lemma size_pad132 (x : bytes) : size x = 132 => size (pad x) = 256.
proof. by move=> hx; rewrite pad132 // !size_cat size_zeros size_be_bytes hx. qed.

lemma nth_pad132 (s : bytes) (c k : int) : size s = 128 => 0 <= k < 256 =>
  nth W8.zero (pad (s ++ be_bytes 4 c)) k =
  if 128 <= k < 132 then nth W8.zero (be_bytes 4 c) (k - 128) else lay128 s k.
proof.
move=> hs hk; have hx : size (s ++ be_bytes 4 c) = 132 by rewrite size_cat size_be_bytes hs.
rewrite pad132 // nth_cat hx /lay128.
case: (k < 132) => h68 /=.
+ by rewrite nth_cat hs; smt().
rewrite (_ : !(k < 128)) 1:/# /=.
case: (k = 132) => h1 /=; first by rewrite h1.
have hz : size (zeros 107) = 107 by rewrite size_zeros.
rewrite (_ : k - 132 <> 0) 1:/# /= nth_cat hz.
case: (k < 240) => h2.
+ by rewrite (_ : k - 133 < 107) 1:/# /= (_ : !(240 <= k)) 1:/# /= nth_nseq 1:/#.
rewrite (_ : !(k - 133 < 107)) 1:/# (_ : 240 <= k) 1:/# /= /be_bytes nth_mkseq 1:/# /=.
smt().
qed.

(* The padded message for counter c, block by block. *)
lemma step_block128 (m : BArray320.t) (x : bytes) (b : int) : size x = 132 => 0 <= b < 2 =>
  (forall k, 0 <= k < 256 => BArray320.get8 m k = nth W8.zero (pad x) k) =>
  compress (foldl compress H0_512 (take b (parse (pad x))))
           (map be64 (chunk 8 (BArray128.to_list (SBArray320_128.get_sub m (128 * b)))))
  = foldl compress H0_512 (take (b + 1) (parse (pad x))).
proof.
move=> hx hb hm; have hp := size_pad132 x hx; have hq := size_parse256 _ hp.
rewrite (take_nth []) 1:hq 1:/# foldl_rcons nth_parse256 //.
by rewrite (sub_block m (pad x) b).
qed.

(* ------------------------------------------------------------------ *)
(* Mgf112_39: 112-byte seed, 39 bytes of output                          *)

lemma mgf112_39_layout_correct (s : BArray112.t) :
  hoare [M.mgf112_39____mgf1_layout : seed = s /\ padded = 256 ==>
    forall k, 0 <= k < 256 => !(112 <= k < 116) =>
      BArray320.get8 res k = lay112 (BArray112.to_list s) k].
proof.
proc.
while (0 <= i <= 8 /\ padded = 256 /\ seed = s /\ to_uint t = 928 %/ 256 ^ i /\
       forall k, 0 <= k < 256 => !(112 <= k < 116) =>
         BArray320.get8 m k = if 256 - i <= k then lay112 (BArray112.to_list s) k
                              else if k < 112 then BArray112.get8 s k
                              else if k = 116 then W8.of_int 128 else W8.zero).
+ auto => /> &hr hi0 _ ht hm hi8; split; first smt().
  split.
  + by rewrite shr8_div ht exprSr 1:/# divz_mul //; apply expr_ge0.
  move=> k hk hk'; rewrite BArray320.get_setE 1:/#.
  case: (k = 255 - i{hr}) => [->|hne] /=.
  + rewrite (trunc_u _ _ ht) /lay112 (_ : !(255 - i{hr} < 112)) 1:/# (_ : 255 - i{hr} <> 116) 1:/#.
    by rewrite (_ : 240 <= 255 - i{hr}) 1:/# (_ : 255 - (255 - i{hr}) = i{hr}) 1:/# /#.
  by move=> hk2; rewrite hm //; smt().
wp; while (0 <= i <= 112 /\ padded = 256 /\ seed = s /\
           forall k, 0 <= k < 256 => BArray320.get8 m k = if k < i then BArray112.get8 s k else W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/# trunc_zext; smt().
wp; while (0 <= i <= inc /\ inc = 256 /\ padded = 256 /\ seed = s /\ z = W64.of_int 0 /\
           forall k, 0 <= k < i => BArray320.get8 m k = W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64; smt().
auto => /> &hr; split; first smt().
move=> m1 i1 hi1 _ hm1 hi1'; split; first smt().
move=> m2 i2 hi2 _ hm2 hi2'; split.
+ move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64 /=; smt().
move=> i3 m3 t3 hi3 hi3a hi3b ht3 hm3 k hk0 hk1 hk'; rewrite hm3 1:/# //.
rewrite (_ : i3 = 8) 1:/# /=.
case: (248 <= k) => // h248.
case: (240 <= k) => h240.
+ by rewrite lay112_zero 1:/# (_ : !(k < 112)) 1:/# (_ : k <> 116) 1:/#.
rewrite /lay112 (_ : !(240 <= k)) 1:/# /=.
by case: (k < 112) => h64 /=; smt().
qed.

lemma mgf112_39_layout_ll : islossless M.mgf112_39____mgf1_layout.
proof.
proc; while (true) (8 - i); first by auto => /#.
wp; while (true) (112 - i); first by auto => /#.
by wp; while (true) (inc - i); auto => /#.
qed.

lemma mgf112_39_set_counter_correct (m0 : BArray320.t) (c0 : int) :
  hoare [M.mgf112_39____mgf1_set_counter : m = m0 /\ c = c0 /\ 0 <= c0 < 256 ==>
    forall k, 0 <= k < 320 => BArray320.get8 res k =
      if 112 <= k < 116 then nth W8.zero (be_bytes 4 c0) (k - 112) else BArray320.get8 m0 k].
proof.
proc.
while (0 <= i <= 4 /\ c = c0 /\ 0 <= c0 < 256 /\
       forall k, 0 <= k < 320 => BArray320.get8 m k =
         if 112 <= k < 112 + i then nth W8.zero (be_bytes 4 c0) (k - 112) else BArray320.get8 m0 k).
+ auto => /> &hr hi0 _ hc0 hc1 hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/#.
  case: (k = 112 + i{hr}) => [->|hne] /=.
  + move=> _; rewrite (_ : 112 <= 112 + i{hr} < i{hr} + 113) 1:/# /=.
    by rewrite be4_byte; smt().
  by move=> hk2; smt().
by auto => />; smt().
qed.

lemma mgf112_39_set_counter_ll : islossless M.mgf112_39____mgf1_set_counter.
proof. by proc; while (true) (4 - i); auto => /#. qed.

lemma mgf112_39_sha512_correct (s : BArray112.t) :
  hoare [M.mgf112_39___mgf1_sha512 : seed = s ==>
           BArray39.to_list res.`1 = mgf1_sha512 (BArray112.to_list s) 39].
proof.
proc.
while (0 <= c <= inc /\ inc = (39 + 63) %/ 64 /\
       (forall k, 0 <= k < 256 => !(112 <= k < 116) =>
          BArray320.get8 m k = lay112 (BArray112.to_list s) k) /\
       forall j, 0 <= j < 39 => j < 64 * c =>
         BArray39.get8 out j = nth W8.zero (mgf1_sha512 (BArray112.to_list s) 39) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if 39 - 64 * c < 64 then 39 - 64 * c else 64) /\
         0 <= c < inc /\ inc = (39 + 63) %/ 64 /\
         hwords h = hash H0_512 (BArray112.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < 256 => !(112 <= k < 116) =>
            BArray320.get8 m k = lay112 (BArray112.to_list s) k) /\
         forall j, 0 <= j < 39 => j < 64 * c + i =>
           BArray39.get8 out j = nth W8.zero (mgf1_sha512 (BArray112.to_list s) 39) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi64] := idx_out 39 c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite BArray39.get_setE; first exact hidx.
    case: (j = 64 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite byte_be64 1:/# nth_mgf1_512 1:/#.
    have -> : (64 * c{hr} + i{hr}) %/ 64 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (64 * c{hr} + i{hr}) %% 64 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite (nth_sha512 _ _ hi64) -hh (nth_hwords _ _ (idx8 _ hi64)).
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = 2 /\ 0 <= c < inc /\ inc = (39 + 63) %/ 64 /\
         hwords h = foldl compress H0_512 (take b (parse (pad (BArray112.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < 256 =>
            BArray320.get8 m k = nth W8.zero (pad (BArray112.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < 256 => !(112 <= k < 116) =>
            BArray320.get8 m k = lay112 (BArray112.to_list s) k) /\
         forall j, 0 <= j < 39 => j < 64 * c =>
           BArray39.get8 out j = nth W8.zero (mgf1_sha512 (BArray112.to_list s) 39) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (sha512_compress_correct (hwords h0) (SBArray320_128.get_sub m0 (128 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hp hm hout hb h1 hh1.
    split; first smt().
    split; first by rewrite hh1 hh step_block112 // size_cat size_be_bytes BArray112.size_to_list.
    smt().
  wp; call sha512_init_correct; exlim m, c => m0 c0.
  call (mgf112_39_set_counter_correct m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> ? m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad116 1:BArray112.size_to_list 1,2:/#.
      by case: (112 <= k < 116) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = 2) 1:/# take_oversize //.
    by rewrite size_parse256 // size_pad116 // size_cat size_be_bytes BArray112.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (out_step 39 c0 i3 j) => //; smt().
wp; call (mgf112_39_layout_correct s).
auto => /> &hr m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite BArray39.size_to_list size_mgf1_512.
by move=> j; rewrite BArray39.size_to_list => hj; rewrite BArray39.get_to_list hout2 // /#.
qed.

lemma mgf112_39_sha512_ll : islossless M.mgf112_39___mgf1_sha512.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call sha512_compress_ll; auto => /#.
  by wp; call sha512_init_ll; call mgf112_39_set_counter_ll; auto => /#.
by wp; call mgf112_39_layout_ll; auto => /#.
qed.

lemma mgf112_39_sha512_total (s : BArray112.t) :
  phoare [M.mgf112_39___mgf1_sha512 : seed = s ==>
           BArray39.to_list res.`1 = mgf1_sha512 (BArray112.to_list s) 39] = 1%r.
proof. by conseq mgf112_39_sha512_ll (mgf112_39_sha512_correct s). qed.

(* ------------------------------------------------------------------ *)
(* Mgf112_42: 112-byte seed, 42 bytes of output                          *)

lemma mgf112_42_layout_correct (s : BArray112.t) :
  hoare [M.mgf112_42____mgf1_layout : seed = s /\ padded = 256 ==>
    forall k, 0 <= k < 256 => !(112 <= k < 116) =>
      BArray320.get8 res k = lay112 (BArray112.to_list s) k].
proof.
proc.
while (0 <= i <= 8 /\ padded = 256 /\ seed = s /\ to_uint t = 928 %/ 256 ^ i /\
       forall k, 0 <= k < 256 => !(112 <= k < 116) =>
         BArray320.get8 m k = if 256 - i <= k then lay112 (BArray112.to_list s) k
                              else if k < 112 then BArray112.get8 s k
                              else if k = 116 then W8.of_int 128 else W8.zero).
+ auto => /> &hr hi0 _ ht hm hi8; split; first smt().
  split.
  + by rewrite shr8_div ht exprSr 1:/# divz_mul //; apply expr_ge0.
  move=> k hk hk'; rewrite BArray320.get_setE 1:/#.
  case: (k = 255 - i{hr}) => [->|hne] /=.
  + rewrite (trunc_u _ _ ht) /lay112 (_ : !(255 - i{hr} < 112)) 1:/# (_ : 255 - i{hr} <> 116) 1:/#.
    by rewrite (_ : 240 <= 255 - i{hr}) 1:/# (_ : 255 - (255 - i{hr}) = i{hr}) 1:/# /#.
  by move=> hk2; rewrite hm //; smt().
wp; while (0 <= i <= 112 /\ padded = 256 /\ seed = s /\
           forall k, 0 <= k < 256 => BArray320.get8 m k = if k < i then BArray112.get8 s k else W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/# trunc_zext; smt().
wp; while (0 <= i <= inc /\ inc = 256 /\ padded = 256 /\ seed = s /\ z = W64.of_int 0 /\
           forall k, 0 <= k < i => BArray320.get8 m k = W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64; smt().
auto => /> &hr; split; first smt().
move=> m1 i1 hi1 _ hm1 hi1'; split; first smt().
move=> m2 i2 hi2 _ hm2 hi2'; split.
+ move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64 /=; smt().
move=> i3 m3 t3 hi3 hi3a hi3b ht3 hm3 k hk0 hk1 hk'; rewrite hm3 1:/# //.
rewrite (_ : i3 = 8) 1:/# /=.
case: (248 <= k) => // h248.
case: (240 <= k) => h240.
+ by rewrite lay112_zero 1:/# (_ : !(k < 112)) 1:/# (_ : k <> 116) 1:/#.
rewrite /lay112 (_ : !(240 <= k)) 1:/# /=.
by case: (k < 112) => h64 /=; smt().
qed.

lemma mgf112_42_layout_ll : islossless M.mgf112_42____mgf1_layout.
proof.
proc; while (true) (8 - i); first by auto => /#.
wp; while (true) (112 - i); first by auto => /#.
by wp; while (true) (inc - i); auto => /#.
qed.

lemma mgf112_42_set_counter_correct (m0 : BArray320.t) (c0 : int) :
  hoare [M.mgf112_42____mgf1_set_counter : m = m0 /\ c = c0 /\ 0 <= c0 < 256 ==>
    forall k, 0 <= k < 320 => BArray320.get8 res k =
      if 112 <= k < 116 then nth W8.zero (be_bytes 4 c0) (k - 112) else BArray320.get8 m0 k].
proof.
proc.
while (0 <= i <= 4 /\ c = c0 /\ 0 <= c0 < 256 /\
       forall k, 0 <= k < 320 => BArray320.get8 m k =
         if 112 <= k < 112 + i then nth W8.zero (be_bytes 4 c0) (k - 112) else BArray320.get8 m0 k).
+ auto => /> &hr hi0 _ hc0 hc1 hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/#.
  case: (k = 112 + i{hr}) => [->|hne] /=.
  + move=> _; rewrite (_ : 112 <= 112 + i{hr} < i{hr} + 113) 1:/# /=.
    by rewrite be4_byte; smt().
  by move=> hk2; smt().
by auto => />; smt().
qed.

lemma mgf112_42_set_counter_ll : islossless M.mgf112_42____mgf1_set_counter.
proof. by proc; while (true) (4 - i); auto => /#. qed.

lemma mgf112_42_sha512_correct (s : BArray112.t) :
  hoare [M.mgf112_42___mgf1_sha512 : seed = s ==>
           BArray42.to_list res.`1 = mgf1_sha512 (BArray112.to_list s) 42].
proof.
proc.
while (0 <= c <= inc /\ inc = (42 + 63) %/ 64 /\
       (forall k, 0 <= k < 256 => !(112 <= k < 116) =>
          BArray320.get8 m k = lay112 (BArray112.to_list s) k) /\
       forall j, 0 <= j < 42 => j < 64 * c =>
         BArray42.get8 out j = nth W8.zero (mgf1_sha512 (BArray112.to_list s) 42) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if 42 - 64 * c < 64 then 42 - 64 * c else 64) /\
         0 <= c < inc /\ inc = (42 + 63) %/ 64 /\
         hwords h = hash H0_512 (BArray112.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < 256 => !(112 <= k < 116) =>
            BArray320.get8 m k = lay112 (BArray112.to_list s) k) /\
         forall j, 0 <= j < 42 => j < 64 * c + i =>
           BArray42.get8 out j = nth W8.zero (mgf1_sha512 (BArray112.to_list s) 42) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi64] := idx_out 42 c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite BArray42.get_setE; first exact hidx.
    case: (j = 64 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite byte_be64 1:/# nth_mgf1_512 1:/#.
    have -> : (64 * c{hr} + i{hr}) %/ 64 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (64 * c{hr} + i{hr}) %% 64 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite (nth_sha512 _ _ hi64) -hh (nth_hwords _ _ (idx8 _ hi64)).
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = 2 /\ 0 <= c < inc /\ inc = (42 + 63) %/ 64 /\
         hwords h = foldl compress H0_512 (take b (parse (pad (BArray112.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < 256 =>
            BArray320.get8 m k = nth W8.zero (pad (BArray112.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < 256 => !(112 <= k < 116) =>
            BArray320.get8 m k = lay112 (BArray112.to_list s) k) /\
         forall j, 0 <= j < 42 => j < 64 * c =>
           BArray42.get8 out j = nth W8.zero (mgf1_sha512 (BArray112.to_list s) 42) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (sha512_compress_correct (hwords h0) (SBArray320_128.get_sub m0 (128 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hp hm hout hb h1 hh1.
    split; first smt().
    split; first by rewrite hh1 hh step_block112 // size_cat size_be_bytes BArray112.size_to_list.
    smt().
  wp; call sha512_init_correct; exlim m, c => m0 c0.
  call (mgf112_42_set_counter_correct m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> ? m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad116 1:BArray112.size_to_list 1,2:/#.
      by case: (112 <= k < 116) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = 2) 1:/# take_oversize //.
    by rewrite size_parse256 // size_pad116 // size_cat size_be_bytes BArray112.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (out_step 42 c0 i3 j) => //; smt().
wp; call (mgf112_42_layout_correct s).
auto => /> &hr m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite BArray42.size_to_list size_mgf1_512.
by move=> j; rewrite BArray42.size_to_list => hj; rewrite BArray42.get_to_list hout2 // /#.
qed.

lemma mgf112_42_sha512_ll : islossless M.mgf112_42___mgf1_sha512.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call sha512_compress_ll; auto => /#.
  by wp; call sha512_init_ll; call mgf112_42_set_counter_ll; auto => /#.
by wp; call mgf112_42_layout_ll; auto => /#.
qed.

lemma mgf112_42_sha512_total (s : BArray112.t) :
  phoare [M.mgf112_42___mgf1_sha512 : seed = s ==>
           BArray42.to_list res.`1 = mgf1_sha512 (BArray112.to_list s) 42] = 1%r.
proof. by conseq mgf112_42_sha512_ll (mgf112_42_sha512_correct s). qed.

(* ------------------------------------------------------------------ *)
(* Mgf128_47: 128-byte seed, 47 bytes of output                          *)

lemma mgf128_47_layout_correct (s : BArray128.t) :
  hoare [M.mgf128_47____mgf1_layout : seed = s /\ padded = 256 ==>
    forall k, 0 <= k < 256 => !(128 <= k < 132) =>
      BArray320.get8 res k = lay128 (BArray128.to_list s) k].
proof.
proc.
while (0 <= i <= 8 /\ padded = 256 /\ seed = s /\ to_uint t = 1056 %/ 256 ^ i /\
       forall k, 0 <= k < 256 => !(128 <= k < 132) =>
         BArray320.get8 m k = if 256 - i <= k then lay128 (BArray128.to_list s) k
                              else if k < 128 then BArray128.get8 s k
                              else if k = 132 then W8.of_int 128 else W8.zero).
+ auto => /> &hr hi0 _ ht hm hi8; split; first smt().
  split.
  + by rewrite shr8_div ht exprSr 1:/# divz_mul //; apply expr_ge0.
  move=> k hk hk'; rewrite BArray320.get_setE 1:/#.
  case: (k = 255 - i{hr}) => [->|hne] /=.
  + rewrite (trunc_u _ _ ht) /lay128 (_ : !(255 - i{hr} < 128)) 1:/# (_ : 255 - i{hr} <> 132) 1:/#.
    by rewrite (_ : 240 <= 255 - i{hr}) 1:/# (_ : 255 - (255 - i{hr}) = i{hr}) 1:/# /#.
  by move=> hk2; rewrite hm //; smt().
wp; while (0 <= i <= 128 /\ padded = 256 /\ seed = s /\
           forall k, 0 <= k < 256 => BArray320.get8 m k = if k < i then BArray128.get8 s k else W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/# trunc_zext; smt().
wp; while (0 <= i <= inc /\ inc = 256 /\ padded = 256 /\ seed = s /\ z = W64.of_int 0 /\
           forall k, 0 <= k < i => BArray320.get8 m k = W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64; smt().
auto => /> &hr; split; first smt().
move=> m1 i1 hi1 _ hm1 hi1'; split; first smt().
move=> m2 i2 hi2 _ hm2 hi2'; split.
+ move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64 /=; smt().
move=> i3 m3 t3 hi3 hi3a hi3b ht3 hm3 k hk0 hk1 hk'; rewrite hm3 1:/# //.
rewrite (_ : i3 = 8) 1:/# /=.
case: (248 <= k) => // h248.
case: (240 <= k) => h240.
+ by rewrite lay128_zero 1:/# (_ : !(k < 128)) 1:/# (_ : k <> 132) 1:/#.
rewrite /lay128 (_ : !(240 <= k)) 1:/# /=.
by case: (k < 128) => h64 /=; smt().
qed.

lemma mgf128_47_layout_ll : islossless M.mgf128_47____mgf1_layout.
proof.
proc; while (true) (8 - i); first by auto => /#.
wp; while (true) (128 - i); first by auto => /#.
by wp; while (true) (inc - i); auto => /#.
qed.

lemma mgf128_47_set_counter_correct (m0 : BArray320.t) (c0 : int) :
  hoare [M.mgf128_47____mgf1_set_counter : m = m0 /\ c = c0 /\ 0 <= c0 < 256 ==>
    forall k, 0 <= k < 320 => BArray320.get8 res k =
      if 128 <= k < 132 then nth W8.zero (be_bytes 4 c0) (k - 128) else BArray320.get8 m0 k].
proof.
proc.
while (0 <= i <= 4 /\ c = c0 /\ 0 <= c0 < 256 /\
       forall k, 0 <= k < 320 => BArray320.get8 m k =
         if 128 <= k < 128 + i then nth W8.zero (be_bytes 4 c0) (k - 128) else BArray320.get8 m0 k).
+ auto => /> &hr hi0 _ hc0 hc1 hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/#.
  case: (k = 128 + i{hr}) => [->|hne] /=.
  + move=> _; rewrite (_ : 128 <= 128 + i{hr} < i{hr} + 129) 1:/# /=.
    by rewrite be4_byte; smt().
  by move=> hk2; smt().
by auto => />; smt().
qed.

lemma mgf128_47_set_counter_ll : islossless M.mgf128_47____mgf1_set_counter.
proof. by proc; while (true) (4 - i); auto => /#. qed.

lemma mgf128_47_sha512_correct (s : BArray128.t) :
  hoare [M.mgf128_47___mgf1_sha512 : seed = s ==>
           BArray47.to_list res.`1 = mgf1_sha512 (BArray128.to_list s) 47].
proof.
proc.
while (0 <= c <= inc /\ inc = (47 + 63) %/ 64 /\
       (forall k, 0 <= k < 256 => !(128 <= k < 132) =>
          BArray320.get8 m k = lay128 (BArray128.to_list s) k) /\
       forall j, 0 <= j < 47 => j < 64 * c =>
         BArray47.get8 out j = nth W8.zero (mgf1_sha512 (BArray128.to_list s) 47) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if 47 - 64 * c < 64 then 47 - 64 * c else 64) /\
         0 <= c < inc /\ inc = (47 + 63) %/ 64 /\
         hwords h = hash H0_512 (BArray128.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < 256 => !(128 <= k < 132) =>
            BArray320.get8 m k = lay128 (BArray128.to_list s) k) /\
         forall j, 0 <= j < 47 => j < 64 * c + i =>
           BArray47.get8 out j = nth W8.zero (mgf1_sha512 (BArray128.to_list s) 47) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi64] := idx_out 47 c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite BArray47.get_setE; first exact hidx.
    case: (j = 64 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite byte_be64 1:/# nth_mgf1_512 1:/#.
    have -> : (64 * c{hr} + i{hr}) %/ 64 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (64 * c{hr} + i{hr}) %% 64 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite (nth_sha512 _ _ hi64) -hh (nth_hwords _ _ (idx8 _ hi64)).
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = 2 /\ 0 <= c < inc /\ inc = (47 + 63) %/ 64 /\
         hwords h = foldl compress H0_512 (take b (parse (pad (BArray128.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < 256 =>
            BArray320.get8 m k = nth W8.zero (pad (BArray128.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < 256 => !(128 <= k < 132) =>
            BArray320.get8 m k = lay128 (BArray128.to_list s) k) /\
         forall j, 0 <= j < 47 => j < 64 * c =>
           BArray47.get8 out j = nth W8.zero (mgf1_sha512 (BArray128.to_list s) 47) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (sha512_compress_correct (hwords h0) (SBArray320_128.get_sub m0 (128 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hp hm hout hb h1 hh1.
    split; first smt().
    split; first by rewrite hh1 hh step_block128 // size_cat size_be_bytes BArray128.size_to_list.
    smt().
  wp; call sha512_init_correct; exlim m, c => m0 c0.
  call (mgf128_47_set_counter_correct m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> ? m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad132 1:BArray128.size_to_list 1,2:/#.
      by case: (128 <= k < 132) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = 2) 1:/# take_oversize //.
    by rewrite size_parse256 // size_pad132 // size_cat size_be_bytes BArray128.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (out_step 47 c0 i3 j) => //; smt().
wp; call (mgf128_47_layout_correct s).
auto => /> &hr m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite BArray47.size_to_list size_mgf1_512.
by move=> j; rewrite BArray47.size_to_list => hj; rewrite BArray47.get_to_list hout2 // /#.
qed.

lemma mgf128_47_sha512_ll : islossless M.mgf128_47___mgf1_sha512.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call sha512_compress_ll; auto => /#.
  by wp; call sha512_init_ll; call mgf128_47_set_counter_ll; auto => /#.
by wp; call mgf128_47_layout_ll; auto => /#.
qed.

lemma mgf128_47_sha512_total (s : BArray128.t) :
  phoare [M.mgf128_47___mgf1_sha512 : seed = s ==>
           BArray47.to_list res.`1 = mgf1_sha512 (BArray128.to_list s) 47] = 1%r.
proof. by conseq mgf128_47_sha512_ll (mgf128_47_sha512_correct s). qed.

(* ------------------------------------------------------------------ *)
(* Mgf128_49: 128-byte seed, 49 bytes of output                          *)

lemma mgf128_49_layout_correct (s : BArray128.t) :
  hoare [M.mgf128_49____mgf1_layout : seed = s /\ padded = 256 ==>
    forall k, 0 <= k < 256 => !(128 <= k < 132) =>
      BArray320.get8 res k = lay128 (BArray128.to_list s) k].
proof.
proc.
while (0 <= i <= 8 /\ padded = 256 /\ seed = s /\ to_uint t = 1056 %/ 256 ^ i /\
       forall k, 0 <= k < 256 => !(128 <= k < 132) =>
         BArray320.get8 m k = if 256 - i <= k then lay128 (BArray128.to_list s) k
                              else if k < 128 then BArray128.get8 s k
                              else if k = 132 then W8.of_int 128 else W8.zero).
+ auto => /> &hr hi0 _ ht hm hi8; split; first smt().
  split.
  + by rewrite shr8_div ht exprSr 1:/# divz_mul //; apply expr_ge0.
  move=> k hk hk'; rewrite BArray320.get_setE 1:/#.
  case: (k = 255 - i{hr}) => [->|hne] /=.
  + rewrite (trunc_u _ _ ht) /lay128 (_ : !(255 - i{hr} < 128)) 1:/# (_ : 255 - i{hr} <> 132) 1:/#.
    by rewrite (_ : 240 <= 255 - i{hr}) 1:/# (_ : 255 - (255 - i{hr}) = i{hr}) 1:/# /#.
  by move=> hk2; rewrite hm //; smt().
wp; while (0 <= i <= 128 /\ padded = 256 /\ seed = s /\
           forall k, 0 <= k < 256 => BArray320.get8 m k = if k < i then BArray128.get8 s k else W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/# trunc_zext; smt().
wp; while (0 <= i <= inc /\ inc = 256 /\ padded = 256 /\ seed = s /\ z = W64.of_int 0 /\
           forall k, 0 <= k < i => BArray320.get8 m k = W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64; smt().
auto => /> &hr; split; first smt().
move=> m1 i1 hi1 _ hm1 hi1'; split; first smt().
move=> m2 i2 hi2 _ hm2 hi2'; split.
+ move=> k hk hk'; rewrite BArray320.get_setE 1:/# trunc64 /=; smt().
move=> i3 m3 t3 hi3 hi3a hi3b ht3 hm3 k hk0 hk1 hk'; rewrite hm3 1:/# //.
rewrite (_ : i3 = 8) 1:/# /=.
case: (248 <= k) => // h248.
case: (240 <= k) => h240.
+ by rewrite lay128_zero 1:/# (_ : !(k < 128)) 1:/# (_ : k <> 132) 1:/#.
rewrite /lay128 (_ : !(240 <= k)) 1:/# /=.
by case: (k < 128) => h64 /=; smt().
qed.

lemma mgf128_49_layout_ll : islossless M.mgf128_49____mgf1_layout.
proof.
proc; while (true) (8 - i); first by auto => /#.
wp; while (true) (128 - i); first by auto => /#.
by wp; while (true) (inc - i); auto => /#.
qed.

lemma mgf128_49_set_counter_correct (m0 : BArray320.t) (c0 : int) :
  hoare [M.mgf128_49____mgf1_set_counter : m = m0 /\ c = c0 /\ 0 <= c0 < 256 ==>
    forall k, 0 <= k < 320 => BArray320.get8 res k =
      if 128 <= k < 132 then nth W8.zero (be_bytes 4 c0) (k - 128) else BArray320.get8 m0 k].
proof.
proc.
while (0 <= i <= 4 /\ c = c0 /\ 0 <= c0 < 256 /\
       forall k, 0 <= k < 320 => BArray320.get8 m k =
         if 128 <= k < 128 + i then nth W8.zero (be_bytes 4 c0) (k - 128) else BArray320.get8 m0 k).
+ auto => /> &hr hi0 _ hc0 hc1 hm hi; split; first smt().
  move=> k hk; rewrite BArray320.get_setE 1:/#.
  case: (k = 128 + i{hr}) => [->|hne] /=.
  + move=> _; rewrite (_ : 128 <= 128 + i{hr} < i{hr} + 129) 1:/# /=.
    by rewrite be4_byte; smt().
  by move=> hk2; smt().
by auto => />; smt().
qed.

lemma mgf128_49_set_counter_ll : islossless M.mgf128_49____mgf1_set_counter.
proof. by proc; while (true) (4 - i); auto => /#. qed.

lemma mgf128_49_sha512_correct (s : BArray128.t) :
  hoare [M.mgf128_49___mgf1_sha512 : seed = s ==>
           BArray49.to_list res.`1 = mgf1_sha512 (BArray128.to_list s) 49].
proof.
proc.
while (0 <= c <= inc /\ inc = (49 + 63) %/ 64 /\
       (forall k, 0 <= k < 256 => !(128 <= k < 132) =>
          BArray320.get8 m k = lay128 (BArray128.to_list s) k) /\
       forall j, 0 <= j < 49 => j < 64 * c =>
         BArray49.get8 out j = nth W8.zero (mgf1_sha512 (BArray128.to_list s) 49) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if 49 - 64 * c < 64 then 49 - 64 * c else 64) /\
         0 <= c < inc /\ inc = (49 + 63) %/ 64 /\
         hwords h = hash H0_512 (BArray128.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < 256 => !(128 <= k < 132) =>
            BArray320.get8 m k = lay128 (BArray128.to_list s) k) /\
         forall j, 0 <= j < 49 => j < 64 * c + i =>
           BArray49.get8 out j = nth W8.zero (mgf1_sha512 (BArray128.to_list s) 49) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi64] := idx_out 49 c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite BArray49.get_setE; first exact hidx.
    case: (j = 64 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite byte_be64 1:/# nth_mgf1_512 1:/#.
    have -> : (64 * c{hr} + i{hr}) %/ 64 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (64 * c{hr} + i{hr}) %% 64 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite (nth_sha512 _ _ hi64) -hh (nth_hwords _ _ (idx8 _ hi64)).
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = 2 /\ 0 <= c < inc /\ inc = (49 + 63) %/ 64 /\
         hwords h = foldl compress H0_512 (take b (parse (pad (BArray128.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < 256 =>
            BArray320.get8 m k = nth W8.zero (pad (BArray128.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < 256 => !(128 <= k < 132) =>
            BArray320.get8 m k = lay128 (BArray128.to_list s) k) /\
         forall j, 0 <= j < 49 => j < 64 * c =>
           BArray49.get8 out j = nth W8.zero (mgf1_sha512 (BArray128.to_list s) 49) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (sha512_compress_correct (hwords h0) (SBArray320_128.get_sub m0 (128 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hp hm hout hb h1 hh1.
    split; first smt().
    split; first by rewrite hh1 hh step_block128 // size_cat size_be_bytes BArray128.size_to_list.
    smt().
  wp; call sha512_init_correct; exlim m, c => m0 c0.
  call (mgf128_49_set_counter_correct m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> ? m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad132 1:BArray128.size_to_list 1,2:/#.
      by case: (128 <= k < 132) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = 2) 1:/# take_oversize //.
    by rewrite size_parse256 // size_pad132 // size_cat size_be_bytes BArray128.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (out_step 49 c0 i3 j) => //; smt().
wp; call (mgf128_49_layout_correct s).
auto => /> &hr m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite BArray49.size_to_list size_mgf1_512.
by move=> j; rewrite BArray49.size_to_list => hj; rewrite BArray49.get_to_list hout2 // /#.
qed.

lemma mgf128_49_sha512_ll : islossless M.mgf128_49___mgf1_sha512.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call sha512_compress_ll; auto => /#.
  by wp; call sha512_init_ll; call mgf128_49_set_counter_ll; auto => /#.
by wp; call mgf128_49_layout_ll; auto => /#.
qed.

lemma mgf128_49_sha512_total (s : BArray128.t) :
  phoare [M.mgf128_49___mgf1_sha512 : seed = s ==>
           BArray49.to_list res.`1 = mgf1_sha512 (BArray128.to_list s) 49] = 1%r.
proof. by conseq mgf128_49_sha512_ll (mgf128_49_sha512_correct s). qed.
