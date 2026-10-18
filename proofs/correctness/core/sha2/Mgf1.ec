(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mgf1.ec (SHA2 sets)
 * ===================
 *
 * MGF1 (RFC 8017, appendix B.2.1) as the model of a SHA2 set runs it at
 * the end of H_msg: _mgf1_sha256 and _mgf1_sha512 of
 * src/hash/sha2/mgf1.jinc, instantiated in thash_sha2.jinc with the seed
 * R || PK.seed || X(R || PK.seed || PK.root || M) of S = 2n + |X| bytes
 * (the role MgfSeed) and m bytes of output (Digest).
 *
 * The proof is the one of MGF1_SHA256.ec and MGF1_SHA512.ec, written once
 * for a seed of any length S. The code lays out the padded message of
 * FIPS 180-4 section 5.1 in the first L bytes of its buffer (MgfBuf):
 *
 *     m[0, S)          seed
 *     m[S, S + 4)      counter c, big-endian (rewritten for each c)
 *     m[S + 4]         0x80
 *     m[S + 5, L - 8)  zero
 *     m[L - 8, L)      8 (S + 4), big-endian
 *
 * L is 64 ceil((S + 13) / 64) for SHA-256 (pad_len256) and
 * 128 ceil((S + 21) / 128) for SHA-512 (pad_len512), whose 16-byte length
 * field starts with eight zero bytes since the bit length is below 2^16.
 * So m[0, L) is pad(seed ++ I2OSP(c, 4)). For each c the code compresses
 * its L/64 or L/128 blocks from the initial value and writes bytes
 * hc .. hc + h - 1 of the output (fewer in the last round) from the
 * big-endian chaining words: block c of T in RFC 8017, h = 32 or 64.
 *
 * Both procedures are proved on every SHA2 set, though each set calls
 * only one of them.
 *
 * Theorems (total correctness):
 *     mgf1_sha256_total   to_list out = mgf1_sha256 seed m
 *     mgf1_sha512_total   to_list out = mgf1_sha512 seed m
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils.
require import Bytes FIPS180_SHA2 RFC8017_MGF1 FIPS205_Params.
require import BArray32 BArray64 BArray128 SetModel CoreExtracted.
require import Thash MsgHash.
require MGF1_SHA256 MGF1_SHA512.

(* ------------------------------------------------------------------ *)
(* Lengths                                                            *)

op pad_len256 : int = 64 * ((MgfSeed.size + 76) %/ 64).
op pad_len512 : int = 128 * ((MgfSeed.size + 148) %/ 128).

lemma mgf_dims :
  0 < MgfSeed.size /\ 8 * (MgfSeed.size + 4) < 65536 /\
  pad_len256 = MgfSeed.size + 13 + (51 - MgfSeed.size) %% 64 /\ pad_len256 <= MgfBuf.size /\
  pad_len512 = MgfSeed.size + 21 + (107 - MgfSeed.size) %% 128 /\ pad_len512 <= MgfBuf.size.
proof. by rewrite /pad_len256 /pad_len512; smt(). qed.

lemma pad256_range : MgfSeed.size + 13 <= pad_len256 <= MgfBuf.size.
proof. by rewrite /pad_len256; smt(). qed.

lemma pad512_range : MgfSeed.size + 13 <= pad_len512 <= MgfBuf.size.
proof. by rewrite /pad_len512; smt(). qed.

lemma digest_size : Digest.size = P.`m.
proof. smt(m_val). qed.

(* ------------------------------------------------------------------ *)
(* The padded message                                                 *)

(* m[0, L) outside the counter bytes, as the layout writes it. *)
op lay (s : bytes) (l k : int) : W8.t =
  if k < MgfSeed.size then nth W8.zero s k
  else if k = MgfSeed.size + 4 then W8.of_int 128
  else if l - 8 <= k then W8.of_int (8 * (MgfSeed.size + 4) %/ 256 ^ (l - 1 - k))
  else W8.zero.

lemma pad256E (x : bytes) :
  SHA256.pad x = x ++ ([W8.of_int 128] ++ (zeros ((55 - size x) %% 64) ++ be_bytes 8 (8 * size x))).
proof. by rewrite /SHA256.pad -!catA. qed.

lemma pad512E (x : bytes) :
  SHA512.pad x = x ++ ([W8.of_int 128] ++ (zeros ((111 - size x) %% 128) ++ be_bytes 16 (8 * size x))).
proof. by rewrite /SHA512.pad -!catA. qed.

lemma size_pad256 (x : bytes) : size x = MgfSeed.size + 4 => size (SHA256.pad x) = pad_len256.
proof.
move=> hx; have [_ [_ [hp _]]] := mgf_dims.
rewrite /SHA256.pad !size_cat size_zeros size_be_bytes hx /= hp; smt().
qed.

lemma size_pad512 (x : bytes) : size x = MgfSeed.size + 4 => size (SHA512.pad x) = pad_len512.
proof.
move=> hx; have [_ [_ [_ [_ [hp _]]]]] := mgf_dims.
rewrite /SHA512.pad !size_cat size_zeros size_be_bytes hx /= hp; smt().
qed.

lemma nth_pad256 (s : bytes) (c k : int) : size s = MgfSeed.size => 0 <= k < pad_len256 =>
  nth W8.zero (SHA256.pad (s ++ be_bytes 4 c)) k =
  if MgfSeed.size <= k < MgfSeed.size + 4 then nth W8.zero (be_bytes 4 c) (k - MgfSeed.size)
  else lay s pad_len256 k.
proof.
move=> hs hk; have [hs0 [_ [hp _]]] := mgf_dims.
have hx : size (s ++ be_bytes 4 c) = MgfSeed.size + 4 by rewrite size_cat size_be_bytes hs.
pose z := (55 - (MgfSeed.size + 4)) %% 64.
have hz : size (zeros z) = z by rewrite size_zeros; smt().
rewrite pad256E hx -/z nth_cat hx /lay.
case: (k < MgfSeed.size + 4) => h4 /=.
+ by rewrite nth_cat hs; smt().
rewrite (_ : !(k < MgfSeed.size)) 1:/# /=.
case: (k = MgfSeed.size + 4) => h1 /=; first by rewrite h1.
rewrite (_ : k - (MgfSeed.size + 4) <> 0) 1:/# /= nth_cat hz.
case: (k < pad_len256 - 8) => h2.
+ by rewrite (_ : k - (MgfSeed.size + 4) - 1 < z) 1:/# /= (_ : !(pad_len256 - 8 <= k)) 1:/# /= nth_nseq 1:/#.
rewrite (_ : !(k - (MgfSeed.size + 4) - 1 < z)) 1:/# (_ : pad_len256 - 8 <= k) 1:/# /=.
rewrite /be_bytes nth_mkseq 1:/# /=.
smt().
qed.

lemma nth_pad512 (s : bytes) (c k : int) : size s = MgfSeed.size => 0 <= k < pad_len512 =>
  nth W8.zero (SHA512.pad (s ++ be_bytes 4 c)) k =
  if MgfSeed.size <= k < MgfSeed.size + 4 then nth W8.zero (be_bytes 4 c) (k - MgfSeed.size)
  else lay s pad_len512 k.
proof.
move=> hs hk; have [hs0 [hl [_ [_ [hp _]]]]] := mgf_dims.
have hx : size (s ++ be_bytes 4 c) = MgfSeed.size + 4 by rewrite size_cat size_be_bytes hs.
pose z := (111 - (MgfSeed.size + 4)) %% 128.
have hz : size (zeros z) = z by rewrite size_zeros; smt().
rewrite pad512E hx -/z nth_cat hx /lay.
case: (k < MgfSeed.size + 4) => h4 /=.
+ by rewrite nth_cat hs; smt().
rewrite (_ : !(k < MgfSeed.size)) 1:/# /=.
case: (k = MgfSeed.size + 4) => h1 /=; first by rewrite h1.
rewrite (_ : k - (MgfSeed.size + 4) <> 0) 1:/# /= nth_cat hz.
case: (k < pad_len512 - 16) => h2.
+ by rewrite (_ : k - (MgfSeed.size + 4) - 1 < z) 1:/# /= (_ : !(pad_len512 - 8 <= k)) 1:/# /= nth_nseq 1:/#.
rewrite (_ : !(k - (MgfSeed.size + 4) - 1 < z)) 1:/# /=.
rewrite /be_bytes nth_mkseq 1:/# /=.
have -> : 16 - 1 - (k - (MgfSeed.size + 4) - 1 - z) = pad_len512 - 1 - k by smt().
case: (pad_len512 - 8 <= k) => // h3.
by rewrite MGF1_SHA512.hi_zero 1,2:/#.
qed.

(* parse of a padded message of q blocks. *)
lemma size_parse256 (p : bytes) (q : int) : 0 <= q => size p = 64 * q => size (SHA256.parse p) = q.
proof. by move=> hq hp; rewrite /SHA256.parse size_map size_chunk // hp; smt(). qed.

lemma size_parse512 (p : bytes) (q : int) : 0 <= q => size p = 128 * q => size (SHA512.parse p) = q.
proof. by move=> hq hp; rewrite /SHA512.parse size_map size_chunk // hp; smt(). qed.

lemma nth_parse256 (p : bytes) (b : int) : 0 <= b => 64 * (b + 1) <= size p =>
  nth [] (SHA256.parse p) b = map be32 (chunk 4 (take 64 (drop (64 * b) p))).
proof.
move=> hb hp; rewrite /SHA256.parse (nth_map []) 1:size_chunk // 1:/#.
by rewrite /chunk nth_mkseq /= 1:/#.
qed.

lemma nth_parse512 (p : bytes) (b : int) : 0 <= b => 128 * (b + 1) <= size p =>
  nth [] (SHA512.parse p) b = map be64 (chunk 8 (take 128 (drop (128 * b) p))).
proof.
move=> hb hp; rewrite /SHA512.parse (nth_map []) 1:size_chunk // 1:/#.
by rewrite /chunk nth_mkseq /= 1:/#.
qed.

lemma sub_block256 (m : MgfBuf.t) (p : bytes) (b : int) : 0 <= b => 64 * (b + 1) <= size p =>
  size p <= MgfBuf.size =>
  (forall k, 0 <= k < size p => MgfBuf.get8 m k = nth W8.zero p k) =>
  BArray64.to_list (MgfBlk256.get_sub m (64 * b)) = take 64 (drop (64 * b) p).
proof.
move=> hb hp hpb hm; apply (eq_from_nth W8.zero).
+ by rewrite BArray64.size_to_list size_take // size_drop 1:/#; smt().
move=> j; rewrite BArray64.size_to_list => hj.
rewrite BArray64.get_to_list MgfBlk256.get8_get_sub hj /= hm 1:/#.
by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
qed.

lemma sub_block512 (m : MgfBuf.t) (p : bytes) (b : int) : 0 <= b => 128 * (b + 1) <= size p =>
  size p <= MgfBuf.size =>
  (forall k, 0 <= k < size p => MgfBuf.get8 m k = nth W8.zero p k) =>
  BArray128.to_list (MgfBlk512.get_sub m (128 * b)) = take 128 (drop (128 * b) p).
proof.
move=> hb hp hpb hm; apply (eq_from_nth W8.zero).
+ by rewrite BArray128.size_to_list size_take // size_drop 1:/#; smt().
move=> j; rewrite BArray128.size_to_list => hj.
rewrite BArray128.get_to_list MgfBlk512.get8_get_sub hj /= hm 1:/#.
by rewrite nth_take 1,2:/# nth_drop 1,2:/#.
qed.

(* The padded message for counter c, block by block. *)
lemma step_block256 (m : MgfBuf.t) (x : bytes) (b : int) :
  size x = MgfSeed.size + 4 => 0 <= b < pad_len256 %/ 64 =>
  (forall k, 0 <= k < pad_len256 => MgfBuf.get8 m k = nth W8.zero (SHA256.pad x) k) =>
  SHA256.compress (foldl SHA256.compress SHA256.H0_256 (take b (SHA256.parse (SHA256.pad x))))
    (map be32 (chunk 4 (BArray64.to_list (MgfBlk256.get_sub m (64 * b)))))
  = foldl SHA256.compress SHA256.H0_256 (take (b + 1) (SHA256.parse (SHA256.pad x))).
proof.
move=> hx hb hm; have [_ [_ [hp hpb]]] := mgf_dims; have hs := size_pad256 x hx.
have hq := size_parse256 (SHA256.pad x) (pad_len256 %/ 64) _ _; 1,2: smt().
have hn := nth_parse256 (SHA256.pad x) b _ _; 1,2: smt().
have hsb := sub_block256 m (SHA256.pad x) b _ _ _ _; 1..3: smt(); first by rewrite hs.
by rewrite (take_nth []) 1:/# foldl_rcons hn hsb.
qed.

lemma step_block512 (m : MgfBuf.t) (x : bytes) (b : int) :
  size x = MgfSeed.size + 4 => 0 <= b < pad_len512 %/ 128 =>
  (forall k, 0 <= k < pad_len512 => MgfBuf.get8 m k = nth W8.zero (SHA512.pad x) k) =>
  SHA512.compress (foldl SHA512.compress SHA512.H0_512 (take b (SHA512.parse (SHA512.pad x))))
    (map be64 (chunk 8 (BArray128.to_list (MgfBlk512.get_sub m (128 * b)))))
  = foldl SHA512.compress SHA512.H0_512 (take (b + 1) (SHA512.parse (SHA512.pad x))).
proof.
move=> hx hb hm; have [_ [_ [_ [_ [hp hpb]]]]] := mgf_dims; have hs := size_pad512 x hx.
have hq := size_parse512 (SHA512.pad x) (pad_len512 %/ 128) _ _; 1,2: smt().
have hn := nth_parse512 (SHA512.pad x) b _ _; 1,2: smt().
have hsb := sub_block512 m (SHA512.pad x) b _ _ _ _; 1..3: smt(); first by rewrite hs.
by rewrite (take_nth []) 1:/# foldl_rcons hn hsb.
qed.

lemma hash256_blocks (x : bytes) : size x = MgfSeed.size + 4 =>
  foldl SHA256.compress SHA256.H0_256 (take (pad_len256 %/ 64) (SHA256.parse (SHA256.pad x)))
  = SHA256.hash SHA256.H0_256 x.
proof.
move=> hx; have [_ [_ [hp _]]] := mgf_dims.
rewrite take_oversize // (size_parse256 _ (pad_len256 %/ 64)) 1:/# 1:size_pad256 //; smt().
qed.

lemma hash512_blocks (x : bytes) : size x = MgfSeed.size + 4 =>
  foldl SHA512.compress SHA512.H0_512 (take (pad_len512 %/ 128) (SHA512.parse (SHA512.pad x)))
  = SHA512.hash SHA512.H0_512 x.
proof.
move=> hx; have [_ [_ [_ [_ [hp _]]]]] := mgf_dims.
rewrite take_oversize // (size_parse512 _ (pad_len512 %/ 128)) 1:/# 1:size_pad512 //; smt().
qed.

lemma nth_hw256 (h : BArray32.t) (i : int) : 0 <= i < 32 =>
  nth W32.zero (hw256 h) (i %/ 4) = BArray32.get32 h (i %/ 4).
proof. by move=> hi; rewrite /hw256 (nth_map 0) 1:size_iota 1:/# /= nth_iota /#. qed.

lemma nth_hw512 (h : BArray64.t) (i : int) : 0 <= i < 64 =>
  nth W64.zero (hw512 h) (i %/ 8) = BArray64.get64 h (i %/ 8).
proof. by move=> hi; rewrite /hw512 (nth_map 0) 1:size_iota 1:/# /= nth_iota /#. qed.

(* ------------------------------------------------------------------ *)
(* The layout and the counter                                         *)

lemma layout_h (s : MgfSeed.t) (l : int) :
  MgfSeed.size + 13 <= l <= MgfBuf.size =>
  hoare [M.mgf____mgf1_layout : seed = s /\ padded = l ==>
    forall k, 0 <= k < l => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
      MgfBuf.get8 res k = lay (MgfSeed.to_list s) l k].
proof.
move=> hl; have [hs0 [hl8 _]] := mgf_dims.
proc.
while (0 <= i <= 8 /\ padded = l /\ seed = s /\ to_uint t = 8 * (MgfSeed.size + 4) %/ 256 ^ i /\
       forall k, 0 <= k < l => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
         MgfBuf.get8 m k = if l - i <= k then lay (MgfSeed.to_list s) l k
                           else if k < MgfSeed.size then MgfSeed.get8 s k
                           else if k = MgfSeed.size + 4 then W8.of_int 128 else W8.zero).
+ auto => /> &hr hi0 _ ht hm hi8; split; first smt().
  split.
  + by rewrite MGF1_SHA256.shr8_div ht exprSr 1:/# divz_mul //; apply expr_ge0.
  move=> k hk hk'; rewrite MgfBuf.get_setE 1:/#.
  case: (k = l - 1 - i{hr}) => [->|hne] /=.
  + rewrite (MGF1_SHA256.trunc_u _ _ ht) /lay (_ : !(l - 1 - i{hr} < MgfSeed.size)) 1:/#.
    rewrite (_ : l - 1 - i{hr} <> MgfSeed.size + 4) 1:/#.
    by rewrite (_ : l - 8 <= l - 1 - i{hr}) 1:/# (_ : l - 1 - (l - 1 - i{hr}) = i{hr}) 1:/# /#.
  by move=> hk2; rewrite hm //; smt().
wp; while (0 <= i <= inc /\ inc = MgfSeed.size /\ padded = l /\ seed = s /\
           forall k, 0 <= k < l => MgfBuf.get8 m k = if k < i then MgfSeed.get8 s k else W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk; rewrite MgfBuf.get_setE 1:/# SHA256_Stream.trunc_zext; smt().
wp; while (0 <= i <= inc /\ inc = l /\ padded = l /\ seed = s /\ z = W64.of_int 0 /\
           forall k, 0 <= k < i => MgfBuf.get8 m k = W8.zero).
+ auto => /> &hr hi0 _ hm hi; split; first smt().
  move=> k hk hk'; rewrite MgfBuf.get_setE 1:/# MGF1_SHA256.trunc64; smt().
auto => /> &hr; split; first smt().
move=> i0 m0 hi0 hi0a hi0b hm0; split; first smt().
move=> i1 m1 hi1 hi1a hi1b hsz hm1; split.
+ move=> k hk0 hk1 hk'; rewrite MgfBuf.get_setE 1:/# MGF1_SHA256.trunc64 /=; smt().
move=> i2 m2 t2 hi2 hi2a hi2b ht2 hm2 k hk0 hk1 hk'; rewrite hm2 1:/# //.
rewrite (_ : i2 = 8) 1:/# /lay /=.
by case: (k < MgfSeed.size) => h64 /=; smt(MgfSeed.get_to_list).
qed.

lemma layout_ll : islossless M.mgf____mgf1_layout.
proof.
proc; while (true) (8 - i); first by auto => /#.
wp; while (true) (inc - i); first by auto => /#.
by wp; while (true) (inc - i); auto => /#.
qed.

lemma set_counter_h (m0 : MgfBuf.t) (c0 : int) :
  hoare [M.mgf____mgf1_set_counter : m = m0 /\ c = c0 /\ 0 <= c0 < 256 ==>
    forall k, 0 <= k < MgfBuf.size => MgfBuf.get8 res k =
      if MgfSeed.size <= k < MgfSeed.size + 4 then nth W8.zero (be_bytes 4 c0) (k - MgfSeed.size)
      else MgfBuf.get8 m0 k].
proof.
have [hs0 _] := mgf_dims.
proc.
while (0 <= i <= 4 /\ c = c0 /\ 0 <= c0 < 256 /\
       forall k, 0 <= k < MgfBuf.size => MgfBuf.get8 m k =
         if MgfSeed.size <= k < MgfSeed.size + i then nth W8.zero (be_bytes 4 c0) (k - MgfSeed.size)
         else MgfBuf.get8 m0 k).
+ auto => /> &hr hi0 _ hc0 hc1 hm hi; split; first smt().
  move=> k hk; rewrite MgfBuf.get_setE 1:/#.
  case: (k = MgfSeed.size + i{hr}) => [hk'|hne] /=.
  + rewrite ifT 1:/# hk' (_ : MgfSeed.size + i{hr} - MgfSeed.size = i{hr}) 1:/#.
    by rewrite MGF1_SHA256.be4_byte; smt().
  by smt().
by auto => />; smt().
qed.

lemma set_counter_ll : islossless M.mgf____mgf1_set_counter.
proof. by proc; while (true) (4 - i); auto => /#. qed.

(* ------------------------------------------------------------------ *)
(* MGF1 over SHA-256                                                  *)

lemma init256_h : hoare [M.__sha256_init : true ==> hw256 res = SHA256.H0_256].
proof. by conseq sha256_init_total. qed.

lemma init512_h : hoare [M.__sha512_init : true ==> hw512 res = SHA512.H0_512].
proof. by conseq sha512_init_total. qed.

lemma init256_ll : islossless M.__sha256_init.
proof. by proc*; call sha256_init_total; auto. qed.

lemma init512_ll : islossless M.__sha512_init.
proof. by proc*; call sha512_init_total; auto. qed.

lemma mgf1_sha256_h (s : MgfSeed.t) :
  hoare [M.mgf___mgf1_sha256 : seed = s ==>
           Digest.to_list res.`1 = mgf1_sha256 (MgfSeed.to_list s) P.`m].
proof.
have hmv := m_val; have hdg := digest_size; have [hs0 [_ [hp hpb]]] := mgf_dims.
proc.
while (0 <= c <= inc /\ inc = (P.`m + 31) %/ 32 /\
       (forall k, 0 <= k < pad_len256 => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
          MgfBuf.get8 m k = lay (MgfSeed.to_list s) pad_len256 k) /\
       forall j, 0 <= j < P.`m => j < 32 * c =>
         Digest.get8 out j = nth W8.zero (mgf1_sha256 (MgfSeed.to_list s) P.`m) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if P.`m - 32 * c < 32 then P.`m - 32 * c else 32) /\
         0 <= c < inc /\ inc = (P.`m + 31) %/ 32 /\
         hw256 h = SHA256.hash SHA256.H0_256 (MgfSeed.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < pad_len256 => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
            MgfBuf.get8 m k = lay (MgfSeed.to_list s) pad_len256 k) /\
         forall j, 0 <= j < P.`m => j < 32 * c + i =>
           Digest.get8 out j = nth W8.zero (mgf1_sha256 (MgfSeed.to_list s) P.`m) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi32] := MGF1_SHA256.idx_out P.`m c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite Digest.get_setE 1:/#.
    case: (j = 32 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite MGF1_SHA256.byte_be32 1:/# MGF1_SHA256.nth_mgf1_256 1:/#.
    have -> : (32 * c{hr} + i{hr}) %/ 32 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (32 * c{hr} + i{hr}) %% 32 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite MGF1_SHA256.nth_sha256 1:/# -hh nth_hw256.
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = pad_len256 %/ 64 /\ 0 <= c < inc /\ inc = (P.`m + 31) %/ 32 /\
         hw256 h = foldl SHA256.compress SHA256.H0_256
                     (take b (SHA256.parse (SHA256.pad (MgfSeed.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < pad_len256 =>
            MgfBuf.get8 m k = nth W8.zero (SHA256.pad (MgfSeed.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < pad_len256 => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
            MgfBuf.get8 m k = lay (MgfSeed.to_list s) pad_len256 k) /\
         forall j, 0 <= j < P.`m => j < 32 * c =>
           Digest.get8 out j = nth W8.zero (mgf1_sha256 (MgfSeed.to_list s) P.`m) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (compress256_h (hw256 h0) (MgfBlk256.get_sub m0 (64 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hpm hm hout hb h1 hh1.
    split; first smt().
    have hx : size (MgfSeed.to_list s ++ be_bytes 4 c{hr}) = MgfSeed.size + 4.
    + by rewrite size_cat size_be_bytes MgfSeed.size_to_list.
    by rewrite hh1 hh (step_block256 _ _ b0 hx _ hpm); smt().
  wp; call init256_h; exlim m, c => m0 c0.
  ecall (set_counter_h m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> h256 m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad256 1:MgfSeed.size_to_list 1,2:/#.
      by case: (MgfSeed.size <= k < MgfSeed.size + 4) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hnb hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = pad_len256 %/ 64) 1:/# hash256_blocks //.
    by rewrite size_cat size_be_bytes MgfSeed.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hn3 hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (MGF1_SHA256.out_step P.`m c0 i3 j) => //; smt().
wp; ecall (layout_h s pad_len256 pad256_range).
auto => /> &hr hpl m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hinc hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite Digest.size_to_list MGF1_SHA256.size_mgf1_256 /#.
by move=> j; rewrite Digest.size_to_list => hj; rewrite Digest.get_to_list hout2 // /#.
qed.

lemma mgf1_sha256_ll : islossless M.mgf___mgf1_sha256.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call set_compress256_ll; auto => /#.
  by wp; call init256_ll; call set_counter_ll; auto => /#.
by wp; call layout_ll; auto => /#.
qed.

lemma mgf1_sha256_total (s : MgfSeed.t) :
  phoare [M.mgf___mgf1_sha256 : seed = s ==>
           Digest.to_list res.`1 = mgf1_sha256 (MgfSeed.to_list s) P.`m] = 1%r.
proof. by conseq mgf1_sha256_ll (mgf1_sha256_h s). qed.

(* ------------------------------------------------------------------ *)
(* MGF1 over SHA-512                                                  *)

lemma mgf1_sha512_h (s : MgfSeed.t) :
  hoare [M.mgf___mgf1_sha512 : seed = s ==>
           Digest.to_list res.`1 = mgf1_sha512 (MgfSeed.to_list s) P.`m].
proof.
have hmv := m_val; have hdg := digest_size; have [hs0 [_ [_ [_ [hp hpb]]]]] := mgf_dims.
proc.
while (0 <= c <= inc /\ inc = (P.`m + 63) %/ 64 /\
       (forall k, 0 <= k < pad_len512 => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
          MgfBuf.get8 m k = lay (MgfSeed.to_list s) pad_len512 k) /\
       forall j, 0 <= j < P.`m => j < 64 * c =>
         Digest.get8 out j = nth W8.zero (mgf1_sha512 (MgfSeed.to_list s) P.`m) j).
+ wp; while (0 <= i <= inc_0 /\ inc_0 = n /\ n = (if P.`m - 64 * c < 64 then P.`m - 64 * c else 64) /\
         0 <= c < inc /\ inc = (P.`m + 63) %/ 64 /\
         hw512 h = SHA512.hash SHA512.H0_512 (MgfSeed.to_list s ++ be_bytes 4 c) /\
         (forall k, 0 <= k < pad_len512 => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
            MgfBuf.get8 m k = lay (MgfSeed.to_list s) pad_len512 k) /\
         forall j, 0 <= j < P.`m => j < 64 * c + i =>
           Digest.get8 out j = nth W8.zero (mgf1_sha512 (MgfSeed.to_list s) P.`m) j).
  + auto => /> &hr hi0 _ hc0 hc1 hh hm hout hi; split; first smt().
    have [hidx hi64] := MGF1_SHA512.idx_out P.`m c{hr} i{hr} hc0 hi0 hi.
    move=> j hj0 hj1 hj2; rewrite Digest.get_setE 1:/#.
    case: (j = 64 * c{hr} + i{hr}) => [->|hne] /=; last by apply hout => /#.
    rewrite MGF1_SHA512.byte_be64 1:/# MGF1_SHA512.nth_mgf1_512 1:/#.
    have -> : (64 * c{hr} + i{hr}) %/ 64 = c{hr}.
    + by rewrite mulzC divzMDl // pdiv_small.
    have -> : (64 * c{hr} + i{hr}) %% 64 = i{hr}.
    + by rewrite mulzC modzMDl pmod_small.
    by rewrite MGF1_SHA512.nth_sha512 1:/# -hh nth_hw512.
  wp.
  while (0 <= b <= inc_0 /\ inc_0 = pad_len512 %/ 128 /\ 0 <= c < inc /\ inc = (P.`m + 63) %/ 64 /\
         hw512 h = foldl SHA512.compress SHA512.H0_512
                     (take b (SHA512.parse (SHA512.pad (MgfSeed.to_list s ++ be_bytes 4 c)))) /\
         (forall k, 0 <= k < pad_len512 =>
            MgfBuf.get8 m k = nth W8.zero (SHA512.pad (MgfSeed.to_list s ++ be_bytes 4 c)) k) /\
         (forall k, 0 <= k < pad_len512 => !(MgfSeed.size <= k < MgfSeed.size + 4) =>
            MgfBuf.get8 m k = lay (MgfSeed.to_list s) pad_len512 k) /\
         forall j, 0 <= j < P.`m => j < 64 * c =>
           Digest.get8 out j = nth W8.zero (mgf1_sha512 (MgfSeed.to_list s) P.`m) j).
  + wp; exlim h, m, b => h0 m0 b0.
    call (compress512_h (hw512 h0) (MgfBlk512.get_sub m0 (128 * b0))).
    auto => /> &hr hb0 _ hc0 hc1 hh hpm hm hout hb h1 hh1.
    split; first smt().
    have hx : size (MgfSeed.to_list s ++ be_bytes 4 c{hr}) = MgfSeed.size + 4.
    + by rewrite size_cat size_be_bytes MgfSeed.size_to_list.
    by rewrite hh1 hh (step_block512 _ _ b0 hx _ hpm); smt().
  wp; call init512_h; exlim m, c => m0 c0.
  ecall (set_counter_h m0 c0).
  auto => />.
  move=> &hr hc0 hc1 hm hout hc; split; first smt().
  move=> h256 m1 hm1 h1 hh1; split.
  + rewrite hh1 take0 /=; split.
    + move=> k hk0 hk1; rewrite hm1 1:/# nth_pad512 1:MgfSeed.size_to_list 1,2:/#.
      by case: (MgfSeed.size <= k < MgfSeed.size + 4) => // hk'; smt().
    by move=> k hk0 hk1 hk'; rewrite hm1 1:/# hk' /=; smt().
  move=> b2 h2 out2 hb2 hb2a hb2b hnb hh2 hp2 hm2 hout2; split.
  + split; first smt().
    rewrite hh2 (_ : b2 = pad_len512 %/ 128) 1:/# hash512_blocks //.
    by rewrite size_cat size_be_bytes MgfSeed.size_to_list.
  move=> i3 out3 hi3 hi3a hi3b hn3 hh3 hout3; split; first smt().
  move=> j hj0 hj1 hj2; apply hout3; first smt().
  by apply (MGF1_SHA512.out_step P.`m c0 i3 j) => //; smt().
wp; ecall (layout_h s pad_len512 pad512_range).
auto => /> &hr hpl m1 hm1; split; first smt().
move=> c2 m2 out2 hc2 hc2a hc2b hinc hm2 hout2.
apply (eq_from_nth W8.zero); first by rewrite Digest.size_to_list MGF1_SHA512.size_mgf1_512 /#.
by move=> j; rewrite Digest.size_to_list => hj; rewrite Digest.get_to_list hout2 // /#.
qed.

lemma mgf1_sha512_ll : islossless M.mgf___mgf1_sha512.
proof.
proc; while (true) (inc - c).
+ move=> z; wp; while (true) (inc_0 - i); first by auto => /#.
  wp; while (true) (inc_0 - b); first by move=> z0; wp; call set_compress512_ll; auto => /#.
  by wp; call init512_ll; call set_counter_ll; auto => /#.
by wp; call layout_ll; auto => /#.
qed.

lemma mgf1_sha512_total (s : MgfSeed.t) :
  phoare [M.mgf___mgf1_sha512 : seed = s ==>
           Digest.to_list res.`1 = mgf1_sha512 (MgfSeed.to_list s) P.`m] = 1%r.
proof. by conseq mgf1_sha512_ll (mgf1_sha512_h s). qed.
