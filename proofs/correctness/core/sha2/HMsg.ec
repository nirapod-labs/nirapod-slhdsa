(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * HMsg.ec (SHA2 sets)
 * ===================
 *
 * H_msg of the SHA2 parameter sets (FIPS 205 section 11.2): _h_msg
 * computes
 *
 *     MGF1-X(R || PK.seed || X(R || PK.seed || PK.root || M), m)
 *
 * on the message M = prefix[0 : prefix_len] || mem[msg : msg + msg_len]
 * of Internal.ec (slh_msg), X being SHA-256 for n = 16 and SHA-512
 * otherwise.
 *
 * The head R || PK.seed || PK.root (3n bytes, shorter than one block of
 * either hash) is copied into the empty stream buffer, the prefix and the
 * message follow as in PRF_msg (MsgHash.absorb_message*_h), and the
 * digest is copied after R || PK.seed into the MGF1 seed. Mgf1.ec gives
 * the mask.
 *
 * Model. As MsgHash.ec: the branches of _h_msg on SHA2_WIDE are literals
 * in each model. h_msg_narrow_h (n = 16) and h_msg_wide_h (n = 24, 32)
 * prove both on every set, the dead one from the contradiction between
 * its condition on n and n_val.
 *
 * Theorems (total correctness):
 *     h_msg_correct   _h_msg returns H_msg(R, PK.seed, PK.root, M), every
 *                     input with msg_ok. Its statement is the H_msg
 *                     premise of Internal.ec.
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
require BitEncoding.
import BitEncoding.BitChunking.
from Jasmin require import JWord JUtils JMemory Jslh.
require import Bytes FIPS180_SHA2 RFC8017_MGF1 FIPS205_Params FIPS205_Hash.
require import BArray32 BArray64 BArray128 SetModel CoreExtracted.
require import JWordList Internal Thash HashKernels MsgHash Mgf1.
require HashExtracted SHA256_Stream SHA512_Stream MGF1_SHA256 MGF1_SHA512.

(* ------------------------------------------------------------------ *)
(* A head shorter than a block                                        *)

lemma short_stream256 (o : bytes) (h : BArray32.t) (buf : BArray64.t) (total : W64.t) :
  size o < 64 => hw256 h = SHA256.H0_256 => to_uint total = size o =>
  SHA256_Stream.pending buf o => SHA256_Stream.stream256 SHA256.H0_256 o h buf total.
proof.
move=> ho hh ht hp; rewrite /SHA256_Stream.stream256 ht /=.
by rewrite SHA256_Stream.parse_short // SHA256_Stream.tail_short.
qed.

lemma short_stream512 (o : bytes) (h : BArray64.t) (buf : BArray128.t) (total : W64.t) :
  size o < 128 => hw512 h = SHA512.H0_512 => to_uint total = size o =>
  SHA512_Stream.pending buf o => SHA512_Stream.stream512 SHA512.H0_512 o h buf total.
proof.
move=> ho hh ht hp; rewrite /SHA512_Stream.stream512 ht /=.
by rewrite SHA512_Stream.parse_short // SHA512_Stream.tail_short.
qed.

lemma sha256_finalize_h (h0 : W32.t list) (m : bytes) :
  hoare [M._sha256_finalize :
           SHA256_Stream.stream256 h0 m h buf total /\ size m < 2^61 ==>
           BArray32.to_list res.`1 = flatten (map w32_be (SHA256.hash h0 m))].
proof. by conseq (sha256_finalize_total h0 m). qed.

lemma sha512_finalize_h (h0 : W64.t list) (m : bytes) :
  hoare [M._sha512_finalize :
           SHA512_Stream.stream512 h0 m h buf total /\ size m < 2^61 ==>
           BArray64.to_list res.`1 = flatten (map w64_be (SHA512.hash h0 m))].
proof. by conseq (sha512_finalize_total h0 m). qed.

(* ------------------------------------------------------------------ *)
(* The head and the seed                                              *)

op head_of (r0 : Node.t) (p0 : PK.t) : bytes = Node.to_list r0 ++ PK.to_list p0.

lemma size_head (r0 : Node.t) (p0 : PK.t) : size (head_of r0 p0) = 3 * P.`n.
proof. by rewrite /head_of size_cat Node.size_to_list PK.size_to_list; smt(n_val). qed.

lemma nth_head (r0 : Node.t) (p0 : PK.t) (j : int) : 0 <= j < 3 * P.`n =>
  nth W8.zero (head_of r0 p0) j = if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n).
proof.
move=> hj; have hn := n_val.
rewrite /head_of nth_cat size_node.
by case: (j < P.`n) => h; [rewrite Node.get_to_list | rewrite PK.get_to_list].
qed.

lemma pk_halves (p0 : PK.t) :
  slice (PK.to_list p0) 0 P.`n ++ slice (PK.to_list p0) P.`n (2 * P.`n) = PK.to_list p0.
proof.
have hn := n_val.
by rewrite ForsPk.slice_cat2 1,2:/# /slice drop0 take_oversize // PK.size_to_list /max /#.
qed.

lemma hmsg_spec (r0 : Node.t) (p0 : PK.t) (msg : bytes) :
  Node.to_list r0 ++ slice (PK.to_list p0) 0 P.`n ++ slice (PK.to_list p0) P.`n (2 * P.`n) ++ msg
  = head_of r0 p0 ++ msg.
proof.
have -> : forall (a b c d : W8.t list), a ++ b ++ c ++ d = a ++ (b ++ c) ++ d by move=> a b c d; rewrite !catA.
by rewrite pk_halves.
qed.

(* The MGF1 seed: R, PK.seed, then the digest d. *)
lemma seed_list (s : MgfSeed.t) (r0 : Node.t) (p0 : PK.t) (d : bytes) :
  size d = MgfSeed.size - 2 * P.`n =>
  (forall j, 0 <= j < MgfSeed.size => MgfSeed.get8 s j =
     if j < P.`n then Node.get8 r0 j
     else if j < 2 * P.`n then PK.get8 p0 (j - P.`n)
     else nth W8.zero d (j - 2 * P.`n)) =>
  MgfSeed.to_list s = Node.to_list r0 ++ slice (PK.to_list p0) 0 P.`n ++ d.
proof.
move=> hd hs; have hn := n_val.
have hsz : MgfSeed.size = 2 * P.`n + size d by smt().
apply (eq_from_nth W8.zero).
+ rewrite MgfSeed.size_to_list !size_cat Node.size_to_list /slice drop0 size_take 1:/# PK.size_to_list.
  smt().
move=> j; rewrite MgfSeed.size_to_list => hj.
rewrite MgfSeed.get_to_list hs 1:/# nth_cat size_cat Node.size_to_list /slice drop0 size_take 1:/#.
rewrite PK.size_to_list nth_cat Node.size_to_list.
case: (j < P.`n) => h1; first by rewrite ifT 1:/# ifT 1:/# Node.get_to_list.
case: (j < 2 * P.`n) => h2.
+ by rewrite ifT 1:/# ifF 1:/# nth_take 1,2:/# PK.get_to_list; smt().
by rewrite ifF 1:/#; smt().
qed.

(* A store of word b + i, i >= 0, leaves the bytes below 8 b. *)
lemma store_below (b i j c : int) : 0 <= i => j < 8 * b =>
  !(8 * (b + i) <= j < 8 * (b + i) + 8 /\ 0 <= j < c).
proof. smt(). qed.

(* The domain of the SHA-2 inputs of H_msg. *)
lemma hmsg_dom (r0 : Node.t) (p0 : PK.t) (mem : global_mem_t) (x : Prefix.t) (pl m ml : W64.t) :
  msg_ok pl m ml =>
  to_uint pl <= Prefix.size /\ to_uint m + to_uint ml < W64.modulus /\
  size (head_of r0 p0) + Prefix.size + to_uint ml < W64.modulus /\
  size (head_of r0 p0 ++ slh_msg mem x pl m ml) < 2^61.
proof.
move=> hok; have [hpl [hm hml]] := msg_sha2 _ _ _ hok.
have hs := size_slh_msg mem x pl m ml hpl.
have [hml0 _] := W64.to_uint_cmp ml; have [hpl0 _] := W64.to_uint_cmp pl.
move: hm => /= hm.
rewrite !size_head size_cat size_head; move: hml hs; rewrite /sha2_msg_max prefix_size /=.
by pose u := size (slh_msg mem x pl m ml); smt(n_val).
qed.

(* ------------------------------------------------------------------ *)
(* H_msg                                                              *)

lemma h_msg_narrow_h (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  P.`n = 16 =>
  hoare [M._h_msg :
    r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Digest.to_list res.`1 =
      H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
        (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)].
proof.
move=> hn16; have hn := n_val.
proc.
seq 17 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
          (forall j, 0 <= j < 3 * P.`n => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
          (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
             if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ pk = p0 /\
         (forall j, 0 <= j < 3 * P.`n => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
         (forall j, 0 <= j < P.`n + 8 * i => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
  + wp; skip => &m [#] h0 h1 hinc hp hh hj hlt; rewrite hp /=; do 3?(split; first smt()).
    move=> j hjr; rewrite MgfSeed.get8_set64dE.
    case: (8 * (P.`n %/ 8 + i{m}) <= j < 8 * (P.`n %/ 8 + i{m}) + 8) => h.
    + by rewrite ifT 1:/# ifF 1:/# PK.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj // /#.
  wp; while (0 <= i <= inc /\ inc = 2 * P.`n %/ 8 /\ pk = p0 /\
             (forall j, 0 <= j < P.`n + 8 * i => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
             (forall j, 0 <= j < P.`n => MgfSeed.get8 seed j = Node.get8 r0 j)).
  + wp; skip => &m [#] h0 h1 hinc hp hh hj hlt; rewrite hp /=.
    do 2?(split; first smt()).
    split; last exact hj.
    move=> j hjr; rewrite Seeds.get8_set64dE.
    case: (8 * (P.`n %/ 8 + i{m}) <= j < 8 * (P.`n %/ 8 + i{m}) + 8) => h.
    + by rewrite ifT 1:/# nth_head 1:/# ifF 1:/# PK.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hh // /#.
  wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ r = r0 /\
             (forall j, 0 <= j < 8 * i => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
             (forall j, 0 <= j < 8 * i => MgfSeed.get8 seed j = Node.get8 r0 j)).
  + wp; skip => &m [#] h0 h1 hinc hr hh hj hlt; rewrite hr /=; do 2?(split; first smt()).
    split.
    + move=> j hjr; rewrite Seeds.get8_set64dE.
      case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
      + by rewrite ifT 1:/# nth_head 1:/# ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
      by rewrite ifF 1:/# hh // /#.
    move=> j hjr; rewrite MgfSeed.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj // /#.
  wp; skip => &m [#] -> -> -> -> -> -> -> hok /=; split; first smt().
  move=> head1 i1 seed1 hlt [#] g0 g1 _ gh gs; split.
  + split; first smt().
    split; first by move=> j hj; apply gh; smt().
    by move=> j hj; apply gs; smt().
  move=> head2 i2 hlt2 [#] k0 k1 _ kh ks; split.
  + split; first smt().
    split; first by move=> j hj; apply kh; smt().
    by move=> j hj; rewrite ifT 1:/#; apply ks.
  move=> i3 seed3 hlt3 [#] l0 l1 _ lh ls; split; first exact hok.
  split; first exact lh.
  by move=> j hj; apply ls; smt().
if; last by conseq (_ : false ==> _) => //; smt().
(* the zeroed block buffer, then R || PK.seed || PK.root in it *)
seq 8 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
         SHA256_Stream.stream256 SHA256.H0_256 (head_of r0 p0) h buf total /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ wp; while (0 <= i <= inc /\ inc = 3 * P.`n %/ 8 /\
             (forall j, 0 <= j < 3 * P.`n => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
             forall j, 0 <= j < 8 * i => BArray64.get8 buf j = Seeds.get8 head j).
  + wp; skip => &m [#] h0 h1 hinc hh hj hlt /=; do 3?(split; first smt()).
    move=> j hjr; rewrite BArray64.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# Seeds.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj /#.
  wp; while (true); first by wp; skip.
  wp; call init256_h; skip => &m [#] -> -> -> -> -> hok hh hs _ h1 hh1 b0 i0 _ /=; split; first smt().
  move=> buf1 i1 hlt [#] g0 g1 g2 _ gb; split; first exact hok.
  split; last exact hs.
  apply short_stream256.
  + by rewrite size_head /#.
  + exact hh1.
  + by rewrite W64.of_uintK size_head /#.
  by move=> j hj; rewrite gb; [smt(size_head) | rewrite hh //; smt(size_head)].
(* the prefix and the message, then the digest *)
seq 2 : (Glob.mem = mem0 /\ msg_ok pl m ml /\
         SHA256_Stream.stream256 SHA256.H0_256 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml) h buf total /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ ecall (absorb_message256_h SHA256.H0_256 (head_of r0 p0) x0 pl m ml mem0).
  wp; skip => &m [#] -> -> -> -> -> hok hst hs; rewrite /SLH64.protect_ptr /=.
  have [hpl [hm [hsz _]]] := hmsg_dom r0 p0 mem0 x0 pl m ml hok.
  move: hm hsz => /= hm hsz.
  split; first by split; [exact hst | split; [exact hpl | split; [exact hm | exact hsz]]].
  by move=> _ r hr; split.
seq 1 : (BArray32.to_list d256 = SHA256.sha256 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml) /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ ecall (sha256_finalize_h SHA256.H0_256 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml)).
  skip => &m [#] _ hok hst hs /=.
  have [_ [_ [_ hsz]]] := hmsg_dom r0 p0 mem0 x0 pl m ml hok.
  move: hsz => /= hsz; split; first by split.
  by move=> _ r hr; split; [rewrite hr /SHA256.sha256 | exact hs].
seq 2 : (forall j, 0 <= j < MgfSeed.size => MgfSeed.get8 seed j =
           if j < P.`n then Node.get8 r0 j
           else if j < 2 * P.`n then PK.get8 p0 (j - P.`n)
           else nth W8.zero (SHA256.sha256 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml)) (j - 2 * P.`n)).
+ while (0 <= i <= 4 /\
         BArray32.to_list d256 = SHA256.sha256 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml) /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n)) /\
         forall j, 0 <= j < 8 * i => MgfSeed.get8 seed (2 * P.`n + j) = BArray32.get8 d256 j).
  + wp; skip => &m [#] h0 h1 hd hs hj hlt /=; do 2?(split; first smt()).
    clear hd; split.
    + move=> j hjr; rewrite MgfSeed.get8_set64dE; have := hs j hjr.
      move=> hsj; have ha : j < 8 * (2 * P.`n %/ 8) by smt().
      by rewrite -hsj ifF //; apply store_below => //; smt().
    move=> j hjr; rewrite MgfSeed.get8_set64dE.
    case: (8 * (2 * P.`n %/ 8 + i{m}) <= 2 * P.`n + j < 8 * (2 * P.`n %/ 8 + i{m}) + 8) => h.
    + by rewrite ifT 1:/# BArray32.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj /#.
  wp; skip => &m [#] hd hs /=; split; first smt().
  move=> i1 seed1 hlt [#] g0 g1 _ gs gd j hj.
  have hms : MgfSeed.size = 2 * P.`n + 32 by smt(MgfSeed.size_to_list).
  case: (j < 2 * P.`n) => h2; first by rewrite gs 1:/#; smt().
  rewrite ifF 1:/#.
  have h3 : 0 <= j - 2 * P.`n < 8 * i1 by smt().
  have := gd _ h3; rewrite (_ : 2 * P.`n + (j - 2 * P.`n) = j) 1:/# => ->.
  by rewrite -BArray32.get_to_list hd.
(* the mask *)
sp; if; last by conseq (_ : false ==> _) => //; smt().
ecall (mgf1_sha256_h seed).
wp; skip => &m hs /=; rewrite /SLH64.protect_ptr => r hr.
case: hs => [[d0 [_ hs]] _].
have hsz : size (SHA256.sha256 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml)) = MgfSeed.size - 2 * P.`n.
+ by rewrite MGF1_SHA256.size_sha256; smt().
(* on the sets with n <> 16 the first rewrites close the goal from hn16 *)
by rewrite hr /H_msg (_ : P.`family <> SHAKE) 1:/P // hn16 /= hmsg_spec; congr;
  rewrite (seed_list seed{m} r0 p0 _ hsz hs).
qed.

lemma h_msg_wide_h (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  P.`n <> 16 =>
  hoare [M._h_msg :
    r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Digest.to_list res.`1 =
      H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
        (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)].
proof.
move=> hn16; have hn := n_val.
proc.
seq 17 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
          (forall j, 0 <= j < 3 * P.`n => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
          (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
             if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ pk = p0 /\
         (forall j, 0 <= j < 3 * P.`n => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
         (forall j, 0 <= j < P.`n + 8 * i => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
  + wp; skip => &m [#] h0 h1 hinc hp hh hj hlt; rewrite hp /=; do 3?(split; first smt()).
    move=> j hjr; rewrite MgfSeed.get8_set64dE.
    case: (8 * (P.`n %/ 8 + i{m}) <= j < 8 * (P.`n %/ 8 + i{m}) + 8) => h.
    + by rewrite ifT 1:/# ifF 1:/# PK.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj // /#.
  wp; while (0 <= i <= inc /\ inc = 2 * P.`n %/ 8 /\ pk = p0 /\
             (forall j, 0 <= j < P.`n + 8 * i => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
             (forall j, 0 <= j < P.`n => MgfSeed.get8 seed j = Node.get8 r0 j)).
  + wp; skip => &m [#] h0 h1 hinc hp hh hj hlt; rewrite hp /=.
    do 2?(split; first smt()).
    split; last exact hj.
    move=> j hjr; rewrite Seeds.get8_set64dE.
    case: (8 * (P.`n %/ 8 + i{m}) <= j < 8 * (P.`n %/ 8 + i{m}) + 8) => h.
    + by rewrite ifT 1:/# nth_head 1:/# ifF 1:/# PK.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hh // /#.
  wp; while (0 <= i <= inc /\ inc = P.`n %/ 8 /\ r = r0 /\
             (forall j, 0 <= j < 8 * i => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
             (forall j, 0 <= j < 8 * i => MgfSeed.get8 seed j = Node.get8 r0 j)).
  + wp; skip => &m [#] h0 h1 hinc hr hh hj hlt; rewrite hr /=; do 2?(split; first smt()).
    split.
    + move=> j hjr; rewrite Seeds.get8_set64dE.
      case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
      + by rewrite ifT 1:/# nth_head 1:/# ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
      by rewrite ifF 1:/# hh // /#.
    move=> j hjr; rewrite MgfSeed.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# Node.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj // /#.
  wp; skip => &m [#] -> -> -> -> -> -> -> hok /=; split; first smt().
  move=> head1 i1 seed1 hlt [#] g0 g1 _ gh gs; split.
  + split; first smt().
    split; first by move=> j hj; apply gh; smt().
    by move=> j hj; apply gs; smt().
  move=> head2 i2 hlt2 [#] k0 k1 _ kh ks; split.
  + split; first smt().
    split; first by move=> j hj; apply kh; smt().
    by move=> j hj; rewrite ifT 1:/#; apply ks.
  move=> i3 seed3 hlt3 [#] l0 l1 _ lh ls; split; first exact hok.
  split; first exact lh.
  by move=> j hj; apply ls; smt().
if; first by conseq (_ : false ==> _) => //; smt().
(* the zeroed block buffer, then R || PK.seed || PK.root in it *)
seq 8 : (prefix = x0 /\ prefix_len = pl /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml /\
         SHA512_Stream.stream512 SHA512.H0_512 (head_of r0 p0) h512 buf512 total /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ wp; while (0 <= i <= inc /\ inc = 3 * P.`n %/ 8 /\
             (forall j, 0 <= j < 3 * P.`n => Seeds.get8 head j = nth W8.zero (head_of r0 p0) j) /\
             forall j, 0 <= j < 8 * i => BArray128.get8 buf512 j = Seeds.get8 head j).
  + wp; skip => &m [#] h0 h1 hinc hh hj hlt /=; do 3?(split; first smt()).
    move=> j hjr; rewrite BArray128.get8_set64dE.
    case: (8 * i{m} <= j < 8 * i{m} + 8) => h.
    + by rewrite ifT 1:/# Seeds.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj /#.
  wp; while (true); first by wp; skip.
  wp; call init512_h; skip => &m [#] -> -> -> -> -> hok hh hs _ h1 hh1 b0 i0 _ /=; split; first smt().
  move=> buf1 i1 hlt [#] g0 g1 g2 _ gb; split; first exact hok.
  split; last exact hs.
  apply short_stream512.
  + by rewrite size_head /#.
  + exact hh1.
  + by rewrite W64.of_uintK size_head /#.
  by move=> j hj; rewrite gb; [smt(size_head) | rewrite hh //; smt(size_head)].
(* the prefix and the message, then the digest *)
seq 2 : (Glob.mem = mem0 /\ msg_ok pl m ml /\
         SHA512_Stream.stream512 SHA512.H0_512 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml) h512 buf512 total /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ ecall (absorb_message512_h SHA512.H0_512 (head_of r0 p0) x0 pl m ml mem0).
  wp; skip => &m [#] -> -> -> -> -> hok hst hs; rewrite /SLH64.protect_ptr /=.
  have [hpl [hm [hsz _]]] := hmsg_dom r0 p0 mem0 x0 pl m ml hok.
  move: hm hsz => /= hm hsz.
  split; first by split; [exact hst | split; [exact hpl | split; [exact hm | exact hsz]]].
  by move=> _ r hr; split.
seq 1 : (BArray64.to_list d512 = SHA512.sha512 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml) /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n))).
+ ecall (sha512_finalize_h SHA512.H0_512 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml)).
  skip => &m [#] _ hok hst hs /=.
  have [_ [_ [_ hsz]]] := hmsg_dom r0 p0 mem0 x0 pl m ml hok.
  move: hsz => /= hsz; split; first by split.
  by move=> _ r hr; split; [rewrite hr /SHA512.sha512 /SHA512.digest | exact hs].
seq 2 : (forall j, 0 <= j < MgfSeed.size => MgfSeed.get8 seed j =
           if j < P.`n then Node.get8 r0 j
           else if j < 2 * P.`n then PK.get8 p0 (j - P.`n)
           else nth W8.zero (SHA512.sha512 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml)) (j - 2 * P.`n)).
+ while (0 <= i <= 8 /\
         BArray64.to_list d512 = SHA512.sha512 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml) /\
         (forall j, 0 <= j < 2 * P.`n => MgfSeed.get8 seed j =
            if j < P.`n then Node.get8 r0 j else PK.get8 p0 (j - P.`n)) /\
         forall j, 0 <= j < 8 * i => MgfSeed.get8 seed (2 * P.`n + j) = BArray64.get8 d512 j).
  + wp; skip => &m [#] h0 h1 hd hs hj hlt /=; do 2?(split; first smt()).
    clear hd; split.
    + move=> j hjr; rewrite MgfSeed.get8_set64dE; have := hs j hjr.
      move=> hsj; have ha : j < 8 * (2 * P.`n %/ 8) by smt().
      by rewrite -hsj ifF //; apply store_below => //; smt().
    move=> j hjr; rewrite MgfSeed.get8_set64dE.
    case: (8 * (2 * P.`n %/ 8 + i{m}) <= 2 * P.`n + j < 8 * (2 * P.`n %/ 8 + i{m}) + 8) => h.
    + by rewrite ifT 1:/# BArray64.get64d_byte 1:/#; congr; smt().
    by rewrite ifF 1:/# hj /#.
  wp; skip => &m [#] hd hs /=; split; first smt().
  move=> i1 seed1 hlt [#] g0 g1 _ gs gd j hj.
  have hms : MgfSeed.size = 2 * P.`n + 64 by smt(MgfSeed.size_to_list).
  case: (j < 2 * P.`n) => h2; first by rewrite gs 1:/#; smt().
  rewrite ifF 1:/#.
  have h3 : 0 <= j - 2 * P.`n < 8 * i1 by smt().
  have := gd _ h3; rewrite (_ : 2 * P.`n + (j - 2 * P.`n) = j) 1:/# => ->.
  by rewrite -BArray64.get_to_list hd.
(* the mask *)
sp; if; first by conseq (_ : false ==> _) => //; smt().
ecall (mgf1_sha512_h seed).
wp; skip => &m hs /=; rewrite /SLH64.protect_ptr => r hr.
case: hs => [[d0 [_ hs]] _].
have hsz : size (SHA512.sha512 (head_of r0 p0 ++ slh_msg mem0 x0 pl m ml)) = MgfSeed.size - 2 * P.`n.
+ by rewrite MGF1_SHA512.size_sha512; smt().
(* on the sets with n = 16 the first rewrites close the goal from hn16 *)
by rewrite hr /H_msg (_ : P.`family <> SHAKE) 1:/P // hn16 /= hmsg_spec; congr;
  rewrite (seed_list seed{m} r0 p0 _ hsz hs).
qed.

lemma h_msg_h (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  hoare [M._h_msg :
    r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Digest.to_list res.`1 =
      H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
        (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)].
proof.
case: (P.`n = 16) => h16; first exact (h_msg_narrow_h r0 p0 x0 pl m ml mem0 h16).
exact (h_msg_wide_h r0 p0 x0 pl m ml mem0 h16).
qed.

(* ------------------------------------------------------------------ *)
(* Termination                                                        *)

lemma sha256_finalize_ll : islossless M._sha256_finalize.
proof.
bypr => &m _.
have -> : Pr[M._sha256_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha256_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA256_Stream.sha256_finalize_ll.
qed.

lemma sha512_finalize_ll : islossless M._sha512_finalize.
proof.
bypr => &m _.
have -> : Pr[M._sha512_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m : true] =
          Pr[HashExtracted.M._sha512_finalize(out{m}, h{m}, buf{m}, total{m}, ms{m}) @ &m : true].
+ by byequiv (_ : ={arg} ==> true) => //; proc; sim.
by byphoare (_ : true ==> true) => //; exact SHA512_Stream.sha512_finalize_ll.
qed.

lemma h_msg_ll : islossless M._h_msg.
proof.
proc.
seq 17 : true 1%r 1%r 0%r _ => //.
+ while (true) (inc - i); first by auto => /#.
  wp; while (true) (inc - i); first by auto => /#.
  wp; while (true) (inc - i); first by auto => /#.
  by auto => /#.
seq 1 : true 1%r 1%r 0%r _ => //.
+ if.
  + while (true) (4 - i); first by auto => /#.
    wp; call sha256_finalize_ll; call absorb_message256_ll; wp.
    while (true) (inc - i); first by auto => /#.
    wp; while (true) (8 - i); first by auto => /#.
    by wp; call init256_ll; auto => /#.
  while (true) (8 - i); first by auto => /#.
  wp; call sha512_finalize_ll; call absorb_message512_ll; wp.
  while (true) (inc - i); first by auto => /#.
  wp; while (true) (16 - i); first by auto => /#.
  by wp; call init512_ll; auto => /#.
by sp; if; [call mgf1_sha256_ll | call mgf1_sha512_ll]; auto.
qed.

lemma h_msg_correct (r0 : Node.t) (p0 : PK.t) (x0 : Prefix.t) (pl m ml : W64.t) (mem0 : global_mem_t) :
  phoare [M._h_msg :
    r = r0 /\ pk = p0 /\ prefix = x0 /\ prefix_len = pl /\ msg = m /\
    msg_len = ml /\ Glob.mem = mem0 /\ msg_ok pl m ml ==>
    Digest.to_list res.`1 =
      H_msg P (Node.to_list r0) (slice (PK.to_list p0) 0 P.`n)
        (slice (PK.to_list p0) P.`n (2 * P.`n)) (slh_msg mem0 x0 pl m ml)] = 1%r.
proof. by conseq h_msg_ll (h_msg_h r0 p0 x0 pl m ml mem0). qed.
