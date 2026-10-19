(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * External.ec
 * ===========
 *
 * The external functions of src/slhdsa/external.jinc and the exports of
 * src/slhdsa/api.jinc against FIPS 205 section 10: _slh_frame builds the
 * M' of Algorithms 22 to 25, and the sign, verify and keygen exports
 * compute slh_sign, hash_slh_sign, slh_verify, hash_slh_verify and
 * slh_keygen (Algorithms 21 to 25) from the internal functions
 * (Internal.ec).
 *
 * Domain block. The exports take the caller's choices as a 257-byte block
 * d: d[0] is the pre-hash selector (0 for pure, 1 .. 12 for the function
 * with OID 2.16.840.1.101.3.4.2.d[0]), d[1] is |ctx| and ctx is
 * d[2 : 2 + |ctx|] (dsel, dlen, dctx). |ctx| is one byte, so the block
 * cannot carry a context longer than 255 bytes: the length check of
 * Algorithms 22 to 25 line 1 is the C layer's (it rejects such a context
 * before building the block), and here size ctx <= 255 holds by
 * construction (dctx_size). ph_of names the function of each selector.
 *
 * Frame. For a selector of at most 12, _slh_frame returns status 0, a
 * prefix whose first prefix_len bytes are
 *
 *     pure:      toByte(0, 1) || toByte(|ctx|, 1) || ctx
 *     pre-hash:  toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M)
 *
 * (frame), and the message length to hash after it: msg_len for pure,
 * 0 for pre-hash, where the whole of M' is in the prefix. For a selector
 * above 12 it returns status all ones and both lengths 0, and the
 * exports neither sign nor accept.
 *
 * Pre-hash premise. _prehash computes PH(M) with the hash layer's SHA-2
 * and Keccak code: the premise hph states that its first len bytes are
 * ph_apply (ph_of sel) M, in the shape of the message hash premises of
 * Internal.ec. Nothing is assumed of len: the frame clamps it to 64, the
 * buffer size, and a digest is never longer.
 *
 * Exports. sign and verify call _slh_frame, then _slh_sign or
 * _slh_verify on (prefix, prefix_len, msg, msg_len'), whose message
 * slh_msg is M' (pure: frame ++ M; pre-hash: frame alone). keygen calls
 * _slh_keygen on the caller's seeds: the entropy draw of Algorithm 21
 * lines 1 to 3 is the C layer's, as is the choice of opt_rand (fresh
 * entropy for hedged signing, PK.seed for deterministic signing,
 * Internal.sign_deterministic). sign_internal and verify_internal are the
 * FIPS 205 section 9 functions on M with no prefix.
 *
 * Model. As Internal.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorems, all total correctness:
 *     slh_frame_correct    _slh_frame returns M' (above).
 *     sign_correct         sign returns slh_sign or hash_slh_sign.
 *     verify_correct       verify returns 0 when slh_verify or
 *                          hash_slh_verify accepts, all ones otherwise.
 *     keygen_correct       keygen returns slh_keygen.
 *     sign_internal_correct, verify_internal_correct
 *                          the section 9 exports.
 *)

require import AllCore List IntDiv StdOrder.
from Jasmin require import JMemory JWord JUtils Jslh.
require import Bytes FIPS205_Encoding FIPS205_Params FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_WOTS FIPS205_Internal FIPS205_External.
require import BArray10 BArray32 BArray64 BArray128 BArray257.
require import SetModel CoreExtracted Encoding WotsLeaf Internal.
require JWordList.

(* ------------------------------------------------------------------ *)
(* The domain block and M'                                            *)

op dsel (d : BArray257.t) : int = to_uint (BArray257.get8 d 0).
op dlen (d : BArray257.t) : int = to_uint (BArray257.get8 d 1).
op dctx (d : BArray257.t) : bytes = slice (BArray257.to_list d) 2 (2 + dlen d).

(* The pre-hash function of selector s, 1 <= s <= 12. *)
op ph_of (s : int) : prehash =
  if s = 1 then PH_SHA2_256 else if s = 2 then PH_SHA2_384 else
  if s = 3 then PH_SHA2_512 else if s = 4 then PH_SHA2_224 else
  if s = 5 then PH_SHA2_512_224 else if s = 6 then PH_SHA2_512_256 else
  if s = 7 then PH_SHA3_224 else if s = 8 then PH_SHA3_256 else
  if s = 9 then PH_SHA3_384 else if s = 10 then PH_SHA3_512 else
  if s = 11 then PH_SHAKE128 else PH_SHAKE256.

(* M = mem[msg : msg + msg_len]. *)
op m_of (mem : global_mem_t) (m ml : W64.t) : bytes = JWordList.memread mem (to_uint m) (to_uint ml).

(* The prefix of M' that _slh_frame writes. *)
op frame (d : BArray257.t) (M : bytes) : bytes =
  if dsel d = 0 then toByte 0 1 ++ toByte (dlen d) 1 ++ dctx d
  else toByte 1 1 ++ toByte (dlen d) 1 ++ dctx d ++ ph_oid (ph_of (dsel d)) ++
       ph_apply (ph_of (dsel d)) M.

(* What _slh_frame returns, (prefix, prefix_len, msg_len', status, msf). *)
op frame_out (d : BArray257.t) (M : bytes) (ml : W64.t)
             (r : Prefix.t * W64.t * W64.t * W64.t * W64.t) : bool =
  if dsel d <= 12 then
    r.`4 = W64.zero /\ to_uint r.`2 <= Prefix.size /\
    take (to_uint r.`2) (Prefix.to_list r.`1) = frame d M /\
    r.`3 = (if dsel d = 0 then ml else W64.zero)
  else r.`4 = W64.of_int (-1) /\ r.`2 = W64.zero /\ r.`3 = W64.zero.

lemma dlen_lt d : 0 <= dlen d < 256.
proof. by rewrite /dlen; have := W8.to_uint_cmp (BArray257.get8 d 1). qed.

lemma dsel_rng d : 0 <= dsel d < 256.
proof. by rewrite /dsel; have := W8.to_uint_cmp (BArray257.get8 d 0). qed.

lemma dctx_size d : size (dctx d) = dlen d.
proof. by rewrite /dctx size_slice; smt(dlen_lt BArray257.size_to_list). qed.

lemma dctx_nth d j : 0 <= j < dlen d => nth W8.zero (dctx d) j = BArray257.get8 d (2 + j).
proof.
move=> hj; rewrite /dctx /slice nth_take 1,2:/# nth_drop 1,2:/#.
by rewrite BArray257.get_to_list.
qed.

lemma toByte1 x : 0 <= x < 256 => toByte x 1 = [W8.of_int x].
proof. by move=> hx; rewrite toByteE // /be_bytes mkseq1 /=. qed.

lemma of_int8_eq x y : x %% 256 = y %% 256 => W8.of_int x = W8.of_int y.
proof. by move=> h; rewrite -(W8.of_int_mod x) -(W8.of_int_mod y) /= h. qed.

op oid_c : bytes = BArray10.to_list nIST_HASH_OID_PREFIX.

lemma oid_cE : oid_c = map W8.of_int [6; 9; 96; -122; 72; 1; 101; 3; 4; 2].
proof. by rewrite /oid_c BArray10.of_listK. qed.

(* OID = 06 09 60 86 48 01 65 03 04 02 || s. *)
lemma ph_oidE s : 1 <= s <= 12 => ph_oid (ph_of s) = oid_c ++ [W8.of_int s].
proof.
move=> hs; rewrite oid_cE.
have : s = 1 \/ s = 2 \/ s = 3 \/ s = 4 \/ s = 5 \/ s = 6 \/ s = 7 \/ s = 8 \/
       s = 9 \/ s = 10 \/ s = 11 \/ s = 12 by smt().
move=> [|[|[|[|[|[|[|[|[|[|[|]]]]]]]]]]] -> /=;
  rewrite /ph_of /= toByteE // /be_bytes;
  do 11! (rewrite mkseqSr_minus 1:// /=); rewrite mkseq0 /=;
  do !split; apply of_int8_eq; smt().
qed.

(* M' byte j, for P = PH(M) (pre-hash) or anything (pure). *)
op fbyte (d : BArray257.t) (P : bytes) (j : int) : W8.t =
  if j = 0 then (if dsel d = 0 then W8.zero else W8.one)
  else if j < 2 + dlen d then BArray257.get8 d j
  else if j < 12 + dlen d then nth W8.zero oid_c (j - 2 - dlen d)
  else if j = 12 + dlen d then BArray257.get8 d 0
  else nth W8.zero P (j - 13 - dlen d).

lemma frame_size d M : dsel d <= 12 =>
  size (frame d M) =
    if dsel d = 0 then 2 + dlen d else 13 + dlen d + size (ph_apply (ph_of (dsel d)) M).
proof.
move=> hs; have := dsel_rng d; rewrite /frame; case: (dsel d = 0) => h0 hr /=.
+ by rewrite !size_cat !size_toByte // dctx_size /#.
have ho : size (ph_oid (ph_of (dsel d))) = 11 by rewrite ph_oidE 1:/# size_cat oid_cE.
rewrite !size_cat !size_toByte // dctx_size ho /#.
qed.

lemma frame_nth d M j : dsel d <= 12 => 0 <= j < size (frame d M) =>
  nth W8.zero (frame d M) j = fbyte d (ph_apply (ph_of (dsel d)) M) j.
proof.
move=> hs hj; have hl := dlen_lt d; have hr := dsel_rng d; have hz := frame_size d M hs.
rewrite /frame /fbyte; case: (dsel d = 0) => h0 /=.
+ rewrite !nth_cat !size_cat !size_toByte // ?dctx_size !toByte1 //.
  case: (j = 0) => [-> //|hj0]; case: (j = 1) => [-> /= | hj1].
  + by rewrite ifT 1:/# /dlen W8.to_uintK.
  have hj2 : j < 2 + dlen d by smt().
  by rewrite ifF 1:/# hj2 /= dctx_nth 1:/#; congr; ring.
have -> : ph_oid (ph_of (dsel d)) = oid_c ++ [W8.of_int (dsel d)] by apply ph_oidE; smt().
have hoc : size oid_c = 10 by rewrite oid_cE.
have hd0 : W8.of_int (dsel d) = BArray257.get8 d 0 by rewrite /dsel W8.to_uintK.
have hd1 : W8.of_int (dlen d) = BArray257.get8 d 1 by rewrite /dlen W8.to_uintK.
rewrite !nth_cat !size_cat !size_toByte // dctx_size hoc !toByte1 // hd0 hd1 /=.
have hc := dctx_nth d (j - 2).
have e1 : j - (2 + dlen d) = j - 2 - dlen d by ring.
have e2 : j - (13 + dlen d) = j - 13 - dlen d by ring.
rewrite e1 e2.
case: (j < 2 + dlen d) => hj2.
+ rewrite ifT 1:/# /=; case: (j = 0) => [/#|hj0]; case: (j = 1) => [/#|hj1].
  by rewrite ifF 1:/# hc 1:/#; congr; ring.
case: (j < 12 + dlen d) => hj12.
+ by rewrite ifT 1:/# ifT 1:/# /#.
case: (j = 12 + dlen d) => hj13.
+ by rewrite ifT 1:/# ifF 1:/# ifT 1:/# /#.
by rewrite ifF 1:/# /#.
qed.

(* The first l bytes of x are L. *)
lemma take_prefix (x : Prefix.t) (L : bytes) :
  size L <= Prefix.size =>
  (forall j, 0 <= j < size L => Prefix.get8 x j = nth W8.zero L j) =>
  take (size L) (Prefix.to_list x) = L.
proof.
move=> hs hx; apply (eq_from_nth W8.zero).
+ by rewrite size_take ?size_ge0 Prefix.size_to_list /#.
move=> j; rewrite size_take ?size_ge0 Prefix.size_to_list => hj.
by rewrite nth_take ?size_ge0 1:/# Prefix.get_to_list hx /#.
qed.

lemma tz8 (x : W8.t) : truncateu8 (zeroextu64 x) = x.
proof.
rewrite W8.to_uint_eq to_uint_truncateu8 to_uint_zeroextu64 /= modz_small //.
by have := W8.to_uint_cmp x => /#.
qed.


lemma frame_take (x : Prefix.t) d M l : dsel d <= 12 => l = size (frame d M) => l <= Prefix.size =>
  (forall j, 0 <= j < l => Prefix.get8 x j = fbyte d (ph_apply (ph_of (dsel d)) M) j) =>
  take l (Prefix.to_list x) = frame d M.
proof.
move=> hs -> hl hx; apply take_prefix => // j hj.
by rewrite frame_nth // hx.
qed.

lemma clampE (x : W64.t) : to_uint x <= 332 =>
  ((W64.of_int 332 \ule x) ? W64.of_int 332 : x) = x.
proof.
move=> hx; rewrite uleE W64.of_uintK /=.
case: (332 <= to_uint x) => // h; apply W64.to_uint_eq; rewrite W64.of_uintK /= /#.
qed.

lemma clamp64 (x : W64.t) (l : W8.t list) : size l = 64 =>
  to_uint ((W64.of_int 64 \ule x) ? W64.of_int 64 : x) <= 64 /\
  take (to_uint ((W64.of_int 64 \ule x) ? W64.of_int 64 : x)) l = take (to_uint x) l.
proof.
move=> hl; rewrite uleE W64.of_uintK /=; case: (64 <= to_uint x) => h /=.
+ by rewrite take_oversize 1:/# take_oversize /#.
smt().
qed.

lemma sel0E (x : W8.t) : (zeroextu64 x = W64.zero) = (to_uint x = 0).
proof. by rewrite W64.to_uint_eq to_uint_zeroextu64. qed.

(* The message _slh_sign and _slh_verify hash after the frame is M'. *)
lemma msg_pure (mem : global_mem_t) (x : Prefix.t) (pl m ml : W64.t) d M :
  dsel d = 0 => take (to_uint pl) (Prefix.to_list x) = frame d M =>
  slh_msg mem x pl m ml = pure_message (dctx d) (m_of mem m ml).
proof.
by move=> h0 hx; rewrite /slh_msg hx /frame h0 /= /pure_message dctx_size.
qed.

lemma msg_ph (mem : global_mem_t) (x : Prefix.t) (pl m : W64.t) d M :
  dsel d <> 0 => take (to_uint pl) (Prefix.to_list x) = frame d M =>
  slh_msg mem x pl m W64.zero = prehash_message (dctx d) (ph_of (dsel d)) M.
proof.
by move=> h0 hx; rewrite /slh_msg hx /frame h0 /= /prehash_message dctx_size ?cats0.
qed.

lemma sign_some M d sk o : slh_sign P M (dctx d) sk o = Some (slh_sign_internal P (pure_message (dctx d) M) sk o).
proof. by rewrite /slh_sign dctx_size; have := dlen_lt d => /#. qed.

lemma hsign_some M d ph sk o :
  hash_slh_sign P M (dctx d) ph sk o = Some (slh_sign_internal P (prehash_message (dctx d) ph M) sk o).
proof. by rewrite /hash_slh_sign dctx_size; have := dlen_lt d => /#. qed.

lemma verify_ctx M s d pk : slh_verify P M s (dctx d) pk = slh_verify_internal P (pure_message (dctx d) M) s pk.
proof. by rewrite /slh_verify dctx_size ifF //; smt(dlen_lt). qed.

lemma hverify_ctx M s d ph pk :
  hash_slh_verify P M s (dctx d) ph pk = slh_verify_internal P (prehash_message (dctx d) ph M) s pk.
proof. by rewrite /hash_slh_verify dctx_size ifF //; smt(dlen_lt). qed.

(* ------------------------------------------------------------------ *)
(* _slh_frame (Algorithms 22 to 25, M')                               *)

lemma slh_frame_h :
  (forall (s m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prehash :
       sel = s /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
       1 <= to_uint s <= 12 /\ to_uint m + to_uint ml <= W64.modulus ==>
       take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 m ml)]
     = 1%r) =>
  forall (d0 : BArray257.t) (m ml : W64.t) (mem0 : global_mem_t),
  hoare [M._slh_frame :
    domain = d0 /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
    to_uint m + to_uint ml <= W64.modulus ==>
    frame_out d0 (m_of mem0 m ml) ml res /\ (dsel d0 = 0 => Glob.mem = mem0)].
proof.
move=> hph d0 m ml mem0.
have hl := dlen_lt d0; have hr := dsel_rng d0.
have hs0 : to_uint (zeroextu64 (BArray257.get8 d0 0)) = dsel d0 by rewrite to_uint_zeroextu64.
have hs1 : to_uint (zeroextu64 (BArray257.get8 d0 1)) = dlen d0 by rewrite to_uint_zeroextu64.
proc.
(* the zero fill: nothing below depends on the old prefix *)
seq 8 : (domain = d0 /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
         to_uint m + to_uint ml <= W64.modulus).
+ by wp; while (domain = d0 /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
                to_uint m + to_uint ml <= W64.modulus); auto.
seq 4 : (domain = d0 /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
         to_uint m + to_uint ml <= W64.modulus /\
         sel = zeroextu64 (BArray257.get8 d0 0) /\ ctx_len = zeroextu64 (BArray257.get8 d0 1)).
+ by auto.
have [hv | hv] : 12 < dsel d0 \/ !(12 < dsel d0) by rewrite orbN.
(* selector above 12: status all ones, both lengths 0 *)
+ rcondf 2; first by auto => />; rewrite uleE hs0 /#.
  by auto => /> *; smt().
rcondt 2; first by auto => />; rewrite uleE hs0 /#.
(* 0x00 or 0x01, |ctx|, ctx *)
seq 11 : (domain = d0 /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
          to_uint m + to_uint ml <= W64.modulus /\ sel = zeroextu64 (BArray257.get8 d0 0) /\
          to_uint end_0 = 2 + dlen d0 /\
          forall j, 0 <= j < 2 + dlen d0 =>
            BArray332.get8 prefix j = fbyte d0 (ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)) j).
+ while (domain = d0 /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
         to_uint m + to_uint ml <= W64.modulus /\ sel = zeroextu64 (BArray257.get8 d0 0) /\
         to_uint end_0 = 2 + dlen d0 /\ 2 <= to_uint i <= to_uint end_0 /\ more = (i \ult end_0) /\
         forall j, 0 <= j < to_uint i =>
           BArray332.get8 prefix j = fbyte d0 (ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)) j).
  + auto => /> &hr hm he hi0 hi1 hj hlt; rewrite ultE in hlt.
    have hi : to_uint (i{hr} + W64.one) = to_uint i{hr} + 1
      by rewrite W64.to_uintD_small W64.to_uint1 /#.
    rewrite hi /=; split; first smt().
    move=> j hj0 hj1; rewrite BArray332.get_setE 1:/# tz8.
    case: (j = to_uint i{hr}) => [->|hne]; last by apply hj => /#.
    by rewrite /fbyte ifF 1:/# ifT 1:/#.
  auto => /> &hr hm.
  have he : to_uint (zeroextu64 (BArray257.get8 d0 1) + W64.of_int 2) = 2 + dlen d0
    by rewrite W64.to_uintD_small hs1 W64.of_uintK /= /#.
  rewrite he /=; split.
  + split; first smt().
    move=> j hj0 hj1; rewrite !BArray332.get_setE 1,2:/#.
    case: (j = 1) => [-> /=|h1].
    + by rewrite tz8 /fbyte /= ifT 1:/#.
    have -> /= : j = 0 by smt().
    rewrite /fbyte /= sel0E /dsel; case: (to_uint (BArray257.get8 d0 0) = 0) => h0 /=.
    + by rewrite tz8; apply W8.to_uint_eq; rewrite h0.
    by rewrite /truncateu8 W64.to_uint1.
  move=> i0 more0 p0 hn hi0 hi1 hf hj j hj0 hj1.
  rewrite ultE he in hf; apply hj => /#.
have [h0 | h0] : dsel d0 = 0 \/ dsel d0 <> 0 by rewrite orbN.
(* pure: prefix_len = 2 + |ctx|, msg_len unchanged *)
+ rcondt 4; first by auto => />; rewrite sel0E; move: h0; rewrite /dsel.
  auto => /> &hr hm he hj; rewrite clampE 1:/# he.
  have hfs := frame_size d0 (m_of mem0 m ml) _; first smt().
  rewrite h0 /= in hfs.
  split; last smt().
  move=> _; split; first smt().
  split; last by rewrite h0.
  by apply frame_take; [smt() | rewrite hfs | smt() | exact hj].
rcondf 4; first by auto => />; rewrite sel0E; move: h0; rewrite /dsel.
(* OID *)
seq 7 : (to_uint m + to_uint ml <= W64.modulus /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
         sel = zeroextu64 (BArray257.get8 d0 0) /\
         to_uint pos = 12 + dlen d0 /\
         forall j, 0 <= j < 12 + dlen d0 =>
           BArray332.get8 prefix j = fbyte d0 (ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)) j).
+ while (to_uint m + to_uint ml <= W64.modulus /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
         sel = zeroextu64 (BArray257.get8 d0 0) /\ oid = nIST_HASH_OID_PREFIX /\ 0 <= k <= 10 /\
         to_uint pos = 2 + dlen d0 + k /\
         forall j, 0 <= j < 2 + dlen d0 + k =>
           BArray332.get8 prefix j = fbyte d0 (ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)) j).
  + auto => /> &hr hm hk0 hk1 hp hj hk.
    have hp1 : to_uint (pos{hr} + W64.one) = to_uint pos{hr} + 1
      by rewrite W64.to_uintD_small W64.to_uint1 /#.
    rewrite hp1 hp /=; split; first smt().
    split; first by ring.
    move=> j hj0 hj1; rewrite BArray332.get_setE 1:/# tz8.
    case: (j = 2 + dlen d0 + k{hr}) => [->|hne]; last by apply hj => /#.
    rewrite /fbyte ifF 1:/# ifF 1:/# ifT 1:/# /oid_c BArray10.get_to_list /=; congr; ring.
  auto => /> &hr hm he hj k0 p0 x0 hk hk0 hk1 hp hj'.
  have hk10 : k0 = 10 by smt().
  move: hp hj'; rewrite hk10 => hp hj'; split; first smt().
  by move=> j hj0 hj1; apply hj' => /#.
(* sel, then PH(M) *)
seq 3 : (to_uint pos = 13 + dlen d0 /\
         (forall j, 0 <= j < 13 + dlen d0 =>
            BArray332.get8 prefix j = fbyte d0 (ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)) j) /\
         take (to_uint len) (BArray64.to_list ph) = ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)).
+ call (_ : sel = zeroextu64 (BArray257.get8 d0 0) /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
            1 <= to_uint (zeroextu64 (BArray257.get8 d0 0)) <= 12 /\ to_uint m + to_uint ml <= W64.modulus ==>
            take (to_uint res.`2) (BArray64.to_list res.`1) =
              ph_apply (ph_of (to_uint (zeroextu64 (BArray257.get8 d0 0)))) (m_of mem0 m ml)).
  + by conseq (hph (zeroextu64 (BArray257.get8 d0 0)) m ml mem0).
  auto => /> &hr hm hp hj; rewrite hs0; split; first smt().
  move=> _ _ r hr'.
  have hp1 : to_uint (pos{hr} + W64.one) = 13 + dlen d0
    by rewrite W64.to_uintD_small W64.to_uint1 /#.
  rewrite hp1 hp hr' /=.
  move=> j hj0 hj1; rewrite BArray332.get_setE 1:/#.
  case: (j = 12 + dlen d0) => [->|hne]; last by apply hj => /#.
  by rewrite /fbyte ifF 1:/# ifF 1:/# ifF 1:/# /= /truncateu8 hs0 /dsel W8.to_uintK.
(* PH(M) copy, prefix_len = pos + len *)
wp.
while (to_uint pos = 13 + dlen d0 /\ to_uint len <= 64 /\
       take (to_uint len) (BArray64.to_list php) = ph_apply (ph_of (dsel d0)) (m_of mem0 m ml) /\
       0 <= to_uint i <= to_uint len /\ more = (i \ult len) /\
       forall j, 0 <= j < 13 + dlen d0 + to_uint i =>
         BArray332.get8 prefix j = fbyte d0 (ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)) j).
+ auto => /> &hr hp hl64 hph' hi0 hi1 hj hlt; rewrite ultE in hlt.
  have hi : to_uint (i{hr} + W64.one) = to_uint i{hr} + 1
    by rewrite W64.to_uintD_small W64.to_uint1 /#.
  have ho : to_uint (pos{hr} + i{hr}) = 13 + dlen d0 + to_uint i{hr}
    by rewrite W64.to_uintD_small /= /#.
  rewrite hi /=; split; first smt().
  move=> j hj0 hj1; rewrite BArray332.get_setE 1:/# ho tz8.
  case: (j = 13 + dlen d0 + to_uint i{hr}) => [->|hne]; last by apply hj => /#.
  rewrite /fbyte ifF 1:/# ifF 1:/# ifF 1:/# ifF 1:/# -hph' nth_take 1,2:/#.
  by rewrite BArray64.get_to_list; congr; ring.
auto => /> &hr hp hj hph'.
have [hc1 hc2] := clamp64 len{hr} (BArray64.to_list ph{hr}) _.
+ by rewrite BArray64.size_to_list.
move: hc1 hc2.
have [l <-] : exists l, l = ((W64.of_int 64 \ule len{hr}) ? W64.of_int 64 : len{hr}).
+ by exists ((W64.of_int 64 \ule len{hr}) ? W64.of_int 64 : len{hr}).
move=> hc1 hc2.
split; first by rewrite hc2 hph' /=; smt(W64.to_uint_cmp).
move=> i0 more0 x0 hn _ _ hi0 hi1 hf hj'.
have hi : to_uint i0 = to_uint l by move: hf; rewrite ultE /#.
have hz : size (ph_apply (ph_of (dsel d0)) (m_of mem0 m ml)) = to_uint l.
+ rewrite -hph' -hc2 size_take; [smt(W64.to_uint_cmp) | rewrite BArray64.size_to_list /max /=; smt()].
have hpl : to_uint (pos{hr} + l) = 13 + dlen d0 + to_uint l by rewrite W64.to_uintD_small /= /#.
rewrite clampE 1:/# hpl; split; last smt().
move=> _; split; first smt().
split; last by rewrite h0.
apply frame_take.
+ smt().
+ by rewrite frame_size 1:/# h0 /= hz.
+ smt().
by move=> j hjj; apply hj' => /#.
qed.

lemma clamp64_le (x : W64.t) : to_uint ((W64.of_int 64 \ule x) ? W64.of_int 64 : x) <= 64.
proof. by rewrite uleE W64.of_uintK /=; case: (64 <= to_uint x) => /#. qed.

lemma prehash_ll :
  (forall (s m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prehash :
       sel = s /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
       1 <= to_uint s <= 12 /\ to_uint m + to_uint ml <= W64.modulus ==>
       take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 m ml)]
     = 1%r) =>
  phoare [M._prehash : 1 <= to_uint sel <= 12 /\ to_uint msg + to_uint msg_len <= W64.modulus ==> true]
  = 1%r.
proof.
move=> hph; proc*; exlim sel, msg, msg_len, Glob.mem => s m ml mem0.
by call (hph s m ml mem0); auto.
qed.

lemma slh_frame_ll :
  (forall (s m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prehash :
       sel = s /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
       1 <= to_uint s <= 12 /\ to_uint m + to_uint ml <= W64.modulus ==>
       take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 m ml)]
     = 1%r) =>
  phoare [M._slh_frame : to_uint msg + to_uint msg_len <= W64.modulus ==> true] = 1%r.
proof.
move=> hph; have hpl := prehash_ll hph.
proc.
seq 13 : (to_uint msg + to_uint msg_len <= W64.modulus /\
          sel = zeroextu64 (BArray257.get8 domain 0) /\ ctx_len = zeroextu64 (BArray257.get8 domain 1) /\
          valid = (sel \ule W64.of_int 12)) 1%r 1%r 0%r _ => //.
+ wp; while (to_uint msg + to_uint msg_len <= W64.modulus) (inc - k).
  + by move=> z; auto => /> /#.
  by auto => /> /#.
+ if; last by auto.
  seq 10 : (to_uint msg + to_uint msg_len <= W64.modulus /\ to_uint sel <= 12) 1%r 1%r 0%r _ => //.
  + while (to_uint msg + to_uint msg_len <= W64.modulus /\ to_uint sel <= 12 /\
           to_uint end_0 <= 257 /\ more = (i \ult end_0)) (to_uint end_0 - to_uint i).
    + move=> z; auto => /> &hr hm hs he hlt; rewrite ultE in hlt.
      have hi : to_uint (i{hr} + W64.one) = to_uint i{hr} + 1
        by rewrite W64.to_uintD_small W64.to_uint1 /#.
      by rewrite hi /#.
    auto => /> &hr hm hv.
    have hs1 : 0 <= to_uint (BArray257.get8 domain{hr} 1) < 256
      by have := W8.to_uint_cmp (BArray257.get8 domain{hr} 1).
    have hz : to_uint (zeroextu64 (BArray257.get8 domain{hr} 1)) = to_uint (BArray257.get8 domain{hr} 1)
      by rewrite to_uint_zeroextu64.
    have he : to_uint (zeroextu64 (BArray257.get8 domain{hr} 1) + W64.of_int 2) =
              to_uint (BArray257.get8 domain{hr} 1) + 2.
    + by rewrite W64.to_uintD_small hz W64.of_uintK /=; smt().
    rewrite he; move: hv; rewrite uleE /= => hv; split; first smt().
    by move=> i0; rewrite ultE /#.
  + seq 3 : (to_uint msg + to_uint msg_len <= W64.modulus /\ to_uint sel <= 12 /\
             pure = (sel = W64.zero)) 1%r 1%r 0%r _ => //.
    + by auto.
    + if; first by auto.
      seq 6 : (to_uint msg + to_uint msg_len <= W64.modulus /\ 1 <= to_uint sel <= 12) 1%r 1%r 0%r _ => //.
      + wp; while (to_uint msg + to_uint msg_len <= W64.modulus /\ 1 <= to_uint sel <= 12) (10 - k).
        + by move=> z; auto => /> /#.
        auto => /> &hr hm hs hp; split; last smt().
        by move: hp; rewrite W64.to_uint_eq /=; smt(W64.to_uint_cmp).
      + wp; while (to_uint len <= 64 /\ more = (i \ult len)) (to_uint len - to_uint i).
        + move=> z; auto => /> &hr hl hlt; rewrite ultE in hlt.
          have hi : to_uint (i{hr} + W64.one) = to_uint i{hr} + 1
            by rewrite W64.to_uintD_small W64.to_uint1 /#.
          by rewrite hi /#.
        wp; call hpl; auto => /> &hr hm hs0 hs1 r; split; first by apply clamp64_le.
        by move=> i0; rewrite ultE /#.
      + hoare; wp; while (to_uint msg + to_uint msg_len <= W64.modulus /\ 1 <= to_uint sel <= 12).
        + by auto.
        auto => /> &hr hm hs hp.
        by move: hp; rewrite W64.to_uint_eq /=; smt(W64.to_uint_cmp).
    + by hoare; auto.
  + hoare; while (to_uint msg + to_uint msg_len <= W64.modulus /\ to_uint sel <= 12).
    + by auto.
    by auto => /> &hr hm hv; move: hv; rewrite uleE /#.
+ hoare; wp; while (to_uint msg + to_uint msg_len <= W64.modulus); first by auto.
  by auto.
qed.

lemma slh_frame_correct :
  (forall (s m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prehash :
       sel = s /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
       1 <= to_uint s <= 12 /\ to_uint m + to_uint ml <= W64.modulus ==>
       take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 m ml)]
     = 1%r) =>
  forall (d0 : BArray257.t) (m ml : W64.t) (mem0 : global_mem_t),
  phoare [M._slh_frame :
    domain = d0 /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
    to_uint m + to_uint ml <= W64.modulus ==>
    frame_out d0 (m_of mem0 m ml) ml res /\ (dsel d0 = 0 => Glob.mem = mem0)] = 1%r.
proof.
move=> hph d0 m ml mem0.
by conseq (slh_frame_ll hph) (slh_frame_h hph d0 m ml mem0) => /#.
qed.

(* ------------------------------------------------------------------ *)
(* The exports (Algorithms 21 to 25, and section 9)                   *)

lemma ones_nz : W64.of_int (-1) <> W64.zero.
proof. by rewrite W64.to_uint_eq W64.of_uintK. qed.

(* What sign returns for the domain block d (Algorithms 22 and 23). *)
op ext_sign (d : BArray257.t) (M sk : bytes) (o : bytes option) : bytes option =
  if dsel d = 0 then slh_sign P M (dctx d) sk o
  else if dsel d <= 12 then hash_slh_sign P M (dctx d) (ph_of (dsel d)) sk o
  else None.

(* What verify accepts for the domain block d (Algorithms 24 and 25). *)
op ext_verify (d : BArray257.t) (M s pk : bytes) : bool =
  if dsel d = 0 then slh_verify P M s (dctx d) pk
  else if dsel d <= 12 then hash_slh_verify P M s (dctx d) (ph_of (dsel d)) pk
  else false.

lemma ext_signE (mem : global_mem_t) (x : Prefix.t) (pl m ml ml' : W64.t) d M sk o :
  dsel d <= 12 => take (to_uint pl) (Prefix.to_list x) = frame d M =>
  ml' = (if dsel d = 0 then ml else W64.zero) =>
  (dsel d = 0 => M = m_of mem m ml) =>
  ext_sign d M sk o = Some (slh_sign_internal P (slh_msg mem x pl m ml') sk o).
proof.
move=> hs hx -> hm; rewrite /ext_sign; case: (dsel d = 0) => h0 /=.
+ by rewrite sign_some (msg_pure _ _ _ _ _ _ _ h0 hx) -hm.
by rewrite hs /= hsign_some (msg_ph _ _ _ _ _ _ h0 hx).
qed.

lemma ext_verifyE (mem : global_mem_t) (x : Prefix.t) (pl m ml ml' : W64.t) d M s pk :
  dsel d <= 12 => take (to_uint pl) (Prefix.to_list x) = frame d M =>
  ml' = (if dsel d = 0 then ml else W64.zero) =>
  (dsel d = 0 => M = m_of mem m ml) =>
  ext_verify d M s pk = slh_verify_internal P (slh_msg mem x pl m ml') s pk.
proof.
move=> hs hx -> hm; rewrite /ext_verify; case: (dsel d = 0) => h0 /=.
+ by rewrite verify_ctx (msg_pure _ _ _ _ _ _ _ h0 hx) -hm.
by rewrite hs /= hverify_ctx (msg_ph _ _ _ _ _ _ h0 hx).
qed.

(* M' is at most Prefix.size bytes of prefix, then M (pure) or nothing
   (pre-hash), so the domain of M with the longest prefix covers it. *)
lemma frame_msg_ok (r : Prefix.t * W64.t * W64.t * W64.t * W64.t) d M (m ml : W64.t) :
  dsel d <= 12 => frame_out d M ml r => msg_dom (W64.of_int Prefix.size) m ml =>
  msg_ok r.`2 m r.`3.
proof.
move=> hs; rewrite /frame_out hs /msg_ok /= => [#] _ hl _ -> hm; split => //.
move: hm; rewrite !msg_domE /sha2_msg_ok /sha2_msg_max W64.of_uintK /= => [#] hm h2; split.
+ by case: (dsel d = 0) => _ //=; smt(W64.to_uint_cmp).
move=> hf; have [_ h2b] := h2 hf; move: h2b; rewrite (_ : Prefix.size = 332) 1:// /= => h2b.
by case: (dsel d = 0) => _ /=; smt(W64.to_uint_cmp).
qed.

(* Algorithms 22 and 23 (hedged with opt_rand fresh, deterministic with
   opt_rand = PK.seed, Internal.sign_deterministic). *)
lemma sign_correct (ok : bytes -> Ctx.t -> bool) :
  (forall (s m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prehash :
       sel = s /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
       1 <= to_uint s <= 12 /\ to_uint m + to_uint ml <= W64.modulus ==>
       take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 m ml)]
     = 1%r) =>
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
  forall (s0 : Sig.t) (m ml : W64.t) (d0 : BArray257.t) (k0 : SK.t) (o0 : Node.t)
         (mem0 : global_mem_t),
  phoare [M.sign :
    sig = s0 /\ msg = m /\ msg_len = ml /\ domain = d0 /\ sk = k0 /\ opt_rand = o0 /\
    Glob.mem = mem0 /\ msg_dom (W64.of_int Prefix.size) m ml ==>
    if dsel d0 <= 12
    then res.`2 = W64.zero /\
         ext_sign d0 (m_of mem0 m ml) (SK.to_list k0) (Some (Node.to_list o0)) = Some (Sig.to_list res.`1)
    else res.`2 = W64.of_int (-1) /\ res.`1 = s0 /\
         ext_sign d0 (m_of mem0 m ml) (SK.to_list k0) (Some (Node.to_list o0)) = None] = 1%r.
proof.
move=> hph hctx hprf hf htl hh htk hpm hhm s0 m ml d0 k0 o0 mem0.
proc.
seq 8 : (sig = s0 /\ msg = m /\ msg_len = ml /\ domain = d0 /\ sk = k0 /\ opt_rand = o0 /\
         Glob.mem = mem0 /\ msg_dom (W64.of_int Prefix.size) m ml) 1%r 1%r 0%r _ => //.
+ by auto.
+ seq 1 : (sig = s0 /\ msg = m /\ sk = k0 /\ opt_rand = o0 /\ msg_dom (W64.of_int Prefix.size) m ml /\
           frame_out d0 (m_of mem0 m ml) ml (prefix, prefix_len, msg_len, status, ms) /\
           (dsel d0 = 0 => Glob.mem = mem0)) 1%r 1%r 0%r _ => //.
  + call (slh_frame_correct hph d0 m ml mem0); auto => /> hm.
    split; [exact (msg_dom_end _ _ _ hm) | move=> _ r; rewrite /frame_out].
    by case: (dsel d0 <= 12) => //= _ [#] -> -> ->; rewrite -(W64.of_int_mod (-1)).
  + exlim prefix, prefix_len, msg_len, Glob.mem => x pl ml' mem1.
    have [hs | hs] : dsel d0 <= 12 \/ !(dsel d0 <= 12) by rewrite orbN.
    + rcondt 6; first by auto => /> &hr; rewrite /frame_out hs => /#.
      wp; call (slh_sign_correct ok hctx hprf hf htl hh htk hpm hhm s0 x pl m ml' k0 o0 mem1).
      auto => /> &hr hm hfo hmem.
      have := frame_msg_ok (x, pl, ml', status{hr}, ms{hr}) d0 _ m ml hs hfo hm.
      rewrite /msg_ok /= => [#] hpl hml; split; first by [].
      move=> _ _ r hr _; move: hfo; rewrite /frame_out hs /= => [#] -> _ hx hml' /=.
      rewrite (ext_signE mem1 x pl m ml ml' d0 (m_of mem0 m ml) _ _ hs hx hml') ?hr //.
      by move=> /hmem ->.
    rcondf 6; first by auto => /> &hr; rewrite /frame_out hs /= => _ [#] -> _ _ _; apply ones_nz.
    auto => /> &hr hm; rewrite /frame_out hs /= => [#] -> _ _ _.
    by rewrite /ext_sign ifF 1:/# ifF 1:/#.
  + hoare; call (slh_frame_h hph d0 m ml mem0); auto => /> hm.
    split; [exact (msg_dom_end _ _ _ hm) | move=> _ r; rewrite /frame_out].
    by case: (dsel d0 <= 12) => //= _ [#] -> -> ->; rewrite -(W64.of_int_mod (-1)).
+ by hoare; auto.
qed.

(* Algorithms 24 and 25. *)
lemma verify_correct (ok : bytes -> Ctx.t -> bool) :
  (forall (s m ml : W64.t) (mem0 : global_mem_t),
     phoare [M._prehash :
       sel = s /\ msg = m /\ msg_len = ml /\ Glob.mem = mem0 /\
       1 <= to_uint s <= 12 /\ to_uint m + to_uint ml <= W64.modulus ==>
       take (to_uint res.`2) (BArray64.to_list res.`1) = ph_apply (ph_of (to_uint s)) (m_of mem0 m ml)]
     = 1%r) =>
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
  forall (s0 : Sig.t) (m ml : W64.t) (d0 : BArray257.t) (p0 : PK.t) (mem0 : global_mem_t),
  phoare [M.verify :
    sig = s0 /\ msg = m /\ msg_len = ml /\ domain = d0 /\ pk = p0 /\ Glob.mem = mem0 /\
    msg_dom (W64.of_int Prefix.size) m ml ==>
    res = if ext_verify d0 (m_of mem0 m ml) (Sig.to_list s0) (PK.to_list p0)
          then W64.zero else W64.of_int (-1)] = 1%r.
proof.
move=> hph hctx hf htl hh htk hhm s0 m ml d0 p0 mem0.
proc.
seq 7 : (sig = s0 /\ msg = m /\ msg_len = ml /\ domain = d0 /\ pk = p0 /\
         Glob.mem = mem0 /\ msg_dom (W64.of_int Prefix.size) m ml) 1%r 1%r 0%r _ => //.
+ by auto.
+ seq 1 : (sig = s0 /\ msg = m /\ pk = p0 /\ msg_dom (W64.of_int Prefix.size) m ml /\
           frame_out d0 (m_of mem0 m ml) ml (prefix, prefix_len, msg_len, status, ms) /\
           (dsel d0 = 0 => Glob.mem = mem0)) 1%r 1%r 0%r _ => //.
  + call (slh_frame_correct hph d0 m ml mem0); auto => /> hm.
    split; [exact (msg_dom_end _ _ _ hm) | move=> _ r; rewrite /frame_out].
    by case: (dsel d0 <= 12) => //= _ [#] -> -> ->; rewrite -(W64.of_int_mod (-1)).
  + exlim prefix, prefix_len, msg_len, Glob.mem => x pl ml' mem1.
    have [hs | hs] : dsel d0 <= 12 \/ !(dsel d0 <= 12) by rewrite orbN.
    + rcondt 6; first by auto => /> &hr; rewrite /frame_out hs => /#.
      wp; call (slh_verify_correct ok hctx hf htl hh htk hhm s0 x pl m ml' p0 mem1).
      auto => /> &hr hm hfo hmem.
      have := frame_msg_ok (x, pl, ml', status{hr}, ms{hr}) d0 _ m ml hs hfo hm.
      rewrite /msg_ok /= => [#] hpl hml; split; first by [].
      move=> _ _ r ->; move: hfo; rewrite /frame_out hs /= => [#] _ _ hx hml'.
      rewrite (ext_verifyE mem1 x pl m ml ml' d0 (m_of mem0 m ml) _ _ hs hx hml') //.
      by move=> /hmem ->.
    rcondf 6; first by auto => /> &hr; rewrite /frame_out hs /= => _ [#] -> _ _ _; apply ones_nz.
    auto => /> &hr hm; rewrite /frame_out hs /= => [#] -> _ _ _.
    have hv : !ext_verify d0 (m_of mem0 m ml) (Sig.to_list s0) (PK.to_list p0)
      by rewrite /ext_verify ifF 1:/# ifF 1:/#.
    by rewrite hv.
  + hoare; call (slh_frame_h hph d0 m ml mem0); auto => /> hm.
    split; [exact (msg_dom_end _ _ _ hm) | move=> _ r; rewrite /frame_out].
    by case: (dsel d0 <= 12) => //= _ [#] -> -> ->; rewrite -(W64.of_int_mod (-1)).
+ by hoare; auto.
qed.

(* Algorithm 21 from line 4: the seeds are the caller's entropy draw. *)
lemma keygen_correct (ok : bytes -> Ctx.t -> bool) :
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
  phoare [M.keygen : seeds = e0 ==>
    (SK.to_list res.`2, PK.to_list res.`1) =
      slh_keygen P (slice (Seeds.to_list e0) 0 P.`n)
        (slice (Seeds.to_list e0) P.`n (2 * P.`n)) (slice (Seeds.to_list e0) (2 * P.`n) (3 * P.`n))] = 1%r.
proof.
move=> hctx hprf hf htl hh e0; proc.
by call (slh_keygen_correct ok hctx hprf hf htl hh e0); auto.
qed.

(* Section 9: slh_sign_internal and slh_verify_internal on M itself. *)
lemma msg_none (mem : global_mem_t) (x : Prefix.t) (m ml : W64.t) :
  slh_msg mem x W64.zero m ml = m_of mem m ml.
proof. by rewrite /slh_msg /m_of /= take0. qed.

lemma sign_internal_correct (ok : bytes -> Ctx.t -> bool) :
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
  forall (s0 : Sig.t) (m ml : W64.t) (k0 : SK.t) (o0 : Node.t) (mem0 : global_mem_t),
  phoare [M.sign_internal :
    sig = s0 /\ msg = m /\ msg_len = ml /\ sk = k0 /\ opt_rand = o0 /\ Glob.mem = mem0 /\
    msg_dom W64.zero m ml ==>
    Sig.to_list res = slh_sign_internal P (m_of mem0 m ml) (SK.to_list k0) (Some (Node.to_list o0))] = 1%r.
proof.
move=> hctx hprf hf htl hh htk hpm hhm s0 m ml k0 o0 mem0; proc.
call (slh_sign_correct ok hctx hprf hf htl hh htk hpm hhm s0 witness W64.zero m ml k0 o0 mem0).
by auto => />; rewrite msg_none.
qed.

lemma verify_internal_correct (ok : bytes -> Ctx.t -> bool) :
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
  forall (s0 : Sig.t) (m ml : W64.t) (p0 : PK.t) (mem0 : global_mem_t),
  phoare [M.verify_internal :
    sig = s0 /\ msg = m /\ msg_len = ml /\ pk = p0 /\ Glob.mem = mem0 /\
    msg_dom W64.zero m ml ==>
    res = if slh_verify_internal P (m_of mem0 m ml) (Sig.to_list s0) (PK.to_list p0)
          then W64.zero else W64.of_int (-1)] = 1%r.
proof.
move=> hctx hf htl hh htk hhm s0 m ml p0 mem0; proc.
call (slh_verify_correct ok hctx hf htl hh htk hhm s0 witness W64.zero m ml p0 mem0).
by auto => />; rewrite msg_none.
qed.
