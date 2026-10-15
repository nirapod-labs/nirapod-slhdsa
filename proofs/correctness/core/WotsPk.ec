(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * WotsPk.ec
 * =========
 *
 * _wots_pk_from_sig of src/slhdsa/wots.jinc computes wots_pkFromSig of
 * FIPS 205 Algorithm 8 for the address A that the standard's caller
 * passes: the caller's ADRS with type WOTS_HASH and key pair keypair.
 * The code sets that type and key pair itself, so the theorem states A
 * from the code's inputs.
 *
 * Chain i starts at block i of the signature, at digit d_i, and runs
 * w - 1 - d_i steps of _wots_chain; its end is stored at bytes i n of
 * tmp. The loop invariant is that the first i n bytes of tmp are the
 * first i chain ends, concatenated. The WOTS_PK address of lines 12 to
 * 14 is built from A in the standard and from the caller's ADRS in the
 * code; pk_adrsE shows they agree. digits_lt16 bounds each digit below
 * w = 16, so the code's 32-bit step count w - 1 - d_i does not wrap.
 *
 * Hash premises. F and T_l enter as hypotheses for one fixed PK.seed pk
 * and ctx c0, the shape of the per-family thash theorems, as in
 * WotsChain.ec. The lossless forms (set_*_ll, wots_chain_llc) close the
 * prefixes that ecall leaves; wots_chain_llc needs only the F premise.
 *
 * The ADRS setters are proved in correctness/slhdsa/ADRS.ec about the
 * set-free model; core_set_chain, core_set_keypair,
 * core_set_type_and_clear and core_copy move those theorems to this
 * set's model, whose copies of the procedures are the same code.
 *
 * Model. As Encoding.ec: this file is checked once against the model of
 * each parameter set, and names the set only through SetModel.
 *
 * Theorem:
 *     wots_pk_from_sig_correct   given the F and T_l premises,
 *                                _wots_pk_from_sig returns
 *                                wots_pkFromSig(sig, msg, pk, A);
 *                                total correctness.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Params FIPS205_Encoding FIPS205_Address FIPS205_Address_Props.
require import FIPS205_Hash FIPS205_WOTS.
require import BArray32 BArray128.
require import SetModel CoreExtracted Wots Encoding WotsChain.
require ADRS AddressExtracted.

(* ADRS setters moved to this set's model, as core_set_hash. *)
lemma core_set_chain (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_chain : arg = (a0, i0) ==>
          BArray32.to_list res = setChainAddress (BArray32.to_list a0) (to_uint i0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_set_chain(adrs{m}, chain{m}) @ &m :
               BArray32.to_list res = setChainAddress (BArray32.to_list a0) (to_uint i0)] =
          Pr[AddressExtracted.M.__adrs_set_chain(a0, i0) @ &m :
               BArray32.to_list res = setChainAddress (BArray32.to_list a0) (to_uint i0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_chain_correct a0 i0).
qed.

lemma core_set_keypair (a0 : BArray32.t) (i0 : W32.t) :
  phoare [M.__adrs_set_keypair : arg = (a0, i0) ==>
          BArray32.to_list res = setKeyPairAddress (BArray32.to_list a0) (to_uint i0)] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_set_keypair(adrs{m}, keypair{m}) @ &m :
               BArray32.to_list res = setKeyPairAddress (BArray32.to_list a0) (to_uint i0)] =
          Pr[AddressExtracted.M.__adrs_set_keypair(a0, i0) @ &m :
               BArray32.to_list res = setKeyPairAddress (BArray32.to_list a0) (to_uint i0)].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_keypair_correct a0 i0).
qed.

lemma core_set_type_and_clear (a0 : BArray32.t) (y0 : int) : 0 <= y0 < 256 =>
  phoare [M.__adrs_set_type_and_clear : arg = (a0, y0) ==>
          BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) y0] = 1%r.
proof.
move=> hy; bypr => &m h.
have -> : Pr[M.__adrs_set_type_and_clear(adrs{m}, adrs_type{m}) @ &m :
               BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) y0] =
          Pr[AddressExtracted.M.__adrs_set_type_and_clear(a0, y0) @ &m :
               BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) y0].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_set_type_and_clear_correct a0 y0 hy).
qed.

lemma core_copy (d0 s0 : BArray32.t) :
  phoare [M.__adrs_copy : arg = (d0, s0) ==> BArray32.to_list res = BArray32.to_list s0] = 1%r.
proof.
bypr => &m h.
have -> : Pr[M.__adrs_copy(dst{m}, src{m}) @ &m : BArray32.to_list res = BArray32.to_list s0] =
          Pr[AddressExtracted.M.__adrs_copy(d0, s0) @ &m : BArray32.to_list res = BArray32.to_list s0].
+ by byequiv (_ : ={arg} ==> ={res}) => //; [proc; sim | smt()].
by byphoare (ADRS.adrs_copy_correct d0 s0).
qed.

(* Every WOTS+ digit is below w = 16. *)
lemma digits_lt16 (x : bytes) (i : int) : size x = P.`n => 0 <= i < len P =>
  0 <= nth 0 (wots_digits P x) i < 16.
proof.
move=> hx hi; rewrite (wots_digits_closed x hx) nth_cat size_mkseq.
have hm : max 0 (2 * P.`n) = 2 * P.`n by smt(n_val).
have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have hc := csum_bound x (2 * P.`n) _; first smt(n_val).
rewrite hm; case: (i < 2 * P.`n) => h.
+ have hd := digit_bound x i.
  by rewrite nth_mkseq; move: hi h hd => /#.
have hn : 0 < P.`n <= 32 by smt(n_val).
move: hi h hc hn; rewrite hl; move: (csum x (2 * P.`n)) => c; move: (P.`n) => N hi h hc hn.
have : i - 2 * N = 0 \/ i - 2 * N = 1 \/ i - 2 * N = 2 by smt().
by case=> [|[|]] -> /=; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Address facts for Algorithm 8                                      *)

lemma take24_sca (x : adrs) i : 24 <= size x => take 24 (setChainAddress x i) = take 24 x.
proof.
move=> h; have hs : size (take 24 x) = 24 by rewrite size_take //; smt().
by rewrite /setChainAddress /slice drop0 /= take_cat size_cat hs /= take_cat hs /= take0 cats0.
qed.

lemma take28_sca (x y : adrs) i : 24 <= size x => take 24 x = take 24 y =>
  take 28 (setChainAddress x i) = take 28 (setChainAddress y i).
proof.
move=> hx h; have hs : size (take 24 y) = 24 by rewrite -h size_take //; smt().
by rewrite /setChainAddress /slice !drop0 /= h !take_cat !size_cat hs /= !take0 !cats0.
qed.

lemma size_tc (a : adrs) y : 16 <= size a => size (setTypeAndClear a y) = 32.
proof. by move=> h; rewrite /setTypeAndClear /slice drop0 !size_cat size_take //; smt(). qed.

lemma size_skp (a : adrs) kp : size a = 32 => size (setKeyPairAddress a kp) = 32.
proof.
by move=> h; rewrite /setKeyPairAddress /slice drop0 !size_cat size_take // size_take // size_drop //; smt().
qed.

lemma tc_skp (a : adrs) kp y : 20 <= size a =>
  setTypeAndClear (setKeyPairAddress a kp) y = setTypeAndClear a y.
proof.
move=> h; have hs : size (take 20 a) = 20 by rewrite size_take //; smt().
by rewrite /setTypeAndClear /setKeyPairAddress /slice !drop0 /= take_cat size_cat hs /= take_cat hs /= take_take.
qed.

lemma tc_tc (a : adrs) y z : 16 <= size a =>
  setTypeAndClear (setTypeAndClear a z) y = setTypeAndClear a y.
proof.
move=> h; have hs : size (take 16 a) = 16 by rewrite size_take //; smt().
by rewrite /setTypeAndClear /slice !drop0 /= take_cat size_cat hs /= take_cat hs /= take0 cats0.
qed.

lemma gkp_skp (a : adrs) kp : 20 <= size a => 0 <= kp < 2 ^ 32 =>
  getKeyPairAddress (setKeyPairAddress a kp) = kp.
proof.
move=> h hk; have hs : size (take 20 a) = 20 by rewrite size_take //; smt().
rewrite /getKeyPairAddress /setKeyPairAddress /slice drop0 /= drop_cat size_cat hs /=.
by rewrite drop_cat hs /= drop0 take_cat /= take0 cats0 toInt_toByte // mod32.
qed.

(* The WOTS_PK address of Algorithm 8, lines 12 to 14, from the caller's
   address A = setKeyPairAddress (setTypeAndClear a WOTS_HASH) kp. *)
lemma pk_adrsE (a : adrs) kp y : size a = 32 => 0 <= kp < 2 ^ 32 =>
  let a' = setKeyPairAddress (setTypeAndClear a WOTS_HASH) kp in
  setKeyPairAddress (setTypeAndClear a' y) (getKeyPairAddress a') =
  setKeyPairAddress (setTypeAndClear a y) kp.
proof.
move=> ha hk /=; have hs := size_tc a WOTS_HASH _; first smt().
by rewrite tc_skp 1:/# tc_tc 1:/# gkp_skp 1:/#.
qed.

(* ------------------------------------------------------------------ *)
(* Blocks of n bytes of the len n byte buffer                         *)

lemma tlen_size : TLenIn.size = len P * P.`n.
proof. by rewrite /len len1_val len2_val n_val. qed.

lemma get_sub_slice (t : TLenIn.t) j : 0 <= j < len P =>
  Node.to_list (TLenNode.get_sub t (j * P.`n)) =
  slice (TLenIn.to_list t) (j * P.`n) ((j + 1) * P.`n).
proof.
move=> hj; have hn := n_val; have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
apply (eq_from_nth W8.zero).
+ rewrite Node.size_to_list /slice size_take; first smt().
  rewrite size_drop; first smt().
  by rewrite TLenIn.size_to_list; move: hj hl hn; move: (len P) (P.`n) => L N /#.
rewrite Node.size_to_list => k hk; rewrite Node.get_to_list TLenNode.get8_get_sub.
rewrite /slice nth_take; 1,2:smt(). rewrite nth_drop; 1,2:smt().
by rewrite TLenIn.get_to_list; smt(n_val).
qed.

lemma take_set_sub (t : TLenIn.t) (c : Node.t) j : 0 <= j < len P =>
  take ((j + 1) * P.`n) (TLenIn.to_list (TLenNode.set_sub t (j * P.`n) c)) =
  take (j * P.`n) (TLenIn.to_list t) ++ Node.to_list c.
proof.
move=> hj; have hn := n_val; have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have hts := tlen_size.
apply (eq_from_nth W8.zero).
+ rewrite size_cat Node.size_to_list !size_take; 1,2:smt().
  by rewrite !TLenIn.size_to_list; move: hj hl hn hts; move: (len P) (P.`n) => L N /#.
rewrite size_take; 1:smt(); rewrite TLenIn.size_to_list => k hk.
rewrite nth_take; 1,2:smt(); rewrite TLenIn.get_to_list TLenNode.get8_set_sub.
rewrite nth_cat size_take; 1:smt(); rewrite TLenIn.size_to_list.
have hjn : (if j * P.`n < max 0 TLenIn.size then j * P.`n else max 0 TLenIn.size) = j * P.`n.
+ by move: hj hl hn hts; move: (len P) (P.`n) => L N /#.
rewrite hjn; case: (k < j * P.`n) => hk2 /=.
+ have -> /= : !(j * P.`n <= k) by smt().
  by rewrite nth_take 1,2:/# TLenIn.get_to_list.
have -> /= : (j * P.`n <= k < j * P.`n + Node.size) /\ (0 <= k < TLenIn.size).
+ by move: hj hl hn hts hk hk2; move: (len P) (P.`n) => L N /#.
done.
qed.

lemma core_tc0 (a0 : BArray32.t) :
  phoare [M.__adrs_set_type_and_clear : arg = (a0, 0) ==>
          BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) 0] = 1%r.
proof. by apply (core_set_type_and_clear a0 0). qed.

lemma core_tc1 (a0 : BArray32.t) :
  phoare [M.__adrs_set_type_and_clear : arg = (a0, 1) ==>
          BArray32.to_list res = setTypeAndClear (BArray32.to_list a0) 1] = 1%r.
proof. by apply (core_set_type_and_clear a0 1). qed.

(* Word facts for the chain loop: the byte offset i n of chain i, and the
   digit read as a 32-bit start. *)
lemma zext64E (x : W32.t) : to_uint (zeroextu64 x) = to_uint x.
proof. by rewrite /zeroextu64 W64.of_uintK modz_small //; have := W32.to_uint_cmp x; smt(). qed.

lemma offE (x : W32.t) c : to_uint x < len P => P.`n = c =>
  to_uint (zeroextu64 x * W64.of_int c) = to_uint x * P.`n.
proof.
move=> hx hc; have hn := n_val; have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
have h0 : 0 <= to_uint x by smt(W32.to_uint_cmp).
have hc' : to_uint (W64.of_int c) = P.`n by rewrite W64.of_uintK -hc hn.
rewrite W64.to_uintM_small; rewrite zext64E hc' //.
by move: hx h0 hl hn; move: (to_uint x) (len P) (P.`n) => X L N /#.
qed.

(* Lossless forms, for the prefixes that ecall leaves. *)
lemma set_chain_ll : islossless M.__adrs_set_chain.
proof. proc*; exlim adrs, chain => a i; call (core_set_chain a i); auto. qed.

lemma set_keypair_ll : islossless M.__adrs_set_keypair.
proof. proc*; exlim adrs, keypair => a i; call (core_set_keypair a i); auto. qed.

lemma set_hash_ll : islossless M.__adrs_set_hash.
proof. proc*; exlim adrs, hash => a i; call (core_set_hash a i); auto. qed.

lemma copy_ll : islossless M.__adrs_copy.
proof. proc*; exlim dst, src => a b; call (core_copy a b); auto. qed.

lemma set_tc_ll : islossless M.__adrs_set_type_and_clear.
proof. by islossless. qed.

(* _wots_chain terminates for every input; the F premise gives the
   termination of _thash_f with the caller's ctx. *)
lemma wots_chain_llc (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  phoare [M._wots_chain : ctx = c0 ==> true] = 1%r.
proof.
move=> hf.
have hfl : phoare [M._thash_f : ctx = c0 ==> true] = 1%r.
+ by proc*; exlim x, adrs => x1 a1; call (hf x1 a1); auto.
proc; wp.
while (more = (j \ult end_0) /\ ctx = c0) (to_uint end_0 - to_uint j).
+ move=> z; wp; call hfl; call set_hash_ll; wp; skip.
  rewrite /protect_ptr /protect_32 /= => &m [#] hm hc hmore hz; split; first done.
  have hlt : to_uint j{m} < to_uint end_0{m} by rewrite -W32.ultE -hm.
  have hjj : to_uint (j{m} + W32.one) = to_uint j{m} + 1.
  + have h1 : to_uint W32.one = 1 by exact W32.to_uint1.
    have hb := W32.to_uint_cmp end_0{m}.
    have hjm : to_uint j{m} + 1 < W32.modulus by move: hlt hb => /#.
    by rewrite W32.to_uintD_small h1.
  by rewrite ?W32.ultE hjj; smt().
by wp; skip => &m -> /=; smt(W32.ultE).
qed.

(* ------------------------------------------------------------------ *)
(* _wots_pk_from_sig (Algorithm 8)                                    *)

lemma wots_pk_from_sig_correct (pk_seed : bytes) c0 :
  (forall (x0 : Node.t) (a0 : BArray32.t),
     phoare [M._thash_f : x = x0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = F P pk_seed (BArray32.to_list a0) (Node.to_list x0)] = 1%r) =>
  (forall (m0 : TLenIn.t) (a0 : BArray32.t),
     phoare [M._thash_t_len : in_0 = m0 /\ ctx = c0 /\ adrs = a0 ==>
       Node.to_list res.`1 = T_l P pk_seed (BArray32.to_list a0) (TLenIn.to_list m0)] = 1%r) =>
  forall (s0 : TLenIn.t) (m0 : Node.t) (a0 : BArray32.t) (kp0 : W32.t),
  phoare [M._wots_pk_from_sig :
    sig = s0 /\ msg = m0 /\ ctx = c0 /\ adrs = a0 /\ keypair = kp0 ==>
    Node.to_list res.`1 =
      wots_pkFromSig P (TLenIn.to_list s0) (Node.to_list m0) pk_seed
        (setKeyPairAddress (setTypeAndClear (BArray32.to_list a0) WOTS_HASH) (to_uint kp0))] = 1%r.
proof.
move=> hf htl s0 m0 a0 kp0.
pose A := setKeyPairAddress (setTypeAndClear (BArray32.to_list a0) WOTS_HASH) (to_uint kp0).
pose D := wots_digits P (Node.to_list m0).
pose pc := fun j => chain P (slice (TLenIn.to_list s0) (j * P.`n) ((j + 1) * P.`n))
                       (nth 0 D j) (w P - 1 - nth 0 D j) pk_seed (setChainAddress A j).
have hl : len P = 2 * P.`n + 3 by smt(len1_val len2_val).
proc.
ecall (htl tmp pk_adrs); wp.
while (0 <= to_uint i <= len P /\ more = (to_uint i < len P) /\ sig = s0 /\ ctx = c0 /\
       map W8.to_uint (WotsDigits.to_list digits) = D /\
       take 24 (BArray32.to_list chain_adrs) = take 24 A /\
       take (to_uint i * P.`n) (TLenIn.to_list tmp) = flatten (map pc (range 0 (to_uint i))))
      (len P - to_uint i).
+ move=> z; inline M.__offset; wp.
  ecall (node_copy_correct cur); wp.
  ecall (wots_chain_correct pk_seed c0 hf cur start steps chain_adrs); wp.
  ecall (node_copy_correct (TLenNode.get_sub8 sig (W64.to_uint off))); wp.
  ecall (core_set_chain chain_adrs i); wp; skip.
  move=> &m [#] hi0 hi1 hmore hs hc hd ha ht hm hz.
  rewrite /protect_ptr /protect_32 /= => r1 hr1 r0 hr0.
  have hI : to_uint i{m} < len P by rewrite -hmore.
  have hoff := offE i{m} _ hI n_val.
  have hdd : to_uint (zeroextu32 (WotsDigits.get8 digits{m} (to_uint (zeroextu64 i{m})))) = nth 0 D (to_uint i{m}).
  + have hb : 0 <= to_uint (WotsDigits.get8 digits{m} (to_uint i{m})) < W32.modulus.
    + by have := W8.to_uint_cmp (WotsDigits.get8 digits{m} (to_uint i{m})); smt().
    rewrite zext64E zext32E W32.of_uintK (pmod_small _ _ hb).
    rewrite -hd (nth_map W8.zero) ?WotsDigits.size_to_list; 1: smt(n_val).
    by rewrite WotsDigits.get_to_list.
  have hdl := digits_lt16 (Node.to_list m0) (to_uint i{m}) _ _; 1,2: smt(Node.size_to_list n_val).
  have hst : to_uint (W32.of_int 15 - zeroextu32 (WotsDigits.get8 digits{m} (to_uint (zeroextu64 i{m})))) =
             15 - nth 0 D (to_uint i{m}).
  + by rewrite W32.to_uintB; rewrite ?W32.uleE hdd W32.of_uintK /=; smt().
  move: hr0; rewrite hoff => hr0; rewrite hdd hst hc /=.
  split; first smt().
  move=> _ r2 [hr2 hr2a] r3 ->.
  have hii : to_uint (i{m} + W32.one) = to_uint i{m} + 1.
  + have h1 : to_uint W32.one = 1 by exact W32.to_uint1.
    have hjm : to_uint i{m} + 1 < W32.modulus by smt(n_val).
    by rewrite W32.to_uintD_small h1.
  have h24 : take 24 (BArray32.to_list r2.`2) = take 24 A.
  + have := congr1 (take 24) _ _ hr2a; rewrite !take_take /= => ->.
    by rewrite hr1 take24_sca ?ADRS.size_bytes_of // ha.
  have hpc : Node.to_list r2.`1 = pc (to_uint i{m}).
  + rewrite hr2 /pc /= w_val hr0 hs get_sub_slice 1:/#.
    rewrite (chain_irrel _ _ _ _ _ (setChainAddress A (to_uint i{m}))) //.
    by rewrite hr1; apply take28_sca => //; rewrite ADRS.size_bytes_of.
  rewrite hii W32.ultE hii W32.of_uintK /=.
  rewrite take_set_sub 1:/# ht hpc rangeSr 1:/# map_rcons flatten_rcons /=.
  by rewrite hs hd h24 /=; smt(n_val).
+ by call set_chain_ll; auto.
+ by call node_copy_ll; wp; call set_chain_ll; auto.
+ call (wots_chain_llc pk_seed c0 hf); wp; call node_copy_ll; wp; call set_chain_ll; wp; skip.
  by rewrite /protect_ptr /=; smt().
wp; while true (inc - k); first by move=> z; wp; skip => /#.
wp; ecall (core_set_keypair pk_adrs keypair); last by do ?(call set_keypair_ll || call set_tc_ll || call copy_ll || call wots_digits_ll); auto.
ecall (core_tc1 pk_adrs); last by do ?(call set_keypair_ll || call set_tc_ll || call copy_ll || call wots_digits_ll); auto.
ecall (core_copy pk_adrs adrs); last by do ?(call set_keypair_ll || call set_tc_ll || call copy_ll || call wots_digits_ll); auto.
ecall (core_set_keypair chain_adrs keypair); last by do ?(call set_keypair_ll || call set_tc_ll || call copy_ll || call wots_digits_ll); auto.
ecall (core_tc0 chain_adrs); last by do ?(call set_keypair_ll || call set_tc_ll || call copy_ll || call wots_digits_ll); auto.
ecall (core_copy chain_adrs adrs); last by do ?(call set_keypair_ll || call set_tc_ll || call copy_ll || call wots_digits_ll); auto.
ecall (wots_digits_correct msg).
wp; skip => &m [#] -> -> -> -> -> /=.
move=> dg hdg c1 hc1 c2 hc2 c3 hc3 p1 hp1 p2 hp2 p3 hp3 k0 t0.
have hA : BArray32.to_list c3 = A by rewrite hc3 hc2 hc1.
have hP : BArray32.to_list p3 = setKeyPairAddress (setTypeAndClear A WOTS_PK) (getKeyPairAddress A).
+ have := pk_adrsE (BArray32.to_list a0) (to_uint kp0) WOTS_PK _ _.
  + exact ADRS.size_bytes_of.
  + by have := W32.to_uint_cmp kp0.
  by rewrite /= -/A => ->; rewrite hp3 hp2 hp1.
split; first smt().
move=> hk; split.
+ rewrite hdg hA range_geq //= take0 /D flatten_nil /=; smt(n_val).
move=> ca cx i0 mo ms0 sg t1; split; first smt().
move=> hnm [#] hi0 hi1 hmo hsg hcx hdd ha2 ht1.
rewrite /protect_ptr /= hcx /= => r ->; rewrite hP.
have hi : to_uint i0 = len P by smt().
have hT : TLenIn.to_list t1 = flatten (map pc (range 0 (len P))).
+ by rewrite -hi -ht1 hi -tlen_size take_oversize // TLenIn.size_to_list; smt().
by rewrite hT /wots_pkFromSig /= /pc /D.
(* The prefix that the last ecall leaves: the whole body terminates. *)
wp; while (ctx = c0 /\ 0 <= to_uint i <= len P /\ more = (to_uint i < len P)) (len P - to_uint i).
+ move=> z; inline M.__offset; wp; call node_copy_ll; wp; call (wots_chain_llc pk_seed c0 hf).
  wp; call node_copy_ll; wp; call set_chain_ll; wp; skip => &m [#] hc hi0 hi1 hmore hm hz.
  have hI : to_uint i{m} < len P by rewrite -hmore.
  have hii : to_uint (i{m} + W32.one) = to_uint i{m} + 1.
  + have h1 : to_uint W32.one = 1 by exact W32.to_uint1.
    have hjm : to_uint i{m} + 1 < W32.modulus by smt(n_val).
    by rewrite W32.to_uintD_small h1.
  rewrite /protect_ptr /protect_32 /= hc /= => *.
  by rewrite W32.ultE hii W32.of_uintK /=; smt(n_val).
wp; while true (inc - k); first by move=> z; wp; skip => /#.
wp; call set_keypair_ll; call set_tc_ll; call copy_ll; call set_keypair_ll; call set_tc_ll.
call copy_ll; call wots_digits_ll; wp; skip => &m [#] _ _ hc _ _ /=.
by move=> k0; smt(n_val).
qed.
