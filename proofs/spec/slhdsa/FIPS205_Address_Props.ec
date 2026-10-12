(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Address_Props.ec
 * ========================
 *
 * Closed forms of toByte and toInt (FIPS 205 Algorithms 2 and 3) and of
 * the ADRS member functions of section 4.3, for proofs that follow an
 * address through a sequence of setter calls.
 *
 *     toByteE           toByte(x, n) is the n-byte big-endian encoding of
 *                       x mod 256^n
 *     toInt_toByte      toInt(toByte(x, n), n) = x mod 256^n
 *     mk_adrs           the 32-byte ADRS with the given layer address,
 *                       tree address, type and three words (Figure 2),
 *                       each field written with toByte
 *     set*E, get*E      every setter replaces one field of mk_adrs, and
 *                       setTypeAndClear also zeroes the three words; the
 *                       getters read a word back mod 2^32
 *)

require import AllCore List IntDiv StdOrder.
import IntOrder.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding FIPS205_Encoding_Props FIPS205_Address.

(* ------------------------------------------------------------------ *)
(* toByte and toInt                                                   *)

(* The state of Algorithm 3 after m of its n steps: total = x div 256^m,
   and the last m bytes of S are written. *)
lemma toByte_state (x n m : int) :
  0 <= m <= n =>
  foldl (fun (st : int * bytes) (i : int) =>
           (st.`1 %/ 256, put st.`2 (n - 1 - i) (W8.of_int (st.`1 %% 256))))
        (x, zeros n) (range 0 m)
  = (x %/ 256 ^ m,
     mkseq (fun j => if n - 1 - j < m then W8.of_int (x %/ 256 ^ (n - 1 - j)) else W8.zero) n).
proof.
elim/natind: m => [m hm0 hm | m hm ih hmn].
+ have -> : m = 0 by smt().
  rewrite range_geq //= ?expr0 ?divz1 /zeros.
  apply (eq_from_nth W8.zero) => [|i hi]; first by rewrite size_nseq size_mkseq.
  by move: hi; rewrite size_nseq => hi; rewrite nth_nseq 1:/# nth_mkseq 1:/# /= /#.
rewrite rangeSr // -cats1 foldl_cat ih 1:/# /=; split.
+ by rewrite exprS // mulrC divzMr 1:expr_ge0.
apply (eq_from_nth W8.zero) => [|i hi]; first by rewrite size_put !size_mkseq.
move: hi; rewrite size_put size_mkseq => hi.
rewrite nth_put 1:size_mkseq 1:/# !nth_mkseq 1,2:/# /=.
case: (n - 1 - m = i) => [<- | hne].
+ rewrite (_: n - 1 - (n - 1 - m) = m) 1:/# /=.
  by rewrite ifT 1:/# -(W8.of_int_mod (x %/ 256 ^ m)).
by rewrite /#.
qed.

lemma toByteE (x n : int) : 0 <= n => toByte x n = be_bytes n x.
proof.
move=> hn; rewrite /toByte toByte_state 1:/# /= /be_bytes.
by apply eq_in_mkseq => i hi /=; rewrite ifT 1:/#.
qed.

lemma size_toByte (x n : int) : 0 <= n => size (toByte x n) = n.
proof. by move=> hn; rewrite toByteE // size_be_bytes /#. qed.

lemma toByte_mod (x n : int) : 0 <= n => toByte (x %% 256 ^ n) n = toByte x n.
proof.
move=> hn; rewrite !toByteE // /be_bytes; apply eq_in_mkseq => i hi /=.
rewrite -(W8.of_int_mod (x %% 256 ^ n %/ _)) -(W8.of_int_mod (x %/ _)) /=.
rewrite (modz_pow_div 256 n (n - 1 - i) x) // 1:/#.
congr; apply modz_dvd; rewrite (_: n - (n - 1 - i) = i + 1) 1:/# exprS 1:/#.
by apply dvdz_mulr; apply dvdzz.
qed.

lemma be_bytesS (n x : int) :
  0 <= n => be_bytes (n + 1) x = rcons (be_bytes n (x %/ 256)) (W8.of_int x).
proof.
move=> hn; apply (eq_from_nth W8.zero) => [|i hi]; first by rewrite size_rcons !size_be_bytes /#.
move: hi; rewrite size_be_bytes => hi.
rewrite nth_rcons size_be_bytes /be_bytes.
case: (i < n) => hin.
+ rewrite ifT 1:/# !nth_mkseq 1,2:/# /=; congr.
  by rewrite (_: n - i = (n - 1 - i) + 1) 1:/# exprS 1:/# divzMr // expr_ge0.
by rewrite ifF 1:/# ifT 1:/# nth_mkseq 1:/# /= (_: n + 1 - 1 - i = 0) 1:/# expr0 divz1.
qed.

lemma modz_mul_split (x a b : int) :
  0 < a => 0 < b => x %% (a * b) = a * (x %/ a %% b) + x %% a.
proof. by move=> ha hb; rewrite !modzE divzMr 1,2:/#; ring. qed.

lemma be_int_be_bytes (n x : int) : 0 <= n => be_int (be_bytes n x) = x %% 256 ^ n.
proof.
elim/natind: n x => [n hn0 x hn | n hn ih x _].
+ have -> : n = 0 by smt().
  by rewrite /be_bytes mkseq0 /be_int /= ?expr0 ?modz1.
rewrite be_bytesS // be_int_rcons ih // W8.of_uintK.
by rewrite exprS // (modz_mul_split x 256 (256 ^ n)) // expr_gt0.
qed.

lemma toInt_be_int (x : bytes) (n : int) :
  0 <= n <= size x => toInt x n = be_int (take n x).
proof.
elim/natind: n => [n hn0 hn | n hn ih hns].
+ have -> : n = 0 by smt().
  by rewrite /toInt range_geq // take0 /be_int.
rewrite /toInt rangeSr // -cats1 foldl_cat /= -/(toInt x n) ih 1:/#.
by rewrite be_int_take_succ 1:/#.
qed.

lemma toInt_toByte (x n : int) : 0 <= n => toInt (toByte x n) n = x %% 256 ^ n.
proof.
move=> hn; rewrite toInt_be_int 1:size_toByte // take_oversize 1:size_toByte //.
by rewrite toByteE // be_int_be_bytes.
qed.

lemma toByte0 (n : int) : 0 <= n => toByte 0 n = nseq n W8.zero.
proof.
move=> hn; rewrite toByteE // /be_bytes.
apply (eq_from_nth W8.zero) => [|i hi]; first by rewrite size_mkseq size_nseq.
by move: hi; rewrite size_mkseq => hi; rewrite nth_mkseq 1:/# nth_nseq 1:/# /=.
qed.

(* ------------------------------------------------------------------ *)
(* Slices of concatenations                                           *)

lemma slice_prefix (x y : bytes) j :
  size x <= j => slice (x ++ y) 0 j = x ++ slice y 0 (j - size x).
proof. by move=> h; rewrite /slice !drop0 take_cat ifF 1:/#. qed.

lemma slice_nil (x : bytes) i : slice x i i = [].
proof. by rewrite /slice take0. qed.

lemma slice_drop (x : bytes) i j : size x = j => 0 <= i <= j => slice x i j = drop i x.
proof. by move=> <- hi; rewrite /slice take_oversize // size_drop /#. qed.

(* ------------------------------------------------------------------ *)
(* Addresses                                                          *)

(* Figure 2: layer address (4 bytes), tree address (12), type (4), and
   three words (4 each). The words are, by type, the key pair address,
   chain address or tree height, and hash address or tree index. *)
op mk_adrs (l t y w2 w1 w0 : int) : adrs =
  toByte l 4 ++ toByte t 12 ++ toByte y 4 ++ toByte w2 4 ++ toByte w1 4 ++ toByte w0 4.

lemma size_toByte4 x : size (toByte x 4) = 4 by rewrite size_toByte.
lemma size_toByte12 x : size (toByte x 12) = 12 by rewrite size_toByte.
hint simplify size_toByte4, size_toByte12.

lemma mk_adrsR l t y w2 w1 w0 :
  mk_adrs l t y w2 w1 w0
  = toByte l 4 ++ (toByte t 12 ++ (toByte y 4 ++ (toByte w2 4 ++ (toByte w1 4 ++ toByte w0 4)))).
proof. by rewrite /mk_adrs !catA. qed.

lemma size_mk_adrs l t y w2 w1 w0 : size (mk_adrs l t y w2 w1 w0) = 32.
proof. by rewrite /mk_adrs !size_cat. qed.

lemma mk_adrs0 : toByte 0 32 = mk_adrs 0 0 0 0 0 0.
proof. by rewrite /mk_adrs !toByte0 // !cat_nseq. qed.

lemma setLayerAddressE l t y w2 w1 w0 v :
  setLayerAddress (mk_adrs l t y w2 w1 w0) v = mk_adrs v t y w2 w1 w0.
proof.
rewrite /setLayerAddress !mk_adrsR (slice_drop _ 4 32) 1:!size_cat //=.
by rewrite drop_cat /= drop0.
qed.

lemma setTreeAddressE l t y w2 w1 w0 v :
  setTreeAddress (mk_adrs l t y w2 w1 w0) v = mk_adrs l v y w2 w1 w0.
proof.
rewrite /setTreeAddress !mk_adrsR.
rewrite slice_prefix //= slice_nil cats0 (slice_drop _ 16 32) 1:!size_cat //=.
by rewrite drop_cat /= drop_cat /= drop0 -!catA.
qed.

lemma setTypeAndClearE l t y w2 w1 w0 v :
  setTypeAndClear (mk_adrs l t y w2 w1 w0) v = mk_adrs l t v 0 0 0.
proof.
rewrite /setTypeAndClear !mk_adrsR.
by rewrite slice_prefix //= slice_prefix //= slice_nil cats0 !toByte0 // !cat_nseq // -!catA.
qed.

lemma setKeyPairAddressE l t y w2 w1 w0 v :
  setKeyPairAddress (mk_adrs l t y w2 w1 w0) v = mk_adrs l t y v w1 w0.
proof.
rewrite /setKeyPairAddress !mk_adrsR.
rewrite slice_prefix //= slice_prefix //= slice_prefix //= slice_nil cats0.
rewrite (slice_drop _ 24 32) 1:!size_cat //=.
by rewrite !drop_cat /= drop0 -!catA.
qed.

lemma setChainAddressE l t y w2 w1 w0 v :
  setChainAddress (mk_adrs l t y w2 w1 w0) v = mk_adrs l t y w2 v w0.
proof.
rewrite /setChainAddress !mk_adrsR.
rewrite slice_prefix //= slice_prefix //= slice_prefix //= slice_prefix //= slice_nil cats0.
rewrite (slice_drop _ 28 32) 1:!size_cat //=.
by rewrite !drop_cat /= drop0 -!catA.
qed.

lemma setHashAddressE l t y w2 w1 w0 v :
  setHashAddress (mk_adrs l t y w2 w1 w0) v = mk_adrs l t y w2 w1 v.
proof.
rewrite /setHashAddress !mk_adrsR.
rewrite slice_prefix //= slice_prefix //= slice_prefix //= slice_prefix //= slice_prefix //=.
by rewrite slice_nil cats0 -!catA.
qed.

lemma getKeyPairAddressE l t y w2 w1 w0 :
  getKeyPairAddress (mk_adrs l t y w2 w1 w0) = w2 %% 2 ^ 32.
proof.
rewrite /getKeyPairAddress !mk_adrsR /slice !drop_cat /= drop0 take_cat /= take0 cats0.
by rewrite toInt_toByte.
qed.

lemma getTreeIndexE l t y w2 w1 w0 :
  getTreeIndex (mk_adrs l t y w2 w1 w0) = w0 %% 2 ^ 32.
proof.
rewrite /getTreeIndex !mk_adrsR (slice_drop _ 28 32) 1:!size_cat //= !drop_cat /= drop0.
by rewrite toInt_toByte.
qed.
