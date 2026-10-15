(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ArchWord.ec (aarch64)
 * =====================
 *
 * The aarch64 word helpers of the extracted model compute the operators of
 * WordSpec. __bswap32 and __bswap64 are the AArch64 REV instructions,
 * which the Jasmin model defines as byte reversal.
 *)

require import AllCore List IntDiv.
from Jasmin require import JModel_armv8a.
require import HashExtracted WordSpec.

lemma bswap32_spec (x0 : W32.t) :
  hoare [M.__bswap32 : x = x0 ==> res = bswap32 x0].
proof. by proc; auto => />; rewrite /REV_32 /bswap32. qed.

(* REV_64 is defined bit by bit: bit i of the result is bit
   8 * (7 - i / 8) + i mod 8 of the operand, which is bit i mod 8 of byte
   7 - i / 8. *)
lemma REV_64E x : REV_64 x = bswap64 x.
proof.
apply W64.wordP => i hi.
rewrite /REV_64 /bswap64 W64.initiE //= W8u8.pack8wE //.
rewrite W8u8.Pack.get_of_list 1:/# /=.
have hm : 0 <= i %% 8 < 8 by smt().
have : i %/ 8 = 0 \/ i %/ 8 = 1 \/ i %/ 8 = 2 \/ i %/ 8 = 3 \/
       i %/ 8 = 4 \/ i %/ 8 = 5 \/ i %/ 8 = 6 \/ i %/ 8 = 7 by smt().
by case=> [->|[->|[->|[->|[->|[->|[->|->]]]]]]] /=;
   rewrite /rev /= W8u8.bits8iE //; congr; smt().
qed.

lemma bswap64_spec (x0 : W64.t) :
  hoare [M.__bswap64 : x = x0 ==> res = bswap64 x0].
proof. by proc; auto => />; rewrite REV_64E. qed.

(* The names the shared proofs use; the x86-64 theory proves the same
   statements for BSWAP_32 and BSWAP_64. *)
lemma bswap32E x : REV_32 x = bswap32 x by rewrite /REV_32 /bswap32.
lemma bswap64E x : REV_64 x = bswap64 x by exact: REV_64E.
