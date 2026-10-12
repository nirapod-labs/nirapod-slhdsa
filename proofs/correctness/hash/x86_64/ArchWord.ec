(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ArchWord.ec (x86_64)
 * ====================
 *
 * The x86_64 word helpers of the extracted model compute the operators of
 * WordSpec. __bswap32 and __bswap64 are the x86-64 BSWAP instructions,
 * which the Jasmin model defines as byte reversal.
 *)

require import AllCore List IntDiv.
from Jasmin require import JModel_x86.
require import HashExtracted WordSpec.

(* The model unpacks the word before listing its bytes; the two listings
   agree byte by byte. *)
lemma BSWAP_32E x : BSWAP_32 x = bswap32 x.
proof.
rewrite /BSWAP_32 /bswap32 /(\o) /=; congr; congr.
by rewrite /W4u8.Pack.to_list /mkseq -iotaredE /= !W4u8.get_unpack8.
qed.

lemma BSWAP_64E x : BSWAP_64 x = bswap64 x.
proof.
rewrite /BSWAP_64 /bswap64 /(\o) /=; congr; congr.
by rewrite /W8u8.Pack.to_list /mkseq -iotaredE /= !W8u8.get_unpack8.
qed.

lemma bswap32_spec (x0 : W32.t) :
  hoare [M.__bswap32 : x = x0 ==> res = bswap32 x0].
proof. by proc; auto => />; rewrite BSWAP_32E. qed.

lemma bswap64_spec (x0 : W64.t) :
  hoare [M.__bswap64 : x = x0 ==> res = bswap64 x0].
proof. by proc; auto => />; rewrite BSWAP_64E. qed.
