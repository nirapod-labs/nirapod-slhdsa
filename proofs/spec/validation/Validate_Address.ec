(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validate_Address.ec
 * ===================
 *
 * Checks of the address encodings of FIPS 205 sections 4.2, 4.3 and 11.2.
 *
 * One address is built with every member function of Table 1 and compared,
 * byte by byte, with the layout of Figures 2 and 6; the getters of Table 1
 * read the fields back; ADRSc is compared with Figure 18; and the Table 3
 * functions applied to a compressed zero address produce the same 22 bytes
 * as compressing the full address. Expected values were computed
 * independently of this file. The general facts give the sizes every
 * member function preserves.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord JUtils.
require import Bytes FIPS205_Encoding FIPS205_Address Validate_Encoding.

op example : adrs =
  setHashAddress
    (setChainAddress
       (setKeyPairAddress
          (setTypeAndClear
             (setTreeAddress (setLayerAddress (toByte 0 32) 5) 0x0102030405060708)
             FORS_TREE)
          0x0a0b0c0d)
       17)
    0x01020304.

lemma example_bytes : example = map W8.of_int
  [0; 0; 0; 5;   0; 0; 0; 0; 1; 2; 3; 4; 5; 6; 7; 8;   0; 0; 0; 3;
   10; 11; 12; 13;   0; 0; 0; 17;   1; 2; 3; 4].
proof.
rewrite /example /setHashAddress /setChainAddress /setKeyPairAddress /setTypeAndClear.
rewrite /setTreeAddress /setLayerAddress /FORS_TREE /slice /toByte /zeros /range.
by rewrite -!mkseq_nseq /mkseq -!iotaredE /=.
qed.

lemma example_getters :
  getKeyPairAddress example = 0x0a0b0c0d /\ getTreeIndex example = 0x01020304.
proof.
rewrite example_bytes /getKeyPairAddress /getTreeIndex /toInt /slice /range.
by rewrite -!iotaredE /= ?W8.of_uintK.
qed.

lemma example_compress : compress example = map W8.of_int
  [5;   1; 2; 3; 4; 5; 6; 7; 8;   3;   10; 11; 12; 13;   0; 0; 0; 17;   1; 2; 3; 4].
proof. by rewrite example_bytes /compress /slice. qed.

lemma example_table3 :
  c_setHashAddress
    (c_setChainAddress
       (c_setKeyPairAddress
          (c_setTypeAndClear
             (c_setTreeAddress (c_setLayerAddress (toByte 0 22) 5) 0x0102030405060708)
             FORS_TREE)
          0x0a0b0c0d)
       17)
    0x01020304
  = compress example.
proof.
rewrite example_compress /c_setHashAddress /c_setChainAddress /c_setKeyPairAddress.
rewrite /c_setTypeAndClear /c_setTreeAddress /c_setLayerAddress /FORS_TREE /slice /toByte /zeros /range.
by rewrite -!mkseq_nseq /mkseq -!iotaredE /=.
qed.

(* ------------------------------------------------------------------ *)
(* General facts: every Table 1 function maps 32-byte addresses to      *)
(* 32-byte addresses.                                                   *)

lemma size_setLayerAddress a l : size a = 32 => size (setLayerAddress a l) = 32.
proof. by move=> ha; rewrite /setLayerAddress size_cat size_toByte // size_slice /#. qed.

lemma size_setTreeAddress a t : size a = 32 => size (setTreeAddress a t) = 32.
proof. by move=> ha; rewrite /setTreeAddress !size_cat size_toByte // !size_slice /#. qed.

lemma size_setTypeAndClear a y : size a = 32 => size (setTypeAndClear a y) = 32.
proof. by move=> ha; rewrite /setTypeAndClear !size_cat !size_toByte // size_slice /#. qed.

lemma size_setKeyPairAddress a i : size a = 32 => size (setKeyPairAddress a i) = 32.
proof. by move=> ha; rewrite /setKeyPairAddress !size_cat size_toByte // !size_slice /#. qed.

lemma size_setChainAddress a i : size a = 32 => size (setChainAddress a i) = 32.
proof. by move=> ha; rewrite /setChainAddress !size_cat size_toByte // !size_slice /#. qed.

lemma size_setHashAddress a i : size a = 32 => size (setHashAddress a i) = 32.
proof. by move=> ha; rewrite /setHashAddress size_cat size_toByte // size_slice /#. qed.

lemma size_compress a : size a = 32 => size (compress a) = 22.
proof. by move=> ha; rewrite /compress !size_cat !size_slice /#. qed.
