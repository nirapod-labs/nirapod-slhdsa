(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIPS205_Address.ec
 * ==================
 *
 * Addresses (ADRS) of FIPS 205 sections 4.2 and 4.3, and the compressed
 * address ADRSc of section 11.2.
 *
 * An address is the 32-byte string itself, as the standard defines it:
 *
 *     bytes  0 ..  3   layer address
 *     bytes  4 .. 15   tree address
 *     bytes 16 .. 19   type
 *     bytes 20 .. 31   three type-specific words
 *
 * every word big-endian. The member functions are the expanded notation of
 * Table 1, verbatim. setTreeHeight shares its row with setChainAddress and
 * setTreeIndex with setHashAddress: each pair writes the same bytes, and the
 * standard uses whichever name fits the address type.
 *
 * Passing convention. Section 4.2 lets the pseudocode pass addresses by
 * reference or by value. These operators return the updated address; the
 * algorithms thread it explicitly wherever a later step of the same
 * algorithm reads a field an earlier step wrote.
 *
 * Compressed form. The SHA2 parameter sets hash ADRSc = ADRS[3] ||
 * ADRS[8:16] || ADRS[19] || ADRS[20:32], 22 bytes. The specification keeps
 * the 32-byte address and compresses it at the hash call. Table 3 gives
 * member functions acting directly on the compressed form; they are stated
 * here too, and their agreement with compress-after-update is a validation
 * lemma, since an implementation may store addresses compressed.
 *)

require import AllCore List IntDiv.
from Jasmin require import JWord.
require import Bytes FIPS205_Encoding.

type adrs = bytes.

(* Section 4.2, footnote 5: the seven address types. *)
op WOTS_HASH  = 0.
op WOTS_PK    = 1.
op TREE       = 2.
op FORS_TREE  = 3.
op FORS_ROOTS = 4.
op WOTS_PRF   = 5.
op FORS_PRF   = 6.

(* ------------------------------------------------------------------ *)
(* Table 1                                                            *)

op setLayerAddress   (a : adrs) (l : int) : adrs = toByte l 4 ++ slice a 4 32.
op setTreeAddress    (a : adrs) (t : int) : adrs = slice a 0 4 ++ toByte t 12 ++ slice a 16 32.
op setTypeAndClear   (a : adrs) (y : int) : adrs = slice a 0 16 ++ toByte y 4 ++ toByte 0 12.
op setKeyPairAddress (a : adrs) (i : int) : adrs = slice a 0 20 ++ toByte i 4 ++ slice a 24 32.
op setChainAddress   (a : adrs) (i : int) : adrs = slice a 0 24 ++ toByte i 4 ++ slice a 28 32.
op setHashAddress    (a : adrs) (i : int) : adrs = slice a 0 28 ++ toByte i 4.

abbrev setTreeHeight = setChainAddress.
abbrev setTreeIndex  = setHashAddress.

op getKeyPairAddress (a : adrs) : int = toInt (slice a 20 24) 4.
op getTreeIndex      (a : adrs) : int = toInt (slice a 28 32) 4.

(* ------------------------------------------------------------------ *)
(* Section 11.2: ADRSc and Table 3                                    *)

op compress (a : adrs) : bytes =
  [nth W8.zero a 3] ++ slice a 8 16 ++ [nth W8.zero a 19] ++ slice a 20 32.

op c_setLayerAddress   (a : bytes) (l : int) : bytes = toByte l 1 ++ slice a 1 22.
op c_setTreeAddress    (a : bytes) (t : int) : bytes = slice a 0 1 ++ toByte t 8 ++ slice a 9 22.
op c_setTypeAndClear   (a : bytes) (y : int) : bytes = slice a 0 9 ++ toByte y 1 ++ toByte 0 12.
op c_setKeyPairAddress (a : bytes) (i : int) : bytes = slice a 0 10 ++ toByte i 4 ++ slice a 14 22.
op c_setChainAddress   (a : bytes) (i : int) : bytes = slice a 0 14 ++ toByte i 4 ++ slice a 18 22.
op c_setHashAddress    (a : bytes) (i : int) : bytes = slice a 0 18 ++ toByte i 4.

op c_getKeyPairAddress (a : bytes) : int = toInt (slice a 10 14) 4.
op c_getTreeIndex      (a : bytes) : int = toInt (slice a 18 22) 4.
