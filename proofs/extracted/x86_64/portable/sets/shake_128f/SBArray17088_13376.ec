(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * GENERATED FILE. DO NOT EDIT.
 *
 * Generator:
 *     jasmin2ec --arch=x86-64 (array model: the jasmin2ec default)
 *
 * Model:
 *     x86_64/portable
 *
 * Regenerate:
 *     make -C proofs extract     (check: make -C proofs check-extraction)
 *)

require import Int.

from Jasmin require import JByte_array.

require import BArray13376 BArray17088.

clone SubByteArray as SBArray17088_13376  with theory Asmall <= BArray13376,
                                               theory Abig <= BArray17088.
