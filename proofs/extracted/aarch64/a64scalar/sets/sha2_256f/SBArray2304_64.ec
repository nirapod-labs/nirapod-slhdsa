(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * GENERATED FILE. DO NOT EDIT.
 *
 * Generator:
 *     jasmin2ec --arch=armv8a (array model: the jasmin2ec default)
 *
 * Model:
 *     aarch64/a64scalar
 *
 * Regenerate:
 *     make -C proofs extract     (check: make -C proofs check-extraction)
 *)

require import Int.

from Jasmin require import JByte_array.

require import BArray64 BArray2304.

clone SubByteArray as SBArray2304_64  with theory Asmall <= BArray64,
                                           theory Abig <= BArray2304.
