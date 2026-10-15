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

require import BArray2272 BArray38624.

clone SubByteArray as SBArray38624_2272  with theory Asmall <= BArray2272,
                                              theory Abig <= BArray38624.
