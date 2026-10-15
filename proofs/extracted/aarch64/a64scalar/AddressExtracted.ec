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
 *
 * Entry proofs/extracted/address.jazz SHA-256 18ebaae05e34ebca128a514c8cfdd905b8f47b4407d5258ff9e96d4531ea63b8
 * Sources under src/slhdsa (SHA-256, path):
 *     2582b4cc49d11c2f74494b660ed803f1f88549029bb7dd3285175c1b066d1e8d  ./address.jinc
 *)

require import AllCore IntDiv CoreMap List Distr.

from Jasmin require import JModel_armv8a.

import SLH64.

require import BArray32.

module M = {
  proc __store_be32 (adrs:BArray32.t, offset:int, v:W32.t) : BArray32.t = {
    var t:W32.t;
    t <- v;
    t <- (t `>>` (W8.of_int 24));
    adrs <- (BArray32.set8 adrs offset (truncateu8 t));
    t <- v;
    t <- (t `>>` (W8.of_int 16));
    adrs <- (BArray32.set8 adrs (offset + 1) (truncateu8 t));
    t <- v;
    t <- (t `>>` (W8.of_int 8));
    adrs <- (BArray32.set8 adrs (offset + 2) (truncateu8 t));
    adrs <- (BArray32.set8 adrs (offset + 3) (truncateu8 v));
    return adrs;
  }
  proc __adrs_zero (adrs:BArray32.t) : BArray32.t = {
    var z:W64.t;
    var i:int;
    z <- (W64.of_int 0);
    i <- 0;
    while ((i < 4)) {
      adrs <- (BArray32.set64 adrs i z);
      i <- (i + 1);
    }
    return adrs;
  }
  proc __adrs_set_layer (adrs:BArray32.t, layer:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 0, layer);
    return adrs;
  }
  proc __adrs_set_tree (adrs:BArray32.t, tree:W64.t) : BArray32.t = {
    var z:W32.t;
    var t:W64.t;
    var i:int;
    z <- (W32.of_int 0);
    adrs <- (BArray32.set32 adrs 1 z);
    i <- 0;
    while ((i < 8)) {
      t <- tree;
      t <- (t `>>` (W8.of_int (8 * (7 - i))));
      adrs <- (BArray32.set8 adrs (8 + i) (truncateu8 t));
      i <- (i + 1);
    }
    return adrs;
  }
  proc __adrs_set_type_and_clear (adrs:BArray32.t, adrs_type:int) : BArray32.t = {
    var t:W64.t;
    t <- (W64.of_int (adrs_type `<<` 24));
    adrs <- (BArray32.set64 adrs 2 t);
    t <- (W64.of_int 0);
    adrs <- (BArray32.set64 adrs 3 t);
    return adrs;
  }
  proc __adrs_set_keypair (adrs:BArray32.t, keypair:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 20, keypair);
    return adrs;
  }
  proc __adrs_copy_keypair (dst:BArray32.t, src:BArray32.t) : BArray32.t = {
    var t:W32.t;
    t <- (BArray32.get32 src 5);
    dst <- (BArray32.set32 dst 5 t);
    return dst;
  }
  proc __adrs_set_chain (adrs:BArray32.t, chain:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 24, chain);
    return adrs;
  }
  proc __adrs_set_tree_height (adrs:BArray32.t, height:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 24, height);
    return adrs;
  }
  proc __adrs_set_hash (adrs:BArray32.t, hash:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 28, hash);
    return adrs;
  }
  proc __adrs_set_tree_index (adrs:BArray32.t, index:W32.t) : BArray32.t = {
    
    adrs <@ __store_be32 (adrs, 28, index);
    return adrs;
  }
  proc __adrs_copy (dst:BArray32.t, src:BArray32.t) : BArray32.t = {
    var i:int;
    var t:W64.t;
    i <- 0;
    while ((i < 4)) {
      t <- (BArray32.get64 src i);
      dst <- (BArray32.set64 dst i t);
      i <- (i + 1);
    }
    return dst;
  }
}.
