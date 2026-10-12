(*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * MerkleTrees_FIPS205.ec
 * ======================
 *
 * The Merkle tree computations of FIPS 205 against the binary-tree
 * operators of the imported security proof (MerkleTrees.ec), for an
 * arbitrary leaf function L and node hash T.
 *
 * FIPS 205 computes a node recursively from its height and index
 * (Algorithms 9 and 15) and a root from a leaf and an authentication path
 * by a loop over the heights (Algorithms 11 and 17). The security proof
 * builds a binary tree from the list of leaves (list2tree) and walks it
 * from the root down, carrying a (height, index) pair (val_bt, cons_ap,
 * val_ap). Nodes are named by height and index in both: the children of
 * node (z, i) are (z - 1, 2i) and (z - 1, 2i + 1).
 *
 *     gnode_list2tree    node (z, i) is the value of the tree built from
 *                        leaves i 2^z .. (i + 1) 2^z - 1
 *     gnode_cons_ap      the authentication path of leaf G is the list of
 *                        sibling nodes sibling(G div 2^j) at height j,
 *                        root side first
 *     gfold_val_ap       the FIPS 205 loop over heights computes val_ap
 *     gfold_gnode        on the authentication path of leaf G, the loop
 *                        returns the node above G (the root at full height)
 *)

require import AllCore List IntDiv StdOrder BitEncoding.
import IntOrder BS2Int.
require import BinaryTrees MerkleTrees.

(* The sibling of node i at its height (FIPS 205 Algorithm 10, line 3). *)
op gsibling (i : int) : int = if i %% 2 = 0 then i + 1 else i - 1.

(* Descending one level from node (z, i) towards child b. *)
op upd_hb (hb : int * int) (b : bool) : int * int =
  (hb.`1 - 1, if b then 2 * hb.`2 + 1 else 2 * hb.`2).

(* A node hash taking (height, index) as one argument, as val_bt expects. *)
op lift_trh ['a] (T : int -> int -> 'a -> 'a -> 'a) (ct : int * int) (x y : 'a) : 'a =
  T ct.`1 ct.`2 x y.

lemma lift_trhE ['a] (T : int -> int -> 'a -> 'a -> 'a) (h b : int) (x y : 'a) :
  lift_trh T (h, b) x y = T h b x y.
proof. by done. qed.

lemma upd_hbE (h b : int) (c : bool) : upd_hb (h, b) c = (h - 1, if c then 2 * b + 1 else 2 * b).
proof. by done. qed.

(* The recursion of Algorithms 9 and 15 over the list of heights still to
   build, highest first. *)
op gnode ['a] (L : int -> 'a) (T : int -> int -> 'a -> 'a -> 'a) (zs : int list) (i : int) : 'a =
  with zs = [] => L i
  with zs = z :: zs' => T z i (gnode L T zs' (2 * i)) (gnode L T zs' (2 * i + 1)).

(* The heights z, z - 1, .., 1 below a node at height z. *)
op hts (z : int) : int list = rev (range 1 (z + 1)).

lemma hts0 : hts 0 = [].
proof. by rewrite /hts range_geq. qed.

lemma htsS z : 0 <= z => hts (z + 1) = (z + 1) :: hts z.
proof. by move=> hz; rewrite /hts rangeSr 1:/# rev_rcons. qed.

(* The loop of Algorithms 11 and 17 from leaf G: at height k the node is
   a left child exactly when bit k of G is 0, and the parent has index
   G div 2^(k + 1). *)
op gfold ['a] (T : int -> int -> 'a -> 'a -> 'a) (auth : int -> 'a) (g : int) (leaf : 'a) (m : int) : 'a =
  foldl (fun (node : 'a) (k : int) =>
           if (g %/ 2 ^ k) %% 2 = 0
           then T (k + 1) (g %/ 2 ^ (k + 1)) node (auth k)
           else T (k + 1) (g %/ 2 ^ (k + 1)) (auth k) node)
        leaf (range 0 m).

lemma div2S (g k : int) : 0 <= k => g %/ 2 ^ (k + 1) = g %/ 2 ^ k %/ 2.
proof. by move=> hk; rewrite exprS // mulrC divzMr // expr_ge0. qed.

lemma div2_split (g k : int) :
  0 <= k => g %/ 2 ^ k = 2 * (g %/ 2 ^ (k + 1)) + (g %/ 2 ^ k) %% 2.
proof. by move=> hk; rewrite div2S //; smt(divz_eq). qed.

(* ------------------------------------------------------------------ *)
(* Nodes                                                              *)

lemma gnode_list2tree ['a] (L : int -> 'a) (T : int -> int -> 'a -> 'a -> 'a) (z i : int) :
  0 <= z =>
  gnode L T (hts z) i
  = val_bt (lift_trh T) upd_hb (list2tree (mkseq (fun j => L (i * 2 ^ z + j)) (2 ^ z))) (z, i).
proof.
move=> hz; elim: z hz i => [|z hz ih] i.
+ by rewrite hts0 /= expr0 mkseq1 /= list2tree1.
rewrite htsS //= exprS // (_: 2 * 2 ^ z = 2 ^ z + 2 ^ z) 1:/#.
rewrite mkseq_add 1,2:expr_ge0 //.
have -> : mkseq (fun j => L (i * (2 ^ z + 2 ^ z) + j)) (2 ^ z)
          = mkseq (fun j => L ((2 * i) * 2 ^ z + j)) (2 ^ z).
+ by apply eq_in_mkseq => j hj /=; congr; ring.
have -> : mkseq (fun j => L (i * (2 ^ z + 2 ^ z) + (2 ^ z + j))) (2 ^ z)
          = mkseq (fun j => L ((2 * i + 1) * 2 ^ z + j)) (2 ^ z).
+ by apply eq_in_mkseq => j hj /=; congr; ring.
rewrite (list2treeS z) // ?size_mkseq ?ler_maxr ?expr_ge0 //=.
by rewrite lift_trhE !upd_hbE /= !ih.
qed.

(* ------------------------------------------------------------------ *)
(* Authentication paths                                               *)

lemma rev_int2bsS (z g : int) :
  0 <= z => rev (int2bs (z + 1) g) = ((g %/ 2 ^ z) %% 2 <> 0) :: rev (int2bs z g).
proof. by move=> hz; rewrite int2bsS // rev_rcons. qed.

lemma gnode_cons_ap ['a] (L : int -> 'a) (T : int -> int -> 'a -> 'a -> 'a) (z g : int) :
  0 <= z => 0 <= g =>
  cons_ap (lift_trh T) upd_hb
          (list2tree (mkseq (fun j => L (g %/ 2 ^ z * 2 ^ z + j)) (2 ^ z)))
          (rev (int2bs z g)) (z, g %/ 2 ^ z)
  = rev (map (fun j => gnode L T (hts j) (gsibling (g %/ 2 ^ j))) (range 0 z)).
proof.
move=> hz hg; elim: z hz => [|z hz ih].
+ by rewrite expr0 mkseq1 /= list2tree1 int2bs0s range_geq.
pose B := g %/ 2 ^ (z + 1).
have hB := div2_split g z hz.
have hsplit : mkseq (fun j => L (B * 2 ^ (z + 1) + j)) (2 ^ (z + 1))
  = mkseq (fun j => L ((2 * B) * 2 ^ z + j)) (2 ^ z)
    ++ mkseq (fun j => L ((2 * B + 1) * 2 ^ z + j)) (2 ^ z).
+ rewrite exprS // (_: 2 * 2 ^ z = 2 ^ z + 2 ^ z) 1:/# mkseq_add 1,2:expr_ge0 //; congr.
  + by apply eq_in_mkseq => j hj /=; congr; ring.
  by apply eq_in_mkseq => j hj /=; congr; ring.
rewrite -/B hsplit (list2treeS z) // ?size_mkseq ?ler_maxr ?expr_ge0 //.
rewrite rev_int2bsS // rangeSr // map_rcons rev_rcons /= !upd_hbE /=.
case: ((g %/ 2 ^ z) %% 2 = 0) => hb /=.
+ move: hB; rewrite hb /= -/B => hB.
  by rewrite -hB ih /= /gsibling hb /= gnode_list2tree //.
have hb1 : (g %/ 2 ^ z) %% 2 = 1 by smt(modz_ge0 ltz_pmod).
move: hB; rewrite hb1 /= -/B => hB.
by rewrite -hB ih /= /gsibling hb /= gnode_list2tree // hB.
qed.

(* ------------------------------------------------------------------ *)
(* Roots from authentication paths                                    *)

lemma gfoldS ['a] (T : int -> int -> 'a -> 'a -> 'a) (auth : int -> 'a) (g : int) (leaf : 'a) (m : int) :
  0 <= m =>
  gfold T auth g leaf (m + 1)
  = let node = gfold T auth g leaf m in
    if (g %/ 2 ^ m) %% 2 = 0
    then T (m + 1) (g %/ 2 ^ (m + 1)) node (auth m)
    else T (m + 1) (g %/ 2 ^ (m + 1)) (auth m) node.
proof. by move=> hm; rewrite /gfold rangeSr // -cats1 foldl_cat. qed.

lemma gfold_val_ap ['a] (T : int -> int -> 'a -> 'a -> 'a) (auth : int -> 'a) (g : int) (leaf : 'a) (m : int) :
  0 <= m =>
  gfold T auth g leaf m
  = val_ap (lift_trh T) upd_hb (rev (map auth (range 0 m))) (rev (int2bs m g)) leaf (m, g %/ 2 ^ m).
proof.
elim: m => [|m hm ih].
+ by rewrite /gfold range_geq // int2bs0s.
rewrite gfoldS // ih rangeSr // map_rcons rev_rcons rev_int2bsS //=.
have hB := div2_split g m hm.
rewrite lift_trhE !upd_hbE /=.
case: ((g %/ 2 ^ m) %% 2 = 0) => hb /=.
+ by move: hB; rewrite hb /= => hB; rewrite -hB.
have hb1 : (g %/ 2 ^ m) %% 2 = 1 by smt(modz_ge0 ltz_pmod).
by move: hB; rewrite hb1 /= => hB; rewrite -hB.
qed.

lemma gfold_gnode ['a] (L : int -> 'a) (T : int -> int -> 'a -> 'a -> 'a) (g m : int) :
  0 <= m =>
  gfold T (fun j => gnode L T (hts j) (gsibling (g %/ 2 ^ j))) g (L g) m
  = gnode L T (hts m) (g %/ 2 ^ m).
proof.
elim: m => [|m hm ih].
+ by rewrite /gfold range_geq // hts0 /= expr0 divz1.
rewrite gfoldS // ih htsS //=.
have hB := div2_split g m hm.
case: ((g %/ 2 ^ m) %% 2 = 0) => hb /=.
+ by move: hB; rewrite hb /= => hB; rewrite /gsibling hb /= -hB.
have hb1 : (g %/ 2 ^ m) %% 2 = 1 by smt(modz_ge0 ltz_pmod).
by move: hB; rewrite hb1 /= => hB; rewrite /gsibling hb /= -hB /#.
qed.
