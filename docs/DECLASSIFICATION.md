# Declassifications

The constant-time checkers (`analysis/README.md`) forbid a branch, loop bound
or memory address from depending on a value typed secret. A `#declassify` in
the source lifts that type for one value. The checker accepts every such
release without judging it, so each one is argued here and at its site, and the
two must agree.

There are two kinds:

- **release**: a value derived from a secret is made observable on purpose,
  because FIPS 205 makes it part of, or recomputable from, the public output;
- **type lift**: a value that is public by contract carries the secret type
  only because the checker types every hash output, memory load and fresh stack
  array as secret.

This list covers the FIPS 205 modules in `src/slhdsa`. The hash
functions in `src/hash` contain no declassification.

| # | Site | Value | Kind |
| --: | :-- | :-- | :-- |
| [1](#1-fors-and-hypertree-indices-signing) | `internal.jinc`, `_slh_sign` | the k FORS indices, `idx_tree`, `idx_leaf` | release |
| [2](#2-wots-digits-signing) | `hypertree.jinc`, `_ht_sign` | the len WOTS+ digits of each layer's message | release |
| [3](#3-indices-verification) | `internal.jinc`, `_slh_verify` | FORS indices, `idx_tree`, `idx_leaf` | type lift; release on the fault check |
| [4](#4-wots-digits-verification) | `wots.jinc`, `_wots_pk_from_sig` | the len WOTS+ digits of the node being verified | type lift; release on the fault check |
| [5](#5-the-verdict) | `hypertree.jinc`, `_ht_verify` | the verdict, 0 or all ones; not the recomputed root nor its difference from PK.root | type lift; release on the fault check |
| [6](#6-the-zero-digit-vector-of-key-generation) | `internal.jinc`, `_slh_keygen` | `no_steps`, an all-zero digit vector | type lift |

Every release is followed by `#protect` of the released scalar (or of each
element where it is read) before it is used: the speculative model treats a
released value as possibly secret under a mispredicted branch until it is
masked with the misspeculation flag.

Repeated signatures: releases 1 and 2 are made once per signature and depend
only on that signature's R and message. Many signatures under one key release
many index sets; this is the normal operation of SLH-DSA, whose security
analysis treats every signature, and so these values, as public.

## The releases

### 1. FORS and hypertree indices, signing

They are computed from H_msg(R, PK.seed, PK.root, M). R is the first n bytes
of the signature and the other inputs are public, so every verifier recomputes
them (FIPS 205 Algorithm 20, line 8): they disclose nothing beyond the
signature. SK.seed, SK.prf, opt_rand and every FORS secret and chain value not
in the signature stay secret. After the release the indices choose leaves,
auth nodes and ADRS fields.

### 2. WOTS+ digits, signing

The message is the FORS public key (layer 0) or the root of the tree signed
one layer below. The verifier recomputes both from the signature (Algorithms
17 and 11), so the digits are a function of the signature. They fix the chain
positions at which signature values are taken.

### 3. Indices, verification

On the verification API every input is public and the digest is a hash output.
On the fault check (see "Withheld signatures") R is read from the withheld
signature, where the signer wrote it, so unless a fault changed R these are
the indices of release 1.

### 4. WOTS+ digits, verification

The node is the FORS public key (layer 0) or the XMSS root (above), recomputed
from the signature; the 2n message digits give the node whole. On the
verification API the node is a function of public inputs. On the fault check
it is a function of the withheld signature: either the correct value at its
position, or after a fault a fresh hash output over withheld values. Argued
under "Withheld signatures".

### 5. The verdict

The verdict is the result of verification. The verification API returns it;
the fault check reports it as the status of the failed call.

### 6. The zero digit vector of key generation

Constant zeros; the treehash of key generation never reads it.

## Withheld signatures

Arguments 1 and 2 rest on the signature being output, and arguments 3 to 5 on
the verification inputs being public. The C layer verifies every new
signature before it releases it (`docs/API.md`, "Fault check"), and withholds
one that does not verify: after a fault during signing, or for a secret key
whose PK.root does not belong to its seeds. By then releases 1 and 2 have been
made, and the check has run the verification export on the withheld
signature, so releases 3 to 5 are of values derived from it.

`_slh_verify` types every byte of the signature secret, and the checkers
accept it only with the releases of rows 3 to 5 in its call tree. Under their
leakage model these are therefore the only functions of the withheld signature
that timing can show:

- the k FORS indices, `idx_tree` and `idx_leaf` (release 1), from the digest
  of the signature's R and the message; verification recomputes the same
  values (row 3) from the R in the signature buffer;
- the WOTS+ digits of every layer's message as signed (release 2), the faulty
  one included: after a fault in the root of layer j, the digits of that
  faulty root, which layer j + 1 signed;
- for each layer, the node that verification recomputes from the withheld
  signature (row 4): the FORS public key at layer 0, then the XMSS root of
  each layer, each revealed whole through its digits;
- the verdict (row 5), which the returned status reports anyway.

What stays hidden: the signature itself (the output buffer is zeroed before
the call returns), and with it every WOTS+ chain value, FORS secret and
authentication node it holds; SK.seed, SK.prf and opt_rand, as for a released
signature. The check runs under the same timing mode as signing, and the
registers are cleared after it.

Why releases 1 and 2 are safe: indices and digits are addresses, not values.
A released signature discloses them together with the chain values they
select; a withheld one discloses only the addresses. A forgery by tree
grafting from a withheld signature would need a WOTS+ signature of a faulty
root, that is the chain values at the positions those digits name, to combine
with a valid signature of the same WOTS+ key; the positions alone do not give
them. (Faults that leave the signature valid are not withheld and are outside
this argument; `docs/SECURITY-MODEL.md`, "Faults".)
Seeing the digits of a faulty root tells an observer which values a released
faulty signature would have contained, and nothing of the values. Repeating
faulty calls, or calls with an inconsistent key, discloses more such addresses
and still no chain value.

Why releases 3 to 5 are safe. Row 3 repeats release 1: the indices are a
function of R and the message, and R in the buffer is the signer's. Row 5 is
the status the caller receives. Row 4 releases values, not addresses, and
each node it releases is one of two kinds:

- the correct value at its position, when nothing below it was faulty: the
  FORS public key or XMSS root of that instance in the key's hypertree. It is
  what any verifier of a signature through that instance computes, and what
  release 2 shows of such a signature. SLH-DSA does not keep these values
  secret; they are the messages that the layers above sign.
- a value that differs from it, after a fault at or below its layer: an
  output of T_k (over FORS roots) or of H (at the top of an authentication
  path) whose inputs include withheld FORS secrets, withheld chain values
  carried forward from wrong positions, or nodes computed from them. Learning
  any withheld value from it needs a preimage of T_k, H, T_len or F. It is not
  a chain value and gives none, so it does not provide the WOTS+ signature
  that a grafting forgery needs. Repeated faulty calls add further outputs of
  this kind, each over the values of that call.

The same holds when a fault changes R in the buffer after signing has used
it: verification then releases the indices of H_msg over the changed R, and
nodes recomputed from withheld values under those indices, outputs of the
same kinds.

Scope of this argument: it rests on the one-wayness of the tweakable hashes
and on the layer structure above. The security proof of SLH-DSA gives the
adversary the released signatures only and does not model these additional
hash outputs. A verification whose timing does not depend on the digits,
completing every chain to its end and selecting each chain value without a
branch, would remove release 4 on the fault check at about twice the chain
evaluations of a verification; the library does not do this.
