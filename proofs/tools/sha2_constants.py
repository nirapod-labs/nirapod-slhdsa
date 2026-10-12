# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# sha2_constants.py
#
# Re-derives the constant tables of FIPS 180-4 from their definitions and
# compares them with the tables written in spec/hash/FIPS180_SHA2.ec:
#
#     K256        section 4.2.2  first 32 fractional bits of the cube roots
#                                of the first 64 primes
#     K512        section 4.2.3  first 64 bits, first 80 primes
#     H0_256      section 5.3.3  square roots of the first 8 primes
#     H0_224      section 5.3.2  second 32 bits of the square roots of the
#                                9th to 16th primes
#     H0_512      section 5.3.5  square roots of the first 8 primes
#     H0_384      section 5.3.4  square roots of the 9th to 16th primes
#     H0_512_224  section 5.3.6  the SHA-512/t IV generation function, t = 224
#     H0_512_256  section 5.3.6  the same, t = 256
#
# Roots are computed with exact integer arithmetic. The IV generation
# function needs SHA-512, which this script implements directly from
# sections 4.1.3, 5.1.2 and 6.4; before the tables are compared, that
# implementation and the derived tables are cross-checked against Python's
# hashlib on a few messages, so an error in the derivation cannot pass
# silently.
#
# Usage: python3 sha2_constants.py spec/hash/FIPS180_SHA2.ec
# Exit status: 0 when every table matches, 1 otherwise.

import hashlib
import re
import sys


def primes(count):
    found, c = [], 2
    while len(found) < count:
        if all(c % p for p in found if p * p <= c):
            found.append(c)
        c += 1
    return found


def iroot(x, r):
    lo, hi = 0, 1
    while hi ** r <= x:
        hi *= 2
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if mid ** r <= x:
            lo = mid
        else:
            hi = mid
    return lo


def frac_bits(p, r, bits):
    """The first `bits` bits of the fractional part of p^(1/r)."""
    return iroot(p << (r * bits), r) & ((1 << bits) - 1)


K256 = [frac_bits(p, 3, 32) for p in primes(64)]
K512 = [frac_bits(p, 3, 64) for p in primes(80)]
H0_256 = [frac_bits(p, 2, 32) for p in primes(8)]
H0_512 = [frac_bits(p, 2, 64) for p in primes(8)]
H0_384 = [frac_bits(p, 2, 64) for p in primes(16)[8:]]
H0_224 = [x & 0xFFFFFFFF for x in H0_384]


def compress_rounds(msg, iv, k, w, rounds, sig, block, lenbytes):
    mask = (1 << w) - 1

    def rotr(x, n):
        return ((x >> n) | (x << (w - n))) & mask

    (b0, b1, b2), (b3, b4, b5), (s0, s1, s2), (s3, s4, s5) = sig
    bitlen = len(msg) * 8
    pad = (block - lenbytes - 1 - len(msg)) % block
    msg = msg + b"\x80" + b"\x00" * pad + bitlen.to_bytes(lenbytes, "big")
    wb = w // 8
    h = list(iv)
    for off in range(0, len(msg), block):
        W = [int.from_bytes(msg[off + wb * i: off + wb * (i + 1)], "big") for i in range(16)]
        for t in range(16, rounds):
            x, y = W[t - 15], W[t - 2]
            sg0 = rotr(x, s0) ^ rotr(x, s1) ^ (x >> s2)
            sg1 = rotr(y, s3) ^ rotr(y, s4) ^ (y >> s5)
            W.append((W[t - 16] + sg0 + W[t - 7] + sg1) & mask)
        a, b, c, d, e, f, g, hh = h
        for t in range(rounds):
            t1 = (hh + (rotr(e, b3) ^ rotr(e, b4) ^ rotr(e, b5))
                  + ((e & f) ^ (~e & g)) + k[t] + W[t]) & mask
            t2 = ((rotr(a, b0) ^ rotr(a, b1) ^ rotr(a, b2))
                  + ((a & b) ^ (a & c) ^ (b & c))) & mask
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & mask, c, b, a, (t1 + t2) & mask
        h = [(x + y) & mask for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(wb, "big") for x in h)


def sha256_with(msg, iv):
    return compress_rounds(msg, iv, K256, 32, 64, ((2, 13, 22), (6, 11, 25), (7, 18, 3), (17, 19, 10)), 64, 8)


def sha512_with(msg, iv):
    return compress_rounds(msg, iv, K512, 64, 80, ((28, 34, 39), (14, 18, 41), (1, 8, 7), (19, 61, 6)), 128, 16)


def sha512t_iv(t):
    ivp = [x ^ 0xA5A5A5A5A5A5A5A5 for x in H0_512]
    d = sha512_with(("SHA-512/%d" % t).encode(), ivp)
    return [int.from_bytes(d[8 * i: 8 * i + 8], "big") for i in range(8)]


H0_512_224 = sha512t_iv(224)
H0_512_256 = sha512t_iv(256)

TABLES = {
    "K256": K256, "K512": K512, "H0_256": H0_256, "H0_224": H0_224,
    "H0_512": H0_512, "H0_384": H0_384, "H0_512_224": H0_512_224, "H0_512_256": H0_512_256,
}


def self_check():
    for m in (b"", b"abc", bytes(range(256)) * 3):
        assert sha256_with(m, H0_256) == hashlib.sha256(m).digest()
        assert sha256_with(m, H0_224)[:28] == hashlib.sha224(m).digest()
        assert sha512_with(m, H0_512) == hashlib.sha512(m).digest()
        assert sha512_with(m, H0_384)[:48] == hashlib.sha384(m).digest()
        assert sha512_with(m, H0_512_224)[:28] == hashlib.new("sha512_224", m).digest()
        assert sha512_with(m, H0_512_256)[:32] == hashlib.new("sha512_256", m).digest()


def main(path):
    self_check()
    with open(path, encoding="utf-8") as f:
        src = f.read()
    ok = True
    for name, expected in TABLES.items():
        m = re.search(r"op %s : W\d+\.t list = map W\d+\.of_int \[(.*?)\]\." % name, src, re.S)
        if m is None:
            print("%s: table not found" % name)
            ok = False
            continue
        found = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]
        same = found == expected
        print("%s: %d words, %s" % (name, len(found), "match" if same else "MISMATCH"))
        ok = ok and same
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
