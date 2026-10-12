#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Recompute every hash constant table from its defining rule and compare it
# with the table in the Jasmin source.
#
#   SHA-256 K           FIPS 180-4 4.2.2  cube roots of the first 64 primes, 32 bits
#   SHA-512 K           FIPS 180-4 4.2.3  cube roots of the first 80 primes, 64 bits
#   SHA-224/256 IV      FIPS 180-4 5.3.2, 5.3.3  square roots, 32 bits
#   SHA-384/512 IV      FIPS 180-4 5.3.4, 5.3.5  square roots, 64 bits
#   SHA-512/t IV        FIPS 180-4 5.3.6  SHA-512 under IV ^ 0xa5..a5 of "SHA-512/t"
#   Keccak RC           FIPS 202 3.2.5    LFSR rc(t), Algorithms 5 and 6
#
# Integer roots are exact (no floating point). The SHA-512/t generation uses
# a small SHA-512 written here from FIPS 180-4, independent of the Jasmin code.
#
# Usage: check_constants.py <src/jasmin/hash>   exit status 0 when all match.

import re
import sys


def primes(n):
    out, c = [], 2
    while len(out) < n:
        if all(c % p for p in out if p * p <= c):
            out.append(c)
        c += 1
    return out


def iroot(x, k):
    """floor(x ** (1/k)) for integers."""
    lo, hi = 0, 1 << ((x.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def frac_bits(p, k, bits):
    """First `bits` bits of the fractional part of p ** (1/k)."""
    return iroot(p << (k * bits), k) & ((1 << bits) - 1)


def frac_bits_skip(p, k, skip, bits):
    """Bits skip+1 .. skip+bits of the fractional part of p ** (1/k)."""
    return frac_bits(p, k, skip + bits) & ((1 << bits) - 1)


SHA256_K = [frac_bits(p, 3, 32) for p in primes(64)]
SHA512_K = [frac_bits(p, 3, 64) for p in primes(80)]
SHA256_IV = [frac_bits(p, 2, 32) for p in primes(8)]
SHA224_IV = [frac_bits_skip(p, 2, 32, 32) for p in primes(16)[8:]]
SHA512_IV = [frac_bits(p, 2, 64) for p in primes(8)]
SHA384_IV = [frac_bits(p, 2, 64) for p in primes(16)[8:]]

M64 = (1 << 64) - 1


def rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def sha512_with_iv(iv, msg):
    ml = len(msg)
    msg = msg + b"\x80" + b"\x00" * ((112 - ml - 1) % 128) + (8 * ml).to_bytes(16, "big")
    h = list(iv)
    for off in range(0, len(msg), 128):
        w = [int.from_bytes(msg[off + 8 * i: off + 8 * i + 8], "big") for i in range(16)]
        for t in range(16, 80):
            s0 = rotr64(w[t - 15], 1) ^ rotr64(w[t - 15], 8) ^ (w[t - 15] >> 7)
            s1 = rotr64(w[t - 2], 19) ^ rotr64(w[t - 2], 61) ^ (w[t - 2] >> 6)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & M64)
        a, b, c, d, e, f, g, hh = h
        for t in range(80):
            t1 = (hh + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41))
                  + ((e & f) ^ (~e & g)) + SHA512_K[t] + w[t]) & M64
            t2 = ((rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39))
                  + ((a & b) ^ (a & c) ^ (b & c))) & M64
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M64, c, b, a, (t1 + t2) & M64
        h = [(x + y) & M64 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return h


def sha512t_iv(t):
    iv = [x ^ 0xa5a5a5a5a5a5a5a5 for x in SHA512_IV]
    return sha512_with_iv(iv, ("SHA-512/%d" % t).encode())


def keccak_rc():
    def rc(t):
        if t % 255 == 0:
            return 1
        r = [1, 0, 0, 0, 0, 0, 0, 0]
        for _ in range(1, t % 255 + 1):
            r = [0] + r
            r[0] ^= r[8]
            r[4] ^= r[8]
            r[5] ^= r[8]
            r[6] ^= r[8]
            r = r[:8]
        return r[0]

    out = []
    for ir in range(24):
        v = 0
        for j in range(7):
            v |= rc(j + 7 * ir) << ((1 << j) - 1)
        out.append(v)
    return out


def table(src, name):
    m = re.search(r"\bu(?:32|64)\[\d+\]\s+" + re.escape(name) + r"\s*=\s*\{(.*?)\};", src, re.S)
    if not m:
        return None
    return [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]


def main():
    root = sys.argv[1]
    checks = [
        ("sha2/sha256_k.jinc", "SHA256_K", SHA256_K),
        ("sha2/sha256.jinc", "SHA256_IV", SHA256_IV),
        ("sha2/sha256.jinc", "SHA224_IV", SHA224_IV),
        ("sha2/sha512_k.jinc", "SHA512_K", SHA512_K),
        ("sha2/sha512.jinc", "SHA512_IV", SHA512_IV),
        ("sha2/sha512.jinc", "SHA384_IV", SHA384_IV),
        ("sha2/sha512.jinc", "SHA512_224_IV", sha512t_iv(224)),
        ("sha2/sha512.jinc", "SHA512_256_IV", sha512t_iv(256)),
        ("keccak/keccak_constants.jinc", "KECCAK_RC", keccak_rc()),
    ]
    bad = 0
    for path, name, want in checks:
        with open(root + "/" + path) as f:
            got = table(f.read(), name)
        ok = got == want
        bad += not ok
        print("%-4s %-26s %-14s %d entries" % ("PASS" if ok else "FAIL", path, name, len(want)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
