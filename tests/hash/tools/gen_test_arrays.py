#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Generate tests/hash/jasmin/test_arrays.jinc: the test exports for the
# fixed-length array forms of the hash primitives and for MGF1.
#
# Jasmin fixes array lengths at compile time, so every tested length needs
# its own namespace instance and its own exports. The exports differ only in
# the length and the primitive, which is why they are generated rather than
# written by hand. Each export copies between C memory and stack arrays,
# protects its arguments (export arguments are only transient under the
# speculative model) and calls one primitive.
#
# Usage (from the repository root):
#
#     python3 -I tests/hash/tools/gen_test_arrays.py > tests/hash/jasmin/test_arrays.jinc
#
# The output depends only on this script. The `generated` target of
# tests/hash/Makefile regenerates it and fails if the committed file differs.

import sys

LENGTHS = [1, 7, 16, 22, 32, 64, 65, 129, 200]

# (hash width, seed length, output length): the six FIPS 205 MGF1 shapes,
# seed = R || PK.seed || digest (2n + 32 or 2n + 64), output m (Table 2).
MGF1 = [("256", 64, 30), ("256", 64, 34), ("512", 112, 39),
        ("512", 112, 42), ("512", 128, 47), ("512", 128, 49)]

HEADER = """\
/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * GENERATED FILE. DO NOT EDIT.
 *
 * Generator:   tests/hash/tools/gen_test_arrays.py
 * Regenerate:  python3 -I tests/hash/tools/gen_test_arrays.py > tests/hash/jasmin/test_arrays.jinc
 *
 * Test exports for the fixed-length array forms: one namespace per tested
 * length (%s), instantiating the array files of the
 * single-way and multi-way hash primitives and the test copy helpers, and
 * the MGF1 instances at the FIPS 205 sizes. Every export protects its
 * arguments before use.
 */
"""


def protect(names):
    return "".join("  %s = #protect(%s, ms);\n" % (n, n) for n in names)


def copy_in(var, nbytes, src):
    w, r = divmod(nbytes, 8)
    s = "  for i = 0 to %d {\n    t = [:u64 %s + 8 * i];\n    %s[:u64 i] = t;\n  }\n" % (w, src, var)
    if r:
        s += ("  for i = %d to %d {\n    t = (64u)[:u8 %s + i];\n    %s[i] = (8u)t;\n  }\n"
              % (8 * w, nbytes, src, var))
    return s


def copy_out(var, nbytes, dst):
    assert nbytes % 8 == 0
    return "  for i = 0 to %d {\n    t = %s[:u64 i];\n    [:u64 %s + 8 * i] = t;\n  }\n" % (
        nbytes // 8, var, dst)


def state_load(n, p):
    return "  for i = 0 to %d {\n    t = [:u64 %s + 8 * i];\n    st[i] = t;\n  }\n" % (n, p)


def state_store(n, p):
    return "  for i = 0 to %d {\n    t = st[i];\n    [:u64 %s + 8 * i] = t;\n  }\n" % (n, p)


def requires():
    s = 'from Hash require "keccak/sponge.jinc"\n'
    s += 'from Hash require "keccak/sponge_x4.jinc"\n'
    s += 'from Hash require "sha2/sha256.jinc"\nfrom Hash require "sha2/sha512.jinc"\n'
    s += 'from Hash require "sha2/sha256_x8.jinc"\nfrom Hash require "sha2/sha512_x4.jinc"\n'
    return s


def namespace(L):
    files = ["keccak/sponge_array.jinc"]
    files.append("keccak/sponge_x4_array.jinc")
    files += ["sha2/sha256_array.jinc", "sha2/sha512_array.jinc"]
    files += ["sha2/sha256_x8_array.jinc", "sha2/sha512_x4_array.jinc"]
    body = "".join('  from Hash require "%s"\n' % f for f in files)
    return "\nnamespace A%d {\n  param int HASH_ARRAY_LEN = %d;\n%s  require \"array_io.jinc\"\n}\n" % (
        L, L, body)


def keccak_single(L):
    return """
#[ct = "public × public × public × public -> public"]
export fn nirapod_slhdsa_hashtest_keccak_absorb_array_{L}(reg u64 p pos rate in) -> reg u64
{{
  stack u64[25] st;
  stack u8[{L}] buf;
  reg u64 ms t;
  inline int i;

  ms = #init_msf();
{prot}{load}  buf = A{L}::__array_load(buf, in);
  () = #spill(p);
  st, pos, ms = A{L}::_keccak_absorb_array(st, pos, rate, buf, ms);
  () = #unspill(p);
  p = #protect(p, ms);
{store}  return pos;
}}

#[ct = "public × public × public × public -> public"]
export fn nirapod_slhdsa_hashtest_keccak_squeeze_array_{L}(reg u64 out p pos rate) -> reg u64
{{
  stack u64[25] st;
  stack u8[{L}] buf;
  reg u64 ms t;
  inline int i;

  ms = #init_msf();
{prot2}{load}  () = #spill(out, p);
  buf, st, pos, ms = A{L}::_keccak_squeeze_array(buf, st, pos, rate, ms);
  () = #unspill(out, p);
  out = #protect(out, ms);
  p = #protect(p, ms);
{store}  A{L}::__array_store(out, buf);
  return pos;
}}
""".format(L=L, prot=protect(["p", "pos", "rate", "in"]), prot2=protect(["out", "p", "pos", "rate"]),
           load=state_load(25, "p"), store=state_store(25, "p"))


def sha2_single(L, w):
    ty, word, bl = ("u32", 4, 64) if w == "256" else ("u64", 8, 128)
    hload = "  for i = 0 to 8 {\n    x = [:%s hp + %d * i];\n    h[i] = x;\n  }\n" % (ty, word)
    hstore = "  for i = 0 to 8 {\n    x = h[i];\n    [:%s hp + %d * i] = x;\n  }\n" % (ty, word)
    return """
#[ct = "public × public × public × public -> public"]
export fn nirapod_slhdsa_hashtest_sha{w}_absorb_array_{L}(reg u64 hp bp total in) -> reg u64
{{
  stack {ty}[8] h;
  stack u8[{bl}] blk;
  stack u8[{L}] buf;
  reg u64 ms t;
  reg {ty} x;
  inline int i;

  ms = #init_msf();
{prot}{hload}{bload}  buf = A{L}::__array_load(buf, in);
  () = #spill(hp, bp);
  h, blk, total, ms = A{L}::_sha{w}_absorb_array(h, blk, total, buf, ms);
  () = #unspill(hp, bp);
  hp = #protect(hp, ms);
  bp = #protect(bp, ms);
{hstore}{bstore}  return total;
}}
""".format(L=L, w=w, ty=ty, bl=bl, prot=protect(["hp", "bp", "total", "in"]), hload=hload,
           hstore=hstore, bload=copy_in("blk", bl, "bp"), bstore=copy_out("blk", bl, "bp"))


X4_HELPERS = """
inline fn __x4_state_load(reg mut ptr u64[100] st, reg u64 p) -> reg ptr u64[100]
{
  reg u64 t;
  inline int i;

  for i = 0 to 100 {
    t = [:u64 p + 8 * i];
    st[i] = t;
  }
  return st;
}

inline fn __x4_state_store(reg u64 p, reg const ptr u64[100] st)
{
  reg u64 t;
  inline int i;

  for i = 0 to 100 {
    t = st[i];
    [:u64 p + 8 * i] = t;
  }
}

#[ct = "public -> ()"]
export fn nirapod_slhdsa_hashtest_keccakf1600_x4(reg u64 p)
{
  stack u64[100] st;
  reg u64 ms;

  ms = #init_msf();
  p = #protect(p, ms);
  st = __x4_state_load(st, p);
  () = #spill(p);
  st, ms = _keccakf1600_x4(st, ms);
  () = #unspill(p);
  p = #protect(p, ms);
  __x4_state_store(p, st);
}

#[ct = "public × public × public × public -> ()"]
export fn nirapod_slhdsa_hashtest_keccak_x4_finalize(reg u64 p pos rate ds)
{
  stack u64[100] st;
  reg u64 ms;

  ms = #init_msf();
  p = #protect(p, ms);
  pos = #protect(pos, ms);
  rate = #protect(rate, ms);
  ds = #protect(ds, ms);
  st = __x4_state_load(st, p);
  () = #spill(p);
  st, ms = _keccak_x4_finalize(st, pos, rate, ds, ms);
  () = #unspill(p);
  p = #protect(p, ms);
  __x4_state_store(p, st);
}
"""


def keccak_x4(L):
    return """
/* in and out hold the four instances' arrays back to back, {L} bytes each. */
#[ct = "public × public × public × public -> public"]
export fn nirapod_slhdsa_hashtest_keccak_x4_absorb_array_{L}(reg u64 p pos rate in) -> reg u64
{{
  stack u64[100] st;
  stack u8[{L}] a0 a1 a2 a3;
  reg u64 ms;

  ms = #init_msf();
{prot}  st = __x4_state_load(st, p);
  a0 = A{L}::__array_load(a0, in);
  in += {L};
  a1 = A{L}::__array_load(a1, in);
  in += {L};
  a2 = A{L}::__array_load(a2, in);
  in += {L};
  a3 = A{L}::__array_load(a3, in);
  () = #spill(p);
  st, pos, ms = A{L}::_keccak_x4_absorb_array(st, pos, rate, a0, a1, a2, a3, ms);
  () = #unspill(p);
  p = #protect(p, ms);
  __x4_state_store(p, st);
  return pos;
}}

#[ct = "public × public × public × public -> public"]
export fn nirapod_slhdsa_hashtest_keccak_x4_squeeze_array_{L}(reg u64 out p pos rate) -> reg u64
{{
  stack u64[100] st;
  stack u8[{L}] a0 a1 a2 a3;
  reg u64 ms;

  ms = #init_msf();
{prot2}  st = __x4_state_load(st, p);
  () = #spill(out, p);
  a0, a1, a2, a3, st, pos, ms = A{L}::_keccak_x4_squeeze_array(a0, a1, a2, a3, st, pos, rate, ms);
  () = #unspill(out, p);
  out = #protect(out, ms);
  p = #protect(p, ms);
  __x4_state_store(p, st);
  A{L}::__array_store(out, a0);
  out += {L};
  A{L}::__array_store(out, a1);
  out += {L};
  A{L}::__array_store(out, a2);
  out += {L};
  A{L}::__array_store(out, a3);
  return pos;
}}
""".format(L=L, prot=protect(["p", "pos", "rate", "in"]), prot2=protect(["out", "p", "pos", "rate"]))


def sha2_multi_fixed(w):
    n, ty, hl, bl, dl, word = (8, "u32", 64, 64, 32, 4) if w == "256" else (4, "u64", 32, 128, 64, 8)
    x = "x8" if w == "256" else "x4"
    nm = "sha%s_%s" % (w, x)
    inits = ["sha256", "sha224"] if w == "256" else ["sha512", "sha384", "sha512_224", "sha512_256"]
    hload = "  for i = 0 to %d {\n    x = [:%s hp + %d * i];\n    h[i] = x;\n  }\n" % (hl, ty, word)
    hstore = "  for i = 0 to %d {\n    x = h[i];\n    [:%s hp + %d * i] = x;\n  }\n" % (hl, ty, word)
    s = ""
    for iv in inits:
        s += """
#[ct = "public -> ()"]
export fn nirapod_slhdsa_hashtest_{iv}_{x}_init(reg u64 hp)
{{
  stack {ty}[{hl}] h;
  reg {ty} x;
  reg u64 ms;
  inline int i;

  ms = #init_msf();
  hp = #protect(hp, ms);
  h = __{iv}_{x}_init(h);
{hstore}}}
""".format(iv=iv, x=x, ty=ty, hl=hl, hstore=hstore)
    s += """
#[ct = "public × public -> ()"]
export fn nirapod_slhdsa_hashtest_{nm}_compress(reg u64 hp bp)
{{
  stack {ty}[{hl}] h;
  stack u8[{nb}] blocks;
  reg {ty} x;
  reg u64 ms t;
  inline int i;

  ms = #init_msf();
  hp = #protect(hp, ms);
  bp = #protect(bp, ms);
{hload}{bload}  () = #spill(hp);
  h, ms = _{nm}_compress(h, blocks, ms);
  () = #unspill(hp);
  hp = #protect(hp, ms);
{hstore}}}

#[ct = "public × public × public × public -> ()"]
export fn nirapod_slhdsa_hashtest_{nm}_finalize(reg u64 out hp bp total)
{{
  stack {ty}[{hl}] h;
  stack u8[{nb}] buf;
  stack u8[{nd}] d;
  reg {ty} x;
  reg u64 ms t;
  inline int i;

  ms = #init_msf();
{prot}{hload}{bufload}  () = #spill(out, hp, bp);
  d, h, buf, ms = _{nm}_finalize(d, h, buf, total, ms);
  () = #unspill(out, hp, bp);
  out = #protect(out, ms);
  hp = #protect(hp, ms);
  bp = #protect(bp, ms);
{hstore}{bufstore}{dstore}}}
""".format(nm=nm, ty=ty, hl=hl, nb=n * bl, nd=n * dl, hload=hload, hstore=hstore,
           bload=copy_in("blocks", n * bl, "bp"), bufload=copy_in("buf", n * bl, "bp"),
           bufstore=copy_out("buf", n * bl, "bp"), dstore=copy_out("d", n * dl, "out"),
           prot=protect(["out", "hp", "bp", "total"]))
    return s


def sha2_multi(L, w):
    n, ty, hl, bl, word = (8, "u32", 64, 64, 4) if w == "256" else (4, "u64", 32, 128, 8)
    x = "x8" if w == "256" else "x4"
    nm = "sha%s_%s" % (w, x)
    hload = "  for i = 0 to %d {\n    x = [:%s hp + %d * i];\n    h[i] = x;\n  }\n" % (hl, ty, word)
    hstore = "  for i = 0 to %d {\n    x = h[i];\n    [:%s hp + %d * i] = x;\n  }\n" % (hl, ty, word)
    return """
/* in holds the {n} instances' {L}-byte arrays back to back. */
#[ct = "public × public × public × public -> public"]
export fn nirapod_slhdsa_hashtest_{nm}_absorb_array_{L}(reg u64 hp bp total in) -> reg u64
{{
  stack {ty}[{hl}] h;
  stack u8[{nb}] buf;
  stack u8[{na}] a;
  reg {ty} x;
  reg u64 ms t;
  inline int i;

  ms = #init_msf();
{prot}{hload}{bufload}{aload}  () = #spill(hp, bp);
  h, buf, total, ms = A{L}::_{nm}_absorb_array(h, buf, total, a, ms);
  () = #unspill(hp, bp);
  hp = #protect(hp, ms);
  bp = #protect(bp, ms);
{hstore}{bufstore}  return total;
}}
""".format(L=L, n=n, nm=nm, ty=ty, hl=hl, nb=n * bl, na=n * L, hload=hload, hstore=hstore,
           bufload=copy_in("buf", n * bl, "bp"), aload=copy_in("a", n * L, "in"),
           bufstore=copy_out("buf", n * bl, "bp"), prot=protect(["hp", "bp", "total", "in"]))


def mgf1(w, S, O):
    return """
namespace M{w}_{S}_{O} {{
  param int MGF1_SEED_LEN = {S};
  param int MGF1_OUT_LEN = {O};
  from Hash require "sha2/mgf1.jinc"
}}

namespace S{w}_{S}_{O} {{
  param int HASH_ARRAY_LEN = {S};
  require "array_io.jinc"
}}

namespace O{w}_{S}_{O} {{
  param int HASH_ARRAY_LEN = {O};
  require "array_io.jinc"
}}

#[ct = "public × public -> ()"]
export fn nirapod_slhdsa_hashtest_mgf1_sha{w}_{S}_{O}(reg u64 out seed)
{{
  stack u8[{S}] s;
  stack u8[{O}] o;
  reg u64 ms;

  ms = #init_msf();
  out = #protect(out, ms);
  seed = #protect(seed, ms);
  s = S{w}_{S}_{O}::__array_load(s, seed);
  () = #spill(out);
  o, ms = M{w}_{S}_{O}::_mgf1_sha{w}(o, s, ms);
  () = #unspill(out);
  out = #protect(out, ms);
  O{w}_{S}_{O}::__array_store(out, o);
}}
""".format(w=w, S=S, O=O)


def main():
    out = [HEADER % ", ".join(map(str, LENGTHS)), requires()]
    for L in LENGTHS:
        out.append(namespace(L))
    for L in LENGTHS:
        out.append(keccak_single(L))
        out.append(sha2_single(L, "256"))
        out.append(sha2_single(L, "512"))
    out.append(X4_HELPERS)
    for L in LENGTHS:
        out.append(keccak_x4(L))
    out.append(sha2_multi_fixed("256"))
    out.append(sha2_multi_fixed("512"))
    for L in LENGTHS:
        out.append(sha2_multi(L, "256"))
        out.append(sha2_multi(L, "512"))
    for w, S, O in MGF1:
        out.append(mgf1(w, S, O))
    sys.stdout.write("".join(out))


if __name__ == "__main__":
    main()
