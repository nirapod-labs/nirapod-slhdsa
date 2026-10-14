# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/core/fill-check.py
# ========================
#
# The source trees of the fill check (`make fill-check`) and of its
# negative controls (`make fill-check-controls`).
#
# A few buffers of the SLH-DSA core are written at constant indices before
# their first use, only so that jasmin-checksafety, which does not count a
# write at a run-time index as initialising, can follow them. Each such
# fill stores the register `fill` after `fill = 0;`; that is the one form
# a fill may take, and the one this script rewrites and counts. The code's
# own invariant is stronger: every byte of the buffer is written by the
# algorithm before it is read, so the value of the fill never reaches an
# output.
#
#   prepare SRC DST
#       copy the Jasmin sources and replace each `fill = 0;` with
#       `fill = 0xa5a5a5a5a5a5a5a5;`. The Makefile builds the library from
#       the copy and runs the ACVP known answers and the core tests on it:
#       code that reads a byte the algorithm has not written, and depends on
#       its value, sees 0xa5 instead of 0 and changes a key or signature.
#   controls SRC WORK TARGET SUBSET
#       for each site, prepare a copy with one more change that makes the
#       code depend on the fill value at that site and on nothing else
#       (CONTROLS): a store that XORs into the buffer instead of writing
#       it, or a read of a slot the algorithm never writes. With zero fills
#       such a copy computes the same keys and signatures; with 0xa5 fills
#       it must not. Each copy is built with make (BUILD=WORK/<site>/build,
#       JASMIN_SRC=WORK/<site>/src) and its known-answer test, the build's
#       TARGET/tests/test_acvp on SUBSET, must fail. A control that builds
#       but passes, or does not build, fails the script. FILL_JOBS in the
#       environment sets the parallel jobs of each build (default 1).
#
# SITES lists every file of the core (src/slhdsa) with a fill and how many
# it holds. A file whose count differs, a constant-index zero store in a
# core file that does not go through `fill`, or a control whose change
# matches no text, fails the script before anything is built. The hash
# layer (src/hash) is copied unchanged and not scanned: `fill` there is a
# buffer's fill level, and its own safety fills are checked by
# tests/hash/tools/fill_check.sh.
#
# Usage: python3 -I tests/core/fill-check.py prepare <jasmin src> <copy dir>
#        python3 -I tests/core/fill-check.py controls <jasmin src> <work dir> <target> <subset>
# prepare prints "fill-check: sites=N" (ci/rules/test-core.toml holds it to a
# count); controls prints one DETECTED or MISSED line per site, then
# "fill-check controls: detected=N of M".

import os
import re
import shutil
import subprocess
import sys

ZERO = "fill = 0;"
FILL = "fill = 0xa5a5a5a5a5a5a5a5;"

SITES = {
    "slhdsa/wots.jinc": 2,      # pk in _wots_leaf_x4, tmp in _wots_pk_from_sig
    "slhdsa/xmss.jinc": 1,      # nodes in _xmss_treehash
    "slhdsa/fors.jinc": 1,      # roots in _fors_pk_from_sig
}

# A constant-index zero store written without the `fill` register.
BARE = re.compile(r"\[:u64 [a-z]\] = 0;")

NODE_XOR = """
/* Fill-check control only (tests/core/fill-check.py): dst ^= src. */
inline fn __node_xor(reg mut ptr u8[SLH_N] dst, reg const ptr u8[SLH_N] src) -> reg ptr u8[SLH_N]
{
  reg u64 t u;
  inline int i;

  for i = 0 to SLH_N / 8 {
    t = src[:u64 i];
    u = dst[:u64 i];
    t ^= u;
    dst[:u64 i] = t;
  }

  return dst;
}
"""

# site: [(file, text, replacement)]; each text must occur exactly once.
CONTROLS = {
    "pk": [("slhdsa/wots.jinc",
            "        t = cur[:u64 SLH_N / 8 * k + w];\n        dst.[:u64 off] = t;\n",
            "        t = cur[:u64 SLH_N / 8 * k + w];\n        src = dst.[:u64 off];\n"
            "        t ^= src;\n        dst.[:u64 off] = t;\n")],
    "tmp": [("slhdsa/wots.jinc",
             "    dst[off : SLH_N] = __node_copy(dst[off : SLH_N], cur);\n",
             "    dst[off : SLH_N] = __node_xor(dst[off : SLH_N], cur);\n")],
    "roots": [("slhdsa/fors.jinc",
               "    dst[root_off : SLH_N] = __node_copy(dst[root_off : SLH_N], node);\n",
               "    dst[root_off : SLH_N] = __node_xor(dst[root_off : SLH_N], node);\n")],
    # Slot h' + 1 exists (a > h') and the fold never parks a node there.
    "nodes": [("slhdsa/xmss.jinc",
               "  root = __node_copy(root, nodes[SLH_HP * SLH_N : SLH_N]);\n",
               "  root = __node_copy(root, nodes[SLH_HP * SLH_N : SLH_N]);\n"
               "  root = __node_xor(root, nodes[(SLH_HP + 1) * SLH_N : SLH_N]);\n")],
}


class Failure(Exception):
    pass


def prepare(src, dst, control=None):
    """Copy src to dst with the fills rewritten (and one control applied)."""
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    errors, sites = [], 0
    for root, _, files in os.walk(os.path.join(dst, "slhdsa")):
        for name in files:
            if not name.endswith(".jinc"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, dst).replace(os.sep, "/")
            with open(path) as f:
                text = f.read()
            for n, line in enumerate(text.splitlines(), 1):
                if BARE.search(line):
                    errors.append(f"{rel}:{n}: a zero store not written through `fill`")
            n = text.count(ZERO)
            if n != SITES.get(rel, 0):
                errors.append(f"{rel}: {n} sites of '{ZERO}', expected {SITES.get(rel, 0)}")
                continue
            if n:
                with open(path, "w") as f:
                    f.write(text.replace(ZERO, FILL))
                sites += n
    errors += [f"{rel}: listed but absent" for rel in SITES
               if not os.path.isfile(os.path.join(dst, rel))]
    if control is not None:
        for rel, old, new in CONTROLS[control]:
            path = os.path.join(dst, rel)
            with open(path) as f:
                text = f.read()
            if text.count(old) != 1:
                errors.append(f"control {control}: {rel}: change matches {text.count(old)} places")
                continue
            with open(path, "w") as f:
                f.write(text.replace(old, new))
        with open(os.path.join(dst, "slhdsa", "encoding.jinc"), "a") as f:
            f.write(NODE_XOR)
    if errors:
        raise Failure("; ".join(errors))
    return sites


def controls(src, work, target, subset):
    make = os.environ.get("MAKE", "make")
    missed = []
    for name in CONTROLS:
        base = os.path.abspath(os.path.join(work, name))
        prepare(src, os.path.join(base, "src"), name)
        test = os.path.join(base, "build", target, "tests", "test_acvp")
        jobs = f"-j{int(os.environ.get('FILL_JOBS', '1'))}"
        b = subprocess.run([make, "--no-print-directory", jobs, f"BUILD={base}/build",
                            f"JASMIN_SRC={base}/src", test], capture_output=True, text=True)
        if b.returncode != 0:
            raise Failure(f"control {name}: build failed: {b.stdout[-300:]}{b.stderr[-300:]}")
        r = subprocess.run([test, subset], capture_output=True, text=True)
        failed = r.returncode != 0 and "FAIL" in r.stdout + r.stderr
        print(f"fill-check control {name}: {'DETECTED' if failed else 'MISSED'} "
              f"(test_acvp exit {r.returncode})")
        if not failed:
            missed.append(name)
    print(f"fill-check controls: detected={len(CONTROLS) - len(missed)} of {len(CONTROLS)}")
    print(f"fill-check controls: {'PASS' if not missed else 'FAIL ' + ','.join(missed)}")
    return 1 if missed else 0


def main(argv):
    try:
        if len(argv) == 4 and argv[1] == "prepare":
            print(f"fill-check: sites={prepare(argv[2], argv[3])}")
            return 0
        if len(argv) == 6 and argv[1] == "controls":
            return controls(*argv[2:])
    except Failure as e:
        print(f"fill-check: {e}", file=sys.stderr)
        return 1
    print("usage: fill-check.py prepare <jasmin src> <copy dir>\n"
          "       fill-check.py controls <jasmin src> <work dir> <target> <subset>",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
