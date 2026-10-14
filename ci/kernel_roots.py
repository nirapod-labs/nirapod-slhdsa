# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/kernel_roots.py
# ==================
#
# Usage: python3 -I ci/kernel_roots.py
#
# The proof models against the library build. A correctness proof of a
# kernel is about the model extracted under the kernel roots of its pair
# (proofs/Makefile, EXTRACTIONS); it says something about the library only
# while the library compiles that variant under the same roots. This check
# ties the two:
#
#   - `make kernel-roots` (top-level Makefile) prints the include roots of
#     every unit, for each target in TARGETS;
#   - every variant a target builds is either bound to a pair
#     (LIBRARY_PAIRS) or listed as having no model (LIBRARY_UNMODELLED),
#     and no entry of either names a variant the library does not build;
#   - the units of one variant are compiled under the same roots, whatever
#     the parameter set;
#   - a bound pair is in EXTRACTIONS, is of the variant's architecture, and
#     its roots equal the library's for every root extraction sets (ROLES).
#
# A failure names the variant and the root that differ. Needs make and the
# tree only, no toolchain (ci/source.py runs it).

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry  # noqa: E402

# The library's targets, as GEN_ARCH and GEN_SYSTEM of the top-level
# Makefile (its GEN_TARGETS).
TARGETS = [("x86_64", "Linux"), ("aarch64", "Linux"), ("aarch64", "Darwin")]

# The roots proofs/tools/extract.sh sets for a hash model, with the
# EXTRACTIONS field each kernel role comes from. Hash and HashWord are not
# fields: extraction always uses the hash tree and the pair's architecture.
KERNEL_FIELDS = {"KeccakKernel": 2, "KeccakKernelX": 3, "Sha2Kernel": 4, "Sha2KernelX": 5}
ROLES = ["Hash", "HashWord"] + list(KERNEL_FIELDS)

HASH_SRC = "src/hash"


def clean_env():
    """The environment without the variables a calling make passes down."""
    env = dict(os.environ)
    for v in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"):
        env.pop(v, None)
    return env


def make(args, root):
    out = subprocess.run(["make", "-s", "--no-print-directory", "-C", root] + args,
                         capture_output=True, text=True, env=clean_env())
    if out.returncode != 0:
        raise RuntimeError(f"make {' '.join(args)}: {out.stderr.strip() or 'failed'}")
    return out.stdout


def parse_units(text):
    """{(arch, variant): {set: {root: dir}}} from `make kernel-roots`."""
    units = {}
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        if len(words) < 2 or (len(words) - 2) % 2:
            raise ValueError(f"kernel-roots: malformed line '{line}'")
        arch, unit = words[0], words[1]
        if unit.count("-") != 1:
            raise ValueError(f"kernel-roots: unit '{unit}' is not <set>-<variant>")
        pset, variant = unit.split("-")
        roots = {}
        for flag, arg in zip(words[2::2], words[3::2]):
            role, eq, path = arg.partition("=")
            if flag != "-I" or not eq:
                raise ValueError(f"kernel-roots: malformed include '{flag} {arg}'")
            roots[role] = path
        units.setdefault((arch, variant), {})[pset] = roots
    return units


def parse_pairs(text):
    """(extractions {pair: fields}, pairs {arch/variant: pair}, unmodelled [arch/variant])"""
    got = {}
    for line in text.splitlines():
        name, _, rest = line.partition(" ")
        got[name] = rest.split()
    if sorted(got) != ["extractions", "pairs", "unmodelled"]:
        raise ValueError(f"print-library-pairs: expected extractions, pairs, unmodelled; got {sorted(got)}")
    extractions = {}
    for e in got["extractions"]:
        fields = e.split(":")
        if len(fields) != 6:
            raise ValueError(f"EXTRACTIONS entry '{e}' has {len(fields)} fields, expected 6")
        extractions[fields[0]] = fields
    pairs = {}
    for b in got["pairs"]:
        variant, eq, pair = b.partition("=")
        if not eq or variant.count("/") != 1 or variant in pairs:
            raise ValueError(f"LIBRARY_PAIRS entry '{b}' is not a new <arch>/<variant>=<pair>")
        pairs[variant] = pair
    return extractions, pairs, got["unmodelled"]


def pair_roots(fields):
    """The roots extraction compiles a pair's hash model under."""
    arch = fields[0].split("/")[0]
    roots = {"Hash": HASH_SRC, "HashWord": f"{HASH_SRC}/{arch}"}
    for role, i in KERNEL_FIELDS.items():
        roots[role] = f"{HASH_SRC}/{fields[i]}"
    return roots


def errors(units, extractions, pairs, unmodelled):
    errs = []
    built = {}
    for (arch, variant), sets in sorted(units.items()):
        name = f"{arch}/{variant}"
        distinct = {tuple(sorted(r.items())) for r in sets.values()}
        if len(distinct) != 1:
            errs.append(f"{name}: the parameter sets are compiled under different roots")
        built[name] = sets[sorted(sets)[0]]
    for name in sorted(set(built) - set(pairs) - set(unmodelled)):
        errs.append(f"{name}: built by the library, neither in LIBRARY_PAIRS nor in LIBRARY_UNMODELLED")
    for name in sorted(set(pairs) & set(unmodelled)):
        errs.append(f"{name}: both in LIBRARY_PAIRS and in LIBRARY_UNMODELLED")
    for name in sorted((set(pairs) | set(unmodelled)) - set(built)):
        errs.append(f"{name}: listed in proofs/Makefile, not built by the library")
    for name, pair in sorted(pairs.items()):
        if name not in built:
            continue
        if pair not in extractions:
            errs.append(f"{name}: bound to {pair}, which is not in EXTRACTIONS")
            continue
        if pair.split("/")[0] != name.split("/")[0]:
            errs.append(f"{name}: bound to {pair}, a pair of another architecture")
            continue
        want = pair_roots(extractions[pair])
        for role in ROLES:
            lib = built[name].get(role)
            if lib != want[role]:
                errs.append(f"{name}: the library compiles {role}={lib}, "
                            f"the model {pair} is extracted with {role}={want[role]}")
    return errs


def main(argv):
    if len(argv) != 1:
        print("usage: kernel_roots.py", file=sys.stderr)
        return 2
    try:
        units = {}
        for arch, system in TARGETS:
            got = parse_units(make(["kernel-roots", f"GEN_ARCH={arch}", f"GEN_SYSTEM={system}"],
                                   registry.ROOT))
            if not got or {a for a, _ in got} != {arch}:
                raise ValueError(f"kernel-roots for {arch}-{system}: no unit of {arch}")
            for k, sets in got.items():
                if k in units and units[k] != sets:
                    raise ValueError(f"{k[0]}/{k[1]}: the roots differ between systems")
                units[k] = sets
        extractions, pairs, unmodelled = parse_pairs(
            make(["print-library-pairs"], os.path.join(registry.ROOT, "proofs")))
    except (RuntimeError, ValueError) as e:
        print(f"kernel-roots: FAIL: {e}")
        return 1
    errs = errors(units, extractions, pairs, unmodelled)
    for e in errs:
        print(f"kernel-roots: FAIL: {e}")
    if errs:
        return 1
    print(f"kernel-roots: PASS ({len(units)} library variants, {len(pairs)} modelled)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
