# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/source.py
# ==================
#
# Usage: python3 -I tools/ci/source.py
#
# The checks that need no toolchain, run first on every event (the job
# `source` of ci.yml):
#
#   components   every directory accounted for, required components
#                present, every hash kernel variant selected by a kernel set
#                (tools/ci/components.py)
#   recipes      every check of the registry has its recipe; every recipe
#                and rules file belongs to a check; a recipe includes
#                tools/ci/mk/common.mk and nothing else, and names no other
#                check's recipe or rules: so a recipe or a rules file is an
#                input of its own check alone (tools/ci/key.py)
#   shards       proofs/Makefile's shards are the registry's, and every
#                EasyCrypt file under proofs/ and third_party/ is checked
#                by exactly one shard, except the shared correctness
#                proofs, which every pair shard checks once
#   hash         tests/hash: the constant tables against their definitions,
#                the generated test sources current
#   proofs       the proof-hole scan, the FIPS 180-4 constants, the
#                inventory files against the extracted pairs
#
# Every check runs; the script fails at the end if any failed.

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import components  # noqa: E402
import key  # noqa: E402
import registry  # noqa: E402

INCLUDE = "include tools/ci/mk/common.mk"


def recipe_errors(reg, files):
    errors = []
    recipes = {f[len(key.RECIPES):-3] for f in files
               if f.startswith(key.RECIPES) and f.endswith(".mk") and f.count("/") == 3}
    rules = {f[len(key.RULES):-5] for f in files
             if f.startswith(key.RULES) and f.endswith(".toml")}
    used = {c["recipe"] for c in reg["checks"].values()}
    errors += [f"check recipe tools/ci/checks/{r}.mk is missing" for r in sorted(used - recipes)]
    errors += [f"tools/ci/checks/{r}.mk is the recipe of no check" for r in sorted(recipes - used)]
    errors += [f"tools/ci/rules/{r}.toml belongs to no check" for r in sorted(rules - set(reg["checks"]))]
    for f in sorted(files):
        inside = f.startswith(key.RECIPES) or f == "tools/ci/mk/common.mk"
        if not inside or not f.endswith(".mk"):
            continue
        with open(f, encoding="utf-8") as fh:
            text = fh.read()
        includes = [l.strip() for l in text.splitlines()
                    if re.match(r"^\s*-?(include|sinclude)\s", l)]
        want = [] if f == "tools/ci/mk/common.mk" else [INCLUDE]
        if includes != want:
            errors.append(f"{f}: includes {includes or 'nothing'}, expected {want or 'nothing'}")
        for ref in re.findall(r"tools/ci/(?:checks|rules)/[A-Za-z0-9_.-]+", text):
            if f.startswith(key.RECIPES) and ref not in (f,):
                errors.append(f"{f}: names {ref}, another check's file")
    return errors


def shard_errors(reg, files):
    errors = []
    shards = [c["shard"] for c in reg["checks"].values() if c["recipe"] == "proofs"]
    out = subprocess.run(["make", "-s", "-C", "proofs", "list-shards"], capture_output=True,
                         text=True)
    listed = out.stdout.split()
    if out.returncode != 0 or sorted(listed) != sorted(shards):
        errors.append(f"proofs/Makefile lists shards {listed}, the registry {shards}")
    out = subprocess.run(["make", "-s", "-C", "proofs", "shard-files"], capture_output=True,
                         text=True)
    if out.returncode != 0:
        return errors + [f"make -C proofs shard-files: {out.stderr.strip()}"]
    where = {}
    for line in out.stdout.splitlines():
        shard, _, path = line.partition(" ")
        if shard not in shards:
            errors.append(f"shard-files names an unknown shard '{shard}'")
        where.setdefault(path, []).append(shard)
    archs = sorted({p["arch"] for p in reg["platforms"].values()})
    pair_shards = [s for s in shards if s in archs]
    proof_files = [f for f in files if f.endswith((".ec", ".eca"))
                   and f.startswith(("proofs/", "third_party/"))]
    for f in sorted(proof_files):
        got = sorted(where.get(f, []))
        shared = f.startswith("proofs/correctness/") and not set(f.split("/")) & set(archs)
        want = sorted(pair_shards) if shared else None
        if shared and got != want:
            errors.append(f"{f}: a shared correctness proof, checked by {got or 'no shard'}, "
                          f"expected once by each of {want}")
        elif not shared and len(got) != 1:
            errors.append(f"{f}: checked by {got or 'no shard'}, expected exactly one")
    errors += [f"shard-files lists {p}, which is not a tracked proof file"
               for p in sorted(set(where) - set(proof_files))]
    return errors


def run(cmd):
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd).returncode == 0


def main(argv):
    if len(argv) != 1:
        print("usage: source.py", file=sys.stderr)
        return 2
    failed = []
    try:
        reg = registry.load()
        registry.hash_sets()
        files = list(key.Tree().files)
    except (registry.RegistryError, key.KeyFailure) as e:
        print(f"source.py: {e}", file=sys.stderr)
        return 1
    found = components.present(reg, files)
    for c, dirs in found.items():
        print(f"component {c}: {'present (' + ' '.join(dirs) + ')' if dirs else 'absent'}")
    for name, errors in (("components", components.layout_errors(reg, files)
                          + components.hash_set_errors(registry.hash_sets(), files)),
                         ("recipes", recipe_errors(reg, files)),
                         ("shards", shard_errors(reg, files) if found["proofs"] else [])):
        for e in errors:
            print(f"source {name}: FAIL: {e}")
        print(f"source {name}: {'FAIL' if errors else 'PASS'}")
        if errors:
            failed.append(name)
    steps = []
    if found["hash"]:
        steps.append(("hash", ["make", "-C", "tests/hash", "constants", "generated"]))
    if found["proofs"]:
        steps.append(("proofs", ["make", "-C", "proofs", "scan-admits", "check-constants",
                                 "check-inventory-files"]))
    for name, cmd in steps:
        ok = run(cmd)
        print(f"source {name}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failed.append(name)
    print(f"source: {'FAIL (' + ', '.join(failed) + ')' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
