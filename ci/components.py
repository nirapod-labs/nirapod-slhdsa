# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/components.py
# ======================
#
# The components of the tree ([components] in tools/ci/checks.toml) and
# what follows from them: which checks apply, and the source checks that
# need no toolchain. A component is present when the commit tracks a file
# under one of its directories.
#
#   applicability(...)   RUN, NOT APPLICABLE (the component is absent and
#                        not required) or NOT RUN (absent while components
#                        that make its absence a gap are present), with the
#                        reason; an error when a required component is
#                        absent or a check's `needs` is not met
#   layout_errors(...)   directories the table does not account for, and
#                        required components that are absent
#   hash_set_errors(...) variant directories of src/hash that no kernel set
#                        selects, and selections of directories that do not
#                        exist (tools/ci/hash-sets.toml)

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry  # noqa: E402


class ComponentError(Exception):
    pass


def present(reg, files):
    """{component: [its directories that exist]}"""
    out = {}
    for c, dirs in reg["components"]["dirs"].items():
        out[c] = [d for d in dirs if any(f.startswith(d + "/") for f in files)]
    return out


def applicability(reg, check, found):
    c = reg["checks"][check] if check in reg["checks"] else reg["agree"]
    comp = c["component"]
    required = reg["components"]["required"]
    missing = [r for r in required if not found[r]]
    if missing:
        raise ComponentError("required components are absent: " + ", ".join(
            f"{m} (none of: {' '.join(reg['components']['dirs'][m])})" for m in missing))
    if not found[comp]:
        dirs = " ".join(reg["components"]["dirs"][comp])
        if c.get("absent") == "NOT RUN" and any(found[n] for n in c.get("not-run-when", [])):
            gap = ", ".join(n for n in c["not-run-when"] if found[n])
            return "NOT RUN", (f"the {comp} component is absent (none of: {dirs}) while {gap} "
                               f"is present: that code is unchecked, not absent")
        return "NOT APPLICABLE", f"the {comp} component is absent (none of: {dirs})"
    for n in c.get("needs", []):
        if not found[n]:
            raise ComponentError(f"{check} needs the {n} component, which is absent")
    return "RUN", f"the {comp} component is present ({' '.join(found[comp])})"


def layout_errors(reg, files):
    comp = reg["components"]
    known = {d for dirs in comp["dirs"].values() for d in dirs}
    containers, other = set(comp["containers"]), set(comp["other-roots"])
    roots = {f.split("/", 1)[0] for f in files if "/" in f}
    inner = {"/".join(f.split("/")[:2]) for f in files
             if f.count("/") >= 2 and f.split("/", 1)[0] in containers}
    unknown = sorted((roots - known - containers - other) | (inner - known))
    errors = [f"directory {d} is not accounted for: add it to its component in "
              f"tools/ci/checks.toml, or to other-roots if it holds none" for d in unknown]
    found = present(reg, files)
    errors += [f"required component {r} is absent (none of: {' '.join(comp['dirs'][r])})"
               for r in comp["required"] if not found[r]]
    return errors


def hash_set_errors(sets, files):
    """Variant directories are src/hash/<family>/<arch>/<variant>/."""
    variants = {"/".join(f.split("/")[2:5]) for f in files
                if f.startswith("src/hash/") and f.count("/") >= 5}
    selected = set()
    for s in sets.values():
        for v in s["vars"]:
            var, _, value = v.partition("=")
            family = "keccak" if var.startswith("KECCAK") else "sha2" if var.startswith("SHA2") else None
            if family is None or not value:
                return [f"kernel set variable '{v}': expected KECCAK*=<arch>/<variant> or SHA2*=..."]
            selected.add(f"{family}/{value}")
    errors = [f"variant directory src/hash/{v} is selected by no kernel set"
              for v in sorted(variants - selected)]
    errors += [f"a kernel set selects src/hash/{v}, which does not exist"
               for v in sorted(selected - variants)]
    return errors


def main(argv):
    """components.py: the presence of each component, and the layout and
    kernel-set checks; exit 1 on any error."""
    import key
    try:
        reg = registry.load()
        files = list(key.Tree().files)
        for c, dirs in present(reg, files).items():
            print(f"component {c}: {'present (' + ' '.join(dirs) + ')' if dirs else 'absent'}")
        errors = layout_errors(reg, files) + hash_set_errors(registry.hash_sets(), files)
    except (registry.RegistryError, key.KeyFailure) as e:
        print(f"components.py: {e}", file=sys.stderr)
        return 1
    for e in errors:
        print(f"components: FAIL: {e}")
    if errors:
        return 1
    print("components: PASS (every directory accounted for, every kernel variant selected)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
