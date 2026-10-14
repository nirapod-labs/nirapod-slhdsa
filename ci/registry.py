# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/registry.py
# ==============
#
# Reads ci/checks.toml and ci/hash-sets.toml, and refuses any
# entry it does not know, so that a misspelt field fails instead of being
# ignored (a skip list under a wrong name would otherwise silently widen a
# check's inputs to everything, or a platform list to nothing).

import os
import tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
REGISTRY = "ci/checks.toml"
HASH_SETS = "ci/hash-sets.toml"

PLATFORM_FIELDS = {"runner", "system", "machine", "arch", "target", "toolchain-options", "jobs"}
CHECK_FIELDS = {"recipe", "shard", "component", "needs", "absent", "not-run-when", "platforms",
                "toolchain", "opam", "jobs", "keep", "skip"}
TOOLCHAINS = ("none", "compiler", "switch")


class RegistryError(Exception):
    pass


def _load(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise RegistryError(f"{path}: {e}") from None


def _strings(value, what):
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise RegistryError(f"{what}: expected a list of non-empty strings")
    return value


def load(root=ROOT):
    reg = _load(os.path.join(root, REGISTRY))
    if set(reg) != {"format", "platforms", "components", "inputs", "checks", "agree"}:
        raise RegistryError(f"{REGISTRY}: tables {sorted(reg)}")
    if reg["format"] != 2:
        raise RegistryError(f"{REGISTRY}: format {reg['format']}, expected 2")
    for name, p in reg["platforms"].items():
        if set(p) != PLATFORM_FIELDS:
            raise RegistryError(f"platform {name}: fields {sorted(p)}")
    comp = reg["components"]
    if set(comp) != {"required", "containers", "other-roots", "dirs"}:
        raise RegistryError(f"[components]: fields {sorted(comp)}")
    for c, dirs in comp["dirs"].items():
        _strings(dirs, f"component {c}")
    for c in _strings(comp["required"], "required"):
        if c not in comp["dirs"]:
            raise RegistryError(f"required component {c} is unknown")
    if set(reg["inputs"]) != {"skip-all"}:
        raise RegistryError(f"[inputs]: fields {sorted(reg['inputs'])}")
    _strings(reg["inputs"]["skip-all"], "skip-all")
    for cid, c in reg["checks"].items():
        extra = set(c) - CHECK_FIELDS
        if extra or not {"recipe", "component", "platforms", "toolchain"} <= set(c):
            raise RegistryError(f"check {cid}: fields {sorted(c)}")
        if not cid.replace("-", "").replace("_", "").isalnum() or cid != cid.lower():
            raise RegistryError(f"check name {cid}: lower-case letters, digits, - and _")
        if c["component"] not in comp["dirs"]:
            raise RegistryError(f"check {cid}: unknown component {c['component']}")
        for n in c.get("needs", []) + c.get("not-run-when", []):
            if n not in comp["dirs"]:
                raise RegistryError(f"check {cid}: unknown component {n}")
        if c.get("absent", "NOT APPLICABLE") not in ("NOT APPLICABLE", "NOT RUN"):
            raise RegistryError(f"check {cid}: absent must be NOT APPLICABLE or NOT RUN")
        if bool(c.get("not-run-when")) != (c.get("absent") == "NOT RUN"):
            raise RegistryError(f"check {cid}: absent = NOT RUN goes with not-run-when")
        for p in _strings(c["platforms"], f"check {cid} platforms"):
            if p not in reg["platforms"]:
                raise RegistryError(f"check {cid}: unknown platform {p}")
        if c["toolchain"] not in TOOLCHAINS:
            raise RegistryError(f"check {cid}: toolchain must be one of {TOOLCHAINS}")
        _strings(c.get("skip", []), f"check {cid} skip")
        _strings(c.get("keep", []), f"check {cid} keep")
    agree = reg["agree"]
    if set(agree) != {"component", "over"} or agree["over"] not in reg["checks"]:
        raise RegistryError("[agree]: fields component and over (a check)")
    return reg


def hash_sets(root=ROOT):
    data = _load(os.path.join(root, HASH_SETS))
    if set(data) != {"sets"}:
        raise RegistryError(f"{HASH_SETS}: tables {sorted(data)}")
    for name, s in data["sets"].items():
        if set(s) != {"arch", "vars", "cpu"}:
            raise RegistryError(f"hash set {name}: fields {sorted(s)}")
        for f in ("arch", "vars", "cpu"):
            if not isinstance(s[f], list) or not all(isinstance(v, str) for v in s[f]):
                raise RegistryError(f"hash set {name}: {f} must be a list of strings")
    return data["sets"]


def sets_for(sets, arch):
    """The kernel sets of an architecture, scalar first."""
    names = [n for n, s in sets.items() if arch in s["arch"]]
    return sorted(names, key=lambda n: (n != "scalar", n))


def legs(reg):
    """(check id, platform) of every check, in registry order."""
    return [(cid, p) for cid, c in reg["checks"].items() for p in c["platforms"]]
