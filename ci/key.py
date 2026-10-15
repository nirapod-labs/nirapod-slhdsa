# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/key.py
# =========
#
# The key of a check: the SHA-256 of everything the check reads, so that
# two runs with the same key ran the same check on the same inputs, and a
# pass recorded under a key on main can stand for a run on a pull request
# with that key (ci/record.py, ci/plan.py).
#
# The key text of check C on platform P is
#
#     format 2
#     check C
#     platform P
#     runner <the hosted runner label of P>
#     toolchain <toolchain identity of P>
#     inputs <digest of the input set of C, then its registry line>
#
# and the key is v2-C-P-<SHA-256 of the key text>, also the record's name.
#
# A digest of a set of files is the SHA-256 of one line per file, sorted by
# path (bytewise):
#
#     <path> NUL <git mode> NUL <SHA-256 of the content, hex> LF
#
# taken from the commit (HEAD), never from the work tree, so that a dirty
# checkout cannot change a key; `git ls-tree -r HEAD` gives the modes,
# `git cat-file blob` the contents, and `key.py inputs C P` lists the
# paths of an input set, so anyone can recompute a key with git and
# sha256sum. The toolchain identity is the same
# digest over every tracked file under toolchain/ followed by the line
# "options <toolchain options of P>"; it is the toolchain's source, not its
# build: the runner's image is not in any key. It is recorded with each
# pass (record.py), and every push to main runs every check on the current
# image.
#
# The input set of C: every tracked file of the commit, minus
#
#   - the paths of [inputs] skip-all and of C's skip list (a path and
#     everything under it; ci/checks.toml),
#   - the files under toolchain/ (they are the toolchain identity),
#   - ci/checks.toml itself (it enters through the registry line),
#   - the recipes ci/checks/*.mk other than C's own, and the rules
#     ci/rules/*.toml other than C's own,
#
# except that, while C reads the top-level Makefile (its skip list does not
# name it), every *.mk file one or two directories below the root, outside
# ci/, stays an input whatever the lists say: that Makefile includes them
# all. A check that skips the Makefile skips them through it, and keeps
# those its lists leave in like any other file.
# So a path nobody listed is an input of every check.
#
# The registry line ends the input digest: "registry <SHA-256 of the
# entry>" LF, where the entry is what ci/checks.toml says about C on P,
# serialised as JSON with sorted keys, no spaces and ASCII escapes, then
# LF (`key.py registry C P` prints it):
#
#   format      the registry's format
#   check       C's own table, every field of it
#   platform    P's table, every field of it
#   skip-all    the [inputs] list
#   components  the required list, and the directories of the required
#               components and of those C names (component, needs,
#               not-run-when): what decides whether C runs at all
#
# Comments, layout and the entries of other checks and platforms are not in
# it, so they leave C's key alone. The rest of the file reaches no check:
# [components] containers and other-roots are read by the layout check of
# ci/source.py, which runs on every commit and has no key, and [agree] by
# agree alone. The rule fails closed: registry.py refuses any table or field
# it does not know, and REGISTRY_FIELDS below must name every one it
# accepts, so that a field added to the registry without a decision here
# fails every key instead of silently staying out of them. A field that can
# change what a check runs, where, or on which inputs belongs in the entry.
#
# The key of agree is over the keys of the test-core legs instead of files:
# its inputs line is the SHA-256 of their key names, one per line, sorted,
# then its registry line, with platform "any", runner "-" and the toolchain
# identity without options. Its entry is the format, [agree], every
# platform's table (agree reads the build record of each) and the
# components as above for its component.
#
# Usage, from the repository root:
#
#   key.py key CHECK PLATFORM     the key text, then "key <name>"
#   key.py inputs CHECK PLATFORM  the paths of the input set, one per line
#   key.py registry CHECK PLATFORM  the registry entry, as serialised
#   key.py agree                  the key text and name of agree

import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry  # noqa: E402

FORMAT = 2
RECIPES = "ci/checks/"
RULES = "ci/rules/"
TOOLCHAIN = "toolchain/"
REGISTRY = registry.REGISTRY
TOP_MAKEFILE = "Makefile"

# Every table and field registry.load() accepts, as it accepts them. A
# change on either side without the other fails every key (header).
REGISTRY_FIELDS = {
    "format": None,
    "platforms": None,
    "components": {"required", "containers", "other-roots", "dirs"},
    "inputs": {"skip-all"},
    "checks": None,
    "agree": None,
}


class KeyFailure(Exception):
    pass


class Tree:
    """The files of one commit: path -> (mode, object id), and the SHA-256
    of each object's content, read once."""

    def __init__(self, rev="HEAD", cwd=None):
        self.cwd = cwd
        out = self._git("ls-tree", "-r", "-z", "--full-tree", rev)
        self.files = {}
        for entry in out.split(b"\0"):
            if not entry:
                continue
            meta, path = entry.split(b"\t", 1)
            mode, kind, oid = meta.decode().split(" ")
            if kind == "commit":
                raise KeyFailure(f"{path.decode()}: submodules are not supported")
            self.files[path.decode()] = (mode, oid)
        if not self.files:
            raise KeyFailure(f"{rev}: no files")
        self._sha = {}

    def _git(self, *args, data=None):
        try:
            return subprocess.run(["git", *args], cwd=self.cwd, input=data, check=True,
                                  capture_output=True).stdout
        except (OSError, subprocess.CalledProcessError) as e:
            raise KeyFailure(f"git {args[0]}: {getattr(e, 'stderr', b'') or e}") from None

    def sha256(self, paths):
        missing = sorted({self.files[p][1] for p in paths} - set(self._sha))
        if missing:
            out = self._git("cat-file", "--batch", data=("\n".join(missing) + "\n").encode())
            pos = 0
            for oid in missing:
                nl = out.index(b"\n", pos)
                head = out[pos:nl].decode().split(" ")
                if head[0] != oid or len(head) != 3:
                    raise KeyFailure(f"git cat-file: unexpected header {head}")
                size = int(head[2])
                self._sha[oid] = hashlib.sha256(out[nl + 1:nl + 1 + size]).hexdigest()
                pos = nl + 1 + size + 1
        return {p: self._sha[self.files[p][1]] for p in paths}


def digest(tree, paths, extra=b""):
    sums = tree.sha256(paths)
    h = hashlib.sha256()
    for p in sorted(paths, key=lambda s: s.encode()):
        h.update(p.encode() + b"\0" + tree.files[p][0].encode() + b"\0" + sums[p].encode() + b"\n")
    h.update(extra)
    return h.hexdigest()


def under(path, entries):
    return any(path == e or path.startswith(e.rstrip("/") + "/") for e in entries)


def included_by_top_makefile(path):
    # The top-level Makefile includes */*.mk and */*/*.mk outside ci/.
    return path.endswith(".mk") and path.count("/") in (1, 2) and not path.startswith("ci/")


def input_set(tree, reg, check):
    c = reg["checks"][check]
    own_recipe = f"{RECIPES}{c['recipe']}.mk"
    own_rules = f"{RULES}{check}.toml"
    skip = reg["inputs"]["skip-all"] + c.get("skip", [])
    reads_top = not under(TOP_MAKEFILE, skip)
    kept = []
    for p in tree.files:
        if reads_top and included_by_top_makefile(p):
            kept.append(p)
            continue
        if p.startswith(TOOLCHAIN) or p == REGISTRY or under(p, skip):
            continue
        if p.startswith(RECIPES) and p.endswith(".mk") and p != own_recipe \
                and "/" not in p[len(RECIPES):]:
            continue
        if p.startswith(RULES) and p != own_rules:
            continue
        kept.append(p)
    if not kept:
        raise KeyFailure(f"{check}: the input set is empty")
    return kept


def _known_fields(reg):
    if set(reg) != set(REGISTRY_FIELDS):
        raise KeyFailure(f"{REGISTRY}: tables {sorted(reg)}, "
                         f"the keys know {sorted(REGISTRY_FIELDS)}")
    for table, fields in REGISTRY_FIELDS.items():
        if fields is not None and set(reg[table]) != fields:
            raise KeyFailure(f"{REGISTRY}: [{table}] fields {sorted(reg[table])}, "
                             f"the keys know {sorted(fields)}")


def _components(reg, names):
    comp = reg["components"]
    names = set(names) | set(comp["required"])
    return {"required": comp["required"], "dirs": {n: comp["dirs"][n] for n in sorted(names)}}


def registry_entry(reg, check, platform):
    """What the registry says about CHECK on PLATFORM (header)."""
    _known_fields(reg)
    c = reg["checks"][check]
    named = [c["component"], *c.get("needs", []), *c.get("not-run-when", [])]
    return {"format": reg["format"], "check": {check: c},
            "platform": {platform: reg["platforms"][platform]},
            "skip-all": reg["inputs"]["skip-all"], "components": _components(reg, named)}


def agree_entry(reg):
    _known_fields(reg)
    return {"format": reg["format"], "agree": reg["agree"], "platforms": reg["platforms"],
            "components": _components(reg, [reg["agree"]["component"]])}


def serialise(entry):
    try:
        return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False) + "\n"
    except (TypeError, ValueError) as e:
        raise KeyFailure(f"{REGISTRY}: a value the keys cannot serialise ({e})") from None


def registry_line(entry):
    return f"registry {hashlib.sha256(serialise(entry).encode()).hexdigest()}\n".encode()


def toolchain_identity(tree, options):
    files = [p for p in tree.files if p.startswith(TOOLCHAIN)]
    if not files:
        raise KeyFailure("no files under toolchain/")
    return digest(tree, files, f"options {options}\n".encode())


def name(check, platform, text):
    return f"v2-{check}-{platform}-{hashlib.sha256(text.encode()).hexdigest()}"


def key(tree, reg, check, platform):
    """(name, text) of the key of CHECK on PLATFORM."""
    if check not in reg["checks"]:
        raise KeyFailure(f"unknown check {check}")
    if platform not in reg["checks"][check]["platforms"]:
        raise KeyFailure(f"{check} does not run on {platform}")
    p = reg["platforms"][platform]
    inputs = digest(tree, input_set(tree, reg, check),
                    registry_line(registry_entry(reg, check, platform)))
    text = (f"format {FORMAT}\ncheck {check}\nplatform {platform}\nrunner {p['runner']}\n"
            f"toolchain {toolchain_identity(tree, p['toolchain-options'])}\n"
            f"inputs {inputs}\n")
    return name(check, platform, text), text


def agree_key(tree, reg):
    over = reg["agree"]["over"]
    names = sorted(key(tree, reg, over, p)[0] for p in reg["checks"][over]["platforms"])
    inputs = hashlib.sha256("".join(n + "\n" for n in names).encode()
                            + registry_line(agree_entry(reg))).hexdigest()
    text = (f"format {FORMAT}\ncheck agree\nplatform any\nrunner -\n"
            f"toolchain {toolchain_identity(tree, '')}\ninputs {inputs}\n")
    return name("agree", "any", text), text


def main(argv):
    try:
        reg = registry.load()
        tree = Tree()
        if len(argv) == 4 and argv[1] == "key":
            n, text = key(tree, reg, argv[2], argv[3])
            print(text + f"key {n}")
            return 0
        if len(argv) == 4 and argv[1] == "inputs":
            key(tree, reg, argv[2], argv[3])
            for p in sorted(input_set(tree, reg, argv[2]), key=lambda s: s.encode()):
                print(p)
            return 0
        if len(argv) == 4 and argv[1] == "registry":
            key(tree, reg, argv[2], argv[3])
            sys.stdout.write(serialise(registry_entry(reg, argv[2], argv[3])))
            return 0
        if len(argv) == 2 and argv[1] == "agree":
            n, text = agree_key(tree, reg)
            print(text + f"key {n}")
            return 0
    except (KeyFailure, registry.RegistryError) as e:
        print(f"key.py: {e}", file=sys.stderr)
        return 1
    print("usage: key.py key CHECK PLATFORM | inputs CHECK PLATFORM | registry CHECK PLATFORM"
          " | agree", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
