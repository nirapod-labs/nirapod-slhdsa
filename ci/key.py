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
#     inputs <digest of the input set of C>
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
#   - the recipes ci/checks/*.mk other than C's own, and the rules
#     ci/rules/*.toml other than C's own,
#
# except that every *.mk file one or two directories below the root, outside
# ci/, stays an input whatever the lists say: the top-level Makefile
# includes them all.
# So a path nobody listed is an input of every check.
#
# The key of agree is over the keys of the test-core legs instead of files:
# its inputs line is the SHA-256 of their key names, one per line, sorted,
# with platform "any", runner "-" and the toolchain identity without
# options.
#
# Usage, from the repository root:
#
#   key.py key CHECK PLATFORM     the key text, then "key <name>"
#   key.py inputs CHECK PLATFORM  the paths of the input set, one per line
#   key.py agree                  the key text and name of agree

import hashlib
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry  # noqa: E402

FORMAT = 2
RECIPES = "ci/checks/"
RULES = "ci/rules/"
TOOLCHAIN = "toolchain/"


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
    kept = []
    for p in tree.files:
        if included_by_top_makefile(p):
            kept.append(p)
            continue
        if p.startswith(TOOLCHAIN) or under(p, skip):
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
    text = (f"format {FORMAT}\ncheck {check}\nplatform {platform}\nrunner {p['runner']}\n"
            f"toolchain {toolchain_identity(tree, p['toolchain-options'])}\n"
            f"inputs {digest(tree, input_set(tree, reg, check))}\n")
    return name(check, platform, text), text


def agree_key(tree, reg):
    over = reg["agree"]["over"]
    names = sorted(key(tree, reg, over, p)[0] for p in reg["checks"][over]["platforms"])
    inputs = hashlib.sha256("".join(n + "\n" for n in names).encode()).hexdigest()
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
        if len(argv) == 2 and argv[1] == "agree":
            n, text = agree_key(tree, reg)
            print(text + f"key {n}")
            return 0
    except (KeyFailure, registry.RegistryError) as e:
        print(f"key.py: {e}", file=sys.stderr)
        return 1
    print("usage: key.py key CHECK PLATFORM | inputs CHECK PLATFORM | agree", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
