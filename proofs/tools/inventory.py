# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# inventory.py
#
# Builds the axiom and theorem inventory of one (architecture, variant)
# pair: a scratch theory requires every theory checked for the pair, then
# asks EasyCrypt to `print axiom` and to print each claimed theorem. The
# result lists
#
#   - every axiom in scope, from any source: an `axiom` declaration, an
#     `axiomatized by` definition, or an axiom a `clone` leaves unrealized,
#     in this project, the imported theories, the extracted models, the
#     Jasmin EasyCrypt library and the EasyCrypt standard library. Each is
#     named by its theory and name with the first 16 hex digits of the
#     SHA-256 of its statement (whitespace collapsed), so that a changed
#     statement shows as a changed line;
#   - the statement of every claimed theorem, in full. A theorem that does
#     not exist makes EasyCrypt fail, and a weakened one shows as a diff.
#
# The committed inventory/<arch>-<variant>.txt is the reviewed list; `make
# check-inventory` regenerates it and fails on any difference, so a new or
# changed axiom or theorem cannot pass without a visible change to it.
#
# Usage:
#   python3 inventory.py --pair P --easycrypt CMD --flags FLAGS
#       [--namespace NS=DIR]... [--theorems "T.name ..."]
#       (--write OUT | --check OUT) FILE...
# FILE... are the .ec/.eca files of the pair. A file whose directory is
# the DIR of a --namespace is required as `from NS require Name`.
# Exit status: 0 on success, 1 when --check finds a difference, 2 on any
# other failure (EasyCrypt error, unparsable output, bad arguments).

import argparse
import difflib
import hashlib
import os
import re
import shlex
import subprocess
import sys
import tempfile

MARK_AXIOMS = "inventory_axioms_follow"
MARK_THEOREMS = "inventory_theorems_follow"
HEADING = re.compile(r"^=+ (\S+) =+$")
# `axiom [tags] name ...`: the tags (e.g. [explicit]) are part of the statement.
AXIOM = re.compile(r"^axiom ((?:\[[^\]]*\] )?)([^\s:\[]+)")


def scratch_theory(files, namespaces, theorems):
    lines = []
    for path in files:
        name = os.path.splitext(os.path.basename(path))[0]
        ns = namespaces.get(os.path.normpath(os.path.dirname(path)))
        lines.append(("from %s require %s." % (ns, name)) if ns else ("require %s." % name))
    lines.append("op %s = 0." % MARK_AXIOMS)
    lines.append("print %s." % MARK_AXIOMS)
    lines.append("print axiom.")
    lines.append("op %s = 0." % MARK_THEOREMS)
    lines.append("print %s." % MARK_THEOREMS)
    for t in theorems:
        lines.append("print lemma %s." % t)
    return "\n".join(lines) + "\n"


def section(out, start, end):
    """Lines strictly between the printed markers start and end (or EOF)."""
    lines = out.split("\n")
    def find(mark, frm):
        for i in range(frm, len(lines)):
            if lines[i].startswith("op %s " % mark):
                return i
        raise ValueError("marker %s not found in EasyCrypt output" % mark)
    i = find(start, 0)
    j = find(end, i + 1) if end else len(lines)
    return lines[i + 1:j]


def parse_axioms(lines):
    entries = []
    theory = None
    current = None
    for line in lines + [""]:
        if line.startswith("* In ["):
            continue  # the category line `print` puts before the marker
        m = HEADING.match(line)
        if m:
            theory = m.group(1)
            continue
        a = AXIOM.match(line)
        if a or not line.startswith(" "):
            if current:
                entries.append(current)
                current = None
        if a:
            if theory is None:
                raise ValueError("axiom before any theory heading: %s" % line)
            current = [theory, a.group(2), [a.group(1) + line[a.end():]]]
        elif current and line.startswith(" "):
            current[2].append(line)
        elif line.strip():
            raise ValueError("unexpected line in axiom list: %s" % line)
    out = []
    for theory, name, body in entries:
        text = " ".join(" ".join(body).split())
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        out.append("%s %s %s" % (theory, name, digest))
    out.sort()
    if len(set(out)) != len(out):
        raise ValueError("duplicate axiom entries")
    return out


def parse_theorems(lines):
    out = []
    for line in lines:
        line = line.rstrip()
        if line or (out and out[-1]):
            out.append(line)
    while out and not out[-1]:
        out.pop()
    return out


def render(pair, axioms, theorems):
    head = [
        # The licence of the generated inventory (not of this script).
        # REUSE-IgnoreStart
        "# SPDX-FileCopyrightText: nirapod-slhdsa contributors",
        "# SPDX-License-Identifier: Apache-2.0",
        # REUSE-IgnoreEnd
        "#",
        "# GENERATED FILE. DO NOT EDIT.",
        "#",
        "# Axioms in scope of the %s proofs, and the statements of the" % pair,
        "# claimed theorems, as the pinned EasyCrypt prints them after requiring",
        "# every theory checked for this pair. One axiom per line: theory, name,",
        "# first 16 hex digits of the SHA-256 of its statement.",
        "#",
        "# Generator: proofs/tools/inventory.py",
        "# Regenerate: make -C proofs inventory   (check: make -C proofs check-inventory)",
        "",
        "axioms %d" % len(axioms),
        "",
    ]
    return "\n".join(head + axioms + ["", "theorems", ""] + theorems) + "\n"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair", required=True)
    ap.add_argument("--easycrypt", required=True)
    ap.add_argument("--flags", required=True)
    ap.add_argument("--namespace", action="append", default=[])
    ap.add_argument("--theorems", default="")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write")
    mode.add_argument("--check")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args(argv)

    namespaces = {}
    for spec in args.namespace:
        ns, _, d = spec.partition("=")
        if not ns or not d:
            print("inventory.py: bad --namespace %s" % spec)
            return 2
        namespaces[os.path.normpath(d)] = ns
    theorems = args.theorems.split()

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "Inventory.ec")
        with open(src, "w", encoding="utf-8") as f:
            f.write(scratch_theory(args.files, namespaces, theorems))
        cmd = shlex.split(args.easycrypt) + ["compile"] + shlex.split(args.flags) + [src]
        run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
    if run.returncode != 0:
        sys.stdout.write(run.stdout)
        sys.stdout.write(run.stderr)
        print("inventory.py: EasyCrypt failed (status %d) for %s" % (run.returncode, args.pair))
        return 2
    try:
        axioms = parse_axioms(section(run.stdout, MARK_AXIOMS, MARK_THEOREMS))
        thms = parse_theorems(section(run.stdout, MARK_THEOREMS, None))
    except ValueError as e:
        print("inventory.py: %s" % e)
        return 2
    if theorems and not thms:
        print("inventory.py: no theorem statements printed")
        return 2
    text = render(args.pair, axioms, thms)

    if args.write:
        with open(args.write, "w", encoding="utf-8") as f:
            f.write(text)
        print("inventory %s: %d axioms, %d theorems -> %s"
              % (args.pair, len(axioms), len(theorems), args.write))
        return 0
    try:
        with open(args.check, encoding="utf-8") as f:
            old = f.read()
    except OSError as e:
        print("inventory.py: %s" % e)
        return 2
    if old == text:
        print("inventory %s: %d axioms, %d theorems, unchanged"
              % (args.pair, len(axioms), len(theorems)))
        return 0
    sys.stdout.writelines(difflib.unified_diff(
        old.splitlines(True), text.splitlines(True),
        args.check, "%s (this run)" % args.pair))
    print("inventory %s: FAIL, differs from %s" % (args.pair, args.check))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
