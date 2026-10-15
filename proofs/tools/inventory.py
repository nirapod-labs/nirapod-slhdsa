# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# inventory.py
#
# Builds the axiom, theorem and definition inventory of one (architecture,
# variant) pair: a scratch theory requires every theory checked for the
# pair, then asks EasyCrypt to `print axiom`, to print each claimed theorem,
# and to `print theory` each theory written by hand. The result lists
#
#   - every axiom in scope, from any source: an `axiom` declaration, an
#     `axiomatized by` definition, or an axiom a `clone` leaves unrealized,
#     in this project, the imported theories, the extracted models, the
#     Jasmin EasyCrypt library and the EasyCrypt standard library. Each is
#     named by its theory and name with the first 16 hex digits of the
#     SHA-256 of its statement (whitespace collapsed), so that a changed
#     statement shows as a changed line;
#   - the statement of every claimed theorem, in full. A theorem that does
#     not exist makes EasyCrypt fail, and a weakened one shows as a diff;
#   - every type, operator, predicate, abbreviation and module defined in
#     the theories of this project and the imported ones (not the generated
#     models under a --generated directory, which `make check-extraction`
#     pins to their sources), by qualified name, kind and the first 16 hex
#     digits of the SHA-256 of its printed definition. A theorem statement
#     means what the definitions it names mean; listing every definition,
#     rather than following the names in the statements, needs no name
#     resolution and cannot miss one reached through an imported theory.
#     Definitions nested more than DEPTH theories deep (clones inside
#     clones) are summarised by one digest per enclosing theory at that
#     depth, with their count.
#
# The committed inventory/<arch>-<variant>.txt is the reviewed list; `make
# check-inventory` regenerates it and fails on any difference, so a new or
# changed axiom, theorem or definition cannot pass without a visible change
# to it. Proofs and lemma statements other than the claimed theorems are not
# listed: changing them cannot change what a claimed theorem says.
#
# Usage:
#   python3 inventory.py --pair P --easycrypt CMD --flags FLAGS
#       [--namespace NS=DIR]... [--generated DIR]... [--theorems "T.name ..."]
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
MARK_DEFS = "inventory_definitions_follow"
HEADING = re.compile(r"^=+ (\S+) =+$")
# `axiom [tags] name ...`: the tags (e.g. [explicit]) are part of the statement.
AXIOM = re.compile(r"^axiom ((?:\[[^\]]*\] )?)([^\s:\[]+)")
# The first line of a declaration in `print theory` output.
MARKER = re.compile(r"^\s*\(\* (?:no )?(?:import|export) \*\)\s*$")
DECL = re.compile(r"^\s*(?:\(\* (?:no )?(?:import|export) \*\) )?(?:(?:abstract|local|declare) )*"
                  r"(op|pred|type|abbrev|lemma|axiom|schema|theory|end|module|inductive|"
                  r"notation|class|instance)\b\s*(.*)$")
KEPT = {"op", "pred", "type", "abbrev", "module", "inductive", "notation", "class", "instance"}


def scratch_theory(files, namespaces, theorems, pinned):
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
    lines.append("op %s = 0." % MARK_DEFS)
    lines.append("print %s." % MARK_DEFS)
    for t in pinned:
        lines.append("print theory %s." % t)
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


# Definitions nested deeper than this many theories (clones inside clones)
# are summarised by one line per theory at this depth.
DEPTH = 2


def decl_name(kind, rest):
    rest = re.sub(r"^(\[[^\]]*\]\s*)+", "", rest)
    if kind == "module-type" and rest.startswith("type "):
        rest = rest[len("type "):]
    # The type parameters come before the name: `type ('a, 'b) t`, `type 'a t`.
    if kind == "type" and rest.startswith("("):
        rest = rest[rest.index(")") + 1:].lstrip()
    elif kind == "type":
        rest = re.sub(r"^'\w+\s+", "", rest)
    # A declaration without a body ends with the full stop: `type t.`
    m = re.match(r"\([^)]*\)|`[^`]*`|\"[^\"]*\"|[^\s:=(\[.]+", rest)
    return m.group(0) if m else "?"


def parse_definitions(lines):
    """Definitions printed by `print theory`, one line each."""
    # Deeply nested output wraps an import marker onto a line of its own;
    # join it to the declaration it belongs to.
    joined = []
    for line in lines:
        if joined and MARKER.match(joined[-1]):
            joined[-1] = joined[-1].rstrip() + " " + line.lstrip()
        else:
            joined.append(line)
    path = []
    items = []
    current = None
    for line in joined + [""]:
        if line.startswith("* In ["):
            continue
        d = DECL.match(line)
        if d or not line.strip():
            if current:
                items.append(current)
                current = None
        if not d:
            if current is not None and line.strip():
                current[3].append(line)
            continue
        kind, rest = d.group(1), d.group(2)
        if kind == "theory":
            path.append(rest.rstrip(".").strip())
        elif kind == "end":
            name = rest.rstrip(".").strip()
            if not path or path[-1] != name:
                raise ValueError("unbalanced theory end: %s" % line)
            path.pop()
        elif kind in KEPT:
            if kind == "module" and rest.startswith("type "):
                kind = "module-type"
            current = [list(path), kind, decl_name(kind, rest), [line]]
        else:
            current = None
    if path:
        raise ValueError("unterminated theory %s" % ".".join(path))
    out = []
    nested = {}
    for path, kind, name, body in items:
        text = " ".join(" ".join(body).split())
        text = re.sub(r"^\(\* (?:no )?(?:import|export) \*\) ", "", text)
        if len(path) <= DEPTH:
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            out.append("%s.%s %s %s" % (".".join(path), name, kind, digest))
        else:
            key = ".".join(path[:DEPTH])
            entry = ".".join(path[DEPTH:]) + " " + kind + " " + name + " " + text
            nested.setdefault(key, []).append(entry)
    for key, entries in nested.items():
        h = hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()[:16]
        out.append("%s.* nested %s %d" % (key, h, len(entries)))
    return sorted(out)


def parse_theorems(lines):
    out = []
    for line in lines:
        line = line.rstrip()
        if line.startswith("* In ["):
            continue  # the category line `print` puts before the next marker
        if line or (out and out[-1]):
            out.append(line)
    while out and not out[-1]:
        out.pop()
    return out


def render(pair, axioms, theorems, defs):
    head = [
        # The licence of the generated inventory (not of this script).
        # REUSE-IgnoreStart
        "# SPDX-FileCopyrightText: nirapod-slhdsa contributors",
        "# SPDX-License-Identifier: Apache-2.0",
        # REUSE-IgnoreEnd
        "#",
        "# GENERATED FILE. DO NOT EDIT.",
        "#",
        "# Axioms in scope of the %s proofs, the statements of the claimed" % pair,
        "# theorems, and the definitions of the hand-written theories, as the",
        "# pinned EasyCrypt prints them after requiring every theory checked for",
        "# this pair. One axiom per line: theory, name, first 16 hex digits of the",
        "# SHA-256 of its statement; one definition per line: qualified name,",
        "# kind, the same digest of its printed definition.",
        "#",
        "# Generator: proofs/tools/inventory.py",
        "# Regenerate: make -C proofs inventory   (check: make -C proofs check-inventory)",
        "",
        "axioms %d" % len(axioms),
        "",
    ]
    return "\n".join(head + axioms + ["", "theorems", ""] + theorems
                     + ["", "definitions %d" % len(defs), ""] + defs) + "\n"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair", required=True)
    ap.add_argument("--easycrypt", required=True)
    ap.add_argument("--flags", required=True)
    ap.add_argument("--namespace", action="append", default=[])
    ap.add_argument("--theorems", default="")
    ap.add_argument("--generated", action="append", default=[])
    # The per-set proofs may define nothing of their own; their definitions
    # are those of the specification, which the pair inventories pin.
    ap.add_argument("--allow-no-definitions", action="store_true")
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
    generated = [os.path.normpath(g) + os.sep for g in args.generated]
    pinned = [os.path.splitext(os.path.basename(f))[0] for f in args.files
              if not any(os.path.normpath(f).startswith(g) for g in generated)]

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "Inventory.ec")
        with open(src, "w", encoding="utf-8") as f:
            f.write(scratch_theory(args.files, namespaces, theorems, pinned))
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
        thms = parse_theorems(section(run.stdout, MARK_THEOREMS, MARK_DEFS))
        defs = parse_definitions(section(run.stdout, MARK_DEFS, None))
    except ValueError as e:
        print("inventory.py: %s" % e)
        return 2
    if theorems and not thms:
        print("inventory.py: no theorem statements printed")
        return 2
    if pinned and not defs and not args.allow_no_definitions:
        print("inventory.py: no definitions printed")
        return 2
    text = render(args.pair, axioms, thms, defs)

    if args.write:
        with open(args.write, "w", encoding="utf-8") as f:
            f.write(text)
        print("inventory %s: %d axioms, %d theorems, %d definitions -> %s"
              % (args.pair, len(axioms), len(theorems), len(defs), args.write))
        return 0
    try:
        with open(args.check, encoding="utf-8") as f:
            old = f.read()
    except OSError as e:
        print("inventory.py: %s" % e)
        return 2
    if old == text:
        print("inventory %s: %d axioms, %d theorems, %d definitions, unchanged"
              % (args.pair, len(axioms), len(theorems), len(defs)))
        return 0
    sys.stdout.writelines(difflib.unified_diff(
        old.splitlines(True), text.splitlines(True),
        args.check, "%s (this run)" % args.pair))
    print("inventory %s: FAIL, differs from %s" % (args.pair, args.check))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
