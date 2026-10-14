# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/counts.py
# ==================
#
# Usage: python3 -I tools/ci/counts.py RULES SECTION PATH [--target T] [--arch A]
#
# Checks that a test run covered at least the cases CI expects of it. A
# suite that passes with fewer cases than its minimum has silently tested
# less: a vector file that lost entries, an iteration count lowered by a
# variable, a filter left in place. Each minimum is the count of the
# complete run on the current vectors and settings; raising coverage needs
# no change here, lowering it does.
#
# RULES is a check's own rules file, tools/ci/rules/<check>.toml, so that a
# changed minimum re-runs that check and no other (tools/ci/key.py). Its
# tables are sections, each with any of:
#
#   [[SECTION.line]]      what, pattern (a regular expression with one
#                         integer group), and minimum or exactly: every
#                         line of PATH that matches is checked, and at
#                         least one must
#   [[SECTION.nonblank]]  what, minimum: PATH has at least that many
#                         non-blank lines
#   [[SECTION.files]]     what, glob (relative to the directory PATH,
#                         {target} replaced by T), exactly: a table of
#                         counts per architecture A
#
# Exit status 0 when every rule holds, 1 otherwise (each failure printed),
# 2 on a usage error or a malformed rules file. Each result line starts
# with "counts ", which is how records keep them (tools/ci/record.py).

import glob
import os
import re
import sys
import tomllib


class RulesError(Exception):
    pass


def load(path, section):
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise RulesError(f"{path}: {e}") from None
    if section not in data:
        raise RulesError(f"{path}: no section [{section}]")
    rules = data[section]
    if not rules or set(rules) - {"line", "nonblank", "files"}:
        raise RulesError(f"{path} [{section}]: expected line, nonblank or files rules")
    for kind, fields in (("line", {"what", "pattern", "minimum", "exactly"}),
                         ("nonblank", {"what", "minimum"}), ("files", {"what", "glob", "exactly"})):
        for r in rules.get(kind, []):
            if set(r) - fields or "what" not in r:
                raise RulesError(f"{path} [{section}.{kind}]: fields {sorted(r)}")
            if kind == "line" and (("minimum" in r) == ("exactly" in r) or "pattern" not in r):
                raise RulesError(f"{path}: a line rule has a pattern and one of minimum, exactly")
    return rules


def check(rules, section, path, target=None, arch=None):
    """(failures, result lines)"""
    out, failed = [], 0
    if "line" in rules or "nonblank" in rules:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    for r in rules.get("line", []):
        rx = re.compile(r["pattern"])
        found = [int(m.group(1)) for m in map(rx.match, lines) if m]
        if not found:
            out.append(f"counts {section}: FAIL, no line for: {r['what']}")
            failed += 1
            continue
        if "minimum" in r:
            ok, want = min(found) >= r["minimum"], f"minimum {r['minimum']}"
        else:
            ok, want = all(n == r["exactly"] for n in found), f"exactly {r['exactly']}"
        out.append(f"counts {section}: {r['what']}: {min(found)} ({want}, {len(found)} run(s)): "
                   f"{'PASS' if ok else 'FAIL'}")
        failed += not ok
    for r in rules.get("nonblank", []):
        n = sum(1 for l in lines if l.strip())
        ok = n >= r["minimum"]
        out.append(f"counts {section}: {r['what']}: {n} lines (minimum {r['minimum']}): "
                   f"{'PASS' if ok else 'FAIL'}")
        failed += not ok
    for r in rules.get("files", []):
        if target is None or arch not in r["exactly"]:
            raise RulesError(f"files rule '{r['what']}' needs --target and an --arch it lists")
        n = len(glob.glob(os.path.join(path, r["glob"].replace("{target}", target))))
        ok = n == r["exactly"][arch]
        out.append(f"counts {section}: {r['what']}: {n} (exactly {r['exactly'][arch]}): "
                   f"{'PASS' if ok else 'FAIL'}")
        failed += not ok
    return failed, out


def main(argv):
    args, opts = [], {}
    it = iter(argv[1:])
    for a in it:
        if a in ("--target", "--arch"):
            opts[a[2:]] = next(it, None)
        else:
            args.append(a)
    if len(args) != 3 or None in opts.values():
        print("usage: counts.py RULES SECTION PATH [--target T] [--arch A]", file=sys.stderr)
        return 2
    try:
        rules = load(args[0], args[1])
        failed, out = check(rules, args[1], args[2], opts.get("target"), opts.get("arch"))
    except (RulesError, OSError, re.error) as e:
        print(f"counts.py: {e}", file=sys.stderr)
        return 2
    print("\n".join(out))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
