# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/status.py
# ============
#
# Usage: python3 -I ci/status.py check | write
#
# docs/status.toml is the one record of the project's results. This script
# renders it into the sections of README.md and docs/STATUS.md that sit
# between a pair of markers
#
#     <!-- begin status:<name> ... -->
#     <!-- end status:<name> -->
#
# `write` replaces every such section with its rendering; `check` renders
# the same and fails, printing a diff, when a file differs, so a status
# edited in only one place cannot reach main (ci/source.py runs it). Each
# file must hold exactly the sections this script renders for it, once.
#
# The record is checked before anything is rendered: every evidence label
# and check status must be a word of the vocabulary below, the twelve
# parameter sets must be listed once each, and every table row must have
# one cell per column.

import difflib
import os
import re
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORD = "docs/status.toml"
RUN_URL = "https://github.com/nirapod-labs/nirapod-slhdsa/actions/runs/"

EVIDENCE = ("PROVEN", "VERIFIED", "MEASURED", "STRONGLY SUPPORTED", "INFERRED", "UNKNOWN")
CHECKS = ("PASS", "FAIL", "INCONCLUSIVE", "NOT RUN", "NOT APPLICABLE")
SETS = {f"SLH-DSA-{h}-{b}{v}" for h in ("SHA2", "SHAKE") for b in (128, 192, 256) for v in "sf"}

SECTION = re.compile(r"(<!-- begin status:([a-z-]+)[^>]*-->\n)(.*?)(<!-- end status:\2 -->)",
                     re.DOTALL)


class StatusError(Exception):
    pass


def load(root=ROOT):
    with open(os.path.join(root, RECORD), "rb") as fh:
        return tomllib.load(fh)


def validate(rec):
    errors = []
    if rec.get("format") != 1:
        errors.append(f"{RECORD}: format must be 1")
    ev = rec.get("evidence", {})
    for k in ("revision", "run", "date"):
        if not isinstance(ev.get(k), str) or not ev.get(k):
            errors.append(f"[evidence] {k} is missing")
    sets = rec.get("sets", [])
    if sorted(sets) != sorted(SETS):
        errors.append("sets must list the twelve FIPS 205 parameter sets once each")
    for i, row in enumerate(rec.get("summary", [])):
        for k in ("claim", "link", "evidence", "scope"):
            if not row.get(k):
                errors.append(f"summary {i + 1}: {k} is missing")
        if row.get("evidence") not in EVIDENCE:
            errors.append(f"summary {i + 1}: evidence '{row.get('evidence')}' is not a label")
        if ("run" in row) != ("revision" in row):
            errors.append(f"summary {i + 1}: run and revision go together")
        if "check" in row and row["check"] not in CHECKS:
            errors.append(f"summary {i + 1}: check '{row['check']}' is not a check status")
    for col in rec.get("per_set", []):
        values = [col.get("value")] + list(col.get("overrides", {}).values())
        for v in values:
            if v not in EVIDENCE + CHECKS:
                errors.append(f"per_set '{col.get('title')}': '{v}' is neither a label nor a status")
        for s in col.get("overrides", {}):
            if s not in SETS:
                errors.append(f"per_set '{col.get('title')}': unknown set {s}")
    for t in rec.get("table", []):
        width = len(t.get("columns", []))
        for row in t.get("rows", []):
            if len(row) != width:
                errors.append(f"table {t.get('id')}: row '{row[0]}' has {len(row)} cells, not {width}")
    if errors:
        raise StatusError("\n".join(errors))


def link(target, page):
    # Links in the record are written from the repository root.
    path, _, anchor = target.partition("#")
    rel = os.path.relpath(path, os.path.dirname(page) or ".")
    return rel + ("#" + anchor if anchor else "")


def table(columns, rows):
    # A column of statuses alone is centred; any other column is left-aligned.
    words = set(EVIDENCE + CHECKS)
    centred = [i > 0 and all(r[i].replace("*", "").split("<br>")[0] in words for r in rows)
               for i in range(len(columns))]
    out = ["| " + " | ".join(columns) + " |",
           "| " + " | ".join(":-:" if c else ":--" for c in centred) + " |"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return out


def run_line(rec, revision=None, run=None):
    ev = rec["evidence"]
    revision, run = revision or ev["revision"], run or ev["run"]
    return f"From CI run [{run}]({RUN_URL}{run}) on `main` at `{revision}`."


def render_summary(rec, page):
    rows = []
    for r in rec["summary"]:
        status = f"**{r['evidence']}**" + (f"<br>{r['check']}" if "check" in r else "")
        rows.append([f"[{r['claim']}]({link(r['link'], page)})", status, r["scope"]])
    ev = rec["evidence"]
    own = "".join(f" Row *{r['claim']}*: run [{r['run']}]({RUN_URL}{r['run']}) at `{r['revision']}`."
                  for r in rec["summary"] if "run" in r)
    return table(["Claim", "Status", "Scope"], rows) + [
        "",
        f"Results of CI run [{ev['run']}]({RUN_URL}{ev['run']}) at `{ev['revision']}`, "
        f"{ev['date']}.{own} Every set, interface and platform: "
        f"[`docs/STATUS.md`]({link('docs/STATUS.md', page)}).",
    ]


def render_sets(rec, page):
    cols = rec["per_set"]
    head = ["SLH-DSA set"] + [f"[{c['title']}]({link(c['link'], page)})" for c in cols]
    # A non-breaking hyphen keeps each name on one line in a narrow column.
    rows = [[s.removeprefix("SLH-DSA-").replace("-", "\u2011")] + [c.get("overrides", {}).get(s, c["value"]) for c in cols]
            for s in rec["sets"]]
    return table(head, rows) + ["", run_line(rec)]


def render_table(rec, t):
    return table(t["columns"], t["rows"]) + ["", run_line(rec, t.get("revision"), t.get("run"))]


def sections(rec):
    # The sections each file holds, and their renderings.
    per_file = {"README.md": {"summary": render_summary(rec, "README.md")},
                "docs/STATUS.md": {"sets": render_sets(rec, "docs/STATUS.md")}}
    for t in rec.get("table", []):
        per_file["docs/STATUS.md"][t["id"]] = render_table(rec, t)
    return per_file


def apply(text, rendered, name):
    found = [m.group(2) for m in SECTION.finditer(text)]
    errors = [f"{name}: section status:{s} appears {found.count(s)} times"
              for s in sorted(set(found)) if found.count(s) > 1]
    errors += [f"{name}: unknown section status:{s}" for s in sorted(set(found) - set(rendered))]
    errors += [f"{name}: section status:{s} is missing" for s in sorted(set(rendered) - set(found))]
    if errors:
        raise StatusError("\n".join(errors))
    return SECTION.sub(lambda m: m.group(1) + "\n".join(rendered[m.group(2)]) + "\n" + m.group(4),
                       text)


def main(argv, root=ROOT):
    if len(argv) != 2 or argv[1] not in ("check", "write"):
        print("usage: status.py check | write", file=sys.stderr)
        return 2
    try:
        rec = load(root)
        validate(rec)
        stale = []
        for name, rendered in sections(rec).items():
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as fh:
                old = fh.read()
            new = apply(old, rendered, name)
            if new == old:
                continue
            if argv[1] == "write":
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new)
                print(f"status: rewrote {name}")
            else:
                stale.append(name)
                sys.stdout.writelines(difflib.unified_diff(
                    old.splitlines(True), new.splitlines(True), name, name + " (rendered)"))
    except (OSError, tomllib.TOMLDecodeError, KeyError, StatusError) as e:
        print(f"status: FAIL: {e}")
        return 1
    if stale:
        print(f"status: FAIL: {', '.join(stale)} differ from {RECORD}; "
              "run python3 -I ci/status.py write")
        return 1
    print("status: PASS" if argv[1] == "check" else "status: written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
