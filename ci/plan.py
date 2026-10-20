# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/plan.py
# ==========
#
# Usage: python3 -I ci/plan.py OUT
#
# The plan of a run of ci.yml: for every check on every platform
# (ci/checks.toml) and for agree, its key (ci/key.py) and what
# this run does with it:
#
#   NOT APPLICABLE  its component is absent (ci/components.py); this
#                   follows from the tree alone, so it is decided here on
#                   every run, needs no runner, and is never recorded
#   NOT RUN         its component is absent while code it would check is
#                   present: a gap, reported as such on every run
#   REUSED          a pull request, and the newest run of ci.yml on main
#                   that ran the check under the same key recorded a pass
#                   (ci/store.py); the summary names that run, its
#                   commit and its runner image
#   RUN             anything else, and everything on a push to main or of
#                   a tag, the schedule and a manual run: main and release
#                   tags never reuse
#
# From the decisions follow the jobs (written to $GITHUB_OUTPUT):
#
#   native-<platform>=true|false and need-<platform>=none|compiler|switch
#                   a platform's job runs when it has a check to run, or
#                   when agree runs (agree needs every platform's build
#                   record); it needs the most of its checks' toolchains
#   shards=[...]    the proof shards to run, each with the toolchain it
#                   needs (JSON, for a matrix)
#   toolchain-x86=true|false, need-x86=...
#                   the linux-x86_64 toolchain job, for the linux-x86_64
#                   checks and the proof shards
#   agree=true|false
#
# OUT receives plan.json (every leg, its key text and decision, and for a
# reused one the run that recorded it) and reused/<key>/, the reused
# records, for the jobs that read them (agree takes reused transcripts from
# there). The job summary is one table.
#
# Any error looking records up (the API, a malformed artifact) is a
# warning, and every check whose record was not found runs: slower, never
# a weaker result.

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import components  # noqa: E402
import ghapi  # noqa: E402
import key  # noqa: E402
import registry  # noqa: E402
import store  # noqa: E402

TOOLCHAIN_ORDER = {"none": 0, "compiler": 1, "switch": 2}
X86 = "linux-x86_64"


def compute(reg, tree):
    """The legs of the plan before any lookup: key and applicability."""
    found = components.present(reg, list(tree.files))
    legs = []
    for cid, platform in registry.legs(reg):
        name, text = key.key(tree, reg, cid, platform)
        status, reason = components.applicability(reg, cid, found)
        c = reg["checks"][cid]
        legs.append({"check": cid, "platform": platform, "key": name, "text": text,
                     "recipe": c["recipe"], "shard": c.get("shard"),
                     "toolchain": c["toolchain"],
                     "decision": "RUN" if status == "RUN" else status, "reason": reason,
                     "record": None})
    name, text = key.agree_key(tree, reg)
    status, reason = components.applicability(reg, "agree", found)
    legs.append({"check": "agree", "platform": "any", "key": name, "text": text,
                 "recipe": None, "shard": None, "toolchain": "none",
                 "decision": "RUN" if status == "RUN" else status, "reason": reason,
                 "record": None})
    return legs


def reuse(legs, st, out_dir):
    """Mark the legs whose record a run on main has as REUSED, and write
    those records under OUT_DIR/reused. Returns warnings."""
    wanted = {l["key"]: l["text"] for l in legs if l["decision"] == "RUN"}
    if not wanted:
        return []
    try:
        found, notes = st.find_records(wanted)
    except ghapi.ApiError as e:
        return [f"records could not be looked up ({e}); every check runs"]
    for l in legs:
        if l["key"] in found:
            run, rec, log, kept = found[l["key"]]
            l["decision"] = "REUSED"
            l["reason"] = f"recorded {rec['status']} on main with the same key"
            l["record"] = {"run": run["id"], "url": rec["run_url"], "commit": rec["commit"],
                           "recorded": rec["recorded"], "image": rec["image"],
                           "status": rec["status"], "event": rec["event"]}
            store.write_record_dir(os.path.join(out_dir, "reused", l["key"]), rec["raw"], log, kept)
    return [f"not reused: {n}" for n in notes]


def jobs(reg, legs):
    agree = next(l for l in legs if l["check"] == "agree")["decision"] == "RUN"
    out = {"agree": agree, "shards": [], "native": {}, "x86": "none"}
    for platform in reg["platforms"]:
        need, run = "none", False
        for l in legs:
            if l["platform"] == platform and l["decision"] == "RUN" and l["recipe"] != "proofs":
                run = True
                need = max(need, l["toolchain"], key=TOOLCHAIN_ORDER.get)
        if agree:
            run, need = True, max(need, "compiler", key=TOOLCHAIN_ORDER.get)
        out["native"][platform] = {"run": run, "need": need}
    x86 = out["native"][X86]["need"] if out["native"][X86]["run"] else "none"
    for l in legs:
        if l["recipe"] == "proofs" and l["decision"] == "RUN":
            out["shards"].append(l["shard"])
            x86 = max(x86, l["toolchain"], key=TOOLCHAIN_ORDER.get)
    out["x86"] = x86
    return out


def summary(plan):
    rows = ["### plan", "",
            f"Event {plan['event']}; records {'reused from main' if plan['reuse'] else 'not reused (only a pull request reuses)'}.",
            "", "| check | platform | decision | detail |", "|---|---|---|---|"]
    for l in plan["legs"]:
        detail = l["reason"]
        r = l["record"]
        if r:
            detail = (f"{r['status']}, run [{r['run']}]({r['url'].split(' ')[0]}) at "
                      f"{r['commit'][:12]}, {r['recorded']}, image {r['image']}")
        rows.append(f"| {l['check']} | {l['platform']} | {l['decision']} | {detail} |")
    j = plan["jobs"]
    started = ([f"native {p} ({v['need']})" for p, v in j["native"].items() if v["run"]]
               + ([f"x86 toolchain ({j['x86']})"] if j["x86"] != "none" else [])
               + ([f"proof shards {' '.join(j['shards'])}"] if j["shards"] else [])
               + (["agree"] if j["agree"] else []))
    rows += ["", "Jobs: " + (", ".join(started) if started else "none beyond the quick checks") + "."]
    for w in plan["warnings"]:
        rows.append(f"- warning: {w}")
    return "\n".join(rows) + "\n"


def may_reuse(env):
    """Only a pull request's run reuses records. A tag's ref never belongs
    to one; the test is there so that a run of a tag cannot reuse whatever
    event GitHub reports for it."""
    return (env.get("GITHUB_EVENT_NAME") == "pull_request"
            and not env.get("GITHUB_REF", "").startswith("refs/tags/"))


def make_plan(env, reg, tree, st, out_dir):
    event = env.get("GITHUB_EVENT_NAME", "local")
    legs = compute(reg, tree)
    reuse_ok = may_reuse(env)
    warnings = reuse(legs, st, out_dir) if reuse_ok else []
    plan = {"format": 2, "event": event, "reuse": reuse_ok, "legs": legs,
            "warnings": warnings}
    plan["jobs"] = jobs(reg, legs)
    return plan


def outputs(plan):
    j = plan["jobs"]
    need = {l["shard"]: l["toolchain"] for l in plan["legs"] if l["recipe"] == "proofs"}
    shards = [{"shard": s, "need": need[s]} for s in j["shards"]]
    lines = []
    for p, v in j["native"].items():
        lines += [f"native-{p}={'true' if v['run'] else 'false'}", f"need-{p}={v['need']}"]
    lines += [f"toolchain-x86={'true' if j['x86'] != 'none' else 'false'}", f"need-x86={j['x86']}",
              "shards=" + json.dumps(shards, separators=(",", ":")),
              f"agree={'true' if j['agree'] else 'false'}"]
    return lines


def main(argv):
    if len(argv) != 2:
        print("usage: plan.py OUT", file=sys.stderr)
        return 2
    out_dir = argv[1]
    try:
        reg, tree = registry.load(), key.Tree()
        os.makedirs(out_dir, exist_ok=True)
        st = store.Store(store.api_from_env()) if may_reuse(os.environ) else None
        plan = make_plan(os.environ, reg, tree, st, out_dir)
    except (registry.RegistryError, key.KeyFailure, components.ComponentError,
            ghapi.ApiError) as e:
        print(f"plan.py: {e}", file=sys.stderr)
        return 1
    with open(os.path.join(out_dir, "plan.json"), "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=1, sort_keys=True)
    text = summary(plan)
    print(text, end="")
    for w in plan["warnings"]:
        print(f"::warning title=plan::{w}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    for line in outputs(plan):
        print(line)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                f.write(line + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
