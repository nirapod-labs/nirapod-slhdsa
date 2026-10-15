# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/gate.py
# ==========
#
# The gates of ci.yml: the jobs whose success stands for the others.
#
#   gate.py all-checks WORKFLOW NEEDS_JSON PLAN_DIR RESULTS
#       The status check branch protection requires. It passes only if
#
#         - the jobs in `needs` are exactly the other jobs of WORKFLOW, so a
#           job added without being added here fails instead of going
#           unchecked;
#         - lint, reuse, source, plan and proofs succeeded;
#         - every other job succeeded if the plan gave it work, and was
#           skipped if not: nothing else (a job skipped because one before
#           it failed counts as passing in branch protection, so this job
#           runs whatever happened and turns that into a failure);
#         - the plan agrees with the tree: the legs, keys and applicability
#           computed again here equal plan.json's;
#         - every leg the plan ran has a PASS record of its key among this
#           run's results, and every leg it reused has its record in the
#           plan's reused/ directory, valid for its key and run.
#
#       Its summary lists every check and platform with its final status:
#       PASS (run here), the status of a reused record with the run that
#       recorded it, NOT APPLICABLE or NOT RUN.
#
#   gate.py proofs NEEDS_JSON PLAN_DIR RESULTS
#       The proof shards: the shard list of proofs/Makefile
#       (`make -s -C proofs list-shards`) equals the registry's; every
#       shard passed, here or in a reused record; the shard job succeeded
#       if the plan gave it shards and was skipped if not.
#
# NEEDS_JSON is the job's `needs` context, serialised with toJSON(needs).
# RESULTS holds the records this run's jobs uploaded (results-*). Exit 1 on
# any failure, each one printed.

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plan as planner  # noqa: E402
import key  # noqa: E402
import record  # noqa: E402
import registry  # noqa: E402

ALWAYS = ("lint", "reuse", "source", "plan", "proofs")


def workflow_jobs(path):
    """The keys of the workflow's `jobs:` mapping: the lines indented by
    exactly two spaces under it, as the workflows here are written."""
    jobs, inside = [], False
    with open(path, encoding="utf-8") as f:
        for line in f:
            if re.match(r"^jobs:\s*$", line):
                inside = True
                continue
            if inside and re.match(r"^\S", line):
                break
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if inside and m:
                jobs.append(m.group(1))
    return jobs


def planned(plan, job):
    j = plan["jobs"]
    if job.startswith("native-"):
        return j["native"].get(job[len("native-"):], {}).get("run")
    # warm runs only in warm mode, in which this gate does not run.
    return {"toolchain-x86": j["x86"] != "none", "proof-shards": bool(j["shards"]),
            "agree": j["agree"], "warm": False}.get(job)


def leg_status(leg, plan_dir, results):
    """(final status, detail, problem or None) of one leg."""
    if leg["decision"] in ("NOT APPLICABLE", "NOT RUN"):
        return leg["decision"], leg["reason"], None
    if leg["decision"] == "REUSED":
        d = os.path.join(plan_dir, "reused", leg["key"])
        try:
            rec, _, _ = record.read_dir(d)
            record.validate(rec, leg["key"], leg["text"], leg["record"]["run"])
        except (OSError, record.RecordError) as e:
            return "FAIL", "", f"the reused record of {leg['key']}: {e}"
        r = leg["record"]
        return rec["status"], f"reused from run {r['run']} ({r['commit'][:12]}, image {r['image']})", None
    d = os.path.join(results, leg["key"])
    try:
        with open(os.path.join(d, "record"), encoding="utf-8") as f:
            rec = record.parse(f.read())
    except (OSError, record.RecordError) as e:
        return "FAIL", "", f"{leg['check']} on {leg['platform']} ran but left no valid record ({e})"
    if rec["key"] != leg["key"] or rec["key_text"] != leg["text"] or rec["status"] != "PASS":
        return "FAIL", "", f"the record of {leg['check']} on {leg['platform']} is not a PASS of its key"
    return "PASS", "run here", None


def cmd_all_checks(workflow, needs, plan_dir, results, reg, tree):
    problems = []
    jobs = workflow_jobs(workflow)
    if "all-checks" not in jobs:
        return ["no job all-checks in " + workflow], []
    expected = set(jobs) - {"all-checks"}
    problems += [f"{j}: not in the needs of all-checks" for j in sorted(expected - set(needs))]
    problems += [f"{j}: in the needs of all-checks but not a job of {workflow}"
                 for j in sorted(set(needs) - expected)]
    with open(os.path.join(plan_dir, "plan.json"), encoding="utf-8") as f:
        plan = json.load(f)
    for j in sorted(needs):
        result = needs[j].get("result")
        if j in ALWAYS:
            want = "success"
        else:
            p = planned(plan, j)
            if p is None:
                problems.append(f"{j}: a job the gate does not know")
                continue
            want = "success" if p else "skipped"
        if result != want:
            problems.append(f"{j}: {result}, expected {want}")
    # The plan against the tree.
    again = planner.compute(reg, tree)
    strip = lambda legs: [(l["check"], l["platform"], l["key"], l["text"],
                           l["decision"] if l["decision"] in ("NOT APPLICABLE", "NOT RUN") else "APPLIES")
                          for l in legs]
    if strip(again) != strip(plan["legs"]):
        problems.append("the plan's legs, keys or applicability differ from this tree's")
    if planner.jobs(reg, plan["legs"]) != plan["jobs"]:
        problems.append("the plan's jobs do not follow from its decisions")
    rows = []
    for leg in plan["legs"]:
        status, detail, problem = leg_status(leg, plan_dir, results)
        if problem:
            problems.append(problem)
        rows.append(f"| {leg['check']} | {leg['platform']} | {status} | {detail} |")
    return problems, rows


def cmd_proofs(needs, plan_dir, results, shards, reg):
    problems = []
    listed = shards.split()
    registered = [c["shard"] for c in reg["checks"].values() if c["recipe"] == "proofs"]
    if sorted(listed) != sorted(registered) or len(set(listed)) != len(listed):
        problems.append(f"proofs/Makefile lists shards {listed}, the registry {registered}")
    with open(os.path.join(plan_dir, "plan.json"), encoding="utf-8") as f:
        plan = json.load(f)
    legs = [l for l in plan["legs"] if l["recipe"] == "proofs"]
    if sorted(l["shard"] for l in legs) != sorted(registered):
        problems.append("the plan does not hold every proof shard")
    rows = []
    for leg in legs:
        status, detail, problem = leg_status(leg, plan_dir, results)
        if problem:
            problems.append(problem)
        elif status != "PASS":
            problems.append(f"shard {leg['shard']}: {status}; every shard must pass")
        rows.append(f"| {leg['shard']} | {status} | {detail} |")
    want = "success" if plan["jobs"]["shards"] else "skipped"
    got = needs.get("proof-shards", {}).get("result")
    if got != want:
        problems.append(f"proof-shards: {got}, expected {want}")
    return problems, rows


def report(title, header, rows, problems):
    lines = [f"### {title}: {'FAIL' if problems else 'PASS'}", "", header,
             "|" + "---|" * (header.count("|") - 1)] + rows
    if problems:
        lines += [""] + [f"- {p}" for p in problems]
    out = "\n".join(lines) + "\n"
    print(out, end="")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(out)


def main(argv):
    try:
        if len(argv) == 6 and argv[1] == "all-checks":
            reg, tree = registry.load(), key.Tree()
            problems, rows = cmd_all_checks(argv[2], json.loads(argv[3]), argv[4], argv[5],
                                            reg, tree)
            report("all-checks", "| check | platform | status | detail |", rows, problems)
            return 1 if problems else 0
        if len(argv) == 5 and argv[1] == "proofs":
            listed = subprocess.run(["make", "-s", "-C", "proofs", "list-shards"],
                                    capture_output=True, text=True, check=True).stdout
            problems, rows = cmd_proofs(json.loads(argv[2]), argv[3], argv[4], listed,
                                        registry.load())
            report("proofs", "| shard | status | detail |", rows, problems)
            return 1 if problems else 0
    except (OSError, ValueError, KeyError, registry.RegistryError, key.KeyFailure,
            subprocess.CalledProcessError,
            planner.components.ComponentError) as e:
        print(f"gate.py: FAIL: {e}", file=sys.stderr)
        return 1
    print("usage: gate.py all-checks WORKFLOW NEEDS PLAN_DIR RESULTS | "
          "proofs NEEDS PLAN_DIR RESULTS", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
