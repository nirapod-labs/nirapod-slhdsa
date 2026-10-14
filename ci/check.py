# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/check.py
# ===========
#
# Runs checks and records them. A check is one recipe,
# `make -f ci/checks/<recipe>.mk ci-<recipe>`, run with the
# parameters of its platform; the same command runs on a workstation with
# the pinned toolchain on the PATH (`check.py run`).
#
# Usage, from the repository root:
#
#   check.py run CHECK PLATFORM
#       compute the key, decide whether the check applies, run it, record it
#   check.py try PLATFORM CHECK...
#       run the checks without recording them, for a toolchain other than
#       the pinned one (.github/workflows/drift.yml); fails if any failed
#   check.py run-planned PLAN PLATFORM [SHARD]
#       the checks plan.json (ci/plan.py) gives this platform (or the
#       one proof shard), one after another; a failing check does not stop
#       the others, and the command fails at the end if any failed
#   check.py agree PLAN RECORDS BUILDS
#       agree: the core transcripts of every platform (from the test-core
#       records under RECORDS, of this run or reused) are byte-identical,
#       and so are the extracted compiler and its assumptions in the build
#       records BUILDS/buildrecord-<platform>/ (ci/toolchain.py agree)
#
# Before a check runs, its key is computed again and compared with the
# plan's, and so is its applicability: the plan and the jobs cannot
# silently disagree about what a check reads. The host must be the
# platform's (system and machine), and in CI the runner label must be the
# registry's (CI_RUNNER).
#
# A check that passed is recorded under build/records/<key>/ (record, log,
# kept files; ci/record.py), with status PASS. A check that failed
# leaves its log under build/records/failed/ and no record: FAIL is never
# recorded. The workflow uploads build/records: as records-<job> from runs
# on main, the ones pull requests reuse, and as results-<job> from every
# run, for the gates of the same run.

import json
import os
import platform as host_platform
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import components  # noqa: E402
import key  # noqa: E402
import record  # noqa: E402
import registry  # noqa: E402

RECORDS = "build/records"


class Failure(Exception):
    pass


def summary(text):
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)


def host_is(reg, plat):
    p = reg["platforms"][plat]
    if (host_platform.system(), host_platform.machine()) != (p["system"], p["machine"]):
        raise Failure(f"this host ({host_platform.system()} {host_platform.machine()}) is not {plat}")
    runner = os.environ.get("CI_RUNNER")
    if os.environ.get("GITHUB_ACTIONS") == "true" and runner != p["runner"]:
        raise Failure(f"the job runs on '{runner}', the registry names '{p['runner']}' for {plat}")


def make_command(reg, cid, plat):
    c, p = reg["checks"][cid], reg["platforms"][plat]
    jobs = c.get("jobs", p["jobs"])
    cmd = ["make", "-f", f"ci/checks/{c['recipe']}.mk", f"ci-{c['recipe']}",
           f"CI_PLATFORM={plat}", f"CI_TARGET={p['target']}", f"CI_ARCH={p['arch']}",
           f"CI_JOBS={jobs}", f"CI_RULES=ci/rules/{cid}.toml"]
    if c.get("shard"):
        cmd.append(f"CI_SHARD={c['shard']}")
    if c["recipe"] in ("test-hash", "analysis-hash"):
        sets = registry.hash_sets()
        names = registry.sets_for(sets, p["arch"])
        cmd.append("CI_HASH_SETS=" + " ".join(names))
        for n in names:
            cmd.append(f"CI_HASH_VARS_{n}=" + " ".join(sets[n]["vars"]))
            cmd.append(f"CI_HASH_CPU_{n}=" + " ".join(sets[n]["cpu"]))
    if c.get("opam"):
        cmd = ["ci/toolchain.sh", "exec"] + cmd
    return cmd


def run_logged(cmd, log_path):
    """Run CMD, its output both printed and written to LOG_PATH; its status."""
    with open(log_path, "w", encoding="utf-8") as log:
        log.write("+ " + " ".join(cmd) + "\n")
        log.flush()
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for raw in p.stdout:
            line = raw.decode("utf-8", errors="replace")
            sys.stdout.write(line)
            log.write(line)
        return p.wait()


def host_lines():
    lines = [host_platform.platform()]
    try:
        cc = subprocess.run(["cc", "--version"], capture_output=True, text=True).stdout
        lines.append("cc " + (cc.splitlines()[0] if cc else "?"))
    except OSError:
        lines.append("cc not found")
    return lines


def write_record(reg, cid, plat, name, text, log_path, env=os.environ):
    c, p = reg["checks"][cid], reg["platforms"][plat]
    keep = [k.replace("{target}", p["target"]) for k in c.get("keep", [])]
    with open(log_path, encoding="utf-8", errors="replace") as f:
        log = f.read()
    counts = [l for l in log.splitlines() if l.startswith("counts ")]
    rec = record.render("PASS", name, text, env, host=host_lines(),
                        build_key=env.get("CI_BUILD_KEY") or None, counts=counts, files=keep)
    d = os.path.join(RECORDS, name)
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(os.path.join(d, "files"))
    for k in keep:
        if not os.path.isfile(k):
            raise Failure(f"{cid}: {k}, which the check keeps, is missing")
        os.makedirs(os.path.dirname(os.path.join(d, "files", k)), exist_ok=True)
        shutil.copy(k, os.path.join(d, "files", k))
    shutil.copy(log_path, os.path.join(d, "log"))
    with open(os.path.join(d, "record"), "w", encoding="utf-8") as f:
        f.write(rec)
    return d


def run_one(reg, tree, cid, plat, expect=None, keep_record=True):
    """True if the check passed (and is recorded), False if it failed."""
    name, text = key.key(tree, reg, cid, plat)
    if expect is not None and (name, text) != expect:
        raise Failure(f"{cid} on {plat}: the key here is {name}, the plan has {expect[0]}")
    status, reason = components.applicability(reg, cid, components.present(reg, list(tree.files)))
    if status != "RUN":
        raise Failure(f"{cid}: {status} ({reason}); the plan decides that, nothing runs")
    os.makedirs(os.path.join(RECORDS, "failed"), exist_ok=True)
    log_path = os.path.join(RECORDS, "failed", f"{cid}-{plat}.log")
    print(f"::group::{cid} on {plat}")
    start = time.monotonic()
    rc = run_logged(make_command(reg, cid, plat), log_path)
    minutes = (time.monotonic() - start) / 60
    print("::endgroup::")
    if rc != 0:
        print(f"check {cid} on {plat}: FAIL (exit {rc}) after {minutes:.1f} min; log {log_path}")
        summary(f"| {cid} | {plat} | FAIL | {minutes:.1f} min |\n")
        return False
    if not keep_record:
        print(f"check {cid} on {plat}: PASS after {minutes:.1f} min, not recorded; log {log_path}")
        summary(f"| {cid} | {plat} | PASS | {minutes:.1f} min |\n")
        return True
    write_record(reg, cid, plat, name, text, log_path)
    os.remove(log_path)
    print(f"check {cid} on {plat}: PASS after {minutes:.1f} min, recorded under {name}")
    summary(f"| {cid} | {plat} | PASS | {minutes:.1f} min |\n")
    return True


def load_plan(path):
    with open(path, encoding="utf-8") as f:
        plan = json.load(f)
    if plan.get("format") != 2:
        raise Failure(f"{path}: not a plan of format 2")
    return plan


def cmd_run_planned(plan_path, plat, shard=None):
    reg, tree = registry.load(), key.Tree()
    host_is(reg, plat)
    plan = load_plan(plan_path)
    legs = [l for l in plan["legs"] if l["platform"] == plat and l["decision"] == "RUN"
            and (l["shard"] == shard if shard else l["recipe"] != "proofs")]
    if shard and len(legs) != 1:
        raise Failure(f"the plan has no proof shard {shard} to run")
    summary("| check | platform | status | time |\n|---|---|---|---|\n")
    failed = [l["check"] for l in legs
              if not run_one(reg, tree, l["check"], plat, (l["key"], l["text"]))]
    print(f"run-planned: {len(legs) - len(failed)} of {len(legs)} checks passed on {plat}"
          + (f"; FAILED: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


def cmd_try(plat, checks):
    reg, tree = registry.load(), key.Tree()
    host_is(reg, plat)
    summary("| check | platform | status | time |\n|---|---|---|---|\n")
    failed = [c for c in checks if not run_one(reg, tree, c, plat, keep_record=False)]
    print(f"try: {len(checks) - len(failed)} of {len(checks)} checks passed on {plat}"
          + (f"; FAILED: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


def cmd_run(cid, plat):
    reg, tree = registry.load(), key.Tree()
    host_is(reg, plat)
    return 0 if run_one(reg, tree, cid, plat) else 1


def find_record(dirs, name):
    for d in dirs:
        p = os.path.join(d, name)
        if os.path.isfile(os.path.join(p, "record")):
            return p
    return None


def cmd_agree(plan_path, records_dir, builds_dir):
    import toolchain
    reg, tree = registry.load(), key.Tree()
    plan = load_plan(plan_path)
    leg = next(l for l in plan["legs"] if l["check"] == "agree")
    if (leg["key"], leg["text"]) != key.agree_key(tree, reg) or leg["decision"] != "RUN":
        raise Failure("agree: the plan's key or decision differs from this tree's")
    over = reg["agree"]["over"]
    transcripts = []
    for l in plan["legs"]:
        if l["check"] != over:
            continue
        src = [records_dir, os.path.join(os.path.dirname(plan_path), "reused")]
        d = find_record(src, l["key"])
        if d is None:
            raise Failure(f"agree: no record of {over} on {l['platform']} ({l['key']})")
        rec, _, kept = record.read_dir(d)
        if rec["status"] != "PASS" or rec["key_text"] != l["text"]:
            raise Failure(f"agree: the record of {over} on {l['platform']} is not a pass of its key")
        t = [v for p, v in kept.items() if "transcript" in p]
        if len(t) != 1:
            raise Failure(f"agree: the record of {over} on {l['platform']} keeps no transcript")
        transcripts.append((l["platform"], t[0]))
    first = transcripts[0]
    for plat, data in transcripts[1:]:
        if data != first[1]:
            raise Failure(f"agree: FAIL, the core transcript of {plat} differs from {first[0]}")
    print(f"agree: the core transcripts of {len(transcripts)} platforms are identical "
          f"({len(first[1].splitlines())} lines)")
    dirs = [os.path.join(builds_dir, f"buildrecord-{p}") for p in reg["platforms"]]
    toolchain.cmd_agree(dirs, reg)
    os.makedirs(RECORDS, exist_ok=True)
    log = os.path.join(RECORDS, "agree.log")
    with open(log, "w", encoding="utf-8") as f:
        f.write("agree: transcripts and build records identical on every platform\n")
    d = os.path.join(RECORDS, leg["key"])
    os.makedirs(os.path.join(d, "files"), exist_ok=True)
    shutil.copy(log, os.path.join(d, "log"))
    with open(os.path.join(d, "record"), "w", encoding="utf-8") as f:
        f.write(record.render("PASS", leg["key"], leg["text"], os.environ))
    os.remove(log)
    return 0


def main(argv):
    import toolchain
    try:
        if len(argv) == 4 and argv[1] == "run":
            return cmd_run(argv[2], argv[3])
        if len(argv) >= 4 and argv[1] == "try":
            return cmd_try(argv[2], argv[3:])
        if len(argv) in (4, 5) and argv[1] == "run-planned":
            return cmd_run_planned(argv[2], argv[3], argv[4] if len(argv) == 5 else None)
        if len(argv) == 5 and argv[1] == "agree":
            return cmd_agree(argv[2], argv[3], argv[4])
    except (Failure, toolchain.Failure, key.KeyFailure, registry.RegistryError,
            components.ComponentError, record.RecordError, OSError, ValueError) as e:
        print(f"check.py: {e}", file=sys.stderr)
        return 1
    print("usage: check.py run CHECK PLATFORM | try PLATFORM CHECK... | "
          "run-planned PLAN PLATFORM [SHARD] | "
          "agree PLAN RECORDS BUILDS", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
