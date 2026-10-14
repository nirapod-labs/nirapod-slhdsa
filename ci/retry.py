# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/retry.py
# =================
#
# Usage: python3 -I tools/ci/retry.py run RUN_ID [--dry-run]
#        python3 -I tools/ci/retry.py classify RUN.json JOBS.json ANNOTATIONS_DIR
#
# Decides whether a completed run of ci.yml failed only because GitHub lost
# a job's runner or never gave it one, and if so re-runs it once
# (.github/workflows/ci-retry.yml). A retry runs the job again from the
# start, so it cannot turn a failure into a pass: the job has to pass by
# itself.
#
# Each job of the run's first attempt is put in one class:
#
#   ok        success or skipped
#   no-runner never started: conclusion `cancelled`, no runner (runner_id 0
#             or none) and no step, or a `cancelled` or `failure` job whose
#             annotations say the job was not acquired by a runner
#   lost      the runner went away while the job ran: conclusion
#             `cancelled` or `failure`, an annotation that the runner lost
#             communication with the server or received a shutdown
#             signal, and no step of the job concluded `failure`
#   gate      a job that only judges other jobs (GATES below) and did not
#             succeed; its failed step is its verdict on the jobs it
#             needs, and it is re-run with them. A gate alone never
#             starts a retry
#   timeout   the job hit its time limit (annotation "exceeded the maximum
#             execution time")
#   failed    anything else: a step failed, the job was cancelled by hand
#             or by a newer run of its concurrency group, or a pattern
#             above is missing
#
# How a failed step is told apart from a lost runner: a failed step is a
# step with conclusion `failure` in the job's steps, and GitHub writes the
# annotation "Process completed with exit code N" for it; a job without a
# runner has no steps at all; a lost runner leaves GitHub's own annotation
# and no failed step. A job that matches both (a failed step and a lost
# runner) is `failed`: when in doubt, nothing is retried.
#
# The run is retried only when all of these hold: it is the first attempt;
# at least one job is no-runner or lost; every job is ok, no-runner, lost
# or gate; and, for a pull request, its head is still the run's head
# commit (a re-run of a superseded commit would cancel the newer run, which
# shares its concurrency group). One job to re-run uses the job re-run
# endpoint, which also re-runs the jobs that need it; several use the
# endpoint that re-runs the failed jobs of the run, which takes cancelled
# jobs too.
#
# Any API error stops the script with status 1 and no retry. The job
# summary lists every job that is not ok, with its class and reason.

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghapi  # noqa: E402

# Jobs that only judge other jobs (ci.yml).
GATES = {"all-checks", "proofs", "agree"}

NOT_ACQUIRED = "The job was not acquired by Runner"
LOST = ("lost communication with the server", "The runner has received a shutdown signal")
TIMEOUT = "exceeded the maximum execution time"


def classify_job(job, annotations):
    """(class, reason) of one job of a completed run."""
    conclusion = job.get("conclusion")
    steps = job.get("steps") or []
    messages = [a.get("message") or "" for a in annotations]
    failed_steps = [s.get("name", "?") for s in steps if s.get("conclusion") == "failure"]
    if conclusion in ("success", "skipped"):
        return "ok", conclusion
    if any(TIMEOUT in m for m in messages):
        return "timeout", "the job exceeded its time limit"
    if job.get("name") in GATES and conclusion in ("failure", "cancelled"):
        return "gate", "judges jobs that did not succeed"
    if failed_steps:
        return "failed", "step failed: " + ", ".join(failed_steps)
    if conclusion == "cancelled" and not job.get("runner_id") and not steps:
        return "no-runner", "cancelled before any runner took it"
    if conclusion in ("cancelled", "failure") and any(NOT_ACQUIRED in m for m in messages):
        return "no-runner", "not acquired by a runner"
    if conclusion in ("cancelled", "failure") and any(p in m for m in messages for p in LOST):
        return "lost", "the runner was lost"
    return "failed", f"conclusion {conclusion}, no runner-loss annotation"


def decide(run, jobs, annotations, pr_heads):
    """(retry, job ids to re-run, table rows, reason). PR_HEADS: the current
    head commits of the open pull requests of the run's branch, or None for
    a run that is not a pull request's."""
    rows, infra, bad = [], [], []
    for job in sorted(jobs, key=lambda j: j.get("name", "")):
        cls, why = classify_job(job, annotations.get(job["id"], []))
        if cls == "ok":
            continue
        rows.append((job.get("name", "?"), job["id"], cls, why))
        if cls in ("no-runner", "lost"):
            infra.append(job["id"])
        elif cls != "gate":
            bad.append(job.get("name", "?"))
    if run.get("run_attempt") != 1:
        return False, [], rows, f"attempt {run.get('run_attempt')}; only a first attempt is retried"
    if not infra:
        return False, [], rows, "no job lost its runner or went without one"
    if bad:
        return False, [], rows, "a job failed by itself: " + ", ".join(bad)
    if pr_heads is not None and run.get("head_sha") not in pr_heads:
        return False, [], rows, "the pull request has a newer head, or none was found"
    return True, infra, rows, f"{len(infra)} job(s) lost their runner or got none"


def summary(run_id, retry, ids, rows, reason):
    out = [f"### ci-retry: run {run_id}: {'RETRY' if retry else 'no retry'}", "", reason + ".", ""]
    if rows:
        out += ["| job | id | class | reason |", "|---|---|---|---|"]
        out += [f"| {n} | {i} | {c} | {w} |" for n, i, c, w in rows]
    if retry:
        out += ["", "Re-run: " + ", ".join(str(i) for i in ids)]
    return "\n".join(out) + "\n"


def pull_request_heads(api, run):
    """Head commits of the open pull requests whose head is the run's branch."""
    if run.get("event") != "pull_request":
        return None
    heads = set()
    for pr in run.get("pull_requests") or []:
        heads.add(api.get(f"pulls/{int(pr['number'])}")["head"]["sha"])
    if not heads:
        owner = ((run.get("head_repository") or {}).get("owner") or {}).get("login")
        branch = run.get("head_branch")
        if owner and branch:
            for pr in api.get("pulls", state="open", head=f"{owner}:{branch}"):
                heads.add(pr["head"]["sha"])
    return heads


def cmd_run(run_id, dry_run):
    api = ghapi.Api(os.environ.get("GITHUB_REPOSITORY", ""))
    run = api.get(f"actions/runs/{run_id}")
    if run.get("path") != ".github/workflows/ci.yml":
        print(f"retry: run {run_id} is not a run of ci.yml ({run.get('path')})")
        return 1
    jobs = api.pages(f"actions/runs/{run_id}/attempts/1/jobs", "jobs")
    annotations = {}
    for job in jobs:
        if job.get("conclusion") not in ("success", "skipped"):
            annotations[job["id"]] = api.get(f"check-runs/{int(job['id'])}/annotations", per_page=100)
    retry, ids, rows, reason = decide(run, jobs, annotations, pull_request_heads(api, run))
    text = summary(run_id, retry, ids, rows, reason)
    print(text, end="")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    if retry and not dry_run:
        if len(ids) == 1:
            api.post(f"actions/jobs/{ids[0]}/rerun")
        else:
            api.post(f"actions/runs/{run_id}/rerun-failed-jobs")
        print(f"retry: re-run requested for run {run_id}")
    return 0


def cmd_classify(run_path, jobs_path, ann_dir):
    with open(run_path, encoding="utf-8") as f:
        run = json.load(f)
    with open(jobs_path, encoding="utf-8") as f:
        jobs = json.load(f)["jobs"]
    annotations = {}
    for job in jobs:
        p = os.path.join(ann_dir, f"{job['id']}.json")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                annotations[job["id"]] = json.load(f)
    pr_heads = {run["head_sha"]} if run.get("event") == "pull_request" else None
    retry, ids, rows, reason = decide(run, jobs, annotations, pr_heads)
    print(summary(run.get("id"), retry, ids, rows, reason), end="")
    return 0


def main(argv):
    try:
        if len(argv) in (3, 4) and argv[1] == "run" and argv[2].isdigit() \
                and (len(argv) == 3 or argv[3] == "--dry-run"):
            return cmd_run(int(argv[2]), len(argv) == 4)
        if len(argv) == 5 and argv[1] == "classify":
            return cmd_classify(argv[2], argv[3], argv[4])
    except ghapi.ApiError as e:
        print(f"retry: {e}; no retry", file=sys.stderr)
        return 1
    print("usage: retry.py run RUN_ID [--dry-run] | classify RUN.json JOBS.json ANNOTATIONS_DIR",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
