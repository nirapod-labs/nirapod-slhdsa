# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_retry.py
# ======================
#
# The retry classifier (ci/retry.py) on the jobs and annotations of
# three real runs of ci.yml, as the API returned them (fields the
# classifier does not read removed; the attempt set to 1, the state the
# retry workflow sees):
#
#   no-runner     pull request #21, run 38420151018: macos-aarch64 /
#                 analysis never got a runner (conclusion cancelled,
#                 runner 0, no steps, "The job was not acquired by Runner
#                 of type hosted even after multiple attempts"); every
#                 check passed; all-checks failed because of it
#   step-failure  pull request #5, run 38329391739: agree failed in a
#                 step, all-checks failed after it
#   superseded    pull request #21, run 38413791208: cancelled by a newer
#                 push ("Canceling since a higher priority waiting request
#                 for ci-21 exists")
#
# and on variations of them that each remove one condition of a retry.

import copy
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import fakeapi  # noqa: E402
import retry  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "retry")


def load(name):
    d = os.path.join(FIXTURES, name)
    with open(os.path.join(d, "run.json")) as f:
        run = json.load(f)
    with open(os.path.join(d, "jobs.json")) as f:
        jobs = json.load(f)["jobs"]
    ann = {}
    for fn in os.listdir(os.path.join(d, "annotations")):
        with open(os.path.join(d, "annotations", fn)) as f:
            ann[int(fn[:-5])] = json.load(f)
    return run, jobs, ann


def job(jobs, name):
    return next(j for j in jobs if j["name"] == name)


class Classifier(unittest.TestCase):
    def test_no_runner_run_retries_exactly_that_job(self):
        run, jobs, ann = load("no-runner")
        ok, ids, rows, _ = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertTrue(ok)
        self.assertEqual(ids, [115376379056])
        classes = {name: cls for name, _, cls, _ in rows}
        self.assertEqual(classes, {"macos-aarch64 / analysis": "no-runner", "all-checks": "gate"})

    def test_step_failure_is_never_retried(self):
        run, jobs, ann = load("step-failure")
        ok, ids, rows, _ = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertFalse(ok)
        self.assertEqual(ids, [])
        self.assertEqual({n: c for n, _, c, _ in rows}, {"agree": "gate", "all-checks": "gate"})

    def test_step_failure_beside_a_runner_loss_is_not_retried(self):
        run, jobs, ann = load("no-runner")
        jobs = copy.deepcopy(jobs)
        t = job(jobs, "linux-x86_64 / test")
        t["conclusion"] = "failure"
        t["steps"][5]["conclusion"] = "failure"
        ok, _, rows, reason = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertFalse(ok)
        self.assertIn("linux-x86_64 / test", reason)

    def test_concurrency_cancellation_is_not_retried(self):
        run, jobs, ann = load("superseded")
        ok, _, _, _ = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertFalse(ok)
        # The same cancellation on a job that is not a gate.
        jobs = copy.deepcopy(jobs)
        p = job(jobs, "proofs")
        p["name"] = "linux-x86_64 / test"
        cls, _ = retry.classify_job(p, ann[p["id"]])
        self.assertEqual(cls, "failed")

    def test_second_attempt_is_not_retried(self):
        run, jobs, ann = load("no-runner")
        run = dict(run, run_attempt=2)
        ok, _, _, reason = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertFalse(ok)
        self.assertIn("attempt 2", reason)

    def test_superseded_head_is_not_retried(self):
        run, jobs, ann = load("no-runner")
        ok, _, _, reason = retry.decide(run, jobs, ann, {"0" * 40})
        self.assertFalse(ok)
        self.assertIn("newer head", reason)
        ok, _, _, _ = retry.decide(run, jobs, ann, set())
        self.assertFalse(ok)

    def test_timeout_is_not_retried(self):
        run, jobs, ann = load("no-runner")
        ann = copy.deepcopy(ann)
        ann[115376379056] = [{"annotation_level": "failure", "message":
                              "The job running on runner GitHub Actions 7 has exceeded the "
                              "maximum execution time of 360 minutes."}]
        ok, _, rows, _ = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertFalse(ok)
        self.assertIn(("macos-aarch64 / analysis", 115376379056, "timeout"),
                      [r[:3] for r in rows])

    def test_lost_runner_without_failed_step_is_retried(self):
        run, jobs, ann = load("no-runner")
        jobs = copy.deepcopy(jobs)
        ann = copy.deepcopy(ann)
        lost = job(jobs, "macos-aarch64 / analysis")
        lost.update(conclusion="failure", runner_id=1000008940,
                    steps=[{"name": "Check out", "conclusion": "success"},
                           {"name": "Run the checks", "conclusion": "cancelled"}])
        ann[lost["id"]] = [{"annotation_level": "failure", "message":
                            "The hosted runner: GitHub Actions 9 lost communication with the "
                            "server. Anything in your workflow that terminates the runner "
                            "process, starves it for CPU/Memory, or blocks its network access "
                            "can cause this error."}]
        ok, ids, rows, _ = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertTrue(ok)
        self.assertEqual(ids, [lost["id"]])
        # The same job with a failed step is a failure, annotation or not.
        lost["steps"][1]["conclusion"] = "failure"
        ok, _, _, _ = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertFalse(ok)

    def test_manual_cancellation_is_not_retried(self):
        run, jobs, ann = load("no-runner")
        jobs = copy.deepcopy(jobs)
        ann = copy.deepcopy(ann)
        j = job(jobs, "macos-aarch64 / analysis")
        j.update(runner_id=1000008940, steps=[{"name": "Check out", "conclusion": "success"}])
        ann[j["id"]] = [{"annotation_level": "failure", "message": "The operation was canceled."}]
        ok, _, _, _ = retry.decide(run, jobs, ann, {run["head_sha"]})
        self.assertFalse(ok)

    def test_push_runs_need_no_pull_request(self):
        run, jobs, ann = load("no-runner")
        run = dict(run, event="push")
        ok, _, _, _ = retry.decide(run, jobs, ann, None)
        self.assertTrue(ok)


class Online(unittest.TestCase):
    """retry.py run against a stand-in API: the queries it makes and the
    re-run it requests."""

    def setUp(self):
        self.api = fakeapi.Server()
        self.addCleanup(self.api.close)
        self.env = {k: os.environ.get(k) for k in
                    ("GITHUB_API_URL", "GITHUB_REPOSITORY", "GH_TOKEN", "GITHUB_STEP_SUMMARY")}
        os.environ.update(GITHUB_API_URL=self.api.url, GITHUB_REPOSITORY="o/r", GH_TOKEN="t")
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        self.addCleanup(self.restore)

    def restore(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def serve(self, name, pr_head):
        run, jobs, ann = load(name)
        run = dict(run, head_repository={"owner": {"login": "o"}}, pull_requests=[])
        r = self.api.routes
        r[f"/repos/o/r/actions/runs/{run['id']}"] = run
        r[f"/repos/o/r/actions/runs/{run['id']}/attempts/1/jobs"] = {"jobs": jobs}
        for jid, a in ann.items():
            r[f"/repos/o/r/check-runs/{jid}/annotations"] = a
        r["/repos/o/r/pulls"] = [{"head": {"sha": pr_head}}]
        r["/repos/o/r/actions/jobs/115376379056/rerun"] = {}
        return run

    def posts(self):
        return [p for m, p, _, _ in self.api.requests if m == "POST"]

    def test_requests_one_job_rerun(self):
        run = self.serve("no-runner", load("no-runner")[0]["head_sha"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(retry.cmd_run(run["id"], False), 0)
        self.assertEqual(self.posts(), ["/repos/o/r/actions/jobs/115376379056/rerun"])
        # The open pull requests were looked up by the head branch.
        self.assertIn("/repos/o/r/pulls?state=open&head=o%3Aproof%2Ffips205-security",
                      [p for m, p, _, _ in self.api.requests])

    def test_superseded_head_requests_nothing(self):
        run = self.serve("no-runner", "0" * 40)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(retry.cmd_run(run["id"], False), 0)
        self.assertEqual(self.posts(), [])

    def test_api_error_requests_nothing(self):
        run = self.serve("no-runner", load("no-runner")[0]["head_sha"])
        del self.api.routes["/repos/o/r/check-runs/115376379056/annotations"]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(retry.main(["retry.py", "run", str(run["id"])]), 1)
        self.assertEqual(self.posts(), [])


if __name__ == "__main__":
    unittest.main()
