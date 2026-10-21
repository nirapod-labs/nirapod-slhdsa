# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_workflows.py
# ==========================
#
# The job conditions of the workflows under .github/workflows: a
# cancelled run stops its jobs.
#
# Cancelling a run re-evaluates the `if` of each running job and cancels
# only the jobs whose condition turns false; `always()` never does. A job
# that runs after a failed or skipped job and does real work therefore
# uses `!cancelled()`. With `always()` it ran on in the cancelled run, and
# the next run of its concurrency group waited for it to end.
#
# all-checks keeps `always()`: it is the required status check, and a
# skipped required check counts as passing.

import glob
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import registry  # noqa: E402

WORKFLOWS = os.path.join(registry.ROOT, ".github", "workflows")
ALWAYS = {("ci.yml", "all-checks")}


def job_conditions(path):
    """{job: the text of its job-level `if`}, for the jobs of the workflow
    that have one: the job keys indented by two spaces under `jobs:`, their
    `if:` by four, a folded condition continued on lines indented deeper."""
    conds, job, cond, inside = {}, None, None, False
    with open(path, encoding="utf-8") as f:
        for line in f:
            if cond is not None:
                if line.strip() and len(line) - len(line.lstrip(" ")) > 4:
                    conds[job] = (conds[job] + " " + line.strip()).strip()
                    continue
                cond = None
            if re.match(r"^jobs:\s*$", line):
                inside = True
                continue
            if not inside:
                continue
            if re.match(r"^\S", line):
                break
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                job = m.group(1)
                continue
            m = re.match(r"^    if:\s*(.*)$", line)
            if m and job:
                cond = conds[job] = re.sub(r"^[>|][-+]?$", "", m.group(1).strip())
    return conds


class Cancellation(unittest.TestCase):
    def conditions(self):
        found = {}
        for path in sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml"))):
            for job, cond in job_conditions(path).items():
                found[(os.path.basename(path), job)] = cond
        return found

    def test_only_all_checks_runs_on_in_a_cancelled_run(self):
        for (name, job), cond in self.conditions().items():
            if (name, job) in ALWAYS:
                continue
            with self.subTest(workflow=name, job=job):
                self.assertNotIn("always()", cond,
                                 f"{name} job {job}: always() keeps it running in a cancelled "
                                 f"run; use !cancelled()")

    def test_the_conditions_are_read(self):
        found = self.conditions()
        self.assertIn("always()", found[("ci.yml", "all-checks")])
        # A folded condition is read whole, up to its last line.
        self.assertIn("!cancelled()", found[("ci.yml", "native-linux-x86_64")])
        self.assertIn("need-linux-x86_64 == 'none'", found[("ci.yml", "native-linux-x86_64")])
        self.assertIn("!cancelled()", found[("ci.yml", "proofs")])

    def test_a_job_level_always_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.yml")
            with open(path, "w", encoding="utf-8") as f:
                f.write("on: push\njobs:\n  a:\n    if: >-\n      needs.b.result == 'success'\n"
                        "      || always()\n    steps:\n      - if: always()\n        run: true\n"
                        "  b:\n    steps:\n      - run: true\n")
            self.assertEqual(job_conditions(path),
                             {"a": "needs.b.result == 'success' || always()"})


if __name__ == "__main__":
    unittest.main()
