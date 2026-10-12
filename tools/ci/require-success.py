# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/require-success.py
# ===========================
#
# Usage: python3 -I tools/ci/require-success.py WORKFLOW SELF NEEDS_JSON
#
# The last job of a workflow, the one status check branch protection
# requires. WORKFLOW is the workflow file, SELF the id of this job in it,
# and NEEDS_JSON the `needs` context of this job, serialised by the
# workflow with toJSON(needs). It passes only if
#
#   - the jobs in `needs` are exactly the other jobs of WORKFLOW, so that a
#     job added to the workflow without being added here fails instead of
#     going unchecked; and
#   - every one of them finished with result "success".
#
# GitHub reports a job that did not run because a job it depends on failed
# as "skipped", and branch protection counts a skipped required check as
# passing. This job therefore runs whatever happened before it and turns
# every result other than "success" (failure, cancelled, skipped) into a
# failure, so that one required check stands for all of them.
#
# The job ids are read from the workflow's `jobs:` mapping: its keys are the
# lines indented by exactly two spaces, as the workflows here are written.
# A file in which no such key is found is an error.

import json
import re
import sys


def workflow_jobs(path):
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


def main(argv):
    if len(argv) != 4:
        print("usage: require-success.py WORKFLOW SELF NEEDS_JSON", file=sys.stderr)
        return 2
    workflow, self_id, needs = argv[1], argv[2], json.loads(argv[3])
    jobs = workflow_jobs(workflow)
    if self_id not in jobs:
        print(f"require-success: no job {self_id} in {workflow} (found {jobs})")
        return 1
    expected = set(jobs) - {self_id}
    failed = 0
    for job in sorted(expected - set(needs)):
        print(f"{job}: not in the needs of {self_id}")
        failed += 1
    for job in sorted(set(needs) - expected):
        print(f"{job}: in the needs of {self_id} but not a job of {workflow}")
        failed += 1
    for job in sorted(needs):
        result = needs[job].get("result")
        print(f"{job}: {result}")
        if result != "success":
            failed += 1
    if failed or not needs:
        print(f"require-success: FAIL ({failed} problem(s), {len(needs)} jobs checked)")
        return 1
    print(f"require-success: all {len(needs)} jobs of {workflow} succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
