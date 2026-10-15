# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/policy.py
# ============
#
# Usage: python3 -I ci/policy.py
#
# Rules for the workflows and actions under .github that the linters do not
# know, checked by the lint job (ci/lint.py):
#
#   - no workflow or action uses the Actions cache (actions/cache, its
#     restore and save actions, or the `cache` input of a setup action): a
#     pull request's run can save an entry that a later run restores, so
#     the only results a run takes from other runs are artifacts of runs on
#     main (ci/store.py);
#   - every workflow sets `permissions: {}` at the top, and every job
#     states its own, from the set PERMISSIONS allows for that job, and no
#     more;
#   - no secret other than the run's own token, and no pull_request_target.
#
# The workflows are read line by line, as they are written here: two-space
# indentation, jobs under `jobs:`, a job's permissions as a mapping under
# `permissions:` or `{}`. A file this reader does not understand fails.

import os
import re
import sys

WORKFLOWS = ".github/workflows"
ACTIONS = ".github/actions"

READ = {"contents": "read"}
ACTIONS_READ = {"contents": "read", "actions": "read"}
# workflow file -> job id -> the permissions it may hold.
PERMISSIONS = {
    "ci.yml": {
        "lint": READ, "reuse": READ, "source": READ, "plan": ACTIONS_READ,
        "toolchain-x86": ACTIONS_READ, "native-linux-x86_64": ACTIONS_READ,
        "native-linux-aarch64": ACTIONS_READ, "native-macos-aarch64": ACTIONS_READ,
        "proof-shards": ACTIONS_READ, "proofs": ACTIONS_READ, "agree": ACTIONS_READ,
        "all-checks": ACTIONS_READ, "warm": ACTIONS_READ,
    },
    "native.yml": {"native": ACTIONS_READ},
    "changelog.yml": {"changelog": {"contents": "read", "pull-requests": "read"}},
    # Starts the re-run; reads the run's jobs, their annotations and the pull
    # request's head. It checks out main and runs nothing of the run.
    "ci-retry.yml": {"retry": {"actions": "write", "checks": "read", "contents": "read",
                               "pull-requests": "read"}},
    "drift.yml": {"setup": READ, "jasmin": READ, "easycrypt": READ},
}

CACHE = re.compile(r"^\s*-?\s*uses:\s*actions/cache(/[a-z]+)?@")
CACHE_INPUT = re.compile(r"^\s*cache(-dependency-path)?:\s*\S")
SECRET = re.compile(r"\$\{\{[^}]*\bsecrets\.(?!GITHUB_TOKEN\b)")


def workflow_permissions(lines):
    """(top-level permissions text, {job: {scope: level} or text})."""
    top, jobs, job, in_jobs, in_perm = None, {}, None, False, None
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        m = re.match(r"^permissions:\s*(.*)$", line)
        if indent == 0:
            in_jobs = line.startswith("jobs:")
            in_perm = None
            if m:
                top = m.group(1).strip()
            continue
        if not in_jobs:
            continue
        if indent == 2:
            m2 = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if not m2:
                raise ValueError(f"cannot read the job line '{line}'")
            job, in_perm = m2.group(1), None
            jobs[job] = None
            continue
        if indent == 4:
            in_perm = None
            m3 = re.match(r"^    permissions:\s*(.*)$", line)
            if m3:
                value = m3.group(1).strip()
                if value:
                    jobs[job] = value
                else:
                    jobs[job] = {}
                    in_perm = job
            continue
        if in_perm and indent == 6:
            m4 = re.match(r"^      ([a-z-]+):\s*(read|write|none)\s*$", line)
            if not m4:
                raise ValueError(f"cannot read the permission line '{line}'")
            jobs[in_perm][m4.group(1)] = m4.group(2)
    return top, jobs


def check_file(path, rel):
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    problems = []
    for n, line in enumerate(lines, 1):
        if CACHE.match(line):
            problems.append(f"{rel}:{n}: uses the Actions cache")
        if CACHE_INPUT.match(line):
            problems.append(f"{rel}:{n}: a cache input of a setup action")
        if SECRET.search(line):
            problems.append(f"{rel}:{n}: uses a secret")
        if re.search(r"\bpull_request_target\b", line.split("#")[0]):
            problems.append(f"{rel}:{n}: pull_request_target")
    if rel.startswith(WORKFLOWS):
        name = os.path.basename(rel)
        try:
            top, jobs = workflow_permissions(lines)
        except ValueError as e:
            return problems + [f"{rel}: {e}"]
        if top != "{}":
            problems.append(f"{rel}: top-level permissions must be {{}}, not {top!r}")
        allowed = PERMISSIONS.get(name)
        if allowed is None:
            problems.append(f"{rel}: a workflow ci/policy.py has no permissions for")
            return problems
        for job, perms in jobs.items():
            if job not in allowed:
                problems.append(f"{rel}: job {job} has no permissions in ci/policy.py")
            elif not isinstance(perms, dict):
                problems.append(f"{rel}: job {job} states no permissions mapping ({perms!r})")
            elif perms != allowed[job]:
                problems.append(f"{rel}: job {job} has permissions {perms}, allowed {allowed[job]}")
        for job in sorted(set(allowed) - set(jobs)):
            problems.append(f"{rel}: ci/policy.py lists a job {job} the workflow lacks")
    return problems


def main(argv):
    problems = []
    for base in (WORKFLOWS, ACTIONS):
        for root, _, files in os.walk(base):
            for f in sorted(files):
                if f.endswith((".yml", ".yaml")):
                    p = os.path.join(root, f)
                    problems += check_file(p, p)
    for p in problems:
        print(f"policy: FAIL: {p}")
    if problems:
        return 1
    print("policy: PASS (no Actions cache, no secret, permissions as listed)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
