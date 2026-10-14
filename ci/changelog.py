# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/changelog.py
# =====================
#
# Usage: python3 -I tools/ci/changelog.py
#
# A pull request that changes what users build, call or rely on describes
# the change in an entry of its own, a new file
# changes/<category>/<pull request number>-<slug>.md (changes/README.md,
# tools/changes.sh). This check fails a pull request that changes
#
#   a file under src/ toolchain/ proofs/ third_party/ analysis/ include/,
#   the top-level Makefile, or a *.mk fragment anywhere
#
# and adds no entry with its own number, unless the pull request carries
# the label `no-changelog` (for a change with nothing to tell a user, such
# as a comment fix). It also fails, label or not, when any file under
# changes/ is malformed (`tools/changes.sh check`). Whether an entry says
# the right thing is for review; this only makes a missing one visible.
#
# Run from the repository root, with HEAD the merge commit GitHub builds
# for a pull request (parents: the base branch, then the pull request
# head). The change is the difference between that merge and its first
# parent: exactly what the merge would add to the base branch, whatever
# the base branch did since the pull request was opened.
#
# Environment, from the workflow (.github/workflows/changelog.yml):
#
#   CI_EVENT          the event name; any event other than pull_request
#                     has nothing to compare, and the check does not apply
#   CI_HEAD           the head commit of the pull request, which must be
#                     the second parent of HEAD
#   CI_PR             the number of the pull request
#   GITHUB_REPOSITORY owner/name of the repository, and GH_TOKEN, a token
#                     that can read its pull requests
#
# The labels are read from the API when the check runs, not from the event
# that started it. The workflow also runs on label events, so adding or
# removing the label re-runs the check with no push, and a re-run of an
# older run sees the labels as they are at that moment.
#
# Any other value, a missing commit, a failed git command or a failed API
# call fails the check (exit 1); a usage error exits 2.

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghapi  # noqa: E402

# Pathspecs of the changes that need an entry, and the same in words.
WATCHED = ["src", "toolchain", "proofs", "third_party", "analysis", "include", "Makefile",
           ":(glob)**/*.mk"]
WATCHED_TEXT = ("src/, toolchain/, proofs/, third_party/, analysis/, include/, "
                "the top-level Makefile or *.mk files")
LABEL = "no-changelog"


class Failure(Exception):
    pass


def git(*args):
    try:
        return subprocess.run(["git", "-c", "core.quotePath=false", *args], check=True,
                              capture_output=True).stdout
    except subprocess.CalledProcessError as e:
        raise Failure(f"git {' '.join(args)}: {e.stderr.decode(errors='replace').strip()}") from None


def commit(rev):
    out = git("rev-parse", "--verify", "-q", f"{rev}^{{commit}}").decode().strip()
    if not out:
        raise Failure(f"{rev} is not a commit")
    return out


def changed(base, *args):
    """Files that differ between BASE and HEAD, as git lists them (-z)."""
    # No rename detection: a move is a deletion plus an addition, so a
    # file moved out of a watched place counts.
    out = git("diff", "--name-only", "--no-renames", "-z", *args[:-1], base, "HEAD", "--", *args[-1])
    return [p.decode() for p in out.split(b"\0") if p]


def pr_labels(repository, number):
    """The labels of the pull request now. An API error is a failure, never
    an empty list."""
    pr = ghapi.Api(repository).get(f"pulls/{number}")
    labels = pr.get("labels")
    if not isinstance(labels, list):
        raise Failure(f"pull request {number}: no label list in the answer")
    return [l.get("name") for l in labels]


def check(env, labels_of=pr_labels, changes_check=("tools/changes.sh", "check")):
    """(status, lines): status 0 for a pass, 1 for a failure."""
    event = env.get("CI_EVENT", "")
    if event != "pull_request":
        return 0, [f"NOT APPLICABLE on event '{event}': only a pull request has a change to check"]
    head_env, pr = env.get("CI_HEAD", ""), env.get("CI_PR", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    if not head_env:
        raise Failure("a pull request needs CI_HEAD")
    if not re.fullmatch(r"[1-9][0-9]*", pr):
        raise Failure(f"CI_PR must be a pull request number, not '{pr}'")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise Failure(f"GITHUB_REPOSITORY must be owner/name, not '{repository}'")
    try:
        base = commit("HEAD^1")
    except Failure:
        raise Failure("HEAD has no first parent; check out the merge commit with fetch-depth 2") from None
    try:
        head = commit("HEAD^2")
    except Failure:
        raise Failure("HEAD is not a merge commit; check out the merge commit with fetch-depth 2") from None
    if head != commit(head_env):
        raise Failure(f"the second parent of HEAD is {head}, not the pull request head {head_env}")

    hits = changed(base, WATCHED)
    added = changed(base, "--diff-filter=A", ["changes"])
    labels = labels_of(repository, pr)

    # Every entry in the tree is well formed, whatever this change touches.
    r = subprocess.run(list(changes_check))
    if r.returncode != 0:
        raise Failure(f"{' '.join(changes_check)} failed")

    # The entry for this change is one the pull request adds under its own
    # number. Entries under other numbers may come too (an entry written
    # after its change was merged), but do not count for this change.
    own = [p for p in added if re.fullmatch(rf"changes/[a-z]+/{pr}-[^/]*\.md", p)]
    n = len(hits)
    if not hits:
        return 0, [f"PASS: no change to {WATCHED_TEXT}"]
    if own:
        return 0, [f"PASS: {n} file(s) changed in {WATCHED_TEXT}, with the entry {own[0]}"]
    if LABEL in labels:
        return 0, [f"PASS: {n} file(s) changed in {WATCHED_TEXT}, labelled {LABEL}, no entry needed"]
    return 1, ["  " + h for h in hits] + [
        f"FAIL: the files above change {WATCHED_TEXT}, and the pull request adds no entry. "
        f"Add changes/<category>/{pr}-<slug>.md (see changes/README.md), or, if users "
        f"have nothing to learn from the change, label the pull request {LABEL}; "
        f"the check runs again on the label."]


def main(argv):
    if len(argv) != 1:
        print("usage: changelog.py", file=sys.stderr)
        return 2
    try:
        status, lines = check(os.environ)
    except (Failure, ghapi.ApiError) as e:
        print(f"changelog.py: {e}", file=sys.stderr)
        return 1
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    for line in lines:
        text = line if line.startswith("  ") else f"changelog: {line}"
        print(text)
        if summary and not line.startswith("  "):
            with open(summary, "a", encoding="utf-8") as f:
                f.write(text + "\n")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
