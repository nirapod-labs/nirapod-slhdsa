#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/changelog.sh
# =====================
#
# Usage: tools/ci/changelog.sh
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
# changes/ is malformed. Whether an entry says the right thing is for review;
# this only makes a missing one visible.
#
# Run from the repository root, with HEAD the merge commit GitHub builds
# for a pull request (parents: the base branch, then the pull request
# head). The change is the difference between that merge and its first
# parent: exactly what the merge would add to the base branch, whatever
# the base branch did since the pull request was opened.
#
# Environment, from the workflow:
#
#   CI_EVENT          the event name; any event other than pull_request
#                     has nothing to compare, and the check does not apply
#   CI_HEAD           the head commit of the pull request, which must be
#                     the second parent of HEAD
#   CI_PR             the number of the pull request
#   CI_NO_CHANGELOG   "true" when the pull request has the label
#                     `no-changelog`, "false" otherwise
#
# The label is read from the event that started the run, so a label added
# after the run takes effect on the next push to the pull request.
#
# Any other value, a missing commit or a failed git command fails the
# check.

set -euo pipefail

# Pathspecs of the changes that need an entry, and the same in words.
WATCHED=(src toolchain proofs third_party analysis include Makefile ':(glob)**/*.mk')
WATCHED_TEXT="src/, toolchain/, proofs/, third_party/, analysis/, include/, the top-level Makefile or *.mk files"

die() { echo "changelog.sh: $*" >&2; exit 1; }

say() {
  echo "changelog: $*"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "changelog: $*" >> "$GITHUB_STEP_SUMMARY"; fi
}

if [ "${CI_EVENT:-}" != pull_request ]; then
  say "NOT APPLICABLE on event '${CI_EVENT:-}': only a pull request has a change to check"
  exit 0
fi

case ${CI_NO_CHANGELOG:-} in
  (true|false) ;;
  (*) die "CI_NO_CHANGELOG must be true or false, not '${CI_NO_CHANGELOG:-}'" ;;
esac
[ -n "${CI_HEAD:-}" ] || die "a pull request needs CI_HEAD"
[[ ${CI_PR:-} =~ ^[1-9][0-9]*$ ]] || die "CI_PR must be a pull request number, not '${CI_PR:-}'"

base=$(git rev-parse --verify -q 'HEAD^1^{commit}') \
  || die "HEAD has no first parent; check out the merge commit with fetch-depth 2"
head=$(git rev-parse --verify -q 'HEAD^2^{commit}') \
  || die "HEAD is not a merge commit; check out the merge commit with fetch-depth 2"
[ "$head" = "$(git rev-parse --verify "$CI_HEAD^{commit}")" ] \
  || die "the second parent of HEAD is $head, not the pull request head $CI_HEAD"

# git selects the files by pathspec, so no file name is parsed here.
# Without rename detection a move is a deletion plus an addition, and a
# file moved out of a watched place counts. An assignment from a failing
# git stops the script.
DIFF=(git -c core.quotePath=false diff --name-only --no-renames)
hits=$("${DIFF[@]}" "$base" HEAD -- "${WATCHED[@]}")
added=$("${DIFF[@]}" --diff-filter=A "$base" HEAD -- changes)

# Every entry in the tree is well formed, whatever this change touches.
tools/changes.sh check

# The entry for this change is one the pull request adds under its own
# number. Entries under other numbers may come too (an entry written
# after its change was merged), but do not count for this change.
own=$(printf '%s\n' "$added" | grep -E "^changes/[a-z]+/$CI_PR-[^/]*\.md\$" || true)

n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
if [ -z "$hits" ]; then
  say "PASS: no change to $WATCHED_TEXT"
elif [ -n "$own" ]; then
  say "PASS: $n file(s) changed in $WATCHED_TEXT, with the entry $(printf '%s\n' "$own" | head -1)"
elif [ "$CI_NO_CHANGELOG" = true ]; then
  say "PASS: $n file(s) changed in $WATCHED_TEXT, labelled no-changelog, no entry needed"
else
  printf '%s\n' "$hits" | sed 's/^/  /'
  say "FAIL: the files above change $WATCHED_TEXT, and the pull request adds no entry." \
      "Add changes/<category>/$CI_PR-<slug>.md (see changes/README.md), or, if users" \
      "have nothing to learn from the change, label the pull request no-changelog and push again."
  exit 1
fi
