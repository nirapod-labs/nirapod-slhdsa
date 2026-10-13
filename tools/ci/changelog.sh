#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/changelog.sh
# =====================
#
# Usage: tools/ci/changelog.sh
#
# A pull request that changes what users build, call or rely on records the
# change in CHANGELOG.md, under "## Unreleased", in the same pull request.
# This check fails a pull request that changes a file under one of
#
#   src/ toolchain/ proofs/ include/ capi/
#
# and leaves CHANGELOG.md untouched, unless the pull request carries the
# label `no-changelog` (for a change with nothing to tell a user, such as a
# comment fix). Whether an entry says the right thing is for review; this
# only makes a missing one visible.
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
#   CI_NO_CHANGELOG   "true" when the pull request has the label
#                     `no-changelog`, "false" otherwise
#
# The label is read from the event that started the run, so a label added
# after the run takes effect on the next push to the pull request.
#
# Any other value, a missing commit or a failed git command fails the
# check.

set -euo pipefail

PATHS="src toolchain proofs include capi"

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

base=$(git rev-parse --verify -q 'HEAD^1^{commit}') \
  || die "HEAD has no first parent; check out the merge commit with fetch-depth 2"
head=$(git rev-parse --verify -q 'HEAD^2^{commit}') \
  || die "HEAD is not a merge commit; check out the merge commit with fetch-depth 2"
[ "$head" = "$(git rev-parse --verify "$CI_HEAD^{commit}")" ] \
  || die "the second parent of HEAD is $head, not the pull request head $CI_HEAD"

# Read in the main shell, where a failing git stops the script; a pipeline
# inside a command substitution would hide it.
changed=$(git diff --name-only "$base" HEAD)

# Paths are compared as text: git quotes unusual file names, and every
# path of interest starts with a plain directory name.
hits=$(printf '%s\n' "$changed" | grep -E "^($(echo "$PATHS" | tr ' ' '|'))/" || true)
logged=$(printf '%s\n' "$changed" | grep -Fx CHANGELOG.md || true)

if [ -z "$hits" ]; then
  say "PASS: nothing changed under $PATHS"
elif [ -n "$logged" ]; then
  say "PASS: $(printf '%s\n' "$hits" | wc -l | tr -d ' ') file(s) changed under $PATHS, and CHANGELOG.md too"
elif [ "$CI_NO_CHANGELOG" = true ]; then
  say "PASS: $(printf '%s\n' "$hits" | wc -l | tr -d ' ') file(s) changed under $PATHS, labelled no-changelog, no entry needed"
else
  printf '%s\n' "$hits" | sed 's/^/  /'
  say "FAIL: the files above change under $PATHS, and CHANGELOG.md does not." \
      "Add an entry under \"## Unreleased\" in CHANGELOG.md, or, if users have" \
      "nothing to learn from the change, label the pull request no-changelog and push again."
  exit 1
fi
