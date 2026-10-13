#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/verdict.sh
# ===================
#
# Recorded verdicts of the expensive checks. A check that passed is
# recorded under a key computed from everything it reads; a pull request
# whose key matches a recorded pass reports that pass, names the run that
# recorded it, and does not run the check again. A check that fails is
# never recorded, and pushes to main and scheduled runs never reuse a
# verdict: they run every check (.github/workflows/ci.yml).
#
# The key of a check is the SHA-256 of
#
#   - the record format and the name of the check;
#   - the platform it runs on;
#   - the cache key of the compiler it runs with, which covers the toolchain
#     sources, the opam switch and the identity of the runner's build tools
#     (tools/ci/toolchain.sh keys);
#   - the git tree id of its input set: the commit's tree with the paths
#     the check does not read removed. Those paths are listed per check
#     beside the component table (tools/ci/Makefile, CI_VERDICT_SKIP), so
#     every other path, one added later included, is an input. The tree id
#     covers names as well as contents, so adding, deleting or renaming an
#     input changes the key.
#
# The check's own scripts and the workflows are inputs, so a change to how
# a check runs runs it.
#
# A verdict lives in build/verdict/<check>/: the record (PASS, the key, the
# run, the commit, and the input tree, which `git ls-tree -r <tree>` lists),
# the check's log, and the files later jobs need from it (files/). The
# workflows save that directory to the Actions cache under the key.
#
# Usage, from the repository root:
#
#   verdict.sh key CHECK PLATFORM TOOL_KEY PATHSPEC...
#       print the key (and add key=... and key-CHECK=... to $GITHUB_OUTPUT);
#       PATHSPEC... are the paths the check does not read. Every *.mk file
#       stays an input: the top-level Makefile includes the fragments it
#       finds, wherever they sit.
#   verdict.sh run CHECK COMMAND...
#       run COMMAND, append its output to the check's log, and return its
#       status
#   verdict.sh record CHECK KEY [FILE...]
#       record a pass, keeping FILE... (paths from the root). Run only after
#       every step of the check has passed
#   verdict.sh report CHECK KEY
#       after a cache hit: check that the restored record is a pass under
#       KEY, put its files back in place, and state the reuse, the run that
#       recorded it and the end of its log in the log and the job summary
#   verdict.sh toolchain REUSE COMPILER_KEY RECORD_FOUND CHECK=FOUND...
#       whether the toolchain job has to restore (or build) the toolchain:
#       not when verdicts are reused (REUSE is true), every CHECK of the
#       platform has a recorded pass (FOUND is true), and the compiler's
#       build record is cached for the cross-platform comparison. Writes
#       toolchain=needed or toolchain=skipped to $GITHUB_OUTPUT, and the
#       decision with the compiler key to the job summary. A check found
#       here and evicted before its job restores it fails that job, which
#       then has no compiler; the next run restores the toolchain.

set -euo pipefail

FORMAT=1
DIR=build/verdict

die() { echo "verdict.sh: $*" >&2; exit 1; }

# The scratch directory of the command, if it made one; removed on exit,
# failures included.
TMP=
trap '[ -z "$TMP" ] || rm -rf "$TMP"' EXIT

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum; else shasum -a 256; fi
}

check_name() {
  case "$1" in
    ''|*[!a-z]*) die "check name '$1': expected lower-case letters" ;;
  esac
}

cmd_key() {
  [ $# -ge 4 ] || die "usage: verdict.sh key CHECK PLATFORM TOOL_KEY PATHSPEC..."
  local check=$1 platform=$2 tool=$3 tree all kept key
  shift 3
  check_name "$check"
  [ -n "$platform" ] || die "key $check: no platform"
  [ -n "$tool" ] || die "key $check: no compiler key"
  git rev-parse --verify -q HEAD > /dev/null || die "key $check: no commit"
  TMP=$(mktemp -d)
  # A private index holding the commit's tree, so the work tree and the
  # real index play no part.
  export GIT_INDEX_FILE="$TMP/index"
  git read-tree HEAD
  git ls-files > "$TMP/all"
  git rm -r -q --cached --ignore-unmatch -- "$@" ':(exclude,glob)**/*.mk' > /dev/null
  git ls-files > "$TMP/kept"
  tree=$(git write-tree)
  unset GIT_INDEX_FILE
  all=$(wc -l < "$TMP/all" | tr -d ' ')
  kept=$(wc -l < "$TMP/kept" | tr -d ' ')
  [ "$kept" -gt 0 ] || die "key $check: the input set is empty"
  {
    echo "format $FORMAT"
    echo "check $check"
    echo "platform $platform"
    echo "compiler $tool"
    echo "inputs $tree"
  } > "$TMP/material"
  key="verdict-$check-$platform-$(sha256_of < "$TMP/material" | cut -d' ' -f1)"
  mkdir -p "$DIR"
  cp "$TMP/material" "$DIR/$check.material"
  sed 's/^/  /' "$DIR/$check.material"
  echo "input set: $kept of $all tracked files (git ls-tree -r $tree)"
  echo "key=$key"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    { echo "key=$key"; echo "key-$check=$key"; } >> "$GITHUB_OUTPUT"
  fi
}

cmd_run() {
  [ $# -ge 2 ] || die "usage: verdict.sh run CHECK COMMAND..."
  local check=$1 rc
  shift
  check_name "$check"
  mkdir -p "$DIR/$check"
  echo "+ $*" >> "$DIR/$check/log"
  set +e
  "$@" 2>&1 | tee -a "$DIR/$check/log"
  rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}

cmd_record() {
  [ $# -ge 2 ] || die "usage: verdict.sh record CHECK KEY [FILE...]"
  local check=$1 key=$2 f d
  shift 2
  check_name "$check"
  d="$DIR/$check"
  [ -n "$key" ] || die "record $check: no key"
  [ -s "$d/log" ] || die "record $check: no log; the check did not run through 'verdict.sh run'"
  [ -f "$DIR/$check.material" ] || die "record $check: no key material; run 'verdict.sh key' first"
  rm -rf "$d/files"
  mkdir -p "$d/files"
  for f in "$@"; do
    case "$f" in /*|*..*) die "record $check: $f is not a path inside the tree" ;; esac
    [ -f "$f" ] || die "record $check: $f is missing"
    mkdir -p "$d/files/$(dirname "$f")"
    cp "$f" "$d/files/$f"
  done
  {
    echo "verdict PASS"
    echo "key $key"
    cat "$DIR/$check.material"
    echo "run ${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-} attempt ${GITHUB_RUN_ATTEMPT:-}"
    echo "commit ${GITHUB_SHA:-$(git rev-parse HEAD)}"
    echo "event ${GITHUB_EVENT_NAME:-local} ${GITHUB_REF:-}"
    echo "recorded $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$d/record"
  echo "verdict.sh: $check PASS recorded under $key"
}

cmd_report() {
  [ $# -eq 2 ] || die "usage: verdict.sh report CHECK KEY"
  local check=$1 key=$2 d f run commit
  check_name "$check"
  d="$DIR/$check"
  [ -f "$d/record" ] || die "report $check: the restored entry has no record"
  grep -qx "verdict PASS" "$d/record" || die "report $check: the restored record is not a pass"
  grep -qxF "key $key" "$d/record" || die "report $check: the restored record is not for $key"
  [ -f "$d/log" ] || die "report $check: the restored entry has no log"
  if [ -d "$d/files" ]; then
    (cd "$d/files" && find . -type f) | while read -r f; do
      f=${f#./}
      mkdir -p "$(dirname "$f")"
      cp "$d/files/$f" "$f"
    done
  fi
  run=$(sed -n 's/^run //p' "$d/record")
  commit=$(sed -n 's/^commit //p' "$d/record")
  {
    echo "### $check: PASS, recorded with identical inputs"
    echo
    echo "Not run again. Its inputs are those of the passing run $run at commit $commit."
    echo
    echo '```'
    cat "$d/record"
    echo '```'
    echo
    echo "End of the recorded log:"
    echo
    echo '```'
    tail -n 40 "$d/log"
    echo '```'
  } > "$DIR/$check.report"
  cat "$DIR/$check.report"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$DIR/$check.report" >> "$GITHUB_STEP_SUMMARY"; fi
}

cmd_toolchain() {
  [ $# -ge 4 ] || die "usage: verdict.sh toolchain REUSE COMPILER_KEY RECORD_FOUND CHECK=FOUND..."
  local reuse=$1 compiler=$2 record=$3 pair missing="" decision reason
  shift 3
  [ -n "$compiler" ] || die "toolchain: no compiler key"
  for pair in "$@"; do
    case "$pair" in
      *=true) ;;
      [a-z]*=*) missing="$missing ${pair%%=*}" ;;
      *) die "toolchain: '$pair' is not CHECK=FOUND" ;;
    esac
  done
  if [ "$reuse" != true ]; then
    decision=needed reason="this event runs every check"
  elif [ -n "$missing" ]; then
    decision=needed reason="no recorded pass for:$missing"
  elif [ "$record" != true ]; then
    decision=needed reason="the compiler's build record is not cached"
  else
    decision=skipped reason="every check of this platform has a recorded pass with this compiler"
  fi
  echo "toolchain=$decision"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "toolchain=$decision" >> "$GITHUB_OUTPUT"; fi
  {
    echo "### toolchain: $decision"
    echo
    echo "$reason."
    echo
    echo "Compiler key: \`$compiler\`"
  } > "$DIR.toolchain"
  cat "$DIR.toolchain"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$DIR.toolchain" >> "$GITHUB_STEP_SUMMARY"; fi
}

case "${1:-}" in
  key)    shift; cmd_key "$@" ;;
  run)    shift; cmd_run "$@" ;;
  record) shift; cmd_record "$@" ;;
  report) shift; cmd_report "$@" ;;
  toolchain) shift; cmd_toolchain "$@" ;;
  *) die "usage: verdict.sh key|run|record|report|toolchain ..." ;;
esac
