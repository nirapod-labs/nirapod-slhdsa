#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/verdict.sh
# ===================
#
# Recorded verdicts of the expensive checks. A check that passed in a run
# on main is recorded under a key computed from everything it reads; a
# pull request whose key matches such a record reports that pass, names
# the run that recorded it, and does not run the check again. A check that
# fails is never recorded, and pushes to main and scheduled runs never
# reuse a verdict: they run every check (.github/workflows/ci.yml).
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
# a check runs runs it. The runner is only partly an input: the compiler
# key covers the C compiler, system and build packages of the toolchain
# job, but not the packages the check jobs install for themselves
# (libcrypto and GMP, `toolchain.sh deps run`) or the runner's python3. A
# runner image update that changes those leaves a recorded pass valid for
# pull requests; pushes to main and the weekly run run every check, so such
# drift shows there.
#
# A verdict lives in build/verdict/<check>/: the record (PASS, the key, the
# run, the commit, the input tree, which `git ls-tree -r <tree>` lists, the
# names of the files kept, and NOT RUN for a check that passed without
# running), the check's log, and the files later jobs need from it
# (files/). Reuse puts back the files the record names, and nothing else.
#
# Where verdicts come from. Only runs on main record one: the workflows
# upload the directory as an artifact of the run, named by the key. A pull
# request takes a verdict only from a run that the API reports as a push,
# a scheduled run or a manual run of ci.yml on main of this repository, and
# downloads it from that run. A pull request's own runs record nothing, and
# nothing they write is read back as a verdict. Verdicts are not kept in
# the Actions cache: a pull request restores entries that its own earlier
# commits saved, with workflows of their choosing, and restoring an entry
# unpacks it with the paths it holds, wherever they point.
#
# Usage, from the repository root:
#
#   verdict.sh key CHECK PLATFORM TOOL_KEY PATHSPEC...
#       print the key, keep it in build/verdict/CHECK.key and add key=...
#       to $GITHUB_OUTPUT; PATHSPEC... are the paths the check does not
#       read. Every *.mk file stays an input: the top-level Makefile
#       includes the fragments it finds, wherever they sit.
#   verdict.sh run CHECK COMMAND...
#       run COMMAND, append its output to the check's log, and return its
#       status
#   verdict.sh record CHECK KEY [FILE...]
#       record a pass under KEY, which has to be the key of the inputs this
#       job keyed, keeping FILE... (paths from the root). Run only after
#       every step of the check has passed, and only on main
#   verdict.sh toolchain REUSE COMPILER_KEY RECORD_FOUND
#       for each check keyed in this job (build/verdict/*.key), the newest
#       run on main that recorded a pass under its key, when REUSE is true;
#       written to $GITHUB_OUTPUT as verdicts=CHECK=RUN ... (RUN empty when
#       there is none). Then whether the toolchain job has to restore (or
#       build) the toolchain: not when every check has such a run and the
#       compiler's build record is cached for the cross-platform
#       comparison. Writes toolchain=needed or toolchain=skipped, and the
#       decision with the compiler key to the job summary. A verdict found
#       here that is gone when its job downloads it fails that job, which
#       then has no compiler; re-running all jobs, not only the failed one,
#       looks the verdicts up again and restores the toolchain.
#   verdict.sh reuse CHECK KEY VERDICTS
#       VERDICTS is the toolchain job's verdicts output. When it names a
#       run for CHECK, download that run's verdict, check that it is a pass
#       under KEY, made from the same key material as this job's, and
#       recorded on main, put its files back in place, and state the reuse,
#       the run that recorded it and the end of its log in the log and the
#       job summary. Writes reused=true, or reused=false when there is no
#       verdict to reuse and the check has to run.

set -euo pipefail

FORMAT=1
DIR=build/verdict
# The runs a verdict is taken from: this repository's ci.yml, on main.
MAIN=main
WORKFLOW=.github/workflows/ci.yml

die() { echo "verdict.sh: $*" >&2; exit 1; }
warn() { echo "::warning::verdict.sh: $*"; }

# output NAME=VALUE: print it, and add it to $GITHUB_OUTPUT in a workflow.
output() {
  echo "$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1" >> "$GITHUB_OUTPUT"; fi
}

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

# A key as cmd_key makes it; it is also the name of the artifact, and goes
# into API queries as is.
key_name() {
  printf '%s\n' "$1" | grep -Eqx 'verdict-[a-z]+-[a-z0-9_-]+-[0-9a-f]{64}' \
    || die "'$1' is not a verdict key"
}

# main_run KEY: the newest run with an artifact named KEY that is a push, a
# scheduled run or a manual run of $WORKFLOW on $MAIN of this repository;
# nothing when there is none. Fails when the API cannot be read.
main_run() {
  local key=$1 repo=${GITHUB_REPOSITORY:-} found run what
  [ -n "$repo" ] || die "GITHUB_REPOSITORY is not set"
  key_name "$key"
  # The artifact's own record of its run rules out most candidates without
  # a further request: a fork's run, or a branch other than main.
  found=$(gh api --paginate "repos/$repo/actions/artifacts?name=$key&per_page=100" --jq "
    .artifacts[]
    | select(.name == \"$key\" and (.expired | not)
             and .workflow_run.head_branch == \"$MAIN\"
             and .workflow_run.head_repository_id == .workflow_run.repository_id)
    | \"\(.created_at) \(.workflow_run.id)\"") || return 1
  for run in $(printf '%s\n' "$found" | sort -r | cut -d' ' -f2); do
    what=$(gh api "repos/$repo/actions/runs/$run" \
      --jq '"\(.event) \(.head_branch) \(.path) \(.head_repository.id == .repository.id)"') || return 1
    case "$what" in
      "push $MAIN $WORKFLOW true"|"schedule $MAIN $WORKFLOW true"|"workflow_dispatch $MAIN $WORKFLOW true")
        echo "$run"
        return 0 ;;
    esac
  done
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
  key_name "$key"
  mkdir -p "$DIR"
  cp "$TMP/material" "$DIR/$check.material"
  echo "$key" > "$DIR/$check.key"
  sed 's/^/  /' "$DIR/$check.material"
  echo "input set: $kept of $all tracked files (git ls-tree -r $tree)"
  output "key=$key"
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
  local check=$1 key=$2 f d expect
  shift 2
  check_name "$check"
  d="$DIR/$check"
  [ -n "$key" ] || die "record $check: no key"
  [ -s "$d/log" ] || die "record $check: no log; the check did not run through 'verdict.sh run'"
  [ -f "$DIR/$check.material" ] || die "record $check: no key material; run 'verdict.sh key' first"
  expect="verdict-$check-$(sed -n 's/^platform //p' "$DIR/$check.material")-$(sha256_of < "$DIR/$check.material" | cut -d' ' -f1)"
  [ "$key" = "$expect" ] || die "record $check: $key is not the key of this job's inputs, $expect"
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
    for f in "$@"; do echo "file $f"; done
    # A check that passed without running (its log says NOT RUN) is
    # recorded as such, so the record itself does not read as a pass of
    # the check.
    if not_run "$d/log"; then echo "status NOT RUN"; fi
  } > "$d/record"
  if not_run "$d/log"; then
    echo "verdict.sh: $check recorded under $key as NOT RUN (its log says so)"
  else
    echo "verdict.sh: $check PASS recorded under $key"
  fi
}

# not_run LOG: the check whose log this is passed without running.
not_run() {
  grep -q '^ci-[a-z-]*: NOT RUN' "$1"
}

# report CHECK KEY RUN: the verdict downloaded from RUN into $DIR/CHECK is
# a pass under KEY, made from the inputs this job keyed, and recorded on
# main by that run; put its files back and state the reuse.
report() {
  local check=$1 key=$2 run=$3 d f n url commit event heading what
  d="$DIR/$check"
  [ -f "$d/record" ] || die "reuse $check: the verdict of run $run has no record"
  [ -f "$DIR/$check.material" ] || die "reuse $check: no key material; run 'verdict.sh key' first"
  # The record opens with the verdict, the key and the key material, in
  # that order (cmd_record).
  [ "$(sed -n 1p "$d/record")" = "verdict PASS" ] || die "reuse $check: the record of run $run is not a pass"
  [ "$(sed -n 2p "$d/record")" = "key $key" ] || die "reuse $check: the record of run $run is not for $key"
  n=$(wc -l < "$DIR/$check.material")
  sed -n "3,$((n + 2))p" "$d/record" | cmp -s - "$DIR/$check.material" \
    || die "reuse $check: the inputs in the record of run $run are not this job's ($DIR/$check.material)"
  [ -f "$d/log" ] || die "reuse $check: the verdict of run $run has no log"
  event=$(sed -n 's/^event //p' "$d/record")
  case "$event" in
    "push refs/heads/$MAIN"|"schedule refs/heads/$MAIN"|"workflow_dispatch refs/heads/$MAIN") ;;
    *) die "reuse $check: the record of run $run was made on '$event', not by a run on $MAIN" ;;
  esac
  url=$(sed -n 's/^run //p' "$d/record")
  case "$url" in
    */actions/runs/"$run"" attempt "*) ;;
    *) die "reuse $check: the record names '$url', not run $run" ;;
  esac
  while IFS= read -r f; do
    case "$f" in
      ''|/*|*..*) die "reuse $check: '$f' in the record of run $run is not a path inside the tree" ;;
    esac
    [ -f "$d/files/$f" ] && [ ! -L "$d/files/$f" ] \
      || die "reuse $check: $f, named in the record of run $run, is not among its files"
    mkdir -p "$(dirname "$f")"
    cp "$d/files/$f" "$f"
  done < <(sed -n 's/^file //p' "$d/record")
  commit=$(sed -n 's/^commit //p' "$d/record")
  # A check can pass without running, when the tree has nothing it could
  # run (ci-safety without its component); its log says NOT RUN, and the
  # reuse says so too rather than PASS.
  if not_run "$d/log"; then
    echo "::warning title=$check NOT RUN::the run on $MAIN with identical inputs did not run $check; see its log"
    heading="NOT RUN, as recorded on $MAIN with identical inputs"
    what="Not run here either. Its inputs are those of run $url at commit $commit, which did not run it."
  else
    heading="PASS, recorded on $MAIN with identical inputs"
    what="Not run again. Its inputs are those of the passing run $url at commit $commit."
  fi
  {
    echo "### $check: $heading"
    echo
    echo "$what"
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

cmd_reuse() {
  [ $# -eq 3 ] || die "usage: verdict.sh reuse CHECK KEY VERDICTS"
  local check=$1 key=$2 verdicts=$3 pair run="" looked=false
  check_name "$check"
  key_name "$key"
  for pair in $verdicts; do
    case "$pair" in
      "$check="*) run=${pair#*=} looked=true ;;
    esac
  done
  [ "$looked" = true ] \
    || die "reuse $check: the toolchain job did not look $check up; is it in CI_VERDICT_PLATFORM_CHECKS (tools/ci/Makefile)?"
  if [ -z "$run" ]; then
    echo "verdict.sh: no pass of $check under $key recorded on $MAIN; the check runs"
    output "reused=false"
    return 0
  fi
  case "$run" in
    *[!0-9]*) die "reuse $check: '$run' is not a run id" ;;
  esac
  TMP=$(mktemp -d)
  if ! gh run download "$run" --repo "${GITHUB_REPOSITORY:?}" --name "$key" --dir "$TMP/verdict"; then
    warn "reuse $check: the verdict of run $run could not be downloaded; the check runs"
    output "reused=false"
    return 0
  fi
  rm -rf "${DIR:?}/$check"
  mkdir -p "$DIR"
  mv "$TMP/verdict" "$DIR/$check"
  report "$check" "$key" "$run"
  output "reused=true"
}

cmd_toolchain() {
  [ $# -eq 3 ] || die "usage: verdict.sh toolchain REUSE COMPILER_KEY RECORD_FOUND"
  local reuse=$1 compiler=$2 record=$3 f check key run verdicts="" found="" missing="" decision reason
  [ -n "$compiler" ] || die "toolchain: no compiler key"
  set -- "$DIR"/*.key
  [ -f "$1" ] || die "toolchain: no verdict keys in $DIR; run 'make -f tools/ci/Makefile ci-platform-verdict-keys' first"
  for f in "$@"; do
    check=$(basename "$f" .key)
    key=$(cat "$f")
    run=""
    if [ "$reuse" = true ] && ! run=$(main_run "$key"); then
      warn "toolchain: the recorded verdicts of $check could not be looked up; it runs"
      run=""
    fi
    verdicts="$verdicts${verdicts:+ }$check=$run"
    if [ -n "$run" ]; then
      found="$found- $check: run $run"$'\n'
    else
      missing="$missing $check"
    fi
  done
  if [ "$reuse" != true ]; then
    decision=needed reason="this event runs every check"
  elif [ -n "$missing" ]; then
    decision=needed reason="no pass recorded on $MAIN for:$missing"
  elif [ "$record" != true ]; then
    decision=needed reason="the compiler's build record is not cached"
  else
    decision=skipped reason="every check of this platform has a pass recorded on $MAIN with this compiler"
  fi
  output "verdicts=$verdicts"
  output "toolchain=$decision"
  {
    echo "### toolchain: $decision"
    echo
    echo "$reason."
    echo
    echo "Compiler key: \`$compiler\`"
    if [ -n "$found" ]; then
      echo
      echo "Passes recorded on $MAIN under this platform's keys:"
      echo
      printf '%s' "$found"
    fi
  } > "$DIR.toolchain"
  cat "$DIR.toolchain"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$DIR.toolchain" >> "$GITHUB_STEP_SUMMARY"; fi
}

case "${1:-}" in
  key)    shift; cmd_key "$@" ;;
  run)    shift; cmd_run "$@" ;;
  record) shift; cmd_record "$@" ;;
  reuse)  shift; cmd_reuse "$@" ;;
  toolchain) shift; cmd_toolchain "$@" ;;
  *) die "usage: verdict.sh key|run|record|toolchain|reuse ..." ;;
esac
