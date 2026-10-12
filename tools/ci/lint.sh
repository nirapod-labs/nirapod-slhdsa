#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/lint.sh
# ================
#
# Correctness checks of the repository's automation and metadata, run from
# the repository root:
#
#   - actionlint on the workflows under .github/workflows: syntax,
#     expressions, job dependencies, action inputs, and the shell scripts of
#     their run steps (through ShellCheck);
#   - ShellCheck on every tracked shell script (a *.sh file, or a file whose
#     first line names sh or bash), at severity "warning" and above: quoting
#     that splits or globs, unset variables, failing commands that are
#     ignored, and similar defects. The "info" and "style" levels are left
#     out; they are matters of taste, and this is not a style gate;
#   - a syntax check of every tracked Python script (*.py, or a python
#     first line), with the runner's python3.
#
# A third check, run on its own:
#
#   - REUSE lint: every file carries copyright and licence information, in
#     its header or in REUSE.toml, and every licence named has its text in
#     LICENSES/. It runs the reuse tool from the FSFE's container image,
#     pinned by the digest of its image index; the runtime pulls the image
#     by that digest and verifies the content against it.
#
# Usage: tools/ci/lint.sh [install DIR | reuse]
#
#   install DIR   download the pinned actionlint and shellcheck (Linux
#                 x86-64 release binaries) into DIR/bin, after checking each
#                 archive against its SHA-256, and put DIR/bin on the PATH
#                 of the following workflow steps
#   reuse         REUSE lint in the pinned image (needs docker); the same
#                 check without docker is `reuse lint` with reuse 6.2.0
#   (no argument) run actionlint and ShellCheck with the binaries on PATH
#
# The versions in use are printed with the results.

set -euo pipefail

ACTIONLINT_VERSION=1.7.12
ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
SHELLCHECK_VERSION=0.11.0
SHELLCHECK_SHA256=b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6
# fsfe/reuse 6.2.0, OCI image index (linux/amd64 and linux/arm64).
REUSE_IMAGE=docker.io/fsfe/reuse@sha256:85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e

die() { echo "lint.sh: $*" >&2; exit 1; }

# fetch URL SHA256 FILE: FILE holds the download, which matched SHA256.
fetch() {
  local got
  curl -fsSL --retry 3 -o "$3" "$1"
  got=$(sha256sum "$3" | cut -d' ' -f1)
  [ "$got" = "$2" ] || die "$1: SHA-256 $got, expected $2"
}

install_tools() {
  local dir=$1 tmp
  [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || die "install: Linux x86-64 only"
  mkdir -p "$dir/bin"
  tmp=$(mktemp -d)
  fetch "https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VERSION/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
        "$ACTIONLINT_SHA256" "$tmp/actionlint.tar.gz"
  tar -C "$tmp" -xzf "$tmp/actionlint.tar.gz" actionlint
  install -m 0755 "$tmp/actionlint" "$dir/bin/actionlint"
  fetch "https://github.com/koalaman/shellcheck/releases/download/v$SHELLCHECK_VERSION/shellcheck-v$SHELLCHECK_VERSION.linux.x86_64.tar.gz" \
        "$SHELLCHECK_SHA256" "$tmp/shellcheck.tar.gz"
  tar -C "$tmp" -xzf "$tmp/shellcheck.tar.gz" "shellcheck-v$SHELLCHECK_VERSION/shellcheck"
  install -m 0755 "$tmp/shellcheck-v$SHELLCHECK_VERSION/shellcheck" "$dir/bin/shellcheck"
  rm -rf "$tmp"
  if [ -n "${GITHUB_PATH:-}" ]; then echo "$dir/bin" >> "$GITHUB_PATH"; fi
}

# tracked_scripts KIND: tracked files that are scripts of KIND (sh, python),
# by extension or by their first line, NUL-separated.
tracked_scripts() {
  local kind=$1 f first
  git ls-files -z | while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    case "$kind:$f" in
      sh:*.sh|python:*.py) printf '%s\0' "$f"; continue ;;
    esac
    IFS= read -r first < "$f" || true
    case "$kind:$first" in
      sh:'#!'*/sh|sh:'#!'*/bash|sh:'#!'*'env bash'|sh:'#!'*'env sh'|python:'#!'*python*)
        printf '%s\0' "$f" ;;
    esac
  done
}

run_checks() {
  local shellcheck n
  shellcheck=$(command -v shellcheck) || die "shellcheck is not on PATH"
  command -v actionlint >/dev/null || die "actionlint is not on PATH"
  echo "actionlint $(actionlint -version | head -1), shellcheck $(shellcheck --version | sed -n 's/^version: //p'), $(python3 --version)"
  actionlint -shellcheck="$shellcheck" -pyflakes=
  echo "actionlint: PASS"
  n=$(tracked_scripts sh | tr -cd '\0' | wc -c | tr -d ' ')
  [ "$n" -gt 0 ] || die "no shell scripts found"
  tracked_scripts sh | xargs -0 shellcheck -S warning -x
  echo "shellcheck: PASS ($n files)"
  n=$(tracked_scripts python | tr -cd '\0' | wc -c | tr -d ' ')
  if [ "$n" -gt 0 ]; then
    tracked_scripts python | xargs -0 python3 -I -c '
import ast, sys
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as f:
        ast.parse(f.read(), path)
'
  fi
  echo "python syntax: PASS ($n files)"
}

# The container runs as the invoking user, so that git inside it, which
# reuse uses to list the files, accepts the ownership of the checkout.
run_reuse() {
  command -v docker >/dev/null || die "docker is not on PATH"
  docker run --rm --user "$(id -u):$(id -g)" --volume "$PWD:/data" --workdir /data \
    "$REUSE_IMAGE" --version | head -1
  docker run --rm --user "$(id -u):$(id -g)" --volume "$PWD:/data" --workdir /data \
    "$REUSE_IMAGE" lint
}

case "${1:-}" in
  install) install_tools "${2:?usage: lint.sh install DIR}" ;;
  reuse) run_reuse ;;
  "") run_checks ;;
  *) echo "usage: lint.sh [install DIR | reuse]" >&2; exit 2 ;;
esac
