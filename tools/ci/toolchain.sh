#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/toolchain.sh
# =====================
#
# The continuous-integration side of the pinned toolchain. The toolchain
# itself is built by toolchain/build.sh; this script prepares a hosted
# runner for it, names its caches, and moves the built compiler between
# jobs. It never builds, patches or edits the compiler.
#
#   deps build      system packages of docs/TOOLCHAIN.md and the pinned opam
#   deps run        what a downstream job needs to run the packed compiler
#                   and the tests (GMP, libcrypto, unzip)
#   keys            cache keys of the switch and of the compiler, written to
#                   $GITHUB_OUTPUT as switch-key= and compiler-key=
#   pack FILE       the compiler (jasminc, jasmin-ct, jasmin2ec) and the
#                   record of its build, as a gzip tar archive
#   install FILE DIR
#                   unpack an archive made by `pack` into DIR, check each
#                   binary against the build record in the same archive,
#                   and put DIR/bin on the PATH of the following workflow
#                   steps (outside a workflow, print the PATH setting)
#   compare A B     two archives of one platform: fail unless their build
#                   records describe the same compiler
#   compare-cached A
#                   pack the build now in toolchain/work (the cached one)
#                   and compare archive A, the cold build, with it
#   no-cached-build fail, explaining that a cold build had no cached build
#                   of the same inputs to be compared with
#   agree A B...    archives of the CI_PLATFORMS platforms (all of them):
#                   fail unless the extracted compiler and its assumptions
#                   are identical
#   prune           remove from the opam root what only an installation
#                   reads (download cache, package sources, documentation),
#                   before the switch is saved to the cache
#   clear           remove the part of toolchain/work the compiler cache
#                   holds
#   cache-paths     the paths of the two cache entries, written to
#                   $GITHUB_OUTPUT as switch= and compiler=, so that every
#                   job that saves or restores an entry names the same paths
#   bin-path        put toolchain/work/bin (all four tools of the cached
#                   build, jasmin-checksafety included) on the PATH of the
#                   following workflow steps
#   exec CMD...     run CMD in the opam switch, in the isolated environment
#                   toolchain/build.sh gives its tools
#
# TOOLCHAIN_OPTIONS holds the options the workflow gives toolchain/build.sh
# before its step (--no-easycrypt on Linux AArch64); they are part of the
# cache keys.
#
# Cache keys. A key is the SHA-256 of everything that can change what the
# cached directory holds, so that a cache hit means "built from these exact
# inputs on this kind of host". Between them, the two keys cover every file
# under toolchain/ except the build directory toolchain/work/:
#
#   switch    the host identity (OS release, machine, C compiler, C
#             library, opam, and the installed versions of the system
#             packages the switch links against, so that a new runner image
#             that changes one of them changes the key instead of restoring
#             a switch built against other libraries), TOOLCHAIN_OPTIONS,
#             and every file under toolchain/ outside toolchain/jasmin/,
#             plus toolchain/jasmin/PIN
#   compiler  the switch key and every file under toolchain/jasmin/: the
#             pin, the patch series and its list, the expected assumptions
#             and admits
#
# This script is not part of either key: what it changes on the host is in
# the host identity, and an edit to its text alone does not force a rebuild.
#
# The workflow saves an entry only after the steps that produce it have
# passed: the switch after `build.sh switch` and its checks, the compiler
# after `build.sh jasmin` and `build.sh test`. A restored entry therefore
# comes from a run in which those steps passed on the inputs its key names.
#
# The packed compiler excludes jasmin-checksafety: it loads the abstract-
# domain libraries of the opam switch by absolute path, so a job that runs
# it restores the switch and compiler caches and uses bin-path instead.
#
# The opam root is toolchain/work/opam, the default of toolchain/build.sh,
# unless OPAMROOT names another one.
#
# Cache entries
# -------------
#
# Switch: the opam root, after `prune` has removed what only an
# installation reads (download cache, package sources, documentation), and
# the switch's own records. The repository checkouts and prover downloads
# under toolchain/work are not cached: only `build.sh switch` reads them, and
# it runs only when this entry is missing.
#
# Compiler: the four tool binaries of the patched tree and the links to them
# that build.sh and this script use, the build record, the wrappers in
# toolchain/work/bin, and the Jasmin EasyCrypt library that `build.sh
# jasmin` installs into the switch (absent without EasyCrypt). The rest of
# the tree (the Rocq development and its compiled proofs, the OCaml build
# directories) is read only during the build.
#
# Budget. The repository has 10 GB of Actions cache, evicted least recently
# used first. Compressed sizes measured with zstd -3 (the cache's
# compressor) on builds of the pinned toolchain: switch 839 MB (Linux
# x86-64) and 649 MB (macOS AArch64), compiler 27 MB (Linux x86-64). The
# Linux AArch64 switch carries no EasyCrypt or provers and is expected to be
# smaller than the x86-64 one; it and the macOS compiler entry have not been
# measured. Taking each unmeasured entry as no larger than its x86-64
# counterpart, one set of entries for the three platforms stays under
# 2.5 GB, plus 70 MB of ACVP vectors; the rest of the budget holds the
# entries of pull requests that change the toolchain.
#
# Every subcommand stops on the first error; there is no fallback path.

set -euo pipefail
umask 022

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SWITCH=${SWITCH:-nirapod-slhdsa}   # the default of toolchain/build.sh
TOOLCHAIN=$ROOT/toolchain
WORK=${WORK:-$TOOLCHAIN/work}
TREE=$WORK/jasmin
export OPAMROOT=${OPAMROOT:-$WORK/opam}
PACKED_TOOLS="jasminc jasmin-ct jasmin2ec"
SWITCH_PATHS="toolchain/work/opam
toolchain/work/logs/switch.txt
toolchain/work/logs/easycrypt-config.txt"
COMPILER_PATHS="toolchain/work/jasmin/compiler/jasminc
toolchain/work/jasmin/compiler/jasmin-ct
toolchain/work/jasmin/compiler/jasmin2ec
toolchain/work/jasmin/compiler/jasmin-checksafety
toolchain/work/jasmin/compiler/_build/install/default/bin
toolchain/work/jasmin/compiler/_build/default/entry/*.exe
toolchain/work/state
toolchain/work/logs
toolchain/work/bin
toolchain/work/opam/$SWITCH/lib/easycrypt/jasmin
toolchain/work/opam/$SWITCH/lib/easycrypt/config/jasmin.conf"
# The build record a packed archive carries. eclib-axioms.log exists only
# where the toolchain has EasyCrypt; every other file always.
RECORD_LOGS="provenance.txt assumptions.log admit-scan.log cil.sha256 binaries.sha256 switch.txt test-suites.txt"
RECORD_LOGS_EASYCRYPT="eclib-axioms.log"

# opam, pinned by the SHA-256 of the release binary; toolchain/build.sh
# requires this release.
OPAM_VERSION=2.6.0
OPAM_URL=https://github.com/ocaml/opam/releases/download/$OPAM_VERSION
opam_asset() {
  case "$1" in
    Linux-x86_64)  echo "opam-$OPAM_VERSION-x86_64-linux a59184447f881005dae70b2ae455c3a7e9549834a41c635c49a5a28235eca758" ;;
    Linux-aarch64) echo "opam-$OPAM_VERSION-arm64-linux aeaeb4294a9abaa7d37844d9138230125933c648e631da2eec888b5e4ce55bde" ;;
    Darwin-arm64)  echo "opam-$OPAM_VERSION-arm64-macos b57ed6cc082e560063989a285c59786b7c670087da2d317a87e4ba4c7973e71f" ;;
    *) return 1 ;;
  esac
}

# System packages, from docs/TOOLCHAIN.md.
APT_BUILD="build-essential git curl unzip m4 pkg-config bubblewrap
           libgmp-dev libmpfr-dev libppl-dev libpcre2-dev zlib1g-dev"
APT_RUN="libgmp-dev libssl-dev unzip"
BREW_BUILD="gmp mpfr ppl pcre2 pkgconf"
BREW_RUN="gmp openssl@3"

PLATFORM="$(uname -s)-$(uname -m)"

die() { echo "toolchain.sh: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$@"
  else shasum -a 256 "$@"; fi
}

# ---------------------------------------------------------------------------
# deps

install_opam() {
  local asset sum file got
  read -r asset sum <<<"$(opam_asset "$PLATFORM")" || die "no opam binary for $PLATFORM"
  file=$(mktemp)
  curl -fsSL --retry 3 -o "$file" "$OPAM_URL/$asset"
  got=$(sha256_of "$file" | cut -d' ' -f1)
  [ "$got" = "$sum" ] || die "$asset: SHA-256 $got, expected $sum"
  sudo install -m 0755 "$file" /usr/local/bin/opam
  rm -f "$file"
  [ "$(opam --version)" = "$OPAM_VERSION" ] || die "opam on PATH is not $OPAM_VERSION"
}

deps_linux() {
  local packages=$1
  sudo apt-get update -q
  # shellcheck disable=SC2086
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $packages
}

deps_macos() {
  local packages=$1
  # shellcheck disable=SC2086
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 brew install --quiet $packages
}

cmd_deps() {
  case "${1:-}:$PLATFORM" in
    build:Linux-*)
      deps_linux "$APT_BUILD"
      # opam builds packages inside bubblewrap, which needs unprivileged user
      # namespaces; the runner image restricts them through AppArmor. This
      # relaxes a kernel hardening setting on the runner, a virtual machine
      # discarded after the job; never run `deps build` on a host you keep.
      if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
        sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
      fi
      install_opam ;;
    build:Darwin-*) deps_macos "$BREW_BUILD"; install_opam ;;
    run:Linux-*)    deps_linux "$APT_RUN" ;;
    run:Darwin-*)   deps_macos "$BREW_RUN" ;;
    *) die "usage: toolchain.sh deps build|run (platform $PLATFORM)" ;;
  esac
}

# ---------------------------------------------------------------------------
# keys

# The host properties a built switch depends on, one per line.
host_identity() {
  local cc_version opam_version libc_version os_version
  # Assignments, so that a missing tool stops the script.
  cc_version=$(cc --version | head -1)
  opam_version=$(opam --version)
  echo "platform $PLATFORM"
  echo "cc $cc_version"
  echo "opam $opam_version"
  case "$PLATFORM" in
    Linux-*)
      libc_version=$(ldd --version | head -1)
      # shellcheck disable=SC1091
      (. /etc/os-release && echo "os $ID $VERSION_ID")
      echo "libc $libc_version"
      # shellcheck disable=SC2086
      dpkg-query -W -f='package ${Package} ${Version}\n' $APT_BUILD | LC_ALL=C sort ;;
    Darwin-*)
      os_version="$(sw_vers -productVersion) $(sw_vers -buildVersion)"
      echo "os macOS $os_version"
      # shellcheck disable=SC2086
      brew list --versions $BREW_BUILD | sed 's/^/package /' | LC_ALL=C sort ;;
  esac
}

# digest_files FILE...: one "SHA-256  path" line per file. Called in the
# main shell, never in a command substitution, so a missing file stops the
# script.
digest_files() {
  local f sum
  for f in "$@"; do
    [ -f "$f" ] || die "$f: missing"
    sum=$(sha256_of "$f" | cut -d' ' -f1)
    printf '%s  %s\n' "$sum" "${f#"$ROOT"/}"
  done
}

# toolchain_files PART: the files of PART, in a fixed order. PART "switch"
# is everything under toolchain/ outside work/ and jasmin/, plus jasmin/PIN;
# PART "compiler" is everything under toolchain/jasmin/.
toolchain_files() {
  case "$1" in
    switch)
      find "$TOOLCHAIN" \( -path "$TOOLCHAIN/work" -o -path "$TOOLCHAIN/jasmin" \) -prune \
           -o -type f -print
      echo "$TOOLCHAIN/jasmin/PIN" ;;
    compiler)
      find "$TOOLCHAIN/jasmin" -type f ;;
  esac | LC_ALL=C sort
}

cmd_keys() {
  local tmp switch compiler f
  [ -f "$TOOLCHAIN/build.sh" ] || die "$TOOLCHAIN/build.sh: missing"
  [ -f "$TOOLCHAIN/jasmin/PIN" ] || die "$TOOLCHAIN/jasmin/PIN: missing"
  # Every input is written to a file by the main shell, where an error stops
  # the script; bash does not stop inside a command substitution.
  tmp=$(mktemp -d)
  host_identity > "$tmp/host"
  toolchain_files switch > "$tmp/switch-files"
  toolchain_files compiler > "$tmp/compiler-files"
  { cat "$tmp/host"
    echo "options ${TOOLCHAIN_OPTIONS:-}"
    while read -r f; do digest_files "$f"; done < "$tmp/switch-files"
  } > "$tmp/switch"
  switch=$(sha256_of "$tmp/switch" | cut -d' ' -f1)
  { echo "$switch"
    while read -r f; do digest_files "$f"; done < "$tmp/compiler-files"
  } > "$tmp/compiler"
  compiler=$(sha256_of "$tmp/compiler" | cut -d' ' -f1)
  echo "host identity:"
  sed 's/^/  /' "$tmp/host"
  echo "options: ${TOOLCHAIN_OPTIONS:-(none)}"
  echo "files: $(wc -l < "$tmp/switch-files" | tr -d ' ') in the switch key," \
       "$(wc -l < "$tmp/compiler-files" | tr -d ' ') more in the compiler key"
  rm -rf "$tmp"
  echo "switch-key=toolchain-switch-$PLATFORM-$switch"
  echo "compiler-key=toolchain-compiler-$PLATFORM-$compiler"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "switch-key=toolchain-switch-$PLATFORM-$switch"
      echo "compiler-key=toolchain-compiler-$PLATFORM-$compiler"
    } >> "$GITHUB_OUTPUT"
  fi
}

# ---------------------------------------------------------------------------
# pack, install

# check_record DIR: the binaries in DIR/bin are those whose SHA-256 the build
# recorded in DIR/logs/binaries.sha256, and each one runs on this host. Both
# come from the same archive, so this detects a damaged or mixed-up
# archive; it is not evidence of where the binaries came from. That rests on
# the archive having been made by the toolchain job of the same workflow run.
check_record() {
  local dir=$1 b want got
  for b in $PACKED_TOOLS; do
    want=$(awk -v b="$b" '$2 == b { print $1 }' "$dir/logs/binaries.sha256")
    got=$(sha256_of "$dir/bin/$b" | cut -d' ' -f1)
    [ -n "$want" ] || die "$b: not in the build record"
    [ "$got" = "$want" ] || die "$b: SHA-256 $got, build record says $want"
  done
  "$dir/bin/jasminc" -version >/dev/null || die "jasminc does not run"
  "$dir/bin/jasmin-ct" --version >/dev/null || die "jasmin-ct does not run"
  "$dir/bin/jasmin2ec" --version >/dev/null || die "jasmin2ec does not run"
}

cmd_pack() {
  local out=${1:?usage: toolchain.sh pack FILE} stage b l
  stage=$(mktemp -d)
  mkdir -p "$stage/toolchain/bin" "$stage/toolchain/logs"
  for b in $PACKED_TOOLS; do
    [ -x "$TREE/compiler/$b" ] || die "$TREE/compiler/$b: not built"
    cp -L "$TREE/compiler/$b" "$stage/toolchain/bin/$b"
  done
  for l in $RECORD_LOGS; do
    [ -f "$WORK/logs/$l" ] || die "$WORK/logs/$l: missing from the build record"
    cp "$WORK/logs/$l" "$stage/toolchain/logs/$l"
  done
  for l in $RECORD_LOGS_EASYCRYPT; do
    if [ -f "$WORK/logs/$l" ]; then cp "$WORK/logs/$l" "$stage/toolchain/logs/$l"; fi
  done
  echo "$PLATFORM" > "$stage/toolchain/PLATFORM"
  check_record "$stage/toolchain"
  tar -C "$stage" -czf "$out" toolchain
  rm -rf "$stage"
  echo "packed $out:"
  cat "$WORK/logs/binaries.sha256"
}

cmd_install() {
  local file=${1:?usage: toolchain.sh install FILE DIR} dir=${2:?usage: toolchain.sh install FILE DIR}
  [ ! -e "$dir" ] || die "$dir already exists"
  mkdir -p "$dir"
  dir=$(cd "$dir" && pwd)
  tar -C "$dir" --strip-components=1 -xzf "$file"
  [ "$(cat "$dir/PLATFORM")" = "$PLATFORM" ] \
    || die "the archive was built on $(cat "$dir/PLATFORM"), this host is $PLATFORM"
  check_record "$dir"
  sed -nE 's/^(jasmin HEAD|jasmin tree|project commit): /  \1: /p' "$dir/logs/provenance.txt"
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$dir/bin" >> "$GITHUB_PATH"
  else
    echo "export PATH=\"$dir/bin:\$PATH\""
  fi
}

# ---------------------------------------------------------------------------
# compare, agree, clear

# record ARCHIVE DIR: the build record (logs/) of an archive made by `pack`.
record() {
  mkdir -p "$2"
  tar -C "$2" --strip-components=2 -xzf "$1" toolchain/logs
}

# The lines of provenance.txt that identify the compiler source, without
# dates, host names or tool paths: the pin, the patched tree and its
# commits, and the series with the digest of each patch.
source_identity() {
  awk '
    /^(jasmin pin|jasmin HEAD|jasmin tree): / { print; block = 0; next }
    /^(commits on the pin|series \(jasmin\/SERIES\)):$/ { print; block = 1; next }
    /^  / { if (block) print; next }
    { block = 0 }
  ' "$1"
}

same() {
  local what=$1 a=$2 b=$3
  if cmp -s "$a" "$b"; then
    echo "  same: $what"
  else
    echo "  DIFFERENT: $what"; diff "$a" "$b" || true
    return 1
  fi
}

# compare_records A B KIND...: A and B agree on the compiler source and on
# each listed record file.
compare_records() {
  local a=$1 b=$2 bad=0 f
  shift 2
  echo "compare $(basename "$a") with $(basename "$b"):"
  source_identity "$a/provenance.txt" > "$a/source-identity" || true
  source_identity "$b/provenance.txt" > "$b/source-identity" || true
  # The caller tests this function's status, which turns off errexit inside
  # it: an unreadable record must therefore fail here explicitly.
  grep -q '^jasmin tree: ' "$a/source-identity" && grep -q '^jasmin tree: ' "$b/source-identity" \
    || { echo "  no patched-tree identity in a provenance record"; return 1; }
  same "compiler source (pin, series, patched tree)" "$a/source-identity" "$b/source-identity" || bad=1
  for f in "$@"; do
    same "$f" "$a/$f" "$b/$f" || bad=1
  done
  return "$bad"
}

# A cold build and the cached build of the same inputs on the same platform
# are the same compiler, byte for byte. What is compared are the two build
# records: the binaries enter through binaries.sha256, which `pack` checked
# against the packed binaries of each build.
cmd_compare() {
  [ $# = 2 ] || die "usage: toolchain.sh compare ARCHIVE ARCHIVE"
  local t
  t=$(mktemp -d)
  record "$1" "$t/a"
  record "$2" "$t/b"
  # The EasyCrypt record is compared when either build has one; a file
  # present on one side only is a difference.
  local extra=""
  if [ -f "$t/a/eclib-axioms.log" ] || [ -f "$t/b/eclib-axioms.log" ]; then extra=eclib-axioms.log; fi
  # shellcheck disable=SC2086
  compare_records "$t/a" "$t/b" cil.sha256 assumptions.log admit-scan.log binaries.sha256 \
    test-suites.txt $extra \
    || die "the two builds differ"
  rm -rf "$t"
}

cmd_compare_cached() {
  [ $# = 1 ] || die "usage: toolchain.sh compare-cached ARCHIVE"
  local cached
  cached=$(mktemp -d)/cached.tar.gz
  cmd_pack "$cached"
  cmd_compare "$1" "$cached"
}

# A scheduled cold build exists to be compared with the cached build of the
# same inputs. Without one (the entry was evicted, or the inputs are new)
# there is no comparison, and the run must not pass as if there had been
# one. The cold build has been saved as the cache entry, so the next cold
# run compares against it.
cmd_no_cached_build() {
  die "cold build: no cached build of these inputs existed, so nothing was compared (INCONCLUSIVE); the cold build is now the cache entry; run the cold build again to compare"
}

# Builds of different platforms extracted the same compiler from the same
# proofs, which rest on the same assumptions. Their binaries differ (each is
# native code for its own host) and are not compared. Every platform of the
# workflow must be present: CI_PLATFORMS archives exactly.
cmd_agree() {
  [ -n "${CI_PLATFORMS:-}" ] || die "CI_PLATFORMS is not set"
  [ $# = "$CI_PLATFORMS" ] || die "expected $CI_PLATFORMS archives, got $#"
  local t i=0 a bad=0
  t=$(mktemp -d)
  for a in "$@"; do
    i=$((i + 1))
    record "$a" "$t/$i-$(basename "$a" .tar.gz)"
  done
  set -- "$t"/*
  a=$1
  shift
  for d in "$@"; do
    compare_records "$a" "$d" cil.sha256 assumptions.log admit-scan.log || bad=1
  done
  [ "$bad" = 0 ] || die "the platforms built different compilers"
  rm -rf "$t"
}

# The switch keeps everything a later build or proof check loads: compiled
# libraries, binaries, provers, its configuration and the opam repository
# state that `opam env` and `opam exec` read.
cmd_prune() {
  local root prefix
  root=$(opam var root)
  prefix=$(opam var prefix --switch="$SWITCH")
  [ -d "$prefix/.opam-switch" ] || die "$prefix is not an opam switch"
  rm -rf "${root:?}/download-cache" "${prefix:?}/.opam-switch/sources" \
         "${prefix:?}/.opam-switch/build" "${prefix:?}/doc" "${prefix:?}/man"
  du -sh "$root" | sed 's/^/opam root after pruning: /'
}

# Remove what the compiler cache holds, so that the cached build can be
# restored next to a cold one in the same job.
cmd_clear() {
  rm -rf "${WORK:?}/jasmin" "${WORK:?}/logs" "${WORK:?}/bin" "${WORK:?}/state"
}

cmd_cache_paths() {
  printf 'switch paths:\n%s\ncompiler paths:\n%s\n' "$SWITCH_PATHS" "$COMPILER_PATHS"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'switch<<END_OF_PATHS\n%s\nEND_OF_PATHS\ncompiler<<END_OF_PATHS\n%s\nEND_OF_PATHS\n' \
      "$SWITCH_PATHS" "$COMPILER_PATHS" >> "$GITHUB_OUTPUT"
  fi
}

cmd_bin_path() {
  local b
  for b in jasminc jasmin-ct jasmin2ec jasmin-checksafety; do
    [ -x "$WORK/bin/$b" ] || die "$WORK/bin/$b: missing; restore the compiler cache first"
  done
  "$WORK/bin/jasmin-checksafety" --version >/dev/null || die "jasmin-checksafety does not run"
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$WORK/bin" >> "$GITHUB_PATH"
  else
    echo "export PATH=\"$WORK/bin:\$PATH\""
  fi
}

# The environment of toolchain/build.sh: its opam root and no other OPAM*
# setting, and home, configuration, data, cache and temporary directories
# under toolchain/work, so that EasyCrypt and Why3 read only the switch's
# configuration, as they did when the build checked it.
cmd_exec() {
  [ $# -ge 1 ] || die "usage: toolchain.sh exec CMD..."
  local v
  for v in $(env | sed -n 's/^\(OPAM[A-Z_]*\)=.*/\1/p'); do
    [ "$v" = OPAMROOT ] || unset "$v"
  done
  mkdir -p "$WORK/home" "$WORK/tmp" "$WORK/xdg/config" "$WORK/xdg/data" \
           "$WORK/xdg/cache" "$WORK/xdg/etc" "$WORK/xdg/share"
  HOME="$WORK/home" TMPDIR="$WORK/tmp" \
  XDG_CONFIG_HOME="$WORK/xdg/config" XDG_DATA_HOME="$WORK/xdg/data" \
  XDG_CACHE_HOME="$WORK/xdg/cache" XDG_CONFIG_DIRS="$WORK/xdg/etc" \
  XDG_DATA_DIRS="$WORK/xdg/share" \
    opam exec --switch="$SWITCH" -- "$@"
}

case "${1:-}" in
  deps)    shift; cmd_deps "$@" ;;
  keys)    shift; cmd_keys "$@" ;;
  pack)    shift; cmd_pack "$@" ;;
  install) shift; cmd_install "$@" ;;
  compare) shift; cmd_compare "$@" ;;
  agree)   shift; cmd_agree "$@" ;;
  compare-cached)  shift; cmd_compare_cached "$@" ;;
  no-cached-build) shift; cmd_no_cached_build "$@" ;;
  prune)   shift; cmd_prune "$@" ;;
  clear)   shift; cmd_clear "$@" ;;
  cache-paths) shift; cmd_cache_paths "$@" ;;
  bin-path) shift; cmd_bin_path "$@" ;;
  exec)    shift; cmd_exec "$@" ;;
  *) echo "usage: toolchain.sh deps|keys|pack|install|compare|compare-cached|no-cached-build|agree|prune|clear|cache-paths|bin-path|exec ..." >&2; exit 2 ;;
esac
