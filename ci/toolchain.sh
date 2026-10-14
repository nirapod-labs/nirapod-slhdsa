#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/toolchain.sh
# ===============
#
# Glue between a hosted runner and the pinned toolchain: system packages,
# packing and unpacking a built toolchain, and running a command in its
# environment. toolchain/build.sh builds the toolchain; ci/toolchain.py
# computes its build keys, finds bundles and checks them. Nothing here
# decides anything: each subcommand runs its steps and stops on the first
# error.
#
#   deps build      the system packages of docs/TOOLCHAIN.md and the pinned
#                   opam
#   deps run        what a job needs to run a built compiler and the tests
#                   (GMP, libcrypto, unzip, zstd)
#   pack-switch FILE
#                   the opam root (after `prune`) and the switch's records,
#                   as tar.zst
#   pack-compiler FILE
#                   the compiler (the four tools, the wrappers in
#                   toolchain/work/bin), its build record (toolchain/work/logs)
#                   and the Jasmin EasyCrypt library installed into the
#                   switch, as tar.gz
#   unpack FILE     unpack either archive at the root of the checkout, where
#                   it was packed: the opam root holds absolute paths, and
#                   every job of the repository checks out at the same path
#   prune           remove from the opam root what only an installation
#                   reads (download cache, package sources, documentation);
#                   ci/toolchain.py puts this list in the switch key
#   bin-path        put toolchain/work/bin on the PATH of the following
#                   workflow steps
#   exec CMD...     run CMD in the opam switch, in the isolated environment
#                   toolchain/build.sh gives its tools
#
# WORK (default toolchain/work) and OPAMROOT (default $WORK/opam) are those
# of toolchain/build.sh. Packing and unpacking use the default paths only.

set -euo pipefail
umask 022

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SWITCH=${SWITCH:-nirapod-slhdsa}   # the default of toolchain/build.sh
WORK=${WORK:-$ROOT/toolchain/work}
export OPAMROOT=${OPAMROOT:-$WORK/opam}
PRUNE_ROOT="download-cache"
PRUNE_SWITCH=".opam-switch/sources .opam-switch/build doc man"
SWITCH_PATHS=(toolchain/work/opam toolchain/work/logs/switch.txt
              toolchain/work/logs/easycrypt-config.txt)
COMPILER_PATHS=(toolchain/work/jasmin/compiler/jasminc toolchain/work/jasmin/compiler/jasmin-ct
                toolchain/work/jasmin/compiler/jasmin2ec
                toolchain/work/jasmin/compiler/jasmin-checksafety
                toolchain/work/jasmin/compiler/_build/install/default/bin
                toolchain/work/jasmin/compiler/_build/default/entry
                toolchain/work/state toolchain/work/logs toolchain/work/bin
                "toolchain/work/opam/$SWITCH/lib/easycrypt/jasmin"
                "toolchain/work/opam/$SWITCH/lib/easycrypt/config/jasmin.conf")

# opam, pinned by the SHA-256 of the release binary; toolchain/build.sh
# requires this release.
OPAM_VERSION=2.6.0
OPAM_URL=https://github.com/ocaml/opam/releases/download/$OPAM_VERSION
APT_BUILD="build-essential git curl unzip m4 pkg-config bubblewrap zstd
           libgmp-dev libmpfr-dev libppl-dev libpcre2-dev zlib1g-dev"
APT_RUN="libgmp-dev libssl-dev unzip zstd"
BREW_BUILD="gmp mpfr ppl pcre2 pkgconf zstd"
BREW_RUN="gmp openssl@3 zstd"
PLATFORM="$(uname -s)-$(uname -m)"

die() { echo "toolchain.sh: $*" >&2; exit 1; }

opam_asset() {
  case "$PLATFORM" in
    Linux-x86_64)  echo "opam-$OPAM_VERSION-x86_64-linux a59184447f881005dae70b2ae455c3a7e9549834a41c635c49a5a28235eca758" ;;
    Linux-aarch64) echo "opam-$OPAM_VERSION-arm64-linux aeaeb4294a9abaa7d37844d9138230125933c648e631da2eec888b5e4ce55bde" ;;
    Darwin-arm64)  echo "opam-$OPAM_VERSION-arm64-macos b57ed6cc082e560063989a285c59786b7c670087da2d317a87e4ba4c7973e71f" ;;
    *) die "no opam binary for $PLATFORM" ;;
  esac
}

# The download is checked against its pin by sha256sum or shasum, which
# exit non-zero on a mismatch.
install_opam() {
  local asset sum dir
  read -r asset sum <<< "$(opam_asset)"
  dir=$(mktemp -d)
  curl -fsSL --retry 3 -o "$dir/$asset" "$OPAM_URL/$asset"
  if command -v sha256sum > /dev/null; then
    (cd "$dir" && echo "$sum  $asset" | sha256sum -c -)
  else
    (cd "$dir" && echo "$sum  $asset" | shasum -a 256 -c -)
  fi
  sudo install -m 0755 "$dir/$asset" /usr/local/bin/opam
  rm -rf "$dir"
  opam --version
}

deps_linux() {
  sudo apt-get update -q
  # shellcheck disable=SC2086
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $1
}

deps_macos() {
  # shellcheck disable=SC2086
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 brew install --quiet $1
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

# existing PATH...: the paths that exist, from the root.
existing() {
  local p
  for p in "$@"; do
    if [ -e "$ROOT/$p" ]; then printf '%s\0' "$p"; fi
  done
}

cmd_pack_switch() {
  local out=${1:?usage: toolchain.sh pack-switch FILE}
  existing "${SWITCH_PATHS[@]}" | (cd "$ROOT" && xargs -0 tar -cf -) | zstd -q -T0 -3 -o "$out"
  ls -l "$out"
}

cmd_pack_compiler() {
  local out=${1:?usage: toolchain.sh pack-compiler FILE}
  existing "${COMPILER_PATHS[@]}" | (cd "$ROOT" && xargs -0 tar -czf "$out")
  ls -l "$out"
}

cmd_unpack() {
  local file=${1:?usage: toolchain.sh unpack FILE}
  case "$file" in
    *.tar.zst) zstd -q -dc "$file" | tar -C "$ROOT" -xf - ;;
    *.tar.gz)  tar -C "$ROOT" -xzf "$file" ;;
    *) die "$file: expected a .tar.zst or .tar.gz archive" ;;
  esac
}

cmd_prune() {
  local root prefix p
  root=$(opam var root)
  prefix=$(opam var prefix --switch="$SWITCH")
  [ -d "$prefix/.opam-switch" ] || die "$prefix is not an opam switch"
  for p in $PRUNE_ROOT; do rm -rf "${root:?}/$p"; done
  for p in $PRUNE_SWITCH; do rm -rf "${prefix:?}/$p"; done
  du -sh "$root"
}

cmd_bin_path() {
  [ -d "$WORK/bin" ] || die "$WORK/bin: missing; build or unpack the compiler first"
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
  deps)          shift; cmd_deps "$@" ;;
  pack-switch)   shift; cmd_pack_switch "$@" ;;
  pack-compiler) shift; cmd_pack_compiler "$@" ;;
  unpack)        shift; cmd_unpack "$@" ;;
  prune)         shift; cmd_prune "$@" ;;
  bin-path)      shift; cmd_bin_path "$@" ;;
  exec)          shift; cmd_exec "$@" ;;
  *) echo "usage: toolchain.sh deps|pack-switch|pack-compiler|unpack|prune|bin-path|exec ..." >&2; exit 2 ;;
esac
