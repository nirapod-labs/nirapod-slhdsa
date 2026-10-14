#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/cpu-has.sh
# ===================
#
# Usage: tools/ci/cpu-has.sh FEATURE...
#
# Exits 0 when this CPU reports every FEATURE, and 1 naming the first one it
# does not. A test run that needs an instruction-set extension calls this
# first, so that a runner without the extension fails the run instead of
# silently testing less. No argument is a success.
#
# Feature names are the kernel's: the flags line of /proc/cpuinfo on Linux
# x86-64 (avx2, sha_ni, ...), its Features line on Linux AArch64 (sha2,
# sha3, sha512, ...). On macOS the name is looked up as
# hw.optional.arm.FEAT_<NAME> (AArch64), for example sha3 -> FEAT_SHA3.

set -eu

case "$(uname -s)" in
  Linux)
    flags=" $(grep -m1 -E '^(flags|Features)[[:space:]]*:' /proc/cpuinfo | cut -d: -f2) "
    for f in "$@"; do
      case "$flags" in
        *" $f "*) ;;
        *) echo "cpu-has.sh: this CPU does not report '$f'" >&2; exit 1 ;;
      esac
    done ;;
  Darwin)
    for f in "$@"; do
      name=hw.optional.arm.FEAT_$(echo "$f" | tr '[:lower:]' '[:upper:]')
      [ "$(sysctl -n "$name" 2>/dev/null || echo 0)" = 1 ] \
        || { echo "cpu-has.sh: this CPU does not report '$f' ($name)" >&2; exit 1; }
    done ;;
  *)
    echo "cpu-has.sh: unsupported system $(uname -s)" >&2; exit 1 ;;
esac
