#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/asm/check-asm.sh
# =========================
#
# Policy checks on the assembly of the parameter-set units, as emitted by
# the compiler (or written to gen/ by `make gen`):
#
#     symbols   every global or weak symbol is nirapod_slhdsa_jz_<unit>__<op>
#               for the unit's own name and one of the five exports
#     division  no division instruction (its timing depends on the
#               operands on both architectures)
#     x18       AArch64: the platform register is never written or read
#     x29       AArch64: the frame-pointer register (fp) is never written or
#               read, so a frame-chain walk during a call stays valid
#     timing    AArch64: every instruction is a data-independent-time
#               instruction of the Arm architecture, or a form that reads
#               no secret by construction (analysis/asm/dit.awk)
#     branches, traps, fence, leave, data
#               the rules of analysis/asm/exports.awk: no branch or call
#               leaves the unit or is indirect; no trap or system-register
#               instruction; every export runs a speculation barrier
#               before its first call and has one RET, reached only through
#               the stack-zeroing epilogue; no data directive in a code
#               section
#
# analysis/asm/check-controls.sh holds a negative control for each rule.
#
# usage: check-asm.sh <arch: aarch64|x86_64> <unit.s>...
# Prints one line per file and per violation; exit status 0 when every file
# passes. A file on which an awk rule exits non-zero fails, since the lines
# that awk did not reach are unchecked.

arch=$1
shift
here=$(dirname "$0")
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for f in "$@"; do
  unit=$(basename "$f" .s | tr '-' '_')
  bad=0

  # A file under gen/ opens with a comment block (licence, provenance)
  # whose words would read as instructions. The rules see a copy with
  # that block blanked, so line numbers stay those of the file; messages
  # name the file itself.
  g=$tmp/$(basename "$f")
  if ! awk 'NR == 1 && /^\/\*/ { c = 1 } c { if (/\*\//) c = 0; print ""; next } { print }' "$f" > "$g"; then
    echo "$f: cannot be read"; bad=1
  fi

  # .global / .globl / .weak / .weak_definition names, with the Mach-O
  # leading underscore removed.
  for sym in $(sed -En 's/^[[:space:]]*\.(globa?l|weak(_definition)?)[[:space:]]+([A-Za-z0-9_]*).*/\3/p' "$g"); do
    name=${sym#_}
    case $name in
      "nirapod_slhdsa_jz_${unit}__keygen"|"nirapod_slhdsa_jz_${unit}__sign"|\
      "nirapod_slhdsa_jz_${unit}__verify"|"nirapod_slhdsa_jz_${unit}__sign_internal"|\
      "nirapod_slhdsa_jz_${unit}__verify_internal") ;;
      *) echo "$f: global symbol $sym outside the export set"; bad=1 ;;
    esac
  done

  case $arch in
    aarch64)
      if grep -Eq '^[[:space:]]+[us]div[[:space:]]' "$g"; then echo "$f: division instruction"; bad=1; fi
      if grep -Eq '\b[xw]18\b' "$g"; then echo "$f: uses x18"; bad=1; fi
      if grep -Eq '\b([xw]29|fp)\b' "$g"; then echo "$f: uses x29"; bad=1; fi
      timing=$(awk -f "$here/dit.awk" "$g") || { echo "$f: dit.awk failed"; bad=1; }
      timing=$(printf '%s\n' "$timing" | sed "s|^$g:|$f:|;/^$/d")
      if [ -n "$timing" ]; then echo "$timing"; bad=1; fi
      ;;
    x86_64)
      if grep -Eq '^[[:space:]]+i?div[bwlq]?[[:space:]]' "$g"; then echo "$f: division instruction"; bad=1; fi
      ;;
    *)
      echo "check-asm.sh: unknown architecture $arch" >&2
      exit 2
      ;;
  esac

  flow=$(awk -v arch="$arch" -f "$here/exports.awk" "$g") || { echo "$f: exports.awk failed"; bad=1; }
  flow=$(printf '%s\n' "$flow" | sed "s|^$g:|$f:|;/^$/d")
  if [ -n "$flow" ]; then echo "$flow"; bad=1; fi

  if [ "$bad" -eq 0 ]; then echo "$f: PASS"; else fail=1; fi
done

exit $fail
