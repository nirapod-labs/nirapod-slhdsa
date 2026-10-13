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
#
# analysis/asm/check-controls.sh holds a negative control for each rule.
#
# usage: check-asm.sh <arch: aarch64|x86_64> <unit.s>...
# Prints one line per file and per violation; exit status 0 when every file
# passes.

arch=$1
shift
fail=0

for f in "$@"; do
  unit=$(basename "$f" .s | tr '-' '_')
  bad=0

  # .global / .globl / .weak / .weak_definition names, with the Mach-O
  # leading underscore removed.
  for sym in $(sed -En 's/^[[:space:]]*\.(globa?l|weak(_definition)?)[[:space:]]+([A-Za-z0-9_]*).*/\3/p' "$f"); do
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
      if grep -Eq '^[[:space:]]+[us]div[[:space:]]' "$f"; then echo "$f: division instruction"; bad=1; fi
      if grep -Eq '\b[xw]18\b' "$f"; then echo "$f: uses x18"; bad=1; fi
      if grep -Eq '\b([xw]29|fp)\b' "$f"; then echo "$f: uses x29"; bad=1; fi
      ;;
    x86_64)
      if grep -Eq '^[[:space:]]+i?div[bwlq]?[[:space:]]' "$f"; then echo "$f: division instruction"; bad=1; fi
      ;;
    *)
      echo "check-asm.sh: unknown architecture $arch" >&2
      exit 2
      ;;
  esac

  if [ "$bad" -eq 0 ]; then echo "$f: PASS"; else fail=1; fi
done

exit $fail
