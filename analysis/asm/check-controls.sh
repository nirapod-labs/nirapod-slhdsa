#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/asm/check-controls.sh
# ==============================
#
# Negative controls of check-asm.sh. Each control is a file with a single
# violation of one rule, named as a real unit so that no other rule has
# anything to object to. Every control must be rejected, and with the
# message of its own rule: a rule that stops firing fails here even while
# the other rules still reject their controls.
#
# usage: check-controls.sh <arch: aarch64|x86_64> <dir>
# Writes each control to <dir>/<name>/sha2_128f-scalar.s and check-asm.sh's
# output for it to <dir>/<name>.log; exit status 0 when every control is
# rejected by its rule.

arch=$1
dir=$2
here=$(dirname "$0")
fail=0
n=0

# control NAME MESSAGE LINE: a control holding LINE (backslash escapes
# expanded), which check-asm.sh must reject with a line ending in MESSAGE
# (an extended regular expression).
control() {
  mkdir -p "$dir/$1"
  f=$dir/$1/sha2_128f-scalar.s
  printf '%b\n' "$3" > "$f"
  if sh "$here/check-asm.sh" "$arch" "$f" > "$dir/$1.log" 2>&1; then
    echo "control $1: accepted"
    fail=1
  elif ! grep -Eq ": $2\$" "$dir/$1.log"; then
    echo "control $1: rejected, but not by its rule ($2)"
    fail=1
  fi
  n=$((n + 1))
}

symbol='global symbol [A-Za-z0-9_]+ outside the export set'
control globl  "$symbol" '\t.globl\tnirapod_slhdsa_jz_sha2_128f_scalar__other'
control global "$symbol" '\t.global\tnirapod_slhdsa_jz_sha2_128f_scalar__other'
control weak   "$symbol" '\t.weak\tnirapod_slhdsa_jz_sha2_128f_scalar__other'

case $arch in
  aarch64)
    control udiv 'division instruction' '\tudiv\tx1, x2, x3'
    control sdiv 'division instruction' '\tsdiv\tw1, w2, w3'
    control x18  'uses x18' '\tmov\tx18, x1'
    control w18  'uses x18' '\tldr\tw18, [sp]'
    control x29  'uses x29' '\tmov\tx29, x1'
    control w29  'uses x29' '\tmov\tw29, w1'
    control fp   'uses x29' '\tstp\tfp, lr, [sp, #-16]!'
    ;;
  x86_64)
    control divq  'division instruction' '\tdivq\t%rcx'
    control idivl 'division instruction' '\tidivl\t%ecx'
    control div   'division instruction' '\tdiv\t%rcx'
    ;;
  *)
    echo "check-controls.sh: unknown architecture $arch" >&2
    exit 2
    ;;
esac

if [ "$fail" -eq 0 ]; then echo "check-controls.sh: $n controls, each rejected by its rule"; fi
exit $fail
