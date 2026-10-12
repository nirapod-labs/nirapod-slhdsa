#!/bin/sh
#
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Fill check for the SHA-2 buffer invariant: the functions never read a
# byte of buf that the current hash has not written (src/jasmin/hash/
# README.md, SHA-2 state). The one-shot functions and the HMAC test exports
# zero their buffer before first use, only so that the safety checker can
# follow the buffer; this check builds a copy in which that zeroing writes
# 0xa5 bytes instead, and runs CAVP and the differential test on it. A read
# of a byte the hash has not written would see 0xa5 rather than 0 and
# change a digest, so the check passes only if every test passes.
#
# Two steps, which can run on different hosts like the main tests:
#
#     fill_check.sh build <hash source dir> <test jasmin dir> <work dir>
#         env: JASMINC JARCH SYSTEM ARCH KECCAK_DIR KECCAKX_DIR SHA2_DIR SHA2X_DIR
#     fill_check.sh run <work dir> <harness .c> <vectors dir>
#         env: CC CFLAGS CRYPTO_LIBS DIFF_SEED DIFF_ITERS
#
# A substitution that does not match its expected number of sites fails
# the build step.

set -eu

mode=$1
shift

FILL=0xa5a5a5a5a5a5a5a5

build() {
  src=$1 tests=$2 work=$3

  rm -rf "$work"
  mkdir -p "$work"
  cp -R "$src" "$work/hash"
  cp -R "$tests" "$work/jasmin"

  refill() {
    file=$1 from=$2 count=$3
    n=$(grep -c -- "$from = 0;" "$file" || true)
    [ "$n" -eq "$count" ] || { echo "fill_check: $file has $n sites of '$from = 0;', expected $count" >&2; exit 1; }
    sed "s/$from = 0;/$from = $FILL;/" "$file" > "$file.new"
    mv "$file.new" "$file"
  }

  refill "$work/hash/sha2/sha256.jinc" 'buf_s\[:u64 i\]' 1
  refill "$work/hash/sha2/sha512.jinc" 'buf_s\[:u64 i\]' 1
  refill "$work/jasmin/test_sha2.jinc" 'buf\[:u64 i\]' 2

  h=$work/hash
  "$JASMINC" -arch "$JARCH" -system "$SYSTEM" \
    -I Hash="$h" -I HashWord="$h/$ARCH" \
    -I KeccakKernel="$h/$KECCAK_DIR" -I KeccakKernelX="$h/$KECCAKX_DIR" \
    -I Sha2Kernel="$h/$SHA2_DIR" -I Sha2KernelX="$h/$SHA2X_DIR" \
    -o "$work/hash_test.s" "$work/jasmin/hash_test.jazz"
}

run() {
  work=$1 harness=$2 vectors=$3

  test -f "$work/hash_test.s" || { echo "fill_check: no filled build in $work" >&2; exit 1; }
  # shellcheck disable=SC2086
  $CC ${CFLAGS:--O2} -o "$work/hash_test" "$harness" "$work/hash_test.s" $CRYPTO_LIBS
  "$work/hash_test" cavp "$vectors"
  "$work/hash_test" diff "$DIFF_SEED" "$DIFF_ITERS"
  echo "fill_check: PASS, every test passes with 0xa5-filled buffers"
}

case $mode in
  build) build "$@" ;;
  run) run "$@" ;;
  *) echo "usage: fill_check.sh build|run ..." >&2; exit 2 ;;
esac
