#!/bin/sh
#
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Negative control for the hash tests: show that the test run detects a
# wrong constant in every kernel family of the selected variants.
#
# A copy of the hash sources gets three single-bit mutations, one round
# constant each in Keccak (RC[0]), SHA-256 (K_0) and SHA-512 (K_0). Every
# kernel variant reads these shared tables, so the mutation reaches the
# variant selected for each root. The copy is compiled and run (CAVP and a
# short differential run). The control passes only if every family listed
# in NEG_FAMILIES has a failing check; a mutation that does not match its
# source text, a build failure or an undetected family fails the control.
#
# A second copy drops one store from each array squeeze: the last byte
# store of the single-way and of the 4-way extract, which writes the byte
# tail of an output. The squeeze sweep of that copy must fail for both, so
# the sweep is shown to catch a single output byte left unwritten.
#
# The two steps can run on different hosts, as the x86-64 tests do:
#
#     negative_control.sh build <hash source dir> <work dir> <test unit .jazz>
#         env: JASMINC JARCH SYSTEM ARCH KECCAK_DIR KECCAKX_DIR SHA2_DIR SHA2X_DIR
#     negative_control.sh run <work dir> <harness .c> <vectors dir>
#         env: CC CRYPTO_LIBS NEG_FAMILIES
#
# *_DIR name each kernel root relative to the hash source dir (for example
# keccak or sha2/x86_64/shani). NEG_FAMILIES is a space-separated list of
# words, each of which must appear in the name of at least one failing
# check, for example "SHA3_256 SHA256Short".

set -eu

mode=$1
shift

build() {
  src=$1 work=$2 unit=$3

  rm -rf "$work"
  mkdir -p "$work"
  cp -R "$src" "$work/hash"

  mutate() {
    file=$work/hash/$1 from=$2 to=$3
    grep -q -- "$from" "$file" || { echo "negative_control: pattern '$from' not found in $1" >&2; exit 1; }
    sed "s/$from/$to/" "$file" > "$file.new"
    mv "$file.new" "$file"
    cmp -s "$src/$1" "$file" && { echo "negative_control: $1 unchanged" >&2; exit 1; }
    return 0
  }

  # drop_store(file, store): delete the last line of the copy at work/store
  # that contains store.
  drop_store() {
    file=$work/store/hash/$1 store=$2
    n=$(grep -c -F -- "$store" "$file" || true)
    [ "$n" -ge 1 ] || { echo "negative_control: '$store' not found in $1" >&2; exit 1; }
    awk -v s="$store" -v n="$n" 'index($0, s) && ++k == n { next } { print }' "$file" > "$file.new"
    mv "$file.new" "$file"
    [ "$(grep -c -F -- "$store" "$file" || true)" -eq $((n - 1)) ] || {
      echo "negative_control: $1 store not dropped" >&2
      exit 1
    }
  }

  mkdir -p "$work/store"
  cp -R "$src" "$work/store/hash"
  drop_store keccak/sponge_array.jinc "out[off] = (8u)t;"
  drop_store keccak/sponge_x4_array.jinc "out3[off] = (8u)t;"

  mutate keccak/keccak_constants.jinc "0x0000000000000001, 0x0000000000008082" "0x0000000000000003, 0x0000000000008082"
  mutate sha2/sha256_k.jinc "0x428a2f98, 0x71374491" "0x428a2f99, 0x71374491"
  mutate sha2/sha512_k.jinc "0x428a2f98d728ae22" "0x428a2f98d728ae23"

  for d in "$work" "$work/store"; do
    h=$d/hash
    "$JASMINC" -arch "$JARCH" -system "$SYSTEM" \
      -I Hash="$h" -I HashWord="$h/$ARCH" \
      -I KeccakKernel="$h/$KECCAK_DIR" -I KeccakKernelX="$h/$KECCAKX_DIR" \
      -I Sha2Kernel="$h/$SHA2_DIR" -I Sha2KernelX="$h/$SHA2X_DIR" \
      -o "$d/hash_test.s" "$unit"
  done
}

run() {
  work=$1 harness=$2 vectors=$3

  for d in "$work" "$work/store"; do
    test -f "$d/hash_test.s" || { echo "negative_control: no mutated build in $d" >&2; exit 1; }
    # shellcheck disable=SC2086
    $CC -O2 -o "$d/hash_test" "$harness" "$d/hash_test.s" $CRYPTO_LIBS
  done

  "$work/hash_test" cavp "$vectors" > "$work/run.log" 2>&1 || true
  "$work/hash_test" diff 1 200 >> "$work/run.log" 2>&1 || true

  for family in $NEG_FAMILIES; do
    grep -q "^FAIL .*$family" "$work/run.log" || {
      echo "negative_control: FAIL, no $family failure detected" >&2
      exit 1
    }
  done
  echo "negative_control: PASS, every family detected ($(grep -c '^FAIL' "$work/run.log") failing checks)"

  "$work/store/hash_test" squeeze 1 > "$work/store/run.log" 2>&1 || true
  for way in x1 x4; do
    grep -q "^FAIL squeeze_$way " "$work/store/run.log" || {
      echo "negative_control: FAIL, the dropped $way squeeze store was not detected" >&2
      exit 1
    }
  done
  echo "negative_control: PASS, every dropped squeeze store detected ($(grep -c '^FAIL' "$work/store/run.log") failing checks)"
}

case $mode in
  build) build "$@" ;;
  run) run "$@" ;;
  *) echo "usage: negative_control.sh build|run ..." >&2; exit 2 ;;
esac
