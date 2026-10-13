#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/core/acvp-control.sh
# ==========================
#
# Negative control of the ACVP known-answer test (test_acvp.c): the test
# must reject a case whose expected answer was changed, so that a parser
# that silently skipped fields, or a comparison that always succeeded,
# cannot pass unnoticed.
#
#     acvp-control.sh <test_acvp binary> <acvp-subset.txt> <work dir>
#
# Two cases of SLH-DSA-SHA2-128f, the first siggen and the first sigver of
# the subset, are each written to a file of their own, once as given and
# once changed:
#
#     siggen  the last hex digit of the expected signature is replaced;
#             the case must fail with "signature differs"
#     sigver  the expected verdict is inverted; the case must fail
#
# The unchanged copy must give PASS on that case and the changed copy FAIL,
# so the failure is the change's and not the file's. A one-case file always
# fails the "a case of each kind for every set" rule of the test, so the
# exit status is required to be 1 for both copies and the verdict is read
# from the case's own line. Exit status 0 when every control behaves so.

set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: acvp-control.sh <test_acvp binary> <acvp-subset.txt> <work dir>" >&2
  exit 2
fi
bin=$1
subset=$2
dir=$3
set_name=SLH-DSA-SHA2-128f
mkdir -p "$dir"

# case_line <kind>: the first case of that kind for set_name.
case_line() {
  awk -v kind="$1" -v set="$set_name" '$1 == kind && $2 == set { print; exit }' "$subset"
}

# run <file> <kind>: run the test on file; print the verdict of its one
# case (the last word of the case line). The exit status must be 1.
run() {
  status=0
  "$bin" "$1" > "$1.log" || status=$?
  if [ "$status" -ne 1 ]; then
    echo "acvp-control: $1: exit status $status, expected 1" >&2
    exit 1
  fi
  awk -v kind="$2" -v set="$set_name" '$1 == set && $2 == kind { v = $NF } END { print v }' \
    "$1.log"
}

# control <kind> <field> <description>: field is the awk field to change.
control() {
  kind=$1
  field=$2
  line=$(case_line "$kind")
  if [ -z "$line" ]; then
    echo "acvp-control: no $kind case for $set_name in $subset" >&2
    exit 1
  fi
  printf '%s\n' "$line" > "$dir/$kind-given.txt"
  printf '%s\n' "$line" | awk -v f="$field" -v kind="$kind" '{
      if (kind == "sigver") {
        $f = ($f == "1") ? "0" : "1"
      } else {
        last = substr($f, length($f), 1)
        $f = substr($f, 1, length($f) - 1) ((last == "0") ? "1" : "0")
      }
      print
    }' > "$dir/$kind-changed.txt"

  given=$(run "$dir/$kind-given.txt" "$kind")
  changed=$(run "$dir/$kind-changed.txt" "$kind")
  if [ "$given" != PASS ] || [ "$changed" != FAIL ]; then
    echo "acvp-control: $kind: given $given, changed $changed (expected PASS, FAIL)" >&2
    exit 1
  fi
  echo "acvp-control: $kind ($3): given case PASS, changed case FAIL"
}

control siggen 8 "last digit of the expected signature"
grep -q "signature differs" "$dir/siggen-changed.txt.log" || {
  echo "acvp-control: siggen failed for another reason than the signature" >&2
  exit 1
}
control sigver 5 "expected verdict inverted"
