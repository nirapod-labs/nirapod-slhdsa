#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/abi/check-exports.sh
# ==========================
#
# The global symbols of the application library are exactly the functions
# that include/nirapod_slhdsa.h declares.
#
#     check-exports.sh list <header> [prefix]
#         Print the function names the header declares, one per line, each
#         with prefix in front (the Mach-O symbol prefix "_", or nothing).
#         The Makefile builds the export list of the library from this.
#
#     check-exports.sh check <header> <archive> [prefix]
#         Compare the defined global symbols of archive (nm) with that list.
#         Prints every symbol that is global but not declared, and every
#         declared function that is not defined; exit status 0 only when
#         there is neither.
#
# A declaration is a line of the header outside comments that starts with
# a type and names nirapod_slhdsa_<name>( ; the header puts every function
# declaration on such a line.

set -eu

usage() {
  echo "usage: check-exports.sh list <header> [prefix]" >&2
  echo "       check-exports.sh check <header> <archive> [prefix]" >&2
  exit 2
}

declared() {
  # Comment lines start with "/*" or " *"; declarations start with a type.
  sed -n 's/^[a-z][a-z_ ]*[ *]\(nirapod_slhdsa_[a-z0-9_]*\)(.*/\1/p' "$1" | LC_ALL=C sort -u
}

[ $# -ge 2 ] || usage
mode=$1

case $mode in
  list)
    prefix=${3:-}
    declared "$2" | sed "s/^/$prefix/"
    ;;
  check)
    [ $# -ge 3 ] || usage
    header=$2
    archive=$3
    prefix=${4:-}
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    declared "$header" > "$tmp/want"
    [ -s "$tmp/want" ] || { echo "check-exports: no declaration found in $header" >&2; exit 2; }

    # nm -g: "<value> <type> <name>" for defined symbols, "U <name>" for
    # undefined ones, and "<member>:" headers; a defined global has an
    # upper-case type other than U.
    nm -g "$archive" > "$tmp/nm"
    awk 'NF == 3 && $2 ~ /^[A-TV-Z]$/ { print $3 }' "$tmp/nm" \
      | sed "s/^$prefix//" | LC_ALL=C sort -u > "$tmp/have"

    status=0
    for sym in $(LC_ALL=C comm -13 "$tmp/want" "$tmp/have"); do
      echo "check-exports: $archive: global symbol $sym is not declared in $header"
      status=1
    done
    for sym in $(LC_ALL=C comm -23 "$tmp/want" "$tmp/have"); do
      echo "check-exports: $archive: $sym is declared in $header but not defined"
      status=1
    done
    if [ "$status" -eq 0 ]; then
      echo "check-exports: $archive: PASS ($(wc -l < "$tmp/want" | tr -d ' ') global symbols, all declared in $header)"
    fi
    exit $status
    ;;
  *)
    usage
    ;;
esac
