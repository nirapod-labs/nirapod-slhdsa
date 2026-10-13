#!/usr/bin/env bash
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/changes.sh
# ================
#
# The unreleased changelog lives in changes/, one file per pull request,
# so that pull requests merged in parallel never edit the same lines. A
# release collects the files into one section of CHANGELOG.md.
#
#   changes/<category>/<pull request number>-<slug>.md
#
# <category> is one of the CATEGORIES below, which are also the order of
# the subsections in a release. <slug> is lower-case letters, digits and
# hyphens. A file holds one or more Markdown list items ("- ...").
#
# The link to the pull request is not written in the entry: the release
# adds it to each list item, from the number in the file name, so the
# link and the name cannot disagree. It goes on a line of its own,
# "  ([PR #N](https://github.com/nirapod-labs/nirapod-slhdsa/pull/N))",
# before the full stop that ends the item, if there is one. An entry
# that already links to a pull request of this repository is rejected.
#
# Usage, from the repository root:
#
#   tools/changes.sh check
#       Fail unless every file under changes/ is changes/README.md or a
#       well-formed entry as above, without a pull request link.
#   tools/changes.sh section VERSION DATE
#       Print the release section for VERSION (vMAJOR.MINOR.PATCH) dated
#       DATE (YYYY-MM-DD): "## VERSION - DATE", then one "### <Category>"
#       per category that has entries, its entries in pull request order,
#       each list item closed by the link to its pull request.
#   tools/changes.sh release VERSION DATE
#       Put that section into CHANGELOG.md, above the newest release, and
#       remove the entries it holds with `git rm`. The result is reviewed
#       and committed as the release commit, before the tag.
#
# Every subcommand stops on the first error and changes nothing until its
# input has been checked.

set -euo pipefail

CATEGORIES="added changed fixed security"
DIR=changes
LOG=CHANGELOG.md
PULL=https://github.com/nirapod-labs/nirapod-slhdsa/pull

die() { echo "changes.sh: $*" >&2; exit 1; }

title() {
  case $1 in
    (added) echo Added ;; (changed) echo Changed ;;
    (fixed) echo Fixed ;; (security) echo Security ;;
    (*) die "no title for category $1" ;;
  esac
}

# entries CATEGORY: the entry files of CATEGORY, by pull request number.
entries() {
  [ -d "$DIR/$1" ] || return 0
  find "$DIR/$1" -type f -name '*.md' | LC_ALL=C sort -t/ -k3,3n
}

cmd_check() {
  local f rel cat name n=0 bad=0
  [ -d "$DIR" ] || die "$DIR/: missing"
  while IFS= read -r f; do
    rel=${f#"$DIR"/}
    if [ -L "$f" ]; then echo "$f: a symbolic link" >&2; bad=1; continue; fi
    [ "$rel" = README.md ] && continue
    cat=${rel%%/*}
    name=${rel#*/}
    if ! [[ " $CATEGORIES " == *" $cat "* ]]; then
      echo "$f: not in a category ($CATEGORIES)" >&2; bad=1; continue
    fi
    if ! [[ $name =~ ^[1-9][0-9]*-[a-z0-9]+(-[a-z0-9]+)*\.md$ ]]; then
      echo "$f: name is not <pull request number>-<slug>.md" >&2; bad=1; continue
    fi
    if ! head -n 1 "$f" | grep -q '^- [^ ]'; then
      echo "$f: does not start with a list item (\"- ...\")" >&2; bad=1; continue
    fi
    if grep -Eiq 'github\.com/nirapod-labs/nirapod-slhdsa/pull/|\[PR #[0-9]' "$f"; then
      echo "$f: links to a pull request; the release adds the link from the name" >&2
      bad=1; continue
    fi
    n=$((n + 1))
  done < <(find "$DIR" -mindepth 1 \( -type f -o -type l \) | LC_ALL=C sort)
  [ "$bad" = 0 ] || die "malformed entries in $DIR/ (listed above)"
  echo "changes: $n entr$([ "$n" = 1 ] && echo y || echo ies), well formed"
}

check_release_args() {
  [ $# = 2 ] || die "usage: changes.sh $CMD VERSION DATE"
  [[ $1 =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || die "$1: not a version vMAJOR.MINOR.PATCH"
  [[ $2 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "$2: not a date YYYY-MM-DD"
}

# linked FILE: the list items of the entry FILE, each closed by the link
# to the pull request in the name of FILE. An item runs from its "- " line
# to the next one; its lines are kept as written, without trailing blank
# lines, and the link is indented as a continuation of the item.
linked() {
  local n=${1##*/}
  n=${n%%-*}
  awk -v link="([PR #$n]($PULL/$n))" '
    function flush(   i, tail) {
      while (k > 0 && buf[k] ~ /^[ \t]*$/) k--
      if (k == 0) return
      sub(/[ \t]+$/, "", buf[k])
      tail = link
      if (sub(/\.$/, "", buf[k])) tail = tail "."
      for (i = 1; i <= k; i++) print buf[i]
      print "  " tail
      k = 0
    }
    /^- / { flush() }
    { buf[++k] = $0 }
    END { flush() }
  ' "$1"
}

# section VERSION DATE: the release section on stdout.
section() {
  local c f first
  echo "## $1 - $2"
  for c in $CATEGORIES; do
    first=1
    while IFS= read -r f; do
      if [ "$first" = 1 ]; then printf '\n### %s\n\n' "$(title "$c")"; first=0; fi
      linked "$f"
    done < <(entries "$c")
  done
}

cmd_section() {
  check_release_args "$@"
  cmd_check > /dev/null
  [ -n "$(for c in $CATEGORIES; do entries "$c"; done)" ] || die "no entries in $DIR/"
  section "$@"
}

cmd_release() {
  local tmp c files
  check_release_args "$@"
  cmd_check > /dev/null
  files=$(for c in $CATEGORIES; do entries "$c"; done)
  [ -n "$files" ] || die "no entries in $DIR/"
  [ -f "$LOG" ] || die "$LOG: missing"
  ! grep -q "^## $1 " "$LOG" || die "$LOG already has a section for $1"
  tmp=$(mktemp)
  section "$@" > "$tmp.section"
  # git rm removes every entry or none: an untracked, modified or staged
  # entry stops the release here, with CHANGELOG.md untouched.
  printf '%s\n' "$files" | xargs git rm -q --
  # Above the first release section, or at the end before any release.
  awk -v sec="$tmp.section" '
    !done && /^## / { while ((getline l < sec) > 0) print l; print ""; done = 1 }
    { print }
    END { if (!done) { print ""; while ((getline l < sec) > 0) print l } }
  ' "$LOG" > "$tmp"
  mv "$tmp" "$LOG"
  rm -f "$tmp.section"
  echo "changes: $1 written to $LOG, $(printf '%s\n' "$files" | wc -l | tr -d ' ') entry file(s) removed from $DIR/"
}

CMD=${1:-}
case $CMD in
  (check)   shift; cmd_check "$@" ;;
  (section) shift; cmd_section "$@" ;;
  (release) shift; cmd_release "$@" ;;
  (*) echo "usage: tools/changes.sh check | section VERSION DATE | release VERSION DATE" >&2; exit 2 ;;
esac
