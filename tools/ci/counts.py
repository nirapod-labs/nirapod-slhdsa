# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/counts.py
# ==================
#
# Usage: python3 -I tools/ci/counts.py SUITE FILE
#
# Checks that a test run in FILE (its output, or for "transcript" the file
# itself) covered at least the cases CI expects of SUITE. A suite that
# passes with fewer cases than its minimum has silently tested less: a
# vector file that lost entries, an iteration count lowered by a variable,
# a filter left in place. Each minimum is the count of the complete run on
# the current vectors and settings; raising coverage needs no change here,
# lowering it does.
#
#   hash        tests/hash `check negative-control`: CAVP checks, the
#               differential checks of DIFF_ITERS=2000, and a negative
#               control that detected every mutated family
#   acvp        tests/acvp `check`: the verdict line of the full vector set
#   diff        tests/diff/difftest.py: agreeing cases of all 12 sets times
#               the 28 interface combinations
#   diff-control
#               difftest.py --control=corrupt-b: mismatches detected
#   transcript  the core transcript: 7 lines for each of the 12 sets. This
#               is a coverage minimum only; whether the lines are right is
#               checked by comparing the transcripts of all platforms
#               byte for byte (ci-agree) and by the tests that wrote them
#
# Exit status 0 when every rule of SUITE matches with at least its minimum,
# 1 otherwise (each failure is printed), 2 on a usage error.

import re
import sys

# suite: list of (description, regex with one integer group, minimum)
RULES = {
    "hash": [
        ("CAVP checks passed with no failure",
         r"^cavp: (\d+) checks passed, 0 failed$", 7128),
        ("differential checks passed with no failure",
         r"^diff: (\d+) checks passed, 0 failed$", 22000),
        ("negative control: failing checks with every family detected",
         r"^negative_control: PASS, every family detected \((\d+) failing checks\)$", 1),
    ],
    "acvp": [
        ("ACVP cases, all run and passed",
         r"^acvp: impl=\S+ variant=\S+ control=none groups=\d+ cases=(\d+) pass=\d+ "
         r"fail=0 notrun=0 filtered=0 verdict=PASS$", 1248),
    ],
    "diff": [
        ("agreeing differential cases",
         r"^difftest: control=none seed=\d+ agree=(\d+) verify_only=0 mismatch=0 "
         r"notrun=0 verdict=PASS$", 336),
    ],
    "diff-control": [
        ("mismatches detected by the negative control",
         r"^difftest: control=corrupt-b seed=\d+ agree=\d+ verify_only=\d+ "
         r"mismatch=(\d+) notrun=\d+ verdict=FAIL$", 1),
    ],
}

TRANSCRIPT_LINES = 84


def main(argv):
    if len(argv) != 3 or (argv[1] not in RULES and argv[1] != "transcript"):
        print("usage: counts.py hash|acvp|diff|diff-control|transcript FILE", file=sys.stderr)
        return 2
    suite, path = argv[1], argv[2]
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    if suite == "transcript":
        real = [l for l in lines if l.strip()]
        ok = len(real) >= TRANSCRIPT_LINES
        print(f"counts {suite}: {len(real)} lines, minimum {TRANSCRIPT_LINES}: "
              f"{'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    failed = 0
    for what, pattern, minimum in RULES[suite]:
        rx = re.compile(pattern)
        found = [int(m.group(1)) for m in map(rx.match, lines) if m]
        if not found:
            print(f"counts {suite}: FAIL, no line for: {what}")
            failed += 1
            continue
        low = min(found)
        status = "PASS" if low >= minimum else "FAIL"
        print(f"counts {suite}: {what}: {low} (minimum {minimum}, {len(found)} run(s)): {status}")
        if low < minimum:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
