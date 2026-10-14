# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# verdicts.py
# ===========
#
# Checks the verdict rules of acvp_runner.c, using a runner built against
# the fake implementation (IMPL=stub) and one built against a real one:
#
#   all-unsupported  every call NOT RUN          -> INCOMPLETE, exit 3, and
#                                                   every published case counted
#   all-error        every call an error         -> FAIL, exit 1, every case
#                                                   failed, including the sigVer
#                                                   cases whose expected result
#                                                   is a rejection
#   reject-only      verify rejects, else error  -> FAIL; exactly the sigVer
#                                                   cases expecting rejection pass
#   restricted       real runner, --sets         -> PASS-RESTRICTED, exit 4
#   one file         real runner, keyGen only    -> PASS-RESTRICTED, exit 4
#   timeout          a call that hangs, --timeout=1 -> INCONCLUSIVE, exit 5
#   crash            a call that aborts          -> killed by a signal, no
#                                                   verdict line, never PASS
#
# A full PASS (all three files, nothing filtered) is exercised by the
# campaigns themselves, which take minutes; these rules take seconds.
#
# The case count check compares the runner's total with the number of lines
# in the flat files, so a runner that skipped cases silently would fail it.
#
# Usage: verdicts.py <stub acvp_runner> <real acvp_runner> <flat dir>

import os
import re
import subprocess
import sys

TIMEOUT = re.compile(r"^acvp: timeout after \d+s in .* verdict=INCONCLUSIVE$")
FINAL = re.compile(r"^acvp: .* cases=(\d+) pass=(\d+) fail=(\d+) notrun=(\d+) "
                   r"filtered=(\d+)(?: scope=\S+)? verdict=(\S+)")


def run(runner, args, env=None):
    p = subprocess.run([runner, *args], capture_output=True, text=True, timeout=600,
                       env={**os.environ, **(env or {})})
    for line in p.stdout.splitlines():
        m = FINAL.match(line)
        if m:
            c, ps, f, n, filt = map(int, m.group(1, 2, 3, 4, 5))
            return p.returncode, c, ps, f, n, filt, m.group(6)
        if TIMEOUT.match(line):
            return p.returncode, 0, 0, 0, 0, 0, "INCONCLUSIVE"
    return p.returncode, 0, 0, 0, 0, 0, None


def main(argv):
    if len(argv) != 4:
        print("usage: verdicts.py <stub acvp_runner> <real acvp_runner> <flat dir>",
              file=sys.stderr)
        return 2
    stub, real, flat = argv[1:]
    files = [os.path.join(flat, f"{m}.txt") for m in ("keyGen", "sigGen", "sigVer")]
    total = sum(sum(1 for _ in open(f)) for f in files)
    reject_expected = sum(1 for line in open(files[2]) if line.rstrip().endswith("pass=0"))
    failures = []

    def check(name, ok, detail):
        print(f"rule {name}: {'OK' if ok else 'BROKEN'} ({detail})")
        if not ok:
            failures.append(name)

    rc, c, ps, f, n, filt, v = run(stub, files, {"SLH_STUB": "unsupported"})
    check("all-unsupported", rc == 3 and v == "INCOMPLETE" and c == total and n == total,
          f"exit={rc} verdict={v} cases={c}/{total} notrun={n}")

    rc, c, ps, f, n, filt, v = run(stub, files, {"SLH_STUB": "error"})
    check("all-error", rc == 1 and v == "FAIL" and c == total and f == total,
          f"exit={rc} verdict={v} failed={f}/{total}")

    rc, c, ps, f, n, filt, v = run(stub, files, {"SLH_STUB": "reject"})
    check("reject-only", rc == 1 and v == "FAIL" and ps == reject_expected and
          f == total - reject_expected,
          f"exit={rc} verdict={v} pass={ps} (expected {reject_expected}) fail={f}")

    rc, c, ps, f, n, filt, v = run(real, ["--sets=SLH-DSA-SHAKE-128f", files[0]])
    check("restricted", rc == 4 and v == "PASS-RESTRICTED" and c == 10 and filt == 110,
          f"exit={rc} verdict={v} cases={c} filtered={filt}")

    rc, c, ps, f, n, filt, v = run(real, [files[0]])
    check("one-file", rc == 4 and v == "PASS-RESTRICTED" and c == 120,
          f"exit={rc} verdict={v} cases={c}")

    rc, *_, v = run(stub, ["--timeout=1", files[0]], {"SLH_STUB": "hang"})
    check("timeout", rc == 5 and v == "INCONCLUSIVE", f"exit={rc} verdict={v}")

    rc, *_, v = run(stub, [files[0]], {"SLH_STUB": "crash"})
    check("crash", rc < 0 and v is None, f"exit={rc} verdict={v}")

    print(f"verdicts: {'PASS' if not failures else 'FAIL ' + ','.join(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
