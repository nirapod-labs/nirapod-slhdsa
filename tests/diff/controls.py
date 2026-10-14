# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# controls.py
# ===========
#
# Checks difftest.py's verdict rules and its detection of a corrupted
# implementation, so a driver that agreed with anything would be caught:
#
#   unsupported  both oracles stubbed NOT RUN     -> INCOMPLETE, exit 3,
#                                                    every case NOT RUN
#   error        both oracles stubbed to error    -> FAIL, exit 1, every case
#                                                    a mismatch (two equal
#                                                    error replies never agree)
#   gap-or-error one stub NOT RUN, the other an   -> FAIL, exit 1, every case
#                error                               a mismatch, not NOT RUN
#   timeout      one oracle hangs, --timeout=1    -> INCONCLUSIVE, exit 5
#   crash        one oracle aborts                -> non-zero exit, no PASS
#   corrupt-b    two real oracles, one signature  -> FAIL, every case a
#                bit flipped per reply               mismatch
#   corrupt-b-keygen   one public-key bit flipped -> FAIL, every case a
#                      per reply                     mismatch at keygen
#   corrupt-b-verify   every verify decision      -> FAIL, every case a
#                      inverted                      mismatch at verify
#   clean        the same two oracles, one set    -> PASS-RESTRICTED, exit 4,
#                                                    every case agrees
#
# The stub oracle is tests/diff/oracle built with IMPL=stub; its behaviour
# comes from SLH_STUB in the environment. A is a real implementation's
# oracle. B defaults to A: the corrupt-b and clean checks then exercise the
# driver against one implementation. With a second, independent
# implementation as B (this library as A and slhdsa-c as B, as CI runs it),
# the clean check is also a cross-implementation agreement.
#
# Usage: controls.py <stub oracle> <oracle A> [<oracle B>]

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FINAL = re.compile(r"^difftest: .* agree=(\d+) verify_only=(\d+) mismatch=(\d+) notrun=(\d+) "
                   r"verdict=(\S+)$")
SET = "SLH-DSA-SHA2-128f"


def difftest(args, env=None, stderr=False):
    """(exit status, final counts or None), and the run's stderr when asked."""
    p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "difftest.py"), "--seed=1",
                        f"--sets={SET}", *args], capture_output=True, text=True, timeout=1800,
                       env={**os.environ, **(env or {})})
    if stderr:
        return (*parse(p), p.stderr)
    return parse(p)


def parse(p):
    for line in p.stdout.splitlines():
        m = FINAL.match(line)
        if m:
            return p.returncode, (*map(int, m.group(1, 2, 3, 4)), m.group(5))
        # Any timeout (no reply, request not taken, oracle not closing) ends
        # with a "difftest:" line whose verdict is INCONCLUSIVE.
        if line.startswith("difftest: ") and line.endswith(" verdict=INCONCLUSIVE"):
            return p.returncode, (0, 0, 0, 0, "INCONCLUSIVE")
    return p.returncode, None


def main(argv):
    if len(argv) not in (3, 4):
        print("usage: controls.py <stub oracle> <oracle A> [<oracle B>]", file=sys.stderr)
        return 2
    stub, a = argv[1:3]
    b = argv[3] if len(argv) == 4 else a
    failures = []

    def check(name, ok, detail):
        print(f"control {name}: {'OK' if ok else 'BROKEN'} ({detail})")
        if not ok:
            failures.append(name)

    n = 6
    rc, r = difftest([f"--a={stub}", f"--b={stub}", f"--count={n}"], {"SLH_STUB": "unsupported"})
    check("unsupported", rc == 3 and r is not None and r[4] == "INCOMPLETE" and r[3] == n,
          f"exit={rc} result={r}")
    rc, r = difftest([f"--a={stub}", f"--b={stub}", f"--count={n}"], {"SLH_STUB": "error"})
    check("error", rc == 1 and r is not None and r[4] == "FAIL" and r[2] == n,
          f"exit={rc} result={r}")
    rc, r = difftest([f"--a=env SLH_STUB=unsupported {stub}", f"--b=env SLH_STUB=error {stub}",
                      f"--count={n}"])
    check("gap-or-error", rc == 1 and r is not None and r[4] == "FAIL" and r[2] == n,
          f"exit={rc} result={r}")
    rc, r = difftest([f"--a={a}", f"--b={stub}", "--count=1", "--timeout=1"], {"SLH_STUB": "hang"})
    check("timeout", rc == 5 and r is not None and r[4] == "INCONCLUSIVE",
          f"exit={rc} result={r}")
    rc, r = difftest([f"--a={a}", f"--b={stub}", "--count=1"], {"SLH_STUB": "crash"})
    check("crash", rc != 0 and (r is None or r[4] != "PASS"), f"exit={rc} result={r}")
    for ctl, step in (("corrupt-b", "sign"), ("corrupt-b-keygen", "keygen"),
                      ("corrupt-b-verify", "verify")):
        rc, r, err = difftest([f"--a={a}", f"--b={b}", f"--count={n}", f"--control={ctl}"],
                              stderr=True)
        steps = {line.split(" step=")[1].split()[0] for line in err.splitlines()
                 if line.startswith("MISMATCH ")}
        check(ctl, rc == 1 and r is not None and r[4] == "FAIL" and r[2] == n
              and steps == {step}, f"exit={rc} result={r} steps={sorted(steps)}")
    rc, r = difftest([f"--a={a}", f"--b={b}", f"--count={n}"])
    check("clean", rc == 4 and r is not None and r[4] == "PASS-RESTRICTED" and r[0] == n,
          f"exit={rc} result={r}")

    print(f"controls: {'PASS' if not failures else 'FAIL ' + ','.join(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
