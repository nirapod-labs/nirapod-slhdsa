# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/core/checker/check.py
# ===========================
#
# Runs jasmin-checksafety on the reproducers of workarounds.jazz and checks
# each verdict: the plain shape must raise its alarm, the shape the source
# uses must raise none. Either change means a workaround in src/slhdsa
# should be revisited (the checker improved) or no longer suffices.
#
# The analysis is the one the safety checks of the core use: x86-64, no
# relational loop variables, arrays above 32 bytes not tracked cell by cell
# (configuration below), the message export pointer declared with --param.
# The verdicts do not depend on the parameter set or the architecture of
# the code shapes.
#
# Usage: python3 -I tests/core/checker/check.py <jasmin-checksafety>
# The checker must be the one toolchain/build.sh builds from the pin: the
# expected verdicts are that build's, and another checker may differ for
# reasons that say nothing about src/slhdsa. `make checker-repro` takes it
# from JASMIN_CHECKSAFETY and refuses to run without it. Prints one line
# per export and exits 1 on any unexpected verdict, checker error or
# timeout.

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "workarounds.jazz")
CONFIG = {"relational_loop_vars": False, "relational_loop_vars_in": [],
          "array_track_max_bytes": 32}

# export: (pointer arguments for --param, expected alarm kind or None)
EXPECT = {
    "fill_plain": ("", "is_init"),
    "fill_first": ("", None),
    "slot_plain": ("", "in_bound"),
    "slot_clamp": ("", None),
    "msg_array": ("msg;", "is_valid"),
    "msg_scalar": ("msg;", None),
}


def verdict(checker, config, export, params):
    """None for no violation, else the set of alarm kinds reported."""
    cmd = [checker, "--arch=x86-64", f"--config={config}", f"--slice={export}", SOURCE]
    if params:
        cmd.insert(2, f"--param={params}")
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=600)
    out = p.stdout + p.stderr
    if "*** No Safety Violation" in out:
        return None
    if "Possible Safety Violation" not in out:
        raise RuntimeError(f"{export}: no verdict (exit {p.returncode})")
    return {k for k in ("is_init", "in_bound", "is_valid") if k + ":" in out or k + " " in out}


def main(argv):
    if len(argv) != 2:
        print("usage: check.py <jasmin-checksafety>", file=sys.stderr)
        return 2
    failures = 0
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(CONFIG, f)
        config = f.name
    try:
        for export, (params, want) in EXPECT.items():
            try:
                got = verdict(argv[1], config, export, params)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
                print(f"checker-repro: {export}: ERROR {e}")
                failures += 1
                continue
            ok = got is None if want is None else got == {want}
            shown = "SAFE" if got is None else "alarm " + ",".join(sorted(got))
            print(f"checker-repro: {export}: {shown}: {'as expected' if ok else 'UNEXPECTED'}")
            failures += not ok
    finally:
        os.remove(config)
    print(f"checker-repro: {'PASS' if failures == 0 else 'FAIL'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
