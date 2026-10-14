# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# controls.py
# ===========
#
# Negative controls for the ACVP pipeline. Each control breaks one link on
# purpose and checks that the pipeline reports the break; a control that
# does not fail as predicted fails this script. Controls:
#
#   baseline       unmodified run on the chosen sets: verdict PASS-RESTRICTED
#                  (exit 4), every case passing
#   flip-output    runner flips the computed result: every case FAILs
#   flip-expected  runner flips the expected result: every case FAILs
#   mutate-input   runner changes the message (keyGen: PK.seed) before the
#                  call: every keyGen and sigGen case FAILs, and in every
#                  sigVer group each case whose signature is valid FAILs
#   tampered-file  one byte of a fetched vector file changed: the fetch
#                  script refuses it
#   orphan-result  an expected result with no prompt case: the converter
#                  refuses the input
#
# Every control must fail for the reason it targets: the corrupted value is
# compared, the tampered file is refused by its digest check, the orphaned
# result is refused by the join. A run that cannot reach a verdict ends the
# script with an error instead of counting as detection.
#
# Passing these controls shows that the pipeline detects these classes of
# defect on the sets run. It does not show that every implementation defect
# would be caught: a defect confined to sets or inputs outside the vectors
# needs the differential and negative tests.
#
# Usage:
#   controls.py <acvp_runner> <flat dir> <json dir> [--sets=A,B] [--variant=V]
#               [--prehash=no]
# <flat dir> holds convert.py output; <json dir> the fetched JSON files.
# The default sets are SHA2-128f and SHAKE-128f: one per hash family, both
# with groups for every interface, pre-hash function and signing mode in
# the pinned vectors, and short enough to keep five runner passes quick.

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
GROUP = re.compile(r"^group (\S+) tg=(\d+) .* cases=(\d+) pass=(\d+) fail=(\d+) notrun=(\d+)$")
FINAL = re.compile(r"^acvp: .* cases=(\d+) pass=(\d+) fail=(\d+) notrun=(\d+) .*verdict=(\S+)")


def run_runner(runner, files, extra):
    p = subprocess.run([runner, *extra, *files], capture_output=True, text=True)
    groups, final = [], None
    for line in p.stdout.splitlines():
        m = GROUP.match(line)
        if m:
            groups.append((m.group(1), int(m.group(2)), *map(int, m.group(3, 4, 5, 6))))
        m = FINAL.match(line)
        if m:
            final = (*map(int, m.group(1, 2, 3, 4)), m.group(5))
    if final is None:
        raise SystemExit(f"controls: runner produced no verdict (exit {p.returncode})\n{p.stderr}")
    return p.returncode, groups, final


def valid_sigver_cases(flat, sets, prehash):
    """Count, per sigVer group run, the cases whose expected result is pass=1."""
    counts = {}
    with open(os.path.join(flat, "sigVer.txt")) as f:
        for line in f:
            fields = dict(t.split("=", 1) for t in line.split()[1:])
            if not prehash and fields["ph"] not in ("-", "none"):
                continue
            if fields["set"] in sets and fields["pass"] == "1":
                tg = int(fields["tg"])
                counts[tg] = counts.get(tg, 0) + 1
    return counts


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    bad = [a for a in argv[1:] if a.startswith("--") and "=" not in a]
    if bad:
        print(f"controls: options take a value: {bad}", file=sys.stderr)
        return 2
    opts = dict(a[2:].split("=", 1) for a in argv[1:] if a.startswith("--"))
    allowed = {"sets", "variant", "prehash"}
    if set(opts) - allowed or opts.get("prehash", "yes") not in ("yes", "no"):
        print(f"controls: bad options {opts}", file=sys.stderr)
        return 2
    prehash = opts.get("prehash", "yes") == "yes"
    if len(args) != 3:
        print("usage: controls.py <runner> <flat dir> <json dir> [--sets=A,B] [--variant=V]"
              " [--prehash=no]",
              file=sys.stderr)
        return 2
    runner, flat, jsondir = args
    sets = opts.get("sets", "SLH-DSA-SHA2-128f,SLH-DSA-SHAKE-128f")
    extra = [f"--sets={sets}"] + ([f"--variant={opts['variant']}"] if "variant" in opts else [])
    if not prehash:
        extra.append("--prehash=no")
    files = [os.path.join(flat, f"{m}.txt") for m in ("keyGen", "sigGen", "sigVer")]
    failures = []

    def check(name, ok, detail):
        print(f"control {name}: {'DETECTED' if ok else 'MISSED'} ({detail})")
        if not ok:
            failures.append(name)

    rc, groups, (cases, npass, nfail, notrun, verdict) = run_runner(
        runner, files, extra + ["--control=none"])
    # Controls always run on chosen sets, so the clean run is PASS-RESTRICTED.
    ok = (rc == 4 and verdict == "PASS-RESTRICTED" and nfail == 0 and notrun == 0
          and cases > 0)
    print(f"control baseline: {'PASS' if ok else 'FAIL'} "
          f"(cases={cases} pass={npass} fail={nfail} notrun={notrun})")
    if not ok:
        failures.append("baseline")
    total = cases

    for ctl in ("flip-output", "flip-expected"):
        rc, groups, (cases, npass, nfail, notrun, verdict) = run_runner(
            runner, files, extra + [f"--control={ctl}"])
        check(ctl, rc == 1 and cases == total and nfail == total,
              f"exit={rc} failed {nfail} of {cases}")

    valid = valid_sigver_cases(flat, set(sets.split(",")), prehash)
    rc, groups, (cases, npass, nfail, notrun, verdict) = run_runner(
        runner, files, extra + ["--control=mutate-input"])
    missed = []
    for mode, tg, gcases, gpass, gfail, gnotrun in groups:
        need = gcases if mode in ("keyGen", "sigGen") else valid.get(tg, 0)
        if gfail < need or need == 0:
            missed.append(f"{mode} tg={tg} fail={gfail} need>={need}")
    check("mutate-input", rc == 1 and cases == total and not missed,
          f"exit={rc} failed {nfail} of {cases}" + (f"; missed {missed[:3]}" if missed else ""))

    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "acvp")
        shutil.copytree(jsondir, dest)
        victim = os.path.join(dest, "SLH-DSA-keyGen-FIPS205", "prompt.json")
        with open(victim, "r+b") as f:
            f.seek(100)
            b = f.read(1)
            f.seek(100)
            f.write(bytes([b[0] ^ 0x01]))
        p = subprocess.run([sys.executable, "-I",
                            os.path.join(ROOT, "tests", "vectors", "fetch-acvp.py"), dest],
                           capture_output=True, text=True)
        check("tampered-file", p.returncode != 0 and "does not match" in p.stderr,
              f"fetch exit={p.returncode}")

        src = os.path.join(tmp, "orphan")
        shutil.copytree(jsondir, src)
        res = os.path.join(src, "SLH-DSA-keyGen-FIPS205", "expectedResults.json")
        with open(res) as f:
            data = json.load(f)
        data["testGroups"][0]["tests"].append({"tcId": 99999, "pk": "00", "sk": "00"})
        with open(res, "w") as f:
            json.dump(data, f)
        p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "convert.py"), src,
                            os.path.join(tmp, "out")], capture_output=True, text=True)
        check("orphan-result", p.returncode != 0 and "without a prompt" in p.stderr,
              f"convert exit={p.returncode}")

    print(f"controls: {'PASS' if not failures else 'FAIL ' + ','.join(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
