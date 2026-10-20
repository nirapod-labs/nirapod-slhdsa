# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/core/memcheck.py
# ======================
#
# Usage: memcheck.py [-j JOBS] VALGRIND LOGDIR TEST_MEMCHECK 'PROGRAM [ARG...]'...
#
# Runs test programs of `make check` under Valgrind's memcheck (`make
# memcheck`). This is testing evidence: memcheck sees the accesses the
# tests make happen, on the inputs they use, on the variants Valgrind's
# CPU lets the library select. It is not a memory-safety verdict on the
# Jasmin code, which only a checker of every path can give.
#
# Each PROGRAM, one argument holding its command line, runs as
#
#     VALGRIND --tool=memcheck --error-exitcode=99 ... PROGRAM [ARG...]
#
# with Valgrind's report in LOGDIR/<name>.memcheck and the program's own
# output in LOGDIR/<name>.out. It passes when it exits 0 and memcheck
# counted no error: no invalid read or write, no use of an uninitialised
# value in a branch, address or system call, no invalid free, no block
# definitely or indirectly lost. With -j, up to JOBS programs run at once
# (each Valgrind process is single-threaded); the results are printed in
# the order given.
#
# Two runs of TEST_MEMCHECK (tests/core/test_memcheck.c) follow:
#
#   variants   natively and under Valgrind. The hash variants a parameter
#              set has on this host but not under Valgrind are listed:
#              their kernels were not run by any program here. The library
#              selects a variant from the CPU it is shown, and Valgrind
#              shows a CPU without the extensions it does not emulate, so
#              those variants are left out rather than run into an
#              instruction Valgrind cannot decode.
#   short      the negative control: a public key buffer one byte short,
#              written by the Jasmin key generation. memcheck must report
#              an invalid write next to that block, or the whole run fails.
#
# An instruction Valgrind cannot decode stops a program with SIGILL; it is
# reported as such, never as a pass.
#
# Output lines start with "memcheck"; ci/rules/memcheck.toml holds the
# counts CI expects. Exit status 0 when every program passed and the
# control was reported, 1 otherwise, 2 on a usage error.

import os
import re
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ERROR_EXIT = 99
FLAGS = [
    "--tool=memcheck",
    f"--error-exitcode={ERROR_EXIT}",
    "--leak-check=full",
    "--errors-for-leak-kinds=definite,indirect",
    "--show-leak-kinds=definite,indirect",
    "--num-callers=30",
]
SUMMARY = re.compile(r"^==\d+== ERROR SUMMARY: (\d+) errors", re.MULTILINE)
UNDECODED = re.compile(r"unhandled instruction|Unrecognised instruction|unhandled instruction bytes")
# The control's block: 2n - 1 = 31 bytes (test_memcheck.c, short).
CONTROL_WRITE = re.compile(r"Invalid write of size \d+")
CONTROL_BLOCK = re.compile(r"is \d+ bytes (?:inside|after) a block of size 31 alloc'd")


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def memcheck(valgrind, logs, name, argv):
    """(exit status, Valgrind's report, program output, seconds)"""
    log = os.path.join(logs, name + ".memcheck")
    out = os.path.join(logs, name + ".out")
    start = time.monotonic()
    with open(out, "w", encoding="utf-8") as f:
        p = subprocess.run([valgrind, *FLAGS, f"--log-file={log}", *argv],
                           stdout=f, stderr=subprocess.STDOUT)
    return p.returncode, read(log), read(out), time.monotonic() - start


def unique_name(argv, seen):
    name = os.path.basename(argv[0])
    seen[name] = seen.get(name, 0) + 1
    return name if seen[name] == 1 else f"{name}-{seen[name]}"


def run_program(valgrind, logs, name, argv):
    """(passed, the lines to print)"""
    rc, report, output, secs = memcheck(valgrind, logs, name, argv)
    counts = [int(n) for n in SUMMARY.findall(report)]
    errors = counts[-1] if counts else None
    if UNDECODED.search(report):
        verdict = "FAIL (an instruction Valgrind cannot decode)"
    elif errors is None:
        verdict = "FAIL (no memcheck summary)"
    elif errors or rc == ERROR_EXIT:
        verdict = "FAIL (memcheck errors)"
    elif rc != 0:
        verdict = f"FAIL (the test failed, exit status {rc})"
    else:
        verdict = "PASS"
    text = (f"memcheck: {' '.join(os.path.basename(a) for a in argv)}: errors={errors} "
            f"exit={rc} seconds={secs:.0f} {verdict}")
    if verdict != "PASS":
        text += "\n" + report + "\n" + output[-4000:]
    return verdict == "PASS", text


def variants(listing):
    """{(set, variant)} the listing reports as runnable."""
    got = set()
    for line in listing.splitlines():
        if line.startswith("variants: "):
            fields = line.split()
            for f in fields[2:]:
                v, _, ok = f.partition("=")
                if ok == "1":
                    got.add((fields[1], v))
    return got


def compare_variants(valgrind, logs, control):
    native = subprocess.run([control, "variants"], capture_output=True, text=True, check=True)
    rc, report, output, _ = memcheck(valgrind, logs, "variants", [control, "variants"])
    if rc != 0:
        print(report)
        raise SystemExit("memcheck: the variant listing failed under Valgrind")
    host, under = variants(native.stdout), variants(output)
    if not host or not under <= host:
        raise SystemExit("memcheck: the variant listings are empty or inconsistent")
    ran = sorted({v for _, v in under})
    missed = sorted(host - under)
    print(f"memcheck: variants run under Valgrind: {' '.join(ran)}")
    print(f"memcheck: variants this host runs that Valgrind does not present: {len(missed)}"
          + (": " + " ".join(f"{s}/{v}" for s, v in missed) if missed else ""))


def run_control(valgrind, logs, control):
    rc, report, output, _ = memcheck(valgrind, logs, "control", [control, "short"])
    detected = (rc == ERROR_EXIT and CONTROL_WRITE.search(report) is not None
                and CONTROL_BLOCK.search(report) is not None)
    print(output.strip())
    print(f"memcheck control: one-byte-short public key buffer: detected={int(detected)} of 1")
    if not detected:
        print(report)
    return detected


def main(argv):
    jobs = 1
    if len(argv) > 2 and argv[1] == "-j" and argv[2].isdigit() and int(argv[2]) > 0:
        jobs, argv = int(argv[2]), argv[:1] + argv[3:]
    if len(argv) < 5:
        print("usage: memcheck.py [-j JOBS] VALGRIND LOGDIR TEST_MEMCHECK 'PROGRAM [ARG...]'...",
              file=sys.stderr)
        return 2
    valgrind, logs, control = argv[1:4]
    os.makedirs(logs, exist_ok=True)
    version = subprocess.run([valgrind, "--version"], capture_output=True, text=True, check=True)
    print(f"memcheck: {version.stdout.strip()}")

    seen, programs = {}, [shlex.split(p) for p in argv[4:]]
    names = [unique_name(prog, seen) for prog in programs]
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(lambda np: run_program(valgrind, logs, *np), zip(names, programs)))
    for _, text in results:
        print(text)
    clean = sum(passed for passed, _ in results)
    compare_variants(valgrind, logs, control)
    detected = run_control(valgrind, logs, control)
    print(f"memcheck: programs={len(programs)} clean={clean}")
    return 0 if clean == len(programs) and detected else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
