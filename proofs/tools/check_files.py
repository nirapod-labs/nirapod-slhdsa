# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# proofs/tools/check_files.py
# ===========================
#
# Usage: python3 -I tools/check_files.py --label LABEL --jobs N
#            --easycrypt EASYCRYPT --flags FLAGS FILE...
#
# Compiles each EasyCrypt FILE on its own, N at a time, and passes only if
# every one of them checks (proofs/Makefile, compile-files). Each file is
# compiled from a scratch copy that ends with a trivial lemma: EasyCrypt
# accepts a file that ends while obligations of a `clone ... proof *` are
# still unrealized, and then treats them as proven; any command after them
# is rejected ("cannot process [axiom] inside a proof script"), so the
# sentinel lemma makes such a file fail. FLAGS are the EasyCrypt options
# (load path, provers, timeout, -no-eco); the file's own directory is added
# to the load path, as it is for the original.
#
# Running files in parallel changes nothing a file checks: each run is a
# separate EasyCrypt process on its own copy, and EasyCrypt does not
# re-check the proofs of the theories a file loads.
#
# For each file it prints, in the order of FILE..., one line with its
# result, wall time and the peak resident memory of the EasyCrypt process
# (the provers it starts are separate processes and not included), and the
# output of a file that failed. Then the total time, and
# "LABEL: PASS <n> files", or
# "LABEL: FAIL <k> of <n> files" and exit 1. No file at all is a failure,
# and so is any error starting EasyCrypt.

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

GATE = "\n(* gate: end of file *)\nlemma end_of_file_gate : true by trivial.\n"


def check_one(path, easycrypt, flags):
    """(ok, seconds, peak MiB, output) of one file."""
    tmp = tempfile.mkdtemp(prefix="ec-check-")
    try:
        copy = os.path.join(tmp, os.path.basename(path))
        shutil.copyfile(path, copy)
        with open(copy, "a", encoding="utf-8") as f:
            f.write(GATE)
        cmd = [easycrypt, "compile", *flags, "-I", os.path.dirname(path) or ".", copy]
        start = time.monotonic()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError as e:
            return False, 0.0, 0.0, f"cannot run {easycrypt}: {e}\n"
        out = proc.stdout.read()
        proc.stdout.close()
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        seconds = time.monotonic() - start
        # ru_maxrss is in kilobytes on Linux and in bytes on macOS.
        scale = 1 if sys.platform == "darwin" else 1024
        peak = usage.ru_maxrss * scale / (1 << 20)
        return proc.returncode == 0, seconds, peak, out.decode("utf-8", errors="replace")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    ap = argparse.ArgumentParser(prog="check_files.py")
    ap.add_argument("--label", required=True)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--easycrypt", required=True)
    ap.add_argument("--flags", required=True)
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv[1:])
    if not args.files:
        print(f"{args.label}: no files")
        return 1
    if args.jobs < 1:
        print(f"{args.label}: --jobs must be at least 1")
        return 1
    flags = shlex.split(args.flags)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda f: check_one(f, args.easycrypt, flags), args.files))
    failed = 0
    for path, (ok, seconds, peak, out) in zip(args.files, results):
        print(f"check {path}: {'PASS' if ok else 'FAIL'} {seconds:.1f} s {peak:.0f} MiB")
        if not ok:
            failed += 1
            print(out.rstrip())
            print(f"FAIL {path}")
    total = sum(r[1] for r in results)
    if failed:
        print(f"{args.label}: FAIL {failed} of {len(args.files)} files")
        return 1
    print(f"{args.label}: {total:.0f} s of EasyCrypt, {args.jobs} file(s) at a time")
    print(f"{args.label}: PASS {len(args.files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
