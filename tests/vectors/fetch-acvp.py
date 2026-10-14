# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/vectors/fetch-acvp.py
# ===========================
#
# Downloads the NIST ACVP SLH-DSA vector files listed in
# tests/vectors/acvp/acvp.lock at the pinned ACVP-Server commit and checks
# each one's size and SHA-256. A file already present is checked, never
# trusted. Any mismatch or network failure ends the script with status 1
# and leaves no unchecked file at its final path: a download goes to
# <file>.partial and is renamed only after it matched the lock.
#
# Only the six file names the runner reads are accepted from the lock, so a
# lock line cannot point the download outside the destination.
#
# Network access: HTTPS to raw.githubusercontent.com, for the files named
# in the lock and nothing else.
#
# Usage: python3 -I tests/vectors/fetch-acvp.py [destination]
# (default destination: build/vectors/acvp).
# The destination receives SLH-DSA-<mode>-FIPS205/<file>.json.

import hashlib
import http.client
import os
import re
import shutil
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCK = os.path.join(ROOT, "tests", "vectors", "acvp", "acvp.lock")
BASE = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/{path}"
NAMES = {f"SLH-DSA-{mode}-FIPS205/{file}.json"
         for mode in ("keyGen", "sigGen", "sigVer")
         for file in ("prompt", "expectedResults")}


class Failure(Exception):
    pass


def read_lock(path):
    """(commit, [(path, bytes, sha256)]) from the lock; refuses anything else."""
    commit, files = None, []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            words = line.split()
            if not words or words[0].startswith("#"):
                continue
            if words[0] == "commit" and len(words) == 2 and commit is None:
                if not re.fullmatch(r"[0-9a-f]{40}", words[1]):
                    raise Failure(f"{path}:{n}: malformed commit")
                commit = words[1]
            elif (words[0] == "file" and len(words) == 4 and words[1] in NAMES
                  and words[2].isdigit() and re.fullmatch(r"[0-9a-f]{64}", words[3])):
                files.append((words[1], int(words[2]), words[3]))
            else:
                raise Failure(f"{path}:{n}: unexpected line")
    if commit is None:
        raise Failure(f"{path}: no commit")
    if sorted(p for p, _, _ in files) != sorted(NAMES):
        raise Failure(f"{path}: must list each of the six files once")
    return commit, files


def matches(path, size, digest):
    if not os.path.isfile(path) or os.path.getsize(path) != size:
        return False
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest() == digest


def fetch(commit, path, size, digest, dest):
    out = os.path.join(dest, path)
    if os.path.exists(out):
        if not matches(out, size, digest):
            raise Failure(f"{path} exists but does not match the lock; remove it and retry")
        print(f"fetch-acvp: ok (cached) {path}")
        return
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".partial"
    url = BASE.format(commit=commit, path=path)
    try:
        try:
            with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
                if not r.geturl().startswith("https://"):
                    raise Failure(f"{path}: redirected off HTTPS")
                shutil.copyfileobj(r, f, 1 << 20)
        except (OSError, http.client.HTTPException) as e:
            raise Failure(f"download failed: {path}: {e}") from None
        if not matches(tmp, size, digest):
            raise Failure(f"{path}: size or SHA-256 does not match the lock")
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    print(f"fetch-acvp: ok {path}")


def main(argv):
    if len(argv) > 2:
        print("usage: fetch-acvp.py [destination]", file=sys.stderr)
        return 2
    dest = argv[1] if len(argv) == 2 else os.path.join(ROOT, "build", "vectors", "acvp")
    try:
        commit, files = read_lock(LOCK)
        for path, size, digest in files:
            fetch(commit, path, size, digest, dest)
    except (Failure, OSError) as e:
        print(f"fetch-acvp: {e}", file=sys.stderr)
        return 1
    print(f"fetch-acvp: {len(files)} files verified against commit {commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
