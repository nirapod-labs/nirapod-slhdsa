# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/core/readme-example.py
# ============================
#
# The quick-start program of README.md, built and run by `make check` so
# that the example a reader copies is the one that works.
#
#   readme-example.py extract README.md DIR
#       writes DIR/example.c, the README's only ```c block as it stands,
#       and DIR/tampered.c, the same program with one bit of the signature
#       flipped on the line before the call to nirapod_slhdsa_verify.
#       Fails if the README has no ```c block or more than one, or if the
#       call it anchors on is missing or appears twice.
#
#   readme-example.py run EXAMPLE TAMPERED
#       runs both programs: EXAMPLE must print "valid" and exit 0,
#       TAMPERED must print "invalid" and exit 1. Anything else fails.
#
# The README is otherwise documentation, which the CI keys leave out; the
# test-core check names it in its `reads` list (ci/checks.toml), so a
# change to the README changes that check's key.

import os
import subprocess
import sys

ANCHOR = "nirapod_slhdsa_verify("
FLIP = "sig[0] ^= 0x01; /* tampered: one bit of R */"


class Failure(Exception):
    pass


def c_block(text):
    """The lines of the only ```c fenced block of TEXT."""
    blocks, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if current is None:
            if stripped == "```c":
                current = []
        elif stripped == "```":
            blocks.append(current)
            current = None
        else:
            current.append(line)
    if current is not None:
        raise Failure("unterminated ```c block")
    if len(blocks) != 1:
        raise Failure(f"{len(blocks)} ```c blocks, expected one")
    return blocks[0]


def tampered(lines):
    """LINES with FLIP inserted, at the same indent, before the line that
    calls nirapod_slhdsa_verify."""
    hits = [i for i, line in enumerate(lines) if ANCHOR in line]
    if len(hits) != 1:
        raise Failure(f"{len(hits)} lines call {ANCHOR[:-1]}, expected one")
    i = hits[0]
    indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
    return lines[:i] + [indent + FLIP] + lines[i:]


def extract(readme, out):
    with open(readme, encoding="utf-8") as f:
        lines = c_block(f.read())
    os.makedirs(out, exist_ok=True)
    for name, body in (("example.c", lines), ("tampered.c", tampered(lines))):
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write("\n".join(body) + "\n")


def run(example, tamper):
    for path, want_out, want_rc in ((example, "valid", 0), (tamper, "invalid", 1)):
        p = subprocess.run([path], capture_output=True, text=True, timeout=600)
        got = p.stdout.strip()
        if got != want_out or p.returncode != want_rc:
            raise Failure(f"{path}: printed {got!r}, exit {p.returncode}; "
                          f"expected {want_out!r}, exit {want_rc}")
        print(f"readme-example: {os.path.basename(path)} printed {got!r}, exit {want_rc}")


def main(argv):
    try:
        if len(argv) == 4 and argv[1] == "extract":
            extract(argv[2], argv[3])
        elif len(argv) == 4 and argv[1] == "run":
            run(argv[2], argv[3])
        else:
            raise Failure("usage: readme-example.py extract README DIR | run EXAMPLE TAMPERED")
    except (Failure, OSError, subprocess.TimeoutExpired) as e:
        print(f"readme-example: FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
