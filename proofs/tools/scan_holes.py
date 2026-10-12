# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# scan_holes.py
#
# Fails when an EasyCrypt file contains a proof hole or a command that lets
# a file compile without its proofs being checked:
#
#   admit, admitted   close a goal or a proof without proving it
#   pragma            changes checking options; `pragma Proofs:weak` makes
#                     EasyCrypt accept every following proof unchecked
#   exit              stops processing the file with status 0, so nothing
#                     after it, including the end-of-file gate lemma of
#                     `make compile-files`, is checked
#   fail              runs a command expecting it to fail, so a statement
#                     prefixed with it is never established
#
# No file of this project or of the imported theories needs any of them.
#
# Comments are removed first (EasyCrypt comments nest), so a hole that has
# been commented out is not reported, while every hole in code is.
#
# Usage: python3 scan_holes.py FILE...
# Exit status: 0 when no file has a finding, 1 when at least one has (each
# is listed as FILE:LINE), 2 on a malformed file (unterminated comment or
# string) or an empty file list, which are also failures.

import re
import sys

FORBIDDEN = re.compile(r"\b(admit|admitted|pragma|exit|fail)\b")


def strip_comments(text):
    """Replace comment characters by spaces, keeping newlines and offsets."""
    out = []
    depth = 0
    in_string = False
    i = 0
    while i < len(text):
        two = text[i:i + 2]
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\":
                out.append(text[i + 1:i + 2])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif two == "(*":
            depth += 1
            out.append("  ")
            i += 2
        elif depth > 0 and two == "*)":
            depth -= 1
            out.append("  ")
            i += 2
        elif depth > 0:
            out.append("\n" if c == "\n" else " ")
            i += 1
        else:
            if c == '"':
                in_string = True
            out.append(c)
            i += 1
    if depth != 0 or in_string:
        raise ValueError("unterminated comment or string")
    return "".join(out)


def main(paths):
    if not paths:
        print("scan_holes.py: no files to scan")
        return 2
    found = 0
    for path in paths:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        try:
            code = strip_comments(text)
        except ValueError as e:
            print("%s: %s" % (path, e))
            return 2
        for lineno, line in enumerate(code.split("\n"), 1):
            if FORBIDDEN.search(line):
                print("%s:%d: %s" % (path, lineno, line.strip()))
                found += 1
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
