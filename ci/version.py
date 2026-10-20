# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/version.py
# =============
#
# Usage: python3 -I ci/version.py [--tag NAME]
#
# The version of the project is written in four places, and this check
# fails unless they agree (ci/source.py runs it on every event):
#
#   include/nirapod_slhdsa.h   NIRAPOD_SLHDSA_VERSION_MAJOR, _MINOR and
#                              _PATCH, each a decimal number, and
#                              NIRAPOD_SLHDSA_VERSION_STRING, which is
#                              "MAJOR.MINOR.PATCH", optionally followed by
#                              a Semantic Versioning pre-release such as
#                              "-rc.1"; each defined exactly once
#   CITATION.cff               the top-level `version` field, exactly once
#   CHANGELOG.md               the newest release heading,
#                              "## vVERSION - YYYY-MM-DD" (the form
#                              ci/changes.sh writes), when there is one;
#                              every heading that starts with "## v" must
#                              have that form, and no version may have two
#   --tag NAME                 on the push of a tag: NAME must be "v" and
#                              the version, and CHANGELOG.md must have a
#                              section for it, the newest
#
# Before the first release CHANGELOG.md has no release heading; the check
# says so and compares the rest. The files are read as text, line by line,
# as they are written here: a definition the header hides behind a
# conditional or a continuation line is not one this reader accepts.

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER = "include/nirapod_slhdsa.h"
CITATION = "CITATION.cff"
CHANGELOG = "CHANGELOG.md"

NUMBER = r"(?:0|[1-9][0-9]*)"
# Semantic Versioning 2.0.0, section 9: dot-separated identifiers, numeric
# ones without leading zeros.
PRE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION = re.compile(rf"^({NUMBER})\.({NUMBER})\.({NUMBER})(?:-({PRE}(?:\.{PRE})*))?$")
DEFINE = re.compile(r"^\s*#\s*define\s+NIRAPOD_SLHDSA_VERSION_([A-Za-z0-9_]*)(.*)$")
MACROS = ("MAJOR", "MINOR", "PATCH", "STRING")
CFF_VERSION = re.compile(r"^version:(.*)$")
HEADING = re.compile(r"^## v(\S+) - (\d{4}-\d{2}-\d{2})$")


def read(root, path):
    with open(os.path.join(root, path), encoding="utf-8") as f:
        return f.read().splitlines()


def header_version(lines):
    """(version or None, errors) from the header's macros."""
    found, errors = {}, []
    for n, line in enumerate(lines, 1):
        m = DEFINE.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if name not in MACROS:
            errors.append(f"{HEADER}:{n}: NIRAPOD_SLHDSA_VERSION_{name} is not one of the "
                          f"version macros {', '.join(MACROS)}")
        elif name in found:
            errors.append(f"{HEADER}:{n}: NIRAPOD_SLHDSA_VERSION_{name} is defined again")
        else:
            found[name] = (n, value)
    for name in MACROS:
        if name not in found:
            errors.append(f"{HEADER}: NIRAPOD_SLHDSA_VERSION_{name} is not defined")
    if errors:
        return None, errors
    numbers = []
    for name in MACROS[:3]:
        n, value = found[name]
        if not re.fullmatch(NUMBER, value):
            errors.append(f"{HEADER}:{n}: NIRAPOD_SLHDSA_VERSION_{name} is {value!r}, "
                          "not a decimal number")
        numbers.append(value)
    n, value = found["STRING"]
    m = re.fullmatch(r'"([^"\\]*)"', value)
    if not m:
        errors.append(f"{HEADER}:{n}: NIRAPOD_SLHDSA_VERSION_STRING is {value!r}, "
                      "not a string literal")
        return None, errors
    text = m.group(1)
    v = VERSION.match(text)
    if not v:
        errors.append(f"{HEADER}:{n}: NIRAPOD_SLHDSA_VERSION_STRING {text!r} is not a "
                      "Semantic Versioning version")
    elif list(v.group(1, 2, 3)) != numbers:
        errors.append(f"{HEADER}:{n}: NIRAPOD_SLHDSA_VERSION_STRING {text!r} disagrees with "
                      f"MAJOR, MINOR and PATCH ({'.'.join(numbers)})")
    return (None if errors else text), errors


def citation_version(lines):
    """(version or None, errors) from CITATION.cff's top-level `version`."""
    values = []
    for n, line in enumerate(lines, 1):
        m = CFF_VERSION.match(line)
        if m:
            values.append((n, m.group(1).strip()))
    if len(values) != 1:
        return None, [f"{CITATION}: {len(values)} top-level `version` fields, expected one"]
    n, value = values[0]
    # A double-quoted, single-quoted or plain scalar, without a comment.
    q = re.fullmatch(r'"([^"\\]*)"|\'([^\']*)\'|([^\s"\'#]+)', value)
    if not q:
        return None, [f"{CITATION}:{n}: version {value!r} is not a plain or quoted scalar"]
    return next(g for g in q.groups() if g is not None), []


def changelog_versions(lines):
    """([versions of the release headings, newest first], errors)."""
    versions, errors = [], []
    for n, line in enumerate(lines, 1):
        if not line.startswith("## v"):
            continue
        m = HEADING.match(line)
        if not m or not VERSION.match(m.group(1)):
            errors.append(f"{CHANGELOG}:{n}: release heading {line!r} is not "
                          "'## vVERSION - YYYY-MM-DD'")
        elif m.group(1) in versions:
            errors.append(f"{CHANGELOG}:{n}: a second section for v{m.group(1)}")
        else:
            versions.append(m.group(1))
    return versions, errors


def check(root, tag=None):
    """(the header's version or None, [errors], [notes])."""
    errors, notes = [], []
    version, e = header_version(read(root, HEADER))
    errors += e
    cited, e = citation_version(read(root, CITATION))
    errors += e
    released, e = changelog_versions(read(root, CHANGELOG))
    errors += e
    if version is None:
        return None, errors, notes
    if cited is not None and cited != version:
        errors.append(f"{CITATION}: version {cited!r}, the header {version!r}")
    if released:
        if released[0] != version:
            errors.append(f"{CHANGELOG}: the newest release is v{released[0]}, "
                          f"the header {version!r}")
    else:
        notes.append(f"{CHANGELOG}: no release heading yet")
    if tag is not None:
        if tag != "v" + version:
            errors.append(f"tag {tag!r}, the header {version!r}: expected 'v{version}'")
        elif not released or released[0] != version:
            errors.append(f"tag {tag!r}: {CHANGELOG} has no newest section for v{version}")
    return version, errors, notes


def main(argv):
    if len(argv) == 1:
        tag = None
    elif len(argv) == 3 and argv[1] == "--tag":
        tag = argv[2]
    else:
        print("usage: version.py [--tag NAME]", file=sys.stderr)
        return 2
    try:
        version, errors, notes = check(ROOT, tag)
    except (OSError, UnicodeDecodeError) as e:
        print(f"version.py: {e}", file=sys.stderr)
        return 1
    for n in notes:
        print(f"version: {n}")
    for e in errors:
        print(f"version: FAIL: {e}")
    if errors:
        print("version: FAIL")
        return 1
    print(f"version: PASS ({version}" + (f", tag {tag}" if tag is not None else ", no tag") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
