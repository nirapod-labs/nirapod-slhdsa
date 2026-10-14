# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_lint.py
# =====================
#
# ci/lint.py: which files count as shell and Python scripts, and the
# download check that refuses an archive whose SHA-256 is not the pinned
# one.

import hashlib
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import fakeapi  # noqa: E402
import lint  # noqa: E402


class Scripts(unittest.TestCase):
    def test_kinds(self):
        with tempfile.TemporaryDirectory() as d:
            cases = {"a.sh": ("", True, False), "b": ("#!/usr/bin/env bash\n", True, False),
                     "c": ("#!/bin/sh\n", True, False), "d.py": ("", False, True),
                     "e": ("#!/usr/bin/env python3\n", False, True),
                     "f.txt": ("bash\n", False, False), "g": ("#!/bin/zsh\n", False, False)}
            for name, (text, sh, py) in cases.items():
                p = os.path.join(d, name)
                with open(p, "w") as f:
                    f.write(text)
                self.assertEqual((lint.is_shell(p), lint.is_python(p)), (sh, py), name)

    def test_every_tool_is_pinned(self):
        for name, (version, url, digest, member) in lint.TOOLS.items():
            self.assertIn(version, url, name)
            self.assertRegex(digest, r"^[0-9a-f]{64}$", name)
            self.assertTrue(url.startswith("https://github.com/"), name)


class Fetch(unittest.TestCase):
    def test_digest_is_checked(self):
        api = fakeapi.Server()
        self.addCleanup(api.close)
        api.routes["/tool.tar.gz"] = b"archive bytes"
        good = hashlib.sha256(b"archive bytes").hexdigest()
        self.assertEqual(lint.fetch(api.url + "/tool.tar.gz", good), b"archive bytes")
        with self.assertRaises(lint.Failure):
            lint.fetch(api.url + "/tool.tar.gz", "0" * 64)


if __name__ == "__main__":
    unittest.main()
