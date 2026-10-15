# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_status.py
# =======================
#
# ci/status.py, with negative controls: the committed README.md and
# docs/STATUS.md agree with docs/status.toml; a rendered section edited by
# hand, a record changed without rewriting the sections, a missing or
# repeated section, a word outside the evidence vocabulary, a missing
# parameter set and a short table row each fail; `write` repairs a stale
# file, after which `check` passes.

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import registry  # noqa: E402
import status  # noqa: E402

ROOT = registry.ROOT
FILES = ("README.md", "docs/STATUS.md", "docs/status.toml")


class Status(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.makedirs(os.path.join(self.tmp, "docs"))
        for f in FILES:
            shutil.copy(os.path.join(ROOT, f), os.path.join(self.tmp, f))

    def edit(self, name, old, new):
        path = os.path.join(self.tmp, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(old, text)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text.replace(old, new, 1))

    def run_status(self, mode, root=None):
        with open(os.devnull, "w") as null:
            out, sys.stdout = sys.stdout, null
            try:
                return status.main(["status.py", mode], root or self.tmp)
            finally:
                sys.stdout = out

    def check(self):
        return self.run_status("check")

    def write(self):
        return self.run_status("write")

    def test_committed_files_agree(self):
        self.assertEqual(self.run_status("check", ROOT), 0)

    def test_hand_edit_of_a_section_fails(self):
        self.edit("docs/STATUS.md", "| NOT RUN | PROVEN |", "| PASS | PROVEN |")
        self.assertEqual(self.check(), 1)

    def test_record_change_without_write_fails_and_write_repairs(self):
        self.edit("docs/status.toml", 'value = "NOT RUN"', 'value = "INCONCLUSIVE"')
        self.assertEqual(self.check(), 1)
        self.assertEqual(self.write(), 0)
        self.assertEqual(self.check(), 0)

    def test_missing_section_fails(self):
        self.edit("README.md", "<!-- end status:summary -->", "")
        self.assertEqual(self.check(), 1)

    def test_repeated_section_fails(self):
        self.edit("docs/STATUS.md", "## Toolchain",
                  "<!-- begin status:agree x -->\n<!-- end status:agree -->\n\n## Toolchain")
        self.assertEqual(self.check(), 1)

    def test_word_outside_vocabulary_fails(self):
        self.edit("docs/status.toml", 'evidence = "PROVEN"', 'evidence = "VERIFIED IN FULL"')
        self.assertEqual(self.check(), 1)

    def test_check_status_outside_vocabulary_fails(self):
        self.edit("docs/status.toml", 'value = "NOT RUN"', 'value = "pending"')
        self.assertEqual(self.check(), 1)

    def test_missing_set_fails(self):
        self.edit("docs/status.toml", '"SLH-DSA-SHAKE-256f",\n', "")
        self.assertEqual(self.check(), 1)

    def test_short_row_fails(self):
        self.edit("docs/status.toml", '["`safety`", "NOT RUN", ', '["`safety`", ')
        self.assertEqual(self.check(), 1)


if __name__ == "__main__":
    unittest.main()
