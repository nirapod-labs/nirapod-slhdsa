# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_policy.py
# =======================
#
# ci/policy.py and its negative controls: the Actions cache, a secret,
# a permission beyond the table, a workflow without `permissions: {}` and
# pull_request_target each fail; the repository's workflows pass.

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import policy  # noqa: E402
import registry  # noqa: E402

ROOT = registry.ROOT


class Policy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        with open(os.path.join(ROOT, ".github/workflows/changelog.yml")) as f:
            self.good = f.read()

    def problems(self, text, name="changelog.yml"):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            f.write(text)
        return policy.check_file(p, f".github/workflows/{name}")

    def test_clean(self):
        self.assertEqual(self.problems(self.good), [])

    def test_violations(self):
        cases = [
            self.good.replace("      - name: Python\n", "      - uses: actions/cache@0123\n      - name: Python\n"),
            self.good.replace("permissions: {}", "permissions: write-all"),
            self.good.replace("      pull-requests: read", "      pull-requests: write"),
            self.good.replace("      pull-requests: read", "      pull-requests: read\n      issues: write"),
            self.good.replace("GH_TOKEN: ${{ github.token }}", "GH_TOKEN: ${{ secrets.PAT }}"),
            self.good.replace("  pull_request:\n", "  pull_request_target:\n"),
        ]
        for c in cases:
            self.assertNotEqual(c, self.good)
            self.assertTrue(self.problems(c), c[:0])

    def test_repository_is_clean(self):
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            self.assertEqual(policy.main(["policy.py"]), 0)
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
