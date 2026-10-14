# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_counts.py
# =======================
#
# ci/counts.py on the rules of the checks: a count below its minimum,
# a missing line, a wrong exact count and a wrong number of files fail;
# every rules file loads.

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import counts  # noqa: E402
import registry  # noqa: E402

ROOT = registry.ROOT


class Counts(unittest.TestCase):
    def run_counts(self, section, log_text, **opts):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as f:
            f.write(log_text)
        self.addCleanup(os.remove, f.name)
        rules = counts.load(os.path.join(ROOT, "ci/rules", self.rules), section)
        return counts.check(rules, section, f.name, **opts)[0]

    def test_hash_minimums(self):
        self.rules = "test-hash.toml"
        good = ("cavp: 7130 checks passed, 0 failed\ndiff: 96000 checks passed, 0 failed\n"
                "squeeze: 45288 checks passed, 0 failed\n"
                "fill_check: PASS, every test passes with 0xa5-filled buffers (4 sites filled)\n"
                "negative_control: PASS, every family detected (9 failing checks)\n"
                "negative_control: PASS, every dropped squeeze store detected (3 failing checks)\n")
        self.assertEqual(self.run_counts("hash", good), 0)
        self.assertEqual(self.run_counts("hash", good.replace("cavp: 7130", "cavp: 7129")), 1)
        self.assertGreater(self.run_counts("hash", good.replace("squeeze: ", "sweep: ")), 0)

    def test_exact_count(self):
        self.rules = "differential.toml"
        line = ("difftest: control=corrupt-b seed=1 agree=0 verify_only=0 mismatch=3 notrun=0 "
                "verdict=FAIL\n")
        self.assertEqual(self.run_counts("diff-control", line + "difftest-control-exit: 1\n"), 0)
        self.assertEqual(self.run_counts("diff-control", line + "difftest-control-exit: 0\n"), 1)

    def test_files_rule(self):
        self.rules = "analysis-units.toml"
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "aarch64-elf", "ct"))
            for i in range(12):
                for ext in ("ok", "ct.log", "sct.log"):
                    open(os.path.join(d, "aarch64-elf", "ct", f"u{i}.{ext}"), "w").close()
            rules = counts.load(os.path.join(ROOT, "ci/rules/analysis-units.toml"), "ct")
            self.assertEqual(counts.check(rules, "ct", d, "aarch64-elf", "aarch64")[0], 0)
            os.remove(os.path.join(d, "aarch64-elf", "ct", "u3.sct.log"))
            self.assertEqual(counts.check(rules, "ct", d, "aarch64-elf", "aarch64")[0], 1)

    def test_every_rules_file_loads(self):
        for f in os.listdir(os.path.join(ROOT, "ci/rules")):
            import tomllib
            with open(os.path.join(ROOT, "ci/rules", f), "rb") as fh:
                for section in tomllib.load(fh):
                    counts.load(os.path.join(ROOT, "ci/rules", f), section)


if __name__ == "__main__":
    unittest.main()
