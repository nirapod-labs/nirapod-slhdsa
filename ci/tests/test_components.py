# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_components.py
# ===========================
#
# ci/components.py and its negative controls: an unknown directory
# fails; a required component deleted fails; an absent component is NOT
# APPLICABLE, and safety NOT RUN while Jasmin code is present; a check
# whose `needs` is unmet is an error; a kernel variant no set selects
# fails, and so does a set that selects a missing one.

import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import components  # noqa: E402
import registry  # noqa: E402

ROOT = registry.ROOT


def tracked():
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         cwd=ROOT, check=True, capture_output=True).stdout
    return [f.decode() for f in out.split(b"\0") if f and os.path.isfile(os.path.join(ROOT, f.decode()))]

class Components(unittest.TestCase):
    def setUp(self):
        self.reg = registry.load()
        self.files = tracked()

    def test_tree_is_clean(self):
        self.assertEqual(components.layout_errors(self.reg, self.files), [])
        self.assertEqual(components.hash_set_errors(registry.hash_sets(), self.files), [])

    def test_unknown_directory_fails(self):
        for f in ("vendor/x.c", "src/other/x.jinc", "tests/fuzz/x.c"):
            self.assertTrue(components.layout_errors(self.reg, self.files + [f]), f)

    def test_required_component_deleted_fails(self):
        files = [f for f in self.files if not f.startswith(("include/", "capi/", "tests/core/",
                                                            "tests/negative/", "tests/abi/"))]
        self.assertTrue(components.layout_errors(self.reg, files))
        with self.assertRaises(components.ComponentError):
            components.applicability(self.reg, "test-core", components.present(self.reg, files))

    def test_validation_component_deleted_fails(self):
        # Deleting the differential test must fail the run, not turn its
        # check into NOT APPLICABLE.
        for check, dirs in (("differential", ("tests/diff/",)),):
            files = [f for f in self.files if not f.startswith(dirs)]
            self.assertTrue(components.layout_errors(self.reg, files), check)
            with self.assertRaises(components.ComponentError):
                components.applicability(self.reg, check, components.present(self.reg, files))

    def test_absent_and_not_run(self):
        found = components.present(self.reg, self.files)
        self.assertEqual(components.applicability(self.reg, "generated", found)[0], "NOT APPLICABLE")
        self.assertEqual(components.applicability(self.reg, "differential", found)[0], "RUN")
        self.assertEqual(components.applicability(self.reg, "safety", found)[0], "NOT RUN")
        found2 = components.present(self.reg, self.files + ["analysis/safety/Makefile"])
        self.assertEqual(components.applicability(self.reg, "safety", found2)[0], "RUN")
        # ACVP without the core is an error, not NOT APPLICABLE.
        reg = registry.load()
        reg["components"]["required"] = ["hash"]
        found3 = components.present(reg, [f for f in self.files if not f.startswith("capi/")
                                          and not f.startswith("include/")
                                          and not f.startswith("tests/")] + ["tests/acvp/x"])
        with self.assertRaises(components.ComponentError):
            components.applicability(reg, "test-acvp", found3)

    def test_unselected_variant_fails(self):
        files = self.files + ["src/hash/keccak/x86_64/avx512/kernel.jinc"]
        self.assertTrue(components.hash_set_errors(registry.hash_sets(), files))
        sets = registry.hash_sets()
        sets["x86_64"]["vars"].append("SHA2_VARIANT=x86_64/missing")
        self.assertTrue(components.hash_set_errors(sets, self.files))


if __name__ == "__main__":
    unittest.main()
