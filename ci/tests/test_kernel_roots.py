# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_kernel_roots.py
# =============================
#
# ci/kernel_roots.py on the tree, then with negative controls: a library
# variant whose kernel root changes, a variant neither bound nor listed, a
# binding to a pair that is not extracted or is of the other architecture,
# a stale entry, sets of one variant under different roots, another fault
# hook and a set list that is not the library's all fail.

import contextlib
import io
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import kernel_roots as kr  # noqa: E402


def line(arch, unit, **roles):
    base = {"Slhdsa": "src/slhdsa", "Hash": "src/hash", "HashWord": f"src/hash/{arch}",
            "KeccakKernel": "src/hash/keccak", "KeccakKernelX": "src/hash/keccak",
            "Sha2Kernel": "src/hash/sha2", "Sha2KernelX": "src/hash/sha2",
            "SlhdsaHook": "src/slhdsa/hook", "Sha2ThashX": "src/slhdsa/thash_sha2_x4/single"}
    base.update(roles)
    return f"{arch} {unit} " + " ".join(f"-I {r}={d}" for r, d in base.items())


PAIRS = ("extractions x86_64/portable:x86-64:keccak:keccak:sha2:sha2 "
         "aarch64/portable:armv8a:keccak:keccak:sha2:sha2 "
         "aarch64/a64scalar:armv8a:keccak/aarch64/scalar:keccak:sha2:sha2\n"
         "pairs x86_64/scalar=x86_64/portable aarch64/scalar=aarch64/a64scalar\n"
         "unmodelled x86_64/avx2\n"
         "sets sha2_128s shake_128s\n")

A64 = {"KeccakKernel": "src/hash/keccak/aarch64/scalar"}


class Roots(unittest.TestCase):
    def check(self, lines, pairs=PAIRS):
        return kr.errors(kr.parse_units("\n".join(lines)), *kr.parse_pairs(pairs))

    def clean(self):
        return [line("x86_64", "sha2_128s-scalar"), line("x86_64", "shake_128s-scalar"),
                line("x86_64", "shake_128s-avx2", KeccakKernelX="src/hash/keccak/x86_64/avx2"),
                line("x86_64", "sha2_128s-avx2", KeccakKernelX="src/hash/keccak/x86_64/avx2"),
                line("aarch64", "sha2_128s-scalar", **A64), line("aarch64", "shake_128s-scalar", **A64)]

    def test_tree(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(kr.main(["kernel_roots.py"]), 0)
        self.assertIn("kernel-roots: PASS", out.getvalue())

    def test_clean(self):
        self.assertEqual(self.check(self.clean()), [])

    def test_changed_library_root_fails(self):
        lines = self.clean()
        lines[4:] = [line("aarch64", "sha2_128s-scalar"), line("aarch64", "shake_128s-scalar")]
        errs = self.check(lines)
        self.assertEqual(len(errs), 1)
        self.assertIn("KeccakKernel=src/hash/keccak,", errs[0])

    def test_changed_model_root_fails(self):
        self.assertTrue(self.check(self.clean(), PAIRS.replace("a64scalar:armv8a:keccak/aarch64/scalar",
                                                               "a64scalar:armv8a:keccak")))

    def test_unclassified_variant_fails(self):
        lines = self.clean() + [line("x86_64", "sha2_128s-shani", Sha2Kernel="src/hash/sha2/x86_64/shani")]
        self.assertIn("neither", self.check(lines)[0])

    def test_stale_entry_fails(self):
        self.assertIn("not built", self.check(self.clean()[:4])[0])

    def test_pair_not_extracted_fails(self):
        self.assertIn("not in EXTRACTIONS",
                      self.check(self.clean(), PAIRS.replace("=aarch64/a64scalar", "=aarch64/a64"))[0])

    def test_other_architecture_fails(self):
        self.assertIn("another architecture",
                      self.check(self.clean(), PAIRS.replace("=aarch64/a64scalar", "=x86_64/portable"))[0])

    def test_sets_differ_fails(self):
        lines = self.clean()
        lines[1] = line("x86_64", "shake_128s-scalar", Sha2KernelX="src/hash/sha2/x86_64/avx2")
        self.assertTrue(any("different roots" in e for e in self.check(lines)))

    def test_set_list_differs_fails(self):
        self.assertTrue(any("CORE_SETS" in e for e in
                            self.check(self.clean(), PAIRS.replace(" shake_128s\n", "\n"))))

    def test_hook_root_differs_fails(self):
        lines = self.clean()
        lines[0] = line("x86_64", "sha2_128s-scalar", SlhdsaHook="tests/negative/fault/fors")
        self.assertTrue(any("SlhdsaHook" in e for e in self.check(lines)))

    def test_four_way_root_differs_fails(self):
        lines = self.clean()
        lines[:2] = [line("x86_64", u, Sha2ThashX="src/slhdsa/thash_sha2_x4/multi")
                     for u in ("sha2_128s-scalar", "shake_128s-scalar")]
        errs = self.check(lines)
        self.assertEqual(len(errs), 1)
        self.assertIn("Sha2ThashX=src/slhdsa/thash_sha2_x4/multi,", errs[0])

    def test_malformed_input_fails(self):
        with self.assertRaises(ValueError):
            kr.parse_units("x86_64 sha2_128s-scalar -I Hash")
        with self.assertRaises(ValueError):
            kr.parse_pairs(PAIRS.replace("unmodelled", "unmodeled"))


if __name__ == "__main__":
    unittest.main()
