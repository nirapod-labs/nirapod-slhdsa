# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/tests/test_source.py
# =============================
#
# tools/ci/source.py and the recipes, with negative controls: a recipe
# including another file, or naming another check's recipe or rules,
# fails, and so does a recipe or rules file of no check; a proof file in no
# shard, one in two shards, a shared correctness proof missing from a pair
# shard and an unknown shard fail. Recipes run with the parameters of their
# platform, on the platform's host and runner only (tools/ci/check.py).

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import check  # noqa: E402
import registry  # noqa: E402
import source  # noqa: E402

ROOT = registry.ROOT


def tracked():
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         cwd=ROOT, check=True, capture_output=True).stdout
    return [f.decode() for f in out.split(b"\0") if f and os.path.isfile(os.path.join(ROOT, f.decode()))]

class Recipes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        shutil.copytree(os.path.join(ROOT, "tools/ci/checks"), os.path.join(self.tmp, "tools/ci/checks"))
        shutil.copytree(os.path.join(ROOT, "tools/ci/rules"), os.path.join(self.tmp, "tools/ci/rules"))
        shutil.copytree(os.path.join(ROOT, "tools/ci/mk"), os.path.join(self.tmp, "tools/ci/mk"))
        self.reg = registry.load()
        self.cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self.cwd)

    def files(self):
        out = []
        for root, _, names in os.walk("tools"):
            out += [os.path.join(root, n) for n in names]
        return out

    def append(self, path, text):
        with open(path, "a") as f:
            f.write(text)

    def test_clean(self):
        self.assertEqual(source.recipe_errors(self.reg, self.files()), [])

    def test_second_include_fails(self):
        self.append("tools/ci/checks/test-hash.mk", "include tools/ci/checks/test-core.mk\n")
        errs = source.recipe_errors(self.reg, self.files())
        self.assertTrue(any("includes" in e for e in errs))
        self.assertTrue(any("another check's file" in e for e in errs))

    def test_naming_other_rules_fails(self):
        self.append("tools/ci/checks/test-core.mk", "X := tools/ci/rules/test-hash.toml\n")
        self.assertTrue(source.recipe_errors(self.reg, self.files()))

    def test_orphans_fail(self):
        with open("tools/ci/checks/orphan.mk", "w") as f:
            f.write("include tools/ci/mk/common.mk\n")
        with open("tools/ci/rules/orphan.toml", "w") as f:
            f.write("")
        errs = source.recipe_errors(self.reg, self.files())
        self.assertEqual(len(errs), 2)

    def test_missing_recipe_fails(self):
        os.remove("tools/ci/checks/asm-policy.mk")
        self.assertTrue(source.recipe_errors(self.reg, self.files()))

class Shards(unittest.TestCase):
    def setUp(self):
        self.reg = registry.load()
        self.files = tracked()
        self.real = subprocess.run(["make", "-s", "-C", "proofs", "shard-files"], cwd=ROOT,
                                   capture_output=True, text=True, check=True).stdout

    def errors(self, shard_files):
        real = subprocess.run

        def fake(cmd, **kw):
            if cmd[-1] == "shard-files":
                return subprocess.CompletedProcess(cmd, 0, shard_files, "")
            return real(cmd, **dict(kw, cwd=ROOT))
        with mock.patch.object(source.subprocess, "run", fake):
            return source.shard_errors(self.reg, self.files)

    def test_every_file_once(self):
        self.assertEqual(self.errors(self.real), [])

    def test_file_in_no_shard_fails(self):
        lines = [l for l in self.real.splitlines() if "SPHINCS_Sets.ec" not in l]
        self.assertTrue(any("SPHINCS_Sets.ec" in e for e in self.errors("\n".join(lines) + "\n")))

    def test_file_in_two_shards_fails(self):
        extra = "sphincs proofs/spec/Bytes.ec\n"
        self.assertTrue(self.errors(self.real + extra))

    def test_shared_proof_missing_from_a_pair_fails(self):
        lines = [l for l in self.real.splitlines()
                 if not (l.startswith("aarch64 ") and l.endswith("WordSpec.ec"))]
        self.assertTrue(any("WordSpec.ec" in e for e in self.errors("\n".join(lines) + "\n")))

    def test_unknown_shard_fails(self):
        self.assertTrue(self.errors(self.real + "bogus proofs/spec/Bytes.ec\n"))

class Commands(unittest.TestCase):
    def test_platform_parameters(self):
        reg = registry.load()
        cmd = check.make_command(reg, "test-hash", "linux-x86_64")
        self.assertIn("CI_HASH_SETS=scalar x86_64", cmd)
        self.assertIn("CI_HASH_CPU_x86_64=avx avx2 sha_ni", cmd)
        self.assertIn("CI_RULES=tools/ci/rules/test-hash.toml", cmd)
        cmd = check.make_command(reg, "proofs-spec", "linux-x86_64")
        self.assertEqual(cmd[:2], ["tools/ci/toolchain.sh", "exec"])
        self.assertIn("CI_SHARD=spec", cmd)
        self.assertIn("CI_JOBS=3", cmd)
        cmd = check.make_command(reg, "test-core", "macos-aarch64")
        self.assertIn("CI_TARGET=aarch64-macho", cmd)
        self.assertIn("CI_JOBS=2", cmd)

    def test_host_must_be_the_platform(self):
        reg = registry.load()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "CI_RUNNER": "ubuntu-26.04"}), \
                mock.patch.object(check.host_platform, "system", return_value="Linux"), \
                mock.patch.object(check.host_platform, "machine", return_value="x86_64"):
            with self.assertRaises(check.Failure):
                check.host_is(reg, "linux-x86_64")
            os.environ["CI_RUNNER"] = "ubuntu-24.04"
            check.host_is(reg, "linux-x86_64")
            with self.assertRaises(check.Failure):
                check.host_is(reg, "macos-aarch64")


if __name__ == "__main__":
    unittest.main()
