# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/tests/test_key.py
# ==========================
#
# Negative controls of the check keys (tools/ci/key.py), on a scratch
# repository holding a copy of this tree: one changed byte in a file of
# each kind changes exactly the keys of the checks that read it, and no
# other.
#
#   (a) a file each check reads changes that check's key;
#   (b) a file of skip-all, or of a check's skip list, leaves the keys of
#       the checks that skip it unchanged;
#   (c) a new file at the root changes every key;
#   a check's own recipe or rules file changes its key alone (a proof
#   shard's recipe is shared by the shards);
#   a *.mk file the top-level Makefile includes changes every key, skip
#   lists notwithstanding;
#   a toolchain file changes every key; a toolchain option only its
#   platform's;
#   the work tree plays no part: only the commit does.

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import key  # noqa: E402
import registry  # noqa: E402

ROOT = registry.ROOT
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@invalid",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def git(cwd, *args):
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, env=ENV,
                          check=True, capture_output=True).stdout


class Keys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.repo = os.path.join(cls.tmp, "repo")
        files = subprocess.run(["git", "ls-files", "-z", "--cached", "--others",
                                "--exclude-standard"], cwd=ROOT, check=True,
                               capture_output=True).stdout.split(b"\0")
        for f in (f.decode() for f in files if f):
            src = os.path.join(ROOT, f)
            if os.path.isfile(src):
                dst = os.path.join(cls.repo, f)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
        # Files that may not exist in the tree yet, so that each kind of
        # path is represented.
        for f in ("tools/ci/checks/test-hash.mk", "tools/ci/checks/proofs.mk",
                  "tools/ci/rules/test-hash.toml", "tools/ci/rules/proofs-spec.toml"):
            p = os.path.join(cls.repo, f)
            if not os.path.exists(p):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as fh:
                    fh.write("# placeholder\n")
        git(cls.tmp, "init", "-q", cls.repo)
        git(cls.repo, "add", "-A")
        git(cls.repo, "commit", "-q", "-m", "base")
        cls.reg = registry.load(cls.repo)
        cls.base = cls.keys(cls.reg)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    @classmethod
    def keys(cls, reg=None):
        reg = reg or cls.reg
        tree = key.Tree(cwd=cls.repo)
        out = {(c, p): key.key(tree, reg, c, p)[0] for c, p in registry.legs(reg)}
        out[("agree", "any")] = key.agree_key(tree, reg)[0]
        return out

    def changed_by(self, path, text=None):
        """The legs whose key differs after appending a byte to PATH (or
        creating it with TEXT) in a new commit; the commit is undone."""
        full = os.path.join(self.repo, path)
        existed = os.path.exists(full)
        if existed:
            with open(full, "rb") as f:
                before = f.read()
        os.makedirs(os.path.dirname(full) or self.repo, exist_ok=True)
        with open(full, "ab") as f:
            f.write((text or " ").encode())
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "change")
        try:
            after = self.keys()
        finally:
            git(self.repo, "reset", "-q", "--hard", "HEAD~1")
            if not existed and os.path.exists(full):
                os.remove(full)
        if existed:
            with open(full, "rb") as f:
                self.assertEqual(f.read(), before)
        return {leg for leg in after if after[leg] != self.base[leg]}

    def legs_of(self, *checks):
        return {(c, p) for c, p in self.base if c in checks}

    def all_legs(self):
        return set(self.base)

    def test_a_inputs_change_their_checks(self):
        hash_checks = self.legs_of("test-hash", "analysis-hash", "safety")
        got = self.changed_by("src/hash/keccak/keccakf1600.jinc")
        # Every check that reads src/hash, and agree through test-core.
        self.assertTrue(self.legs_of("test-hash", "analysis-hash", "test-core",
                                     "analysis-units", "asm-policy", "proofs-extraction") <= got)
        self.assertFalse(got & self.legs_of("proofs-sphincs", "proofs-spec", "proofs-x86_64"))
        got = self.changed_by("tests/hash/Makefile")
        self.assertEqual(got, hash_checks)
        got = self.changed_by("third_party/formosa-slhdsa/README.md")
        self.assertEqual(got, self.legs_of("proofs-sphincs", "proofs-spec", "proofs-x86_64",
                                           "proofs-aarch64"))
        # The extraction reads the SLH-DSA core too (extracted/address.jazz).
        got = self.changed_by("src/slhdsa/address.jinc")
        self.assertIn(("proofs-extraction", "linux-x86_64"), got)
        self.assertFalse(got & self.legs_of("proofs-sphincs", "proofs-spec", "test-hash"))
        got = self.changed_by("capi/api.c")
        self.assertIn(("test-core", "macos-aarch64"), got)
        self.assertIn(("agree", "any"), got)
        self.assertFalse(got & self.legs_of("test-hash", "proofs-spec", "analysis-units"))

    def test_b_skipped_paths_change_nothing(self):
        for path in ("docs/API.md", "README.md", "changes/README.md", "tools/ci/retry.py",
                     "tools/ci/tests/test_key.py", ".github/workflows/drift.yml",
                     "proofs/README.md"):
            self.assertEqual(self.changed_by(path), set(), path)

    def test_c_new_root_file_changes_every_key(self):
        self.assertEqual(self.changed_by("NEWFILE", "x"), self.all_legs())
        self.assertEqual(self.changed_by("newdir/x.c", "x"), self.all_legs())

    def test_recipe_and_rules_are_per_check(self):
        self.assertEqual(self.changed_by("tools/ci/checks/test-hash.mk"),
                         self.legs_of("test-hash"))
        self.assertEqual(self.changed_by("tools/ci/rules/test-hash.toml"),
                         self.legs_of("test-hash"))
        self.assertEqual(self.changed_by("tools/ci/rules/proofs-spec.toml"),
                         self.legs_of("proofs-spec"))
        shards = {c for c in self.reg["checks"] if self.reg["checks"][c]["recipe"] == "proofs"}
        self.assertEqual(self.changed_by("tools/ci/checks/proofs.mk"), self.legs_of(*shards))

    def test_included_makefile_fragments_change_every_key(self):
        self.assertEqual(self.changed_by("analysis/ct/ct.mk"), self.all_legs())
        self.assertEqual(self.changed_by("proofs/x.mk", "x"), self.all_legs())

    def test_toolchain_changes_every_key(self):
        self.assertEqual(self.changed_by("toolchain/jasmin/PIN"), self.all_legs())
        reg = registry.load(self.repo)
        reg["platforms"]["linux-aarch64"]["toolchain-options"] = "--other"
        after = self.keys(reg)
        self.assertEqual({l for l in after if after[l] != self.base[l]},
                         {l for l in after if l[1] == "linux-aarch64"} | {("agree", "any")})

    def test_shared_ci_files_change_every_key(self):
        for path in ("tools/ci/key.py", "tools/ci/checks.toml", ".github/workflows/ci.yml"):
            self.assertEqual(self.changed_by(path), self.all_legs(), path)

    def test_work_tree_plays_no_part(self):
        p = os.path.join(self.repo, "src/hash/keccak/keccakf1600.jinc")
        with open(p, "a") as f:
            f.write("dirty")
        try:
            self.assertEqual(self.keys(), self.base)
        finally:
            git(self.repo, "checkout", "-q", "--", "src/hash/keccak/keccakf1600.jinc")

    def test_key_text_names_its_parts(self):
        tree = key.Tree(cwd=self.repo)
        n, text = key.key(tree, self.reg, "test-hash", "macos-aarch64")
        lines = text.splitlines()
        self.assertEqual([l.split(" ")[0] for l in lines],
                         ["format", "check", "platform", "runner", "toolchain", "inputs"])
        self.assertEqual(lines[3], "runner macos-26")
        self.assertRegex(n, r"^v2-test-hash-macos-aarch64-[0-9a-f]{64}$")
        with self.assertRaises(key.KeyFailure):
            key.key(tree, self.reg, "safety", "macos-aarch64")


if __name__ == "__main__":
    unittest.main()
