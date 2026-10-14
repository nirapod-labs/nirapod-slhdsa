# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/tests/test_drift.py
# ============================
#
# tools/ci/drift.py on scratch repositories: an "upstream" with two
# commits, and a toolchain/ whose series holds a patch upstream has since
# taken, a changelog patch whose context upstream moved, a patch that
# still applies, and (in one case) a patch upstream contradicts. The
# report must say which is which, the scratch copy must hold exactly the
# kept patches on the new pin, and refs in any other form than the three
# accepted ones must be refused before git sees them.

import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import drift  # noqa: E402

ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@invalid",
           GIT_AUTHOR_DATE="2026-01-01T00:00:00Z", GIT_COMMITTER_DATE="2026-01-01T00:00:00Z",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def git(cwd, *args):
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, env=ENV,
                          check=True, capture_output=True, text=True).stdout.strip()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class Drift(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.environ.pop("GITHUB_OUTPUT", None)
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        # Upstream at the pin.
        up = self.up = os.path.join(self.tmp, "upstream")
        write(f"{up}/a.txt", "one\ntwo\n" + "".join(f"line {i}\n" for i in range(3, 10)) + "ten\n")
        write(f"{up}/b.txt", "alpha\nbeta\n")
        write(f"{up}/CHANGELOG.md", "# Changes\n\n- old entry\n")
        git(self.tmp, "init", "-q", "-b", "main", up)
        git(up, "add", "-A")
        git(up, "commit", "-q", "-m", "pin")
        self.pin = git(up, "rev-parse", "HEAD")
        # Our patches, made on the pin.
        work = os.path.join(self.tmp, "work")
        git(self.tmp, "clone", "-q", up, work)
        self.patches = {}

        def patch(name, path, old, new):
            git(work, "checkout", "-q", "--detach", self.pin)
            with open(f"{work}/{path}") as f:
                text = f.read()
            write(f"{work}/{path}", text.replace(old, new))
            git(work, "commit", "-q", "-am", name)
            out = os.path.join(self.tmp, f"{name}.patch")
            with open(out, "w") as f:
                f.write(git(work, "format-patch", "--stdout", "-1", "HEAD") + "\n")
            self.patches[name] = out

        patch("0001-b", "b.txt", "beta\n", "beta\ngamma\n")
        patch("0002-log", "CHANGELOG.md", "- old entry\n", "- old entry\n- our entry\n")
        patch("0003-a", "a.txt", "ten\n", "ten\neleven\n")
        patch("0004-clash", "a.txt", "two\n", "TWO\n")
        # Upstream moves on: it takes 0001, rewrites the changelog context
        # and the line 0004 changes.
        write(f"{up}/b.txt", "alpha\nbeta\ngamma\n")
        write(f"{up}/CHANGELOG.md", "# Changes\n\n- newer entry\n- old entry, reworded\n")
        write(f"{up}/a.txt", "one\ndeux\n" + "".join(f"line {i}\n" for i in range(3, 10)) + "ten\n")
        git(up, "commit", "-q", "-am", "upstream moves")
        self.head = git(up, "rev-parse", "HEAD")
        git(up, "update-ref", "refs/pull/7/head", self.pin)

    def project(self, names):
        """A project repository whose toolchain/ carries the patches NAMES."""
        root = os.path.join(self.tmp, "project-" + "-".join(n[:4] for n in names))
        lines = []
        for n in names:
            dst = f"{root}/toolchain/jasmin/patches/{n}.patch"
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy(self.patches[n], dst)
            with open(dst, "rb") as f:
                lines.append(f"patches/{n}.patch {hashlib.sha256(f.read()).hexdigest()}\n")
        write(f"{root}/toolchain/jasmin/SERIES", "# the series\n\n" + "".join(lines))
        write(f"{root}/toolchain/jasmin/PIN",
              f"# pin\nJASMIN_URL={self.up}\nJASMIN_COMMIT={self.pin}\n")
        write(f"{root}/toolchain/easycrypt/PIN",
              f"EASYCRYPT_URL={self.up}\nEASYCRYPT_COMMIT={self.pin}\n")
        git(self.tmp, "init", "-q", root)
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "project")
        return root

    def resolve(self, root, ref, name):
        d = os.path.join(self.tmp, name)
        with redirect_stdout(io.StringIO()):
            drift.cmd_resolve("jasmin", ref, d, root)
        return d, git(d, "rev-parse", "HEAD")

    def test_series_report_and_scratch_copy(self):
        root = self.project(["0001-b", "0002-log", "0003-a"])
        up, commit = self.resolve(root, "main", "u1")
        self.assertEqual(commit, self.head)
        out = os.path.join(self.tmp, "out1")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(drift.cmd_series(up, out, root), 0)
        with open(f"{out}/report.md") as f:
            report = f.read()
        self.assertIn("| patches/0001-b.patch | upstream |", report)
        self.assertIn("| patches/0002-log.patch | conflicts (changelog only) |", report)
        self.assertIn("| patches/0003-a.patch | applies |", report)
        t = f"{out}/tree/toolchain/jasmin"
        with open(f"{t}/PIN") as f:
            self.assertIn(f"JASMIN_COMMIT={self.head}\n", f.read())
        self.assertEqual(sorted(os.listdir(f"{t}/patches")), ["0003-a.patch"])
        self.assertEqual(drift.series(f"{t}/SERIES"), drift.series(f"{root}/toolchain/jasmin/SERIES")[2:])
        # The copy is committed and clean, as toolchain/build.sh requires.
        self.assertEqual(git(f"{out}/tree", "status", "--porcelain"), "")
        # The project's own toolchain/ is untouched.
        self.assertEqual(git(root, "status", "--porcelain"), "")

    def test_conflict_outside_the_changelog_stops(self):
        root = self.project(["0001-b", "0004-clash", "0003-a"])
        up, _ = self.resolve(root, self.head, "u2")
        out = os.path.join(self.tmp, "out2")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(drift.cmd_series(up, out, root), 1)
        with open(f"{out}/report.md") as f:
            report = f.read()
        self.assertIn("| patches/0004-clash.patch | conflicts |", report)
        self.assertIn("cannot be built", report)
        self.assertFalse(os.path.exists(f"{out}/tree"))

    def test_dropped_patch_lets_the_rest_build(self):
        root = self.project(["0001-b", "0004-clash", "0003-a"])
        up, _ = self.resolve(root, "main", "u8")
        out = os.path.join(self.tmp, "out8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(drift.cmd_series(up, out, root, drop=["patches/0004"]), 0)
        with open(f"{out}/report.md") as f:
            self.assertIn("| patches/0004-clash.patch | dropped |", f.read())
        self.assertEqual(sorted(os.listdir(f"{out}/tree/toolchain/jasmin/patches")),
                         ["0003-a.patch"])

    def test_series_on_its_own_pin_applies(self):
        root = self.project(["0001-b", "0002-log", "0003-a", "0004-clash"])
        up, _ = self.resolve(root, "pull/7/head", "u3")
        out = os.path.join(self.tmp, "out3")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(drift.cmd_series(up, out, root), 0)
        with open(f"{out}/report.md") as f:
            self.assertEqual(f.read().count("| applies |"), 4)

    def test_ref_forms(self):
        root = self.project(["0003-a"])
        self.assertEqual(self.resolve(root, self.head[:9], "u4")[1], self.head)
        self.assertEqual(self.resolve(root, "pull/7/head", "u5")[1], self.pin)
        for bad in ("--upload-pack=x", "main..x", "HEAD~1", "main@{1}", "a b", "-x",
                    "pull/7/merge", "refs/heads/main", ".hidden", "x.lock", ""):
            self.assertIsNone(drift.ref_kind(bad), bad)
            with self.assertRaises(drift.Failure):
                drift.cmd_resolve("jasmin", bad, os.path.join(self.tmp, "never"), root)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "never")))
        with self.assertRaises(drift.Failure):
            self.resolve(root, "no-such-branch", "u6")
        with self.assertRaises(drift.Failure):
            self.resolve(root, "f" * 12, "u7")

    def test_easycrypt_copy(self):
        root = self.project(["0003-a"])
        out = os.path.join(self.tmp, "out4")
        with redirect_stdout(io.StringIO()):
            drift.cmd_easycrypt(self.head, out, root)
        with open(f"{out}/tree/toolchain/easycrypt/PIN") as f:
            self.assertIn(f"EASYCRYPT_COMMIT={self.head}", f.read())
        with open(f"{out}/tree/toolchain/jasmin/PIN") as f:
            self.assertIn(f"JASMIN_COMMIT={self.pin}", f.read())
        with self.assertRaises(drift.Failure):
            drift.cmd_easycrypt("main", os.path.join(self.tmp, "out5"), root)


class Setup(unittest.TestCase):
    def run_setup(self, **env):
        out = tempfile.NamedTemporaryFile(delete=False)
        out.close()
        self.addCleanup(os.remove, out.name)
        os.environ["GITHUB_OUTPUT"] = out.name
        self.addCleanup(os.environ.pop, "GITHUB_OUTPUT", None)
        base = {"MAINTAINERS": "athexweb3 orvenweb3", "ACTOR": "athexweb3",
                "TRIGGERING_ACTOR": "athexweb3", "COMPONENT": "both", "JASMIN_REF": "main",
                "EASYCRYPT_REF": "main", "PLATFORMS": "linux-x86_64", "EVENT": "workflow_dispatch"}
        base.update(env)
        with redirect_stdout(io.StringIO()):
            drift.cmd_setup(base)
        with open(out.name) as f:
            return dict(l.rstrip("\n").split("=", 1) for l in f)

    def test_dispatch_by_a_maintainer(self):
        o = self.run_setup(COMPONENT="jasmin", PLATFORMS="all", JASMIN_REF="pull/1624/head",
                           EASYCRYPT_REF="--bad", JASMIN_DROP="patches/0001 patches-simd/0002")
        self.assertEqual(o["jasmin-drop"], "patches/0001 patches-simd/0002")
        self.assertEqual((o["jasmin"], o["easycrypt"]), ("true", "false"))
        self.assertEqual(len(drift.json.loads(o["jasmin-platforms"])), 3)

    def test_schedule_is_both_lanes_on_main(self):
        o = self.run_setup(EVENT="schedule", ACTOR="someone", TRIGGERING_ACTOR="someone",
                           COMPONENT="", PLATFORMS="")
        self.assertEqual((o["jasmin"], o["easycrypt"]), ("true", "true"))
        self.assertEqual([p["platform"] for p in drift.json.loads(o["jasmin-platforms"])],
                         ["linux-x86_64"])

    def test_refusals(self):
        for env in ({"ACTOR": "someone"}, {"TRIGGERING_ACTOR": "dependabot[bot]"},
                    {"COMPONENT": "proofs"}, {"PLATFORMS": "windows"},
                    {"JASMIN_REF": "main..x"}, {"EASYCRYPT_REF": "$(id)"},
                    {"EVENT": "push"}, {"EVENT": "pull_request"},
                    {"JASMIN_DROP": "0001"}, {"JASMIN_DROP": "patches/0001;x"},
                    {"JASMIN_DROP": "../patches/0001"}):
            with self.assertRaises(drift.Failure, msg=str(env)):
                self.run_setup(**env)


if __name__ == "__main__":
    unittest.main()
