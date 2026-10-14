# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_check.py
# ======================
#
# ci/check.py: a check runs only with the plan's key and only when it
# applies, its pass is recorded with status PASS and its kept files, a
# failure leaves no record; agree compares the transcripts of every
# platform, from this run's records or reused ones, and fails on one byte
# of difference.

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import check  # noqa: E402
import key  # noqa: E402
import plan  # noqa: E402
import record  # noqa: E402
import registry  # noqa: E402
import toolchain  # noqa: E402

ENV = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
       "GITHUB_RUN_ID": "41", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40,
       "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}


class Base(unittest.TestCase):
    def setUp(self):
        self.reg = registry.load()
        self.tree = key.Tree(cwd=registry.ROOT)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self.cwd)
        patcher = mock.patch.object(key, "Tree", lambda *a, **k: self.tree)
        patcher.start()
        self.addCleanup(patcher.stop)


class RunOne(Base):
    def fake_make(self, rc, transcript=None):
        def run(cmd, log_path):
            with open(log_path, "w") as f:
                f.write("counts transcript: core transcript: 84 lines (minimum 84): PASS\n")
            if transcript is not None:
                os.makedirs("build/ci", exist_ok=True)
                with open("build/ci/transcript-x86_64-elf.txt", "w") as f:
                    f.write(transcript)
            return rc
        return mock.patch.object(check, "run_logged", run)

    def test_pass_is_recorded_with_its_files(self):
        with self.fake_make(0, "t\n"), redirect_stdout(io.StringIO()), \
                mock.patch.dict(os.environ, ENV):
            self.assertTrue(check.run_one(self.reg, self.tree, "test-core", "linux-x86_64"))
        name, text = key.key(self.tree, self.reg, "test-core", "linux-x86_64")
        rec, log, kept = record.read_dir(os.path.join(check.RECORDS, name))
        self.assertEqual((rec["status"], rec["key_text"]), ("PASS", text))
        self.assertEqual(kept, {"build/ci/transcript-x86_64-elf.txt": b"t\n"})
        self.assertEqual(rec["counts"], ["counts transcript: core transcript: 84 lines (minimum 84): PASS"])

    def test_failure_leaves_no_record(self):
        with self.fake_make(2), redirect_stdout(io.StringIO()):
            self.assertFalse(check.run_one(self.reg, self.tree, "test-hash", "linux-x86_64"))
        self.assertEqual(os.listdir(check.RECORDS), ["failed"])

    def test_key_must_be_the_plans(self):
        name, text = key.key(self.tree, self.reg, "test-hash", "linux-x86_64")
        with self.fake_make(0), redirect_stdout(io.StringIO()):
            with self.assertRaises(check.Failure):
                check.run_one(self.reg, self.tree, "test-hash", "linux-x86_64",
                              (name, text.replace("inputs ", "inputs 0")))

    def test_check_that_does_not_apply_never_runs(self):
        with self.fake_make(0), redirect_stdout(io.StringIO()):
            for cid in ("differential", "safety"):
                with self.assertRaises(check.Failure):
                    check.run_one(self.reg, self.tree, cid, "linux-x86_64")


class Agree(Base):
    def setUp(self):
        super().setUp()
        os.makedirs("plan")
        self.plan = plan.make_plan({"GITHUB_EVENT_NAME": "push"}, self.reg, self.tree, None, "plan")
        import json
        with open("plan/plan.json", "w") as f:
            json.dump(self.plan, f)
        for leg in self.plan["legs"]:
            if leg["check"] == "test-core":
                self.transcript(leg, "line\n" * 84)
        for p in self.reg["platforms"]:
            d = f"builds/buildrecord-{p}"
            os.makedirs(d)
            for name in toolchain.RECORD:
                with open(os.path.join(d, name), "w") as f:
                    f.write("jasmin tree: t\n" if name == "provenance.txt" else f"{name}\n")

    def transcript(self, leg, text, where="results"):
        d = os.path.join(where, leg["key"])
        os.makedirs(os.path.join(d, "files/build/ci"), exist_ok=True)
        f = "build/ci/transcript-x.txt"
        with open(os.path.join(d, "files", f), "w") as fh:
            fh.write(text)
        with open(os.path.join(d, "log"), "w") as fh:
            fh.write("log\n")
        with open(os.path.join(d, "record"), "w") as fh:
            fh.write(record.render("PASS", leg["key"], leg["text"], ENV, files=[f]))

    def agree(self):
        with redirect_stdout(io.StringIO()):
            return check.cmd_agree("plan/plan.json", "results", "builds")

    def test_identical_platforms_agree_and_are_recorded(self):
        self.assertEqual(self.agree(), 0)
        leg = next(l for l in self.plan["legs"] if l["check"] == "agree")
        self.assertTrue(os.path.isfile(os.path.join(check.RECORDS, leg["key"], "record")))

    def test_one_byte_of_difference_fails(self):
        leg = next(l for l in self.plan["legs"] if l["check"] == "test-core"
                   and l["platform"] == "macos-aarch64")
        shutil.rmtree(os.path.join("results", leg["key"]))
        self.transcript(leg, "line\n" * 83 + "linf\n")
        with self.assertRaises(check.Failure):
            self.agree()

    def test_reused_transcript_counts(self):
        leg = next(l for l in self.plan["legs"] if l["check"] == "test-core"
                   and l["platform"] == "linux-aarch64")
        shutil.rmtree(os.path.join("results", leg["key"]))
        with self.assertRaises(check.Failure):
            self.agree()
        self.transcript(leg, "line\n" * 84, where="plan/reused")
        self.assertEqual(self.agree(), 0)

    def test_build_records_must_agree(self):
        with open("builds/buildrecord-linux-aarch64/cil.sha256", "w") as f:
            f.write("other\n")
        with self.assertRaises(toolchain.Failure):
            self.agree()


if __name__ == "__main__":
    unittest.main()
