# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/tests/test_record.py
# =============================
#
# Records (tools/ci/record.py) and where they may come from
# (tools/ci/store.py), against a stand-in API:
#
#   - a record starts with its status, and a NOT RUN record reads NOT RUN
#     and is never reused (control e); a record in the old format, whose
#     first line said PASS for a check that had not run, is refused
#     outright;
#   - a record is taken only when its key text equals this run's line by
#     line and it names the run it came from;
#   - an artifact uploaded by a pull request's run under a records- name
#     is ignored (control d), and so are artifacts of a fork's run, of
#     another branch, of another workflow (drift), of an old run, of a run
#     whose commit is not on main, of a run without a plan, and any
#     artifact not named records-*;
#   - when the newest run on main planned a check and left no PASS record
#     (it failed), an older pass is not reused.

import datetime
import io
import json
import os
import sys
import unittest
import urllib.parse
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import fakeapi  # noqa: E402
import ghapi  # noqa: E402
import record  # noqa: E402
import store  # noqa: E402

NAME = "v2-test-hash-linux-x86_64-" + "a" * 64
TEXT = ("format 2\ncheck test-hash\nplatform linux-x86_64\nrunner ubuntu-24.04\n"
        "toolchain " + "b" * 64 + "\ninputs " + "c" * 64 + "\n")


def env(run_id, event="push", ref="refs/heads/main"):
    return {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
            "GITHUB_RUN_ID": str(run_id), "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "d" * 40,
            "GITHUB_EVENT_NAME": event, "GITHUB_REF": ref, "ImageOS": "ubuntu24",
            "ImageVersion": "20261012.1"}


class Records(unittest.TestCase):
    def test_round_trip(self):
        text = record.render("PASS", NAME, TEXT, env(7), host=["cc 13"], build_key="k",
                             counts=["counts hash: PASS"], files=["build/ci/t.txt"])
        rec = record.parse(text)
        self.assertEqual(text.splitlines()[0], "status PASS")
        self.assertEqual((rec["status"], rec["key"], rec["key_text"], rec["run_id"]),
                         ("PASS", NAME, TEXT, 7))
        self.assertEqual(rec["files"], ["build/ci/t.txt"])
        record.validate(rec, NAME, TEXT, 7)

    def test_e_not_run_reads_not_run(self):
        for status in ("NOT RUN", "NOT APPLICABLE"):
            rec = record.parse(record.render(status, NAME, TEXT, env(7)))
            self.assertEqual(rec["status"], status)
            with self.assertRaises(record.RecordError):
                record.validate(rec, NAME, TEXT, 7)

    def test_old_format_is_refused(self):
        old = ("verdict PASS\nkey verdict-safety-linux-x86_64-" + "a" * 64 + "\nformat 1\n"
               "check safety\nplatform linux-x86_64\ncompiler k\ninputs t\nrun u attempt 1\n"
               "commit c\nevent push refs/heads/main\nrecorded now\nstatus NOT RUN\n")
        with self.assertRaises(record.RecordError):
            record.parse(old)

    def test_failures_are_never_recorded(self):
        for status in ("FAIL", "INCONCLUSIVE", "PASS "):
            with self.assertRaises(record.RecordError):
                record.render(status, NAME, TEXT, env(7))

    def test_validation(self):
        rec = record.parse(record.render("PASS", NAME, TEXT, env(7)))
        cases = [
            (NAME[:-1] + "f", TEXT, 7),
            (NAME, TEXT.replace("inputs c", "inputs e"), 7),
            (NAME, TEXT.replace("runner ubuntu-24.04", "runner ubuntu-26.04"), 7),
            (NAME, TEXT, 8),
        ]
        for name, text, run in cases:
            with self.assertRaises(record.RecordError):
                record.validate(rec, name, text, run)
        for e in (env(7, "pull_request", "refs/pull/3/merge"), env(7, "push", "refs/heads/x")):
            with self.assertRaises(record.RecordError):
                record.validate(record.parse(record.render("PASS", NAME, TEXT, e)), NAME, TEXT, 7)

    def test_malformed(self):
        good = record.render("PASS", NAME, TEXT, env(7), files=["a"])
        bad = [good.replace("status PASS", "status  PASS"), good[:-1],
               good.replace("file a", "file ../a"), good + "host x\n",
               good + "extra line\n", good.replace("\ninputs ", "\ninput ")]
        for b in bad:
            with self.assertRaises(record.RecordError):
                record.parse(b)
        with self.assertRaises(record.RecordError):
            record.render("PASS", NAME, TEXT, env(7), files=["/etc/passwd"])


def zipped(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


class Lookup(unittest.TestCase):
    NOW = datetime.datetime(2026, 10, 14, tzinfo=datetime.timezone.utc)

    def setUp(self):
        self.api = fakeapi.Server()
        self.addCleanup(self.api.close)
        self.runs, self.arts = [], {}

        def runs_route(method, path, body):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            event = q["event"][0]
            return {"workflow_runs": [r for r in self.runs if r["event"] == event]}

        self.api.routes["/repos/o/r/actions/workflows/ci.yml/runs"] = runs_route

    def run_(self, rid, event="push", branch="main", path=".github/workflows/ci.yml",
             fork=False, created="2026-10-13T00:00:00Z", on_main=True, planned=(NAME,)):
        sha = f"{rid:040x}"
        r = {"id": rid, "event": event, "head_branch": branch, "path": path,
             "created_at": created, "repository": {"id": 1}, "head_sha": sha,
             "head_repository": {"id": 2 if fork else 1}}
        self.runs.append(r)
        self.api.routes[f"/repos/o/r/compare/{sha}...main"] = {
            "status": "ahead" if on_main else "diverged"}
        self.api.routes[f"/repos/o/r/actions/runs/{rid}/artifacts"] = {"artifacts": []}
        if planned is not None:
            plan = {"legs": [{"key": k, "decision": "RUN"} for k in planned]}
            self.artifact(rid, rid * 100 + 99, "plan", {"plan.json": json.dumps(plan)})
        return r

    def artifact(self, rid, aid, name, entries):
        self.api.routes[f"/repos/o/r/actions/runs/{rid}/artifacts"]["artifacts"].append(
            {"id": aid, "name": name, "expired": False, "workflow_run": {"id": rid}})
        self.api.routes[f"/repos/o/r/actions/artifacts/{aid}/zip"] = zipped(entries)

    def rec(self, run_id, status="PASS", e=None, text=TEXT):
        return {f"{NAME}/record": record.render(status, NAME, text, e or env(run_id)),
                f"{NAME}/log": "log\n"}

    def lookup(self):
        s = store.Store(ghapi.Api("o/r", token="t", root=self.api.url, pause=0), now=self.NOW)
        return s.find_records({NAME: TEXT})

    def test_found_in_newest_main_run(self):
        self.run_(10, created="2026-10-12T00:00:00Z")
        self.artifact(10, 100, "records-native-linux-x86_64", self.rec(10))
        self.run_(11, event="schedule", created="2026-10-13T00:00:00Z")
        self.artifact(11, 110, "records-native-linux-x86_64", self.rec(11))
        found, _ = self.lookup()
        run, rec, log, _ = found[NAME]
        self.assertEqual((run["id"], rec["status"]), (11, "PASS"))

    def test_newest_run_without_a_pass_closes_the_key(self):
        # Run 11 planned the check and failed it (no record), or recorded
        # something other than a pass: the older pass of run 10 stays unused.
        self.run_(10, created="2026-10-12T00:00:00Z")
        self.artifact(10, 100, "records-native-linux-x86_64", self.rec(10))
        self.run_(11, created="2026-10-13T00:00:00Z")
        found, notes = self.lookup()
        self.assertEqual(found, {})
        self.assertTrue(any("planned it and has no PASS record" in n for n in notes))
        self.artifact(11, 110, "records-native-linux-x86_64", self.rec(11, status="NOT RUN"))
        self.assertEqual(self.lookup()[0], {})

    def test_newest_run_that_did_not_plan_the_key_is_passed_over(self):
        self.run_(10, created="2026-10-12T00:00:00Z")
        self.artifact(10, 100, "records-native-linux-x86_64", self.rec(10))
        self.run_(11, created="2026-10-13T00:00:00Z", planned=("v2-other-any-" + "0" * 64,))
        found, _ = self.lookup()
        self.assertEqual(found[NAME][0]["id"], 10)

    def test_run_off_main_or_without_plan_is_ignored(self):
        self.run_(12, on_main=False)
        self.artifact(12, 120, "records-native-linux-x86_64", self.rec(12))
        self.run_(13, planned=None)
        self.artifact(13, 130, "records-native-linux-x86_64", self.rec(13))
        self.assertEqual(self.lookup()[0], {})

    def test_damaged_artifact_is_skipped(self):
        self.run_(14)
        self.artifact(14, 140, "records-native-linux-x86_64", self.rec(14))
        self.api.routes["/repos/o/r/actions/artifacts/140/zip"] = b"PK\x03\x04 not a zip"
        found, notes = self.lookup()
        self.assertEqual(found, {})

    def test_d_untrusted_artifacts_are_ignored(self):
        # Every candidate holds a record that would match if it were trusted.
        self.run_(20, event="pull_request", branch="main")
        self.artifact(20, 200, "records-native-linux-x86_64", self.rec(20))
        self.run_(21, fork=True)
        self.artifact(21, 210, "records-native-linux-x86_64", self.rec(21))
        self.run_(22, branch="feature")
        self.artifact(22, 220, "records-native-linux-x86_64", self.rec(22))
        self.run_(23, path=".github/workflows/drift.yml")
        self.artifact(23, 230, "records-native-linux-x86_64", self.rec(23))
        self.run_(24, created="2026-06-01T00:00:00Z")
        self.artifact(24, 240, "records-native-linux-x86_64", self.rec(24))
        self.run_(25)
        self.artifact(25, 250, "drift-jasmin-linux-x86_64", self.rec(25))
        self.artifact(25, 251, NAME, self.rec(25))
        found, _ = self.lookup()
        self.assertEqual(found, {})

    def test_record_naming_another_run_is_refused(self):
        self.run_(30)
        self.artifact(30, 300, "records-native-linux-x86_64", self.rec(29))
        found, notes = self.lookup()
        self.assertEqual(found, {})
        self.assertTrue(any("run 29" in n for n in notes), notes)

    def test_record_of_other_inputs_is_refused(self):
        self.run_(40)
        self.artifact(40, 400, "records-native-linux-x86_64",
                      self.rec(40, text=TEXT.replace("inputs c", "inputs f")))
        found, notes = self.lookup()
        self.assertEqual(found, {})

    def test_record_from_a_pull_request_event_is_refused(self):
        # A push run on main whose record says it was made on a pull request.
        self.run_(50)
        self.artifact(50, 500, "records-native-linux-x86_64",
                      self.rec(50, e=env(50, "pull_request", "refs/pull/1/merge")))
        self.assertEqual(self.lookup()[0], {})

    def test_api_error_propagates(self):
        self.run_(60)
        self.api.routes["/repos/o/r/actions/runs/60/artifacts"] = None
        with self.assertRaises(ghapi.ApiError):
            self.lookup()

    def test_kept_files_must_be_in_the_artifact(self):
        self.run_(70)
        entries = {f"{NAME}/record": record.render("PASS", NAME, TEXT, env(70),
                                                   files=["build/ci/t.txt"]),
                   f"{NAME}/log": "log\n"}
        self.artifact(70, 700, "records-native-linux-x86_64", entries)
        self.assertEqual(self.lookup()[0], {})
        entries[f"{NAME}/files/build/ci/t.txt"] = "transcript\n"
        self.artifact(70, 701, "records-native-linux-aarch64", entries)
        found, _ = self.lookup()
        self.assertEqual(found[NAME][3], {"build/ci/t.txt": b"transcript\n"})


if __name__ == "__main__":
    unittest.main()
