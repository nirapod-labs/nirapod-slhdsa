# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_plan.py
# =====================
#
# The plan (ci/plan.py) and the gates (ci/gate.py) on this
# tree, with records served by a stand-in store, and the negative controls
# of the gates:
#
#   - a pull request that changes only documentation finds every record on
#     main and starts no platform job, macOS included;
#   - a push to main reuses nothing, and a record other than a pass is
#     never reused;
#   - all-checks fails when a planned job was skipped, when an unplanned job
#     ran, when a job is missing from its needs, when a leg is removed from
#     the plan, when a leg the plan ran has no PASS record, and when a
#     reused record does not match its key;
#   - the proofs gate fails when a shard is missing from the plan or from
#     proofs/Makefile, or when a shard did not pass.

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import gate  # noqa: E402
import key  # noqa: E402
import plan  # noqa: E402
import record  # noqa: E402
import registry  # noqa: E402

ENV = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
       "GITHUB_RUN_ID": "41", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40,
       "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}


class FakeStore:
    """Answers find_records from records it was given, as runs on main."""

    def __init__(self, records, status="PASS"):
        self.records = records
        self.status = status

    def find_records(self, wanted):
        found = {}
        for name, text in wanted.items():
            if name in self.records:
                raw = record.render(self.status, name, text, ENV, files=self.records[name])
                rec = record.parse(raw)
                rec["raw"] = raw
                try:
                    record.validate(rec, name, text, 41)
                except record.RecordError:
                    continue
                kept = {f: b"transcript\n" for f in self.records[name]}
                found[name] = ({"id": 41}, rec, "log\n", kept)
        return found, []


class Plans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = registry.load()
        cls.tree = key.Tree()
        cls.legs = plan.compute(cls.reg, cls.tree)

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def all_records(self):
        out = {}
        for l in self.legs:
            if l["decision"] == "RUN":
                keep = [k.replace("{target}", self.reg["platforms"][l["platform"]]["target"])
                        for k in self.reg["checks"].get(l["check"], {}).get("keep", [])]
                out[l["key"]] = keep
        return out

    def make(self, event, st):
        return plan.make_plan({"GITHUB_EVENT_NAME": event}, self.reg, self.tree, st, self.tmp)

    def test_applicability_follows_the_tree(self):
        by = {(l["check"], l["platform"]): l["decision"] for l in self.legs}
        self.assertEqual(by[("differential", "macos-aarch64")], "RUN")
        self.assertEqual(by[("test-acvp", "linux-aarch64")], "RUN")
        self.assertEqual(by[("generated", "linux-x86_64")], "NOT APPLICABLE")
        self.assertEqual(by[("safety", "linux-x86_64")], "NOT RUN")
        self.assertEqual(by[("test-core", "macos-aarch64")], "RUN")
        self.assertEqual(by[("agree", "any")], "RUN")

    def test_docs_pull_request_starts_no_platform_job(self):
        p = self.make("pull_request", FakeStore(self.all_records()))
        j = p["jobs"]
        self.assertEqual({k: v["run"] for k, v in j["native"].items()},
                         {k: False for k in self.reg["platforms"]})
        self.assertEqual((j["x86"], j["shards"], j["agree"]), ("none", [], False))
        self.assertTrue(all(l["decision"] != "RUN" for l in p["legs"]))
        outs = dict(o.split("=", 1) for o in plan.outputs(p))
        self.assertEqual(outs["native-macos-aarch64"], "false")
        self.assertEqual(outs["shards"], "[]")
        # The reused records are where the gates read them.
        reused = [l for l in p["legs"] if l["decision"] == "REUSED"]
        for l in reused:
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, "reused", l["key"], "record")))

    def test_record_that_is_not_a_pass_is_never_reused(self):
        p = self.make("pull_request", FakeStore(self.all_records(), status="NOT RUN"))
        self.assertFalse([l for l in p["legs"] if l["decision"] == "REUSED"])

    def test_one_check_missing_runs_only_its_platform(self):
        recs = self.all_records()
        miss = next(l for l in self.legs if l["check"] == "test-hash" and l["platform"] == "macos-aarch64")
        del recs[miss["key"]]
        p = self.make("pull_request", FakeStore(recs))
        j = p["jobs"]
        self.assertEqual({k: v["run"] for k, v in j["native"].items()},
                         {"linux-x86_64": False, "linux-aarch64": False, "macos-aarch64": True})
        self.assertEqual(j["native"]["macos-aarch64"]["need"], "compiler")
        self.assertEqual((j["x86"], j["shards"]), ("none", []))

    def test_a_shard_missing_runs_the_x86_toolchain_with_the_switch(self):
        recs = self.all_records()
        miss = next(l for l in self.legs if l["check"] == "proofs-spec")
        del recs[miss["key"]]
        p = self.make("pull_request", FakeStore(recs))
        self.assertEqual(p["jobs"]["shards"], ["spec"])
        self.assertEqual(p["jobs"]["x86"], "switch")
        self.assertIn('"need":"switch"', dict(o.split("=", 1) for o in plan.outputs(p))["shards"])

    def test_agree_runs_every_platform(self):
        recs = self.all_records()
        del recs[next(l for l in self.legs if l["check"] == "agree")["key"]]
        p = self.make("pull_request", FakeStore(recs))
        self.assertTrue(all(v["run"] and v["need"] == "compiler" for v in p["jobs"]["native"].values()))

    def test_main_reuses_nothing(self):
        for event in ("push", "schedule", "workflow_dispatch"):
            p = self.make(event, FakeStore(self.all_records()))
            self.assertFalse(p["reuse"])
            self.assertTrue(all(l["decision"] in ("RUN", "NOT APPLICABLE", "NOT RUN")
                                for l in p["legs"]))

    def test_lookup_error_runs_everything(self):
        class Broken:
            def find_records(self, wanted):
                import ghapi
                raise ghapi.ApiError("HTTP 500")
        p = self.make("pull_request", Broken())
        self.assertTrue(p["warnings"])
        self.assertTrue(all(l["decision"] != "REUSED" for l in p["legs"]))


class AllChecks(unittest.TestCase):
    """all-checks on a full run (a push to main) whose every job passed."""

    @classmethod
    def setUpClass(cls):
        cls.reg = registry.load()
        cls.tree = key.Tree()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.plan_dir = os.path.join(self.tmp, "plan")
        os.makedirs(self.plan_dir)
        self.results = os.path.join(self.tmp, "results")
        os.makedirs(self.results)
        self.plan = plan.make_plan({"GITHUB_EVENT_NAME": "push"}, self.reg, self.tree, None,
                                   self.plan_dir)
        self.write_plan()
        for l in self.plan["legs"]:
            if l["decision"] == "RUN":
                self.result(l)
        jobs = gate.workflow_jobs(os.path.join(registry.ROOT, ".github/workflows/ci.yml"))
        self.needs = {j: {"result": "success"} for j in jobs if j != "all-checks"}
        # Only warm mode runs it, and all-checks does not run then.
        self.needs["warm"] = {"result": "skipped"}

    def write_plan(self):
        with open(os.path.join(self.plan_dir, "plan.json"), "w") as f:
            json.dump(self.plan, f)

    def result(self, leg, status="PASS"):
        d = os.path.join(self.results, leg["key"])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "record"), "w") as f:
            f.write(record.render(status, leg["key"], leg["text"], ENV))

    def problems(self):
        return gate.cmd_all_checks(os.path.join(registry.ROOT, ".github/workflows/ci.yml"),
                                   self.needs, self.plan_dir, self.results, self.reg,
                                   self.tree)[0]

    def test_passes(self):
        self.assertEqual(self.problems(), [])

    def test_skipped_planned_job_fails(self):
        self.needs["native-macos-aarch64"] = {"result": "skipped"}
        self.assertTrue(any("native-macos-aarch64" in p for p in self.problems()))

    def test_cancelled_or_failed_job_fails(self):
        for r in ("cancelled", "failure"):
            self.needs["proofs"] = {"result": r}
            self.assertTrue(self.problems())

    def test_warm_job_in_a_gated_run_fails(self):
        self.needs["warm"] = {"result": "success"}
        self.assertTrue(any("warm" in p for p in self.problems()))

    def test_job_missing_from_needs_fails(self):
        del self.needs["agree"]
        self.assertTrue(any("not in the needs" in p for p in self.problems()))

    def test_unknown_job_in_needs_fails(self):
        self.needs["extra"] = {"result": "success"}
        self.assertTrue(self.problems())

    def test_unplanned_job_must_be_skipped(self):
        self.plan["jobs"]["agree"] = False
        self.write_plan()
        self.assertTrue(any("agree" in p for p in self.problems()))

    def test_leg_removed_from_the_plan_fails(self):
        self.plan["legs"] = [l for l in self.plan["legs"] if l["check"] != "analysis-hash"]
        self.write_plan()
        self.assertTrue(any("differ from this tree" in p for p in self.problems()))

    def test_leg_marked_not_applicable_fails(self):
        leg = next(l for l in self.plan["legs"] if l["check"] == "test-core")
        leg["decision"] = "NOT APPLICABLE"
        self.write_plan()
        self.assertTrue(self.problems())

    def test_ran_leg_without_record_fails(self):
        leg = next(l for l in self.plan["legs"] if l["check"] == "proofs-sphincs")
        shutil.rmtree(os.path.join(self.results, leg["key"]))
        self.assertTrue(any("left no valid record" in p for p in self.problems()))

    def test_ran_leg_with_record_of_other_inputs_fails(self):
        leg = copy.deepcopy(next(l for l in self.plan["legs"] if l["check"] == "test-hash"))
        d = os.path.join(self.results, leg["key"])
        with open(os.path.join(d, "record"), "w") as f:
            f.write(record.render("PASS", leg["key"], leg["text"].replace("inputs ", "inputs 0"),
                                  ENV))
        self.assertTrue(self.problems())

    def test_reused_record_must_match(self):
        leg = next(l for l in self.plan["legs"] if l["check"] == "test-hash")
        leg["decision"] = "REUSED"
        leg["record"] = {"run": 41, "url": "u", "commit": "c" * 40, "recorded": "t",
                         "image": "i", "status": "PASS", "event": "push refs/heads/main"}
        self.write_plan()
        d = os.path.join(self.plan_dir, "reused", leg["key"])
        os.makedirs(d)
        with open(os.path.join(d, "log"), "w") as f:
            f.write("log\n")
        with open(os.path.join(d, "record"), "w") as f:
            f.write(record.render("PASS", leg["key"], leg["text"], dict(ENV, GITHUB_RUN_ID="40")))
        self.assertTrue(any("reused record" in p for p in self.problems()))


class ProofsGate(unittest.TestCase):
    def setUp(self):
        self.reg = registry.load()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.plan_dir = os.path.join(self.tmp, "plan")
        os.makedirs(self.plan_dir)
        self.results = os.path.join(self.tmp, "results")
        os.makedirs(self.results)
        self.plan = plan.make_plan({"GITHUB_EVENT_NAME": "push"}, self.reg, key.Tree(), None,
                                   self.plan_dir)
        with open(os.path.join(self.plan_dir, "plan.json"), "w") as f:
            json.dump(self.plan, f)
        for l in self.plan["legs"]:
            if l["recipe"] == "proofs":
                d = os.path.join(self.results, l["key"])
                os.makedirs(d)
                with open(os.path.join(d, "record"), "w") as f:
                    f.write(record.render("PASS", l["key"], l["text"], ENV))
        self.listed = " ".join(c["shard"] for c in self.reg["checks"].values()
                               if c["recipe"] == "proofs")
        self.needs = {"plan": {"result": "success"}, "proof-shards": {"result": "success"}}

    def problems(self, listed=None):
        return gate.cmd_proofs(self.needs, self.plan_dir, self.results,
                               self.listed if listed is None else listed, self.reg)[0]

    def test_passes(self):
        self.assertEqual(self.problems(), [])

    def test_missing_shard_fails(self):
        leg = next(l for l in self.plan["legs"] if l.get("shard") == "x86_64")
        shutil.rmtree(os.path.join(self.results, leg["key"]))
        self.assertTrue(self.problems())

    def test_shard_lists_must_agree(self):
        self.assertTrue(self.problems(self.listed.replace("extraction", "")))
        self.assertTrue(self.problems(self.listed + " extra"))

    def test_skipped_shard_job_fails_when_planned(self):
        self.needs["proof-shards"] = {"result": "skipped"}
        self.assertTrue(self.problems())


if __name__ == "__main__":
    unittest.main()
