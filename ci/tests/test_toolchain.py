# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_toolchain.py
# ==========================
#
# ci/toolchain.py: what changes the build keys, the check of packed
# binaries against their build record, the comparison of two build
# records, the agreement of the platforms, the weekly cold comparison
# against a stored bundle, and, with a stand-in API, the daily warm run
# and the report of how a host identity differs from main's.

import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
import zipfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import fakeapi  # noqa: E402
import key  # noqa: E402
import plan  # noqa: E402
import registry  # noqa: E402
import toolchain  # noqa: E402

PROVENANCE = """date: 2026-10-12T00:00:00Z
platform: Linux-x86_64 (Linux 6.8)
project commit: 1111
jasmin pin: e8f5 (https://github.com/jasmin-lang/jasmin.git)
jasmin HEAD: aaaa
jasmin tree: bbbb
commits on the pin:
  c1 one
  c2 two
series (jasmin/SERIES):
  patches/0001.patch 1234
proof build: from scratch
C compiler: cc 13
"""


def record(**changes):
    rec = {"provenance.txt": PROVENANCE, "assumptions.log": "Axioms:\nfoo : bar\n",
           "admit-scan.log": "proofs/x.v:1: Admitted.\n", "cil.sha256": "aa  ./a.ml\n",
           "binaries.sha256": "11  jasminc\n", "switch.txt": "switch\n",
           "test-suites.txt": "tests/a.output\n"}
    rec.update(changes)
    return rec


def archive(rec):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in rec.items():
            data = text.encode()
            info = tarfile.TarInfo(f"toolchain/work/logs/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Records(unittest.TestCase):
    def test_source_identity_ignores_dates_and_hosts(self):
        a = toolchain.source_identity(PROVENANCE)
        b = toolchain.source_identity(PROVENANCE.replace("2026-10-12", "2026-10-19")
                                      .replace("cc 13", "cc 14").replace("Linux 6.8", "Linux 6.9"))
        self.assertEqual(a, b)
        self.assertNotEqual(a, toolchain.source_identity(PROVENANCE.replace("  c2 two", "  c3")))
        with self.assertRaises(toolchain.Failure):
            toolchain.source_identity("date: x\n")

    def test_compare(self):
        a = toolchain.read_record(archive(record()))
        self.assertTrue(toolchain.compare(a, a, toolchain.record_files(a, a))[1])
        for change in ({"cil.sha256": "ab  ./a.ml\n"}, {"binaries.sha256": "12  jasminc\n"},
                       {"provenance.txt": PROVENANCE.replace("jasmin tree: bbbb", "jasmin tree: c")}):
            b = toolchain.read_record(archive(record(**change)))
            self.assertFalse(toolchain.compare(a, b, toolchain.record_files(a, b))[1], change)
        # Binaries differ between hosts: left out of the host-independent set.
        b = toolchain.read_record(archive(record(**{"binaries.sha256": "12  jasminc\n"})))
        self.assertTrue(toolchain.compare(a, b, toolchain.record_files(a, b, host=False))[1])
        # An EasyCrypt record on one side only is a difference.
        b = toolchain.read_record(archive(record(**{"eclib-axioms.log": "x\n"})))
        self.assertFalse(toolchain.compare(a, b, toolchain.record_files(a, b))[1])

    def test_incomplete_record_is_refused(self):
        rec = record()
        del rec["assumptions.log"]
        with self.assertRaises(toolchain.Failure):
            toolchain.read_record(archive(rec))

    def test_agree(self):
        reg = registry.load()
        with tempfile.TemporaryDirectory() as d:
            dirs = []
            for i, rec in enumerate((record(), record(**{"binaries.sha256": "2  jasminc\n"}),
                                     record(**{"cil.sha256": "ff  ./a.ml\n"}))):
                p = os.path.join(d, str(i))
                os.makedirs(p)
                for name, text in rec.items():
                    with open(os.path.join(p, name), "w") as f:
                        f.write(text)
                dirs.append(p)
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(toolchain.Failure):
                    toolchain.cmd_agree(dirs, reg)
                with self.assertRaises(toolchain.Failure):
                    toolchain.cmd_agree(dirs[:2], reg)
                shutil.rmtree(dirs[2])
                shutil.copytree(dirs[1], dirs[2])
                self.assertEqual(toolchain.cmd_agree(dirs, reg), 0)


class Verify(unittest.TestCase):
    def test_binaries_against_the_record(self):
        with tempfile.TemporaryDirectory() as d:
            comp = os.path.join(d, "jasmin", "compiler")
            os.makedirs(comp)
            os.makedirs(os.path.join(d, "logs"))
            lines = []
            for b in toolchain.TOOLS:
                p = os.path.join(comp, b)
                with open(p, "w") as f:
                    f.write(f"#!/bin/sh\necho {b} 1.0\n")
                os.chmod(p, 0o755)
                lines.append(f"{toolchain.sha256_file(p)}  {b}\n")
            with open(os.path.join(d, "logs", "binaries.sha256"), "w") as f:
                f.writelines(lines)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(toolchain.cmd_verify("switch", d), 0)
            # Without the switch, jasmin-checksafety cannot start: it is
            # checked against the record but not run.
            p = os.path.join(comp, "jasmin-checksafety")
            with open(p, "w") as f:
                f.write("#!/bin/sh\nexit 1\n")
            lines[-1] = f"{toolchain.sha256_file(p)}  jasmin-checksafety\n"
            with open(os.path.join(d, "logs", "binaries.sha256"), "w") as f:
                f.writelines(lines)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(toolchain.cmd_verify("compiler", d), 0)
            with self.assertRaises(toolchain.Failure):
                toolchain.cmd_verify("switch", d)
            with open(os.path.join(comp, "jasmin2ec"), "a") as f:
                f.write("# changed\n")
            with self.assertRaises(toolchain.Failure):
                toolchain.cmd_verify("compiler", d)


class BuildKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for f, text in {"toolchain/build.sh": "b\n", "toolchain/jasmin/PIN": "p\n",
                        "toolchain/jasmin/SERIES": "s\n", "toolchain/easycrypt/PIN": "e\n",
                        "src/x.jinc": "x\n"}.items():
            p = os.path.join(self.tmp, f)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(text)
        self.git("init", "-q")
        self.commit()

    def git(self, *args):
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=t",
                        "-c", "user.email=t@invalid", *args], cwd=self.tmp, check=True,
                       capture_output=True)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "x", "--allow-empty")

    def keys(self, identity=("platform Linux-x86_64", "cc 13"), options=""):
        return toolchain.build_keys(key.Tree(cwd=self.tmp), options, list(identity))

    def change(self, path):
        with open(os.path.join(self.tmp, path), "a") as f:
            f.write("+\n")
        self.commit()

    def test_what_changes_which_key(self):
        s0, c0 = self.keys()
        s, c = self.keys(identity=("platform Linux-x86_64", "cc 14"))
        self.assertTrue(s != s0 and c != c0)
        s, c = self.keys(options="--no-easycrypt")
        self.assertTrue(s != s0 and c != c0)
        self.change("src/x.jinc")
        self.assertEqual(self.keys(), (s0, c0))
        self.change("toolchain/jasmin/SERIES")
        s1, c1 = self.keys()
        self.assertTrue(s1 == s0 and c1 != c0)
        self.change("toolchain/jasmin/PIN")
        s2, c2 = self.keys()
        self.assertTrue(s2 != s1 and c2 != c1)
        self.change("toolchain/easycrypt/PIN")
        s3, c3 = self.keys()
        self.assertTrue(s3 != s2 and c3 != c2)


class Prune(unittest.TestCase):
    def test_prune_list_is_the_one_in_the_key(self):
        # ci/toolchain.sh removes what toolchain.PRUNE says, which is
        # in the switch key; the two must name the same paths.
        import re
        with open(os.path.join(registry.ROOT, "ci/toolchain.sh")) as f:
            sh = f.read()
        root = re.search(r'^PRUNE_ROOT="([^"]*)"$', sh, re.M).group(1)
        switch = re.search(r'^PRUNE_SWITCH="([^"]*)"$', sh, re.M).group(1)
        self.assertEqual(toolchain.PRUNE, f"root: {root}; switch: {switch}")


class WithApi(unittest.TestCase):
    """A stand-in API, runs of ci.yml on main, and a stand-in host identity."""

    def setUp(self):
        self.api = fakeapi.Server()
        self.addCleanup(self.api.close)
        self.saved = {k: os.environ.get(k) for k in
                      ("GITHUB_API_URL", "GITHUB_REPOSITORY", "GH_TOKEN", "GITHUB_RUN_ID")}
        os.environ.update(GITHUB_API_URL=self.api.url, GITHUB_REPOSITORY="o/r", GH_TOKEN="t",
                          GITHUB_RUN_ID="999")
        self.addCleanup(self.restore)
        self.identity = toolchain.host_identity
        toolchain.host_identity = lambda: ["platform test"]
        self.addCleanup(setattr, toolchain, "host_identity", self.identity)
        self.reg = registry.load()
        self.tree = key.Tree()
        sw, comp = toolchain.build_keys(self.tree, "", ["platform test"])
        self.name = toolchain.names("linux-x86_64", sw, comp)[1]
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.cold = os.path.join(self.tmp, "cold.tar.gz")
        with open(self.cold, "wb") as f:
            f.write(archive(record()))
        self.runs = []
        self.api.routes["/repos/o/r/actions/workflows/ci.yml/runs"] = \
            lambda m, p, b: {"workflow_runs": [r for r in self.runs if f"event={r['event']}" in p]}

    def restore(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def run_with(self, rid, artifacts, event="push"):
        """A run RID of ci.yml on main with ARTIFACTS, [(name, {member: bytes})]."""
        sha = f"{rid:040x}"
        self.runs.append({"id": rid, "event": event, "head_branch": "main", "head_sha": sha,
                          "path": ".github/workflows/ci.yml", "created_at": "2026-10-13T00:00:00Z",
                          "repository": {"id": 1}, "head_repository": {"id": 1}})
        self.api.routes[f"/repos/o/r/compare/{sha}...main"] = {"status": "ahead"}
        listing = []
        for i, (name, members) in enumerate(artifacts):
            aid = rid * 10 + i
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for m, data in members.items():
                    z.writestr(m, data)
            listing.append({"id": aid, "name": name, "expired": False, "workflow_run": {"id": rid}})
            self.api.routes[f"/repos/o/r/actions/artifacts/{aid}/zip"] = buf.getvalue()
        self.api.routes[f"/repos/o/r/actions/runs/{rid}/artifacts"] = {"artifacts": listing}

    def bundle(self, rid, name, rec):
        self.run_with(rid, [(name, {"compiler.tar.gz": archive(rec)})])

    def outputs(self):
        """Collect $GITHUB_OUTPUT into a file; returns a reader of its lines."""
        out = tempfile.NamedTemporaryFile(delete=False)
        out.close()
        self.addCleanup(os.remove, out.name)
        os.environ["GITHUB_OUTPUT"] = out.name
        self.addCleanup(os.environ.pop, "GITHUB_OUTPUT", None)

        def read():
            with open(out.name) as f:
                return dict(l.rstrip("\n").split("=", 1) for l in f)
        return read


class ColdCompare(WithApi):
    def cold_compare(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = toolchain.cmd_cold_compare("linux-x86_64", self.cold, self.reg, self.tree)
        return rc, out.getvalue()

    def test_same_key(self):
        self.bundle(1, self.name, record())
        rc, out = self.cold_compare()
        self.assertEqual(rc, 0)
        self.assertIn("same key", out)

    def test_store_output(self):
        out = tempfile.NamedTemporaryFile(delete=False)
        out.close()
        self.addCleanup(os.remove, out.name)
        os.environ["GITHUB_OUTPUT"] = out.name
        self.addCleanup(os.environ.pop, "GITHUB_OUTPUT", None)
        self.bundle(1, self.name, record(**{"binaries.sha256": "99  jasminc\n"}))
        with self.assertRaises(toolchain.Failure):
            self.cold_compare()
        with open(out.name) as f:
            self.assertEqual(f.read(), "store=false\n")

    def test_same_key_different_binaries_fails(self):
        self.bundle(1, self.name, record(**{"binaries.sha256": "99  jasminc\n"}))
        with self.assertRaises(toolchain.Failure):
            self.cold_compare()

    def test_same_source_other_host(self):
        self.bundle(1, "tc-compiler-linux-x86_64-" + "0" * 64,
                    record(**{"binaries.sha256": "99  jasminc\n"}))
        rc, out = self.cold_compare()
        self.assertEqual(rc, 0)
        self.assertIn("NOT APPLICABLE: binaries.sha256", out)

    def test_same_source_other_extraction_fails(self):
        self.bundle(1, "tc-compiler-linux-x86_64-" + "0" * 64,
                    record(**{"cil.sha256": "ff  ./a.ml\n"}))
        with self.assertRaises(toolchain.Failure):
            self.cold_compare()

    def test_nothing_to_compare_is_inconclusive(self):
        self.bundle(1, "tc-compiler-linux-x86_64-" + "0" * 64,
                    record(**{"provenance.txt": PROVENANCE.replace("jasmin tree: bbbb", "jasmin tree: z")}))
        rc, out = self.cold_compare()
        self.assertEqual(rc, 1)
        self.assertIn("INCONCLUSIVE", out)

    def test_own_run_is_never_the_comparison(self):
        self.bundle(999, self.name, record())
        rc, out = self.cold_compare()
        self.assertEqual(rc, 1)


class IdentityChanges(unittest.TestCase):
    def test_fields_that_differ(self):
        old = ["platform Darwin-arm64", "cc Apple clang 21.0.0", "os macOS 26.6.2 25G83",
               "package gmp 6.3.0", "package mpfr 4.2.2", "package ppl 1.2_1"]
        new = ["platform Darwin-arm64", "cc Apple clang 21.0.1", "os macOS 26.6.2 25G83",
               "package gmp 6.3.1", "package mpfr 4.2.2", "package pcre2 10.48"]
        self.assertEqual(toolchain.identity_changes(old, new), [
            "cc: Apple clang 21.0.0 -> Apple clang 21.0.1",
            "package gmp: 6.3.0 -> 6.3.1",
            "package pcre2: (absent) -> 10.48",
            "package ppl: 1.2_1 -> (absent)"])
        self.assertEqual(toolchain.identity_changes(old, list(reversed(old))), [])


class Warm(WithApi):
    """toolchain.py warm and find on linux-x86_64, with the host check and the
    host identity stood in."""

    PLAT = "linux-x86_64"
    IDENTITY = ["platform test", "cc 13", "package libgmp-dev 6.3.0"]

    def setUp(self):
        super().setUp()
        toolchain.host_identity = lambda: list(self.IDENTITY)
        p = self.reg["platforms"][self.PLAT]
        saved = toolchain.host_platform
        toolchain.host_platform = types.SimpleNamespace(system=lambda: p["system"],
                                                        machine=lambda: p["machine"])
        self.addCleanup(setattr, toolchain, "host_platform", saved)
        sw, comp = toolchain.build_keys(self.tree, p["toolchain-options"], self.IDENTITY)
        self.sname, self.cname = toolchain.names(self.PLAT, sw, comp)
        self.read = self.outputs()

    def need(self, need):
        saved = toolchain.main_need
        toolchain.main_need = lambda reg, tree, plat: need
        self.addCleanup(setattr, toolchain, "main_need", saved)

    def warm(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = toolchain.cmd_warm(self.PLAT, self.reg, self.tree)
        return rc, self.read(), out.getvalue()

    def test_need_is_what_a_push_to_main_resolves(self):
        jobs = plan.make_plan({"GITHUB_EVENT_NAME": "push"}, self.reg, self.tree, None,
                              tempfile.mkdtemp(dir=self.tmp))["jobs"]
        self.assertEqual(toolchain.main_need(self.reg, self.tree, "linux-x86_64"), jobs["x86"])
        for p in ("linux-aarch64", "macos-aarch64"):
            want = jobs["native"][p]["need"] if jobs["native"][p]["run"] else "none"
            self.assertEqual(toolchain.main_need(self.reg, self.tree, p), want)

    def test_warm_legs_are_the_runners_of_the_registry(self):
        # The key does not name the runner, so a warm leg on another runner
        # than the platform's would store bundles no pull request asks for.
        import re
        with open(os.path.join(registry.ROOT, ".github/workflows/ci.yml")) as f:
            legs = re.findall(r"^\s+- \{platform: (\S+), runner: (\S+), jobs: \d+, "
                              r"native: (true|false)\}$", f.read(), re.M)
        self.assertEqual({p: r for p, r, _ in legs},
                         {p: v["runner"] for p, v in self.reg["platforms"].items()})
        # Only the linux-x86_64 toolchain job resolves without the test
        # dependencies installed first.
        self.assertEqual({p for p, _, n in legs if n == "false"}, {plan.X86})

    def test_modes_name_the_cron_lines(self):
        # A mode is chosen by comparing github.event.schedule with its cron
        # line: a retimed line that the conditions miss would run the cold
        # or warm schedule as a plain run of every check.
        import re
        with open(os.path.join(registry.ROOT, ".github/workflows/ci.yml")) as f:
            text = f.read()
        crons = re.findall(r'^    - cron: "([^"]+)"$', text, re.M)
        modes = re.findall(r"github\.event\.schedule == '([^']+)' \|\| inputs\.(\w+) == true",
                           text)
        self.assertEqual(len(crons), 2)
        self.assertEqual({c for c, _ in modes}, set(crons))
        self.assertEqual({m: {c for c, n in modes if n == m} for _, m in modes},
                         {"cold": {crons[0]}, "warm": {crons[1]}})

    def test_stored_bundles_stop_it(self):
        self.need("switch")
        self.run_with(1, [(self.sname, {}), (self.cname, {})])
        rc, out, log = self.warm()
        self.assertEqual((rc, out["build"], out["need"]), (0, "false", "switch"))
        self.assertIn("nothing to build", log)

    def test_missing_switch_is_built_only_when_needed(self):
        self.run_with(1, [(self.cname, {})])
        self.need("compiler")
        self.assertEqual(self.warm()[1]["build"], "false")
        self.need("switch")
        self.assertEqual(self.warm()[1]["build"], "true")

    def test_new_host_identity_is_built_and_named(self):
        self.need("compiler")
        old = ["platform test", "cc 12", "package libgmp-dev 6.3.0"]
        sw, comp = toolchain.build_keys(self.tree, "", old)
        self.run_with(1, [(toolchain.names(self.PLAT, sw, comp)[1], {}),
                          (toolchain.identity_name(self.PLAT, comp),
                           {toolchain.IDENTITY_FILE: "\n".join(old) + "\n"})])
        rc, out, log = self.warm()
        self.assertEqual((rc, out["build"]), (0, "true"))
        self.assertIn("differs from run 1's", log)
        self.assertIn("cc: 12 -> 13", log)

    def test_no_toolchain_needed(self):
        self.need("none")
        rc, out, log = self.warm()
        self.assertEqual((rc, out["build"], out["need"]), (0, "false", "none"))
        self.assertEqual(self.api.requests, [])

    def test_api_error_fails(self):
        self.need("compiler")
        del self.api.routes["/repos/o/r/actions/workflows/ci.yml/runs"]
        with redirect_stdout(io.StringIO()), self.assertRaises(toolchain.ghapi.ApiError):
            toolchain.cmd_warm(self.PLAT, self.reg, self.tree)

    def find(self, path=None):
        out = io.StringIO()
        with redirect_stdout(out):
            toolchain.cmd_find(self.PLAT, self.reg, self.tree, path)
        return self.read(), out.getvalue()

    def test_find_writes_the_identity_and_names_the_change(self):
        self.run_with(1, [(toolchain.identity_name(self.PLAT, "0" * 64),
                           {toolchain.IDENTITY_FILE: "platform test\ncc 13\n"
                                                     "package libgmp-dev 6.2.1\n"})])
        path = os.path.join(self.tmp, "identity.txt")
        out, log = self.find(path)
        self.assertEqual((out["compiler-run"], out["identity-artifact"]),
                         ("", toolchain.identity_name(self.PLAT, self.cname.rsplit("-", 1)[1])))
        self.assertIn("package libgmp-dev: 6.2.1 -> 6.3.0", log)
        with open(path) as f:
            self.assertEqual(f.read().splitlines(), self.IDENTITY)

    def test_find_same_identity_points_at_the_sources(self):
        self.run_with(1, [(toolchain.identity_name(self.PLAT, "0" * 64),
                           {toolchain.IDENTITY_FILE: "\n".join(self.IDENTITY) + "\n"})])
        self.assertIn("toolchain files or the build options differ", self.find()[1])

    def test_find_ignores_an_identity_from_a_pull_request(self):
        self.run_with(1, [(toolchain.identity_name(self.PLAT, "0" * 64),
                           {toolchain.IDENTITY_FILE: "cc 1\n"})], event="pull_request")
        self.assertIn("no run on main has recorded one", self.find()[1])

    def test_find_survives_a_damaged_identity(self):
        self.run_with(1, [(toolchain.identity_name(self.PLAT, "0" * 64), {"other": b"x"})])
        out, log = self.find()
        self.assertIn("could not be read", log)
        self.assertEqual(out["compiler-run"], "")


if __name__ == "__main__":
    unittest.main()
