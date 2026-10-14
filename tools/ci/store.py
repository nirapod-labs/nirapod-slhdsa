# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/store.py
# =================
#
# The one place where a run takes results of other runs: the artifacts of
# runs of this repository's .github/workflows/ci.yml on main, as the API
# reports them. A run counts only if
#
#   - it was started by a push, the schedule or a manual dispatch, for the
#     branch main of this repository (not a fork), within DAYS days;
#   - its commit is on main (the compare API): a manual run of a tag that
#     happens to be called main runs that tag's workflow, which nobody
#     reviewed, and is turned down here;
#   - it is not the run asking (GITHUB_RUN_ID).
#
# Nothing else is trusted: no Actions cache, no artifact of a pull
# request's run (whatever it is named), no artifact of another workflow
# (drift-* included).
#
# What is taken from there:
#
#   records    artifacts records-<job>: one directory per check, named by
#              its key (tools/ci/record.py); a record counts only if its
#              status is PASS, its key text equals the one this run
#              computed, and it names the run it came from
#   bundles    artifacts tc-<part>-<platform>-<key>: the toolchain built
#              by a run on main (tools/ci/toolchain.py)
#
# A key is answered by the newest trusted run that planned to run it (its
# artifact `plan`): its PASS record if it left one, and otherwise nothing,
# even if an older run passed. A check that failed, was cancelled or has
# not finished in the newest run on main is therefore run again rather than
# reused from an earlier pass. Runs are visited newest first, at most RUNS.
#
# Every API error propagates (ghapi.ApiError). The callers turn it into
# "run the check" or "build the toolchain"; never into a pass. A damaged
# artifact is noted and skipped.

import datetime
import json
import os
import posixpath
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghapi  # noqa: E402
import record  # noqa: E402

WORKFLOW = "ci.yml"
WORKFLOW_PATH = ".github/workflows/ci.yml"
BRANCH = "main"
EVENTS = record.TRUSTED_EVENTS
RUNS = 30
DAYS = 90
DAMAGED = (record.RecordError, UnicodeDecodeError, KeyError, ValueError, zipfile.BadZipFile,
           zlib.error, EOFError, OSError)


def trusted(run, now):
    """A run of ci.yml on main of this repository, by a trusted event, recent."""
    try:
        created = datetime.datetime.strptime(run["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
        same_repo = run["head_repository"]["id"] == run["repository"]["id"]
    except (KeyError, TypeError, ValueError):
        return False
    return (run.get("event") in EVENTS and run.get("head_branch") == BRANCH
            and run.get("path") == WORKFLOW_PATH and same_repo
            and now - created <= datetime.timedelta(days=DAYS))


class Store:
    """EXCLUDE: a run id never used, by default the run this job is part
    of (GITHUB_RUN_ID), so that a run never takes its own results as
    another run's."""

    def __init__(self, api, now=None, exclude=None):
        self.api = api
        self.now = now or datetime.datetime.now(datetime.timezone.utc)
        self.exclude = exclude if exclude is not None else os.environ.get("GITHUB_RUN_ID", "")
        self._runs = None
        self._artifacts = {}
        self._on_main = {}

    def candidates(self):
        if self._runs is None:
            found = {}
            for event in EVENTS:
                for r in self.api.pages(f"actions/workflows/{WORKFLOW}/runs", "workflow_runs",
                                        limit=RUNS, branch=BRANCH, event=event):
                    if trusted(r, self.now) and str(r["id"]) != str(self.exclude):
                        found[r["id"]] = r
            self._runs = sorted(found.values(), key=lambda r: r["created_at"], reverse=True)[:RUNS]
        return self._runs

    def on_main(self, run):
        """The run's commit is main or one of its ancestors."""
        sha = run.get("head_sha")
        if not isinstance(sha, str) or len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
            return False
        if sha not in self._on_main:
            status = self.api.get(f"compare/{sha}...{BRANCH}").get("status")
            self._on_main[sha] = status in ("ahead", "identical")
        return self._on_main[sha]

    def runs(self):
        """The trusted runs, newest first, each checked to be on main when
        it is first visited."""
        for run in self.candidates():
            if self.on_main(run):
                yield run

    def artifacts(self, run):
        if run["id"] not in self._artifacts:
            arts = self.api.pages(f"actions/runs/{run['id']}/artifacts", "artifacts")
            self._artifacts[run["id"]] = [
                a for a in arts if not a.get("expired")
                and (a.get("workflow_run") or {}).get("id") == run["id"]]
        return self._artifacts[run["id"]]

    def find_artifact(self, name):
        """(run, artifact) of the newest trusted run with an artifact NAME,
        or None."""
        for run in self.runs():
            for a in self.artifacts(run):
                if a["name"] == name:
                    return run, a
        return None

    def planned(self, run, notes):
        """The keys the run's plan ran, or None without a readable plan."""
        arts = [a for a in self.artifacts(run) if a["name"] == "plan"]
        if len(arts) != 1:
            notes.append(f"run {run['id']}: no plan artifact; its records are not used")
            return None
        try:
            z = self.api.artifact_zip(arts[0]["id"])
            plan = json.loads(z.read("plan.json").decode("utf-8"))
            return {l["key"] for l in plan["legs"] if l["decision"] == "RUN"}
        except (ghapi.ApiError, TypeError, *DAMAGED) as e:
            notes.append(f"run {run['id']}: unreadable plan ({e}); its records are not used")
            return None

    def find_records(self, wanted):
        """WANTED maps key names to key texts. Returns ({name: (run, fields,
        log, kept files)}, notes): for each key, the PASS record of the
        newest trusted run that planned it, if that run left one; and why
        candidates were turned down."""
        found, closed, notes = {}, set(), []
        for run in self.runs():
            pending = set(wanted) - set(found) - closed
            if not pending:
                break
            planned = self.planned(run, notes)
            if planned is None:
                continue
            here = pending & planned
            if not here:
                continue
            for a in self.artifacts(run):
                if not a["name"].startswith("records-"):
                    continue
                try:
                    z = self.api.artifact_zip(a["id"])
                except ghapi.ApiError as e:
                    notes.append(f"{a['name']} of run {run['id']}: {e}")
                    continue
                for name, entry in read_records(z, here - set(found), notes, run["id"]):
                    rec, log, kept = entry
                    try:
                        record.validate(rec, name, wanted[name], run["id"])
                    except record.RecordError as e:
                        notes.append(f"{name} in run {run['id']}: {e}")
                        continue
                    found[name] = (run, rec, log, kept)
            for name in sorted(here - set(found)):
                closed.add(name)
                notes.append(f"{name}: run {run['id']} planned it and has no PASS record "
                             "(failed, cancelled or not finished); it is not reused")
        return found, notes


def read_records(z, names, notes, run_id):
    """The records of NAMES in the zip archive Z (an artifact records-*):
    yields (name, (fields, log, kept files)). Only the members a record
    needs are read; no member is written to disk."""
    try:
        members = set(z.namelist())
    except DAMAGED as e:
        notes.append(f"run {run_id}: unreadable records artifact ({e})")
        return
    for name in sorted(names):
        if f"{name}/record" not in members:
            continue
        try:
            raw = z.read(f"{name}/record").decode("utf-8")
            rec = record.parse(raw)
            rec["raw"] = raw
            if f"{name}/log" not in members:
                raise record.RecordError("no log")
            log = z.read(f"{name}/log").decode("utf-8", errors="replace")
            kept = {}
            for p in rec["files"]:
                member = posixpath.join(name, "files", p)
                if posixpath.normpath(member) != member or member not in members:
                    raise record.RecordError(f"{p}, named in the record, is not among its files")
                kept[p] = z.read(member)
        except DAMAGED as e:
            notes.append(f"{name} in run {run_id}: {e}")
            continue
        yield name, (rec, log, kept)


def write_record_dir(directory, rec_text, log, kept):
    """A record directory as record.read_dir reads it."""
    os.makedirs(os.path.join(directory, "files"), exist_ok=True)
    with open(os.path.join(directory, "record"), "w", encoding="utf-8") as f:
        f.write(rec_text)
    with open(os.path.join(directory, "log"), "w", encoding="utf-8") as f:
        f.write(log)
    for p, data in kept.items():
        full = os.path.join(directory, "files", p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)


def api_from_env():
    return ghapi.Api(os.environ.get("GITHUB_REPOSITORY", ""))
