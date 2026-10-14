# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/record.py
# ============
#
# The record of a check that finished: what a pull request reuses instead
# of running the check again (ci/plan.py). It is a text file whose
# first line is the check's status, so that a record of a check that did
# not run can never read as a pass:
#
#     status PASS | NOT APPLICABLE | NOT RUN
#     key v2-<check>-<platform>-<hex>
#     <the six lines of the key text, as ci/key.py writes them>
#     run <run URL> attempt <n>
#     commit <commit id>
#     event <event> <ref>
#     recorded <UTC time>
#     image <runner image name> <image version>
#     host <a line describing the host>          (zero or more)
#     build-key <the toolchain build key>        (zero or one)
#     count <a line of ci/counts.py>       (zero or more)
#     file <path of a kept file>                 (zero or more)
#
# FAIL and INCONCLUSIVE are never recorded. The record sits in a directory
# with the check's log and, under files/, the files it keeps; the directory
# is named by the key. Runs on main upload these directories as artifacts
# named records-<job>.
#
# What a reuse accepts (validate): status PASS; the key and every line of
# the key text equal to those the pull request computed; the run line
# naming the run the record was downloaded from; the event a push, a
# schedule or a manual run on main. The store has already checked, through
# the API, that the run is this repository's ci.yml on main
# (ci/store.py). Checks write PASS records only; NOT APPLICABLE and
# NOT RUN follow from the tree and are decided on every run
# (ci/plan.py). A record with any other status is never reused.

import datetime
import os
import re

STATUSES = ("PASS", "NOT APPLICABLE", "NOT RUN")
TRUSTED_EVENTS = ("push", "schedule", "workflow_dispatch")
MAIN_REF = "refs/heads/main"
KEY_FIELDS = ("format", "check", "platform", "runner", "toolchain", "inputs")
NAME = re.compile(r"v2-[a-z0-9_-]+-(linux-x86_64|linux-aarch64|macos-aarch64|any)-[0-9a-f]{64}")


class RecordError(Exception):
    pass


def render(status, name, key_text, env, host=(), build_key=None, counts=(), files=()):
    if status not in STATUSES:
        raise RecordError(f"status '{status}' is never recorded")
    if not NAME.fullmatch(name):
        raise RecordError(f"'{name}' is not a key")
    lines = [f"status {status}", f"key {name}"] + key_text.rstrip("\n").split("\n")
    # Outside a workflow (a workstation run) the run is "local", run 0,
    # event "local": never one a reuse accepts.
    server = env.get("GITHUB_SERVER_URL") or "local"
    lines += [
        f"run {server}/{env.get('GITHUB_REPOSITORY') or 'local'}/actions/runs/"
        f"{env.get('GITHUB_RUN_ID') or 0} attempt {env.get('GITHUB_RUN_ATTEMPT') or 0}",
        f"commit {env.get('GITHUB_SHA') or 'local'}",
        f"event {env.get('GITHUB_EVENT_NAME') or 'local'} {env.get('GITHUB_REF') or 'local'}",
        "recorded " + datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        f"image {env.get('ImageOS', '-')} {env.get('ImageVersion', '-')}",
    ]
    lines += [f"host {h}" for h in host]
    if build_key:
        lines.append(f"build-key {build_key}")
    lines += [f"count {c}" for c in counts]
    for f in files:
        if f.startswith("/") or ".." in f.split("/") or "\n" in f:
            raise RecordError(f"'{f}' is not a path inside the tree")
        lines.append(f"file {f}")
    for l in lines:
        if "\n" in l or "\r" in l:
            raise RecordError("a record line holds a line break")
    text = "\n".join(lines) + "\n"
    parse(text)
    return text


def parse(text):
    """The fields of a record; RecordError unless it has exactly the shape
    above."""
    lines = text.split("\n")
    if lines[-1] != "":
        raise RecordError("the record does not end with a line break")
    lines = lines[:-1]
    if len(lines) < 13:
        raise RecordError("the record is too short")
    if not lines[0].startswith("status ") or lines[0][7:] not in STATUSES:
        raise RecordError(f"line 1 is not a status: '{lines[0][:60]}'")
    rec = {"status": lines[0][7:]}
    if not lines[1].startswith("key ") or not NAME.fullmatch(lines[1][4:]):
        raise RecordError("line 2 is not a key")
    rec["key"] = lines[1][4:]
    text_lines = lines[2:8]
    if [l.split(" ", 1)[0] for l in text_lines] != list(KEY_FIELDS):
        raise RecordError("lines 3 to 8 are not a key text")
    rec["key_text"] = "\n".join(text_lines) + "\n"
    m = re.fullmatch(r"run (\S+)/actions/runs/([0-9]+) attempt ([0-9]+)", lines[8])
    if not m:
        raise RecordError("line 9 is not a run")
    rec["run_url"], rec["run_id"], rec["attempt"] = lines[8][4:], int(m.group(2)), int(m.group(3))
    fixed = (("commit", 9), ("event", 10), ("recorded", 11), ("image", 12))
    for field, i in fixed:
        if not lines[i].startswith(field + " "):
            raise RecordError(f"line {i + 1} is not '{field}'")
        rec[field] = lines[i][len(field) + 1:]
    ev = rec["event"].split(" ")
    if len(ev) != 2:
        raise RecordError("the event line is not '<event> <ref>'")
    rec["event_name"], rec["ref"] = ev
    rec.update(host=[], build_key=None, counts=[], files=[])
    order = {"host": 0, "build-key": 1, "count": 2, "file": 3}
    last = -1
    for l in lines[13:]:
        field, _, value = l.partition(" ")
        if field not in order or order[field] < last or (field == "build-key" and rec["build_key"]):
            raise RecordError(f"unexpected line '{l[:60]}'")
        last = order[field]
        if field == "host":
            rec["host"].append(value)
        elif field == "build-key":
            rec["build_key"] = value
        elif field == "count":
            rec["counts"].append(value)
        else:
            if value.startswith("/") or ".." in value.split("/") or not value:
                raise RecordError(f"'{value}' is not a path inside the tree")
            rec["files"].append(value)
    return rec


def validate(rec, name, key_text, run_id):
    """RecordError unless REC can stand for a run of the check keyed NAME."""
    if rec["status"] != "PASS":
        raise RecordError(f"the record says {rec['status']}, and only a PASS is reused")
    if rec["key"] != name:
        raise RecordError(f"the record is for {rec['key']}, not {name}")
    if rec["key_text"] != key_text:
        raise RecordError("the key text of the record differs from this run's")
    if rec["run_id"] != run_id:
        raise RecordError(f"the record names run {rec['run_id']}, not run {run_id}")
    if rec["event_name"] not in TRUSTED_EVENTS or rec["ref"] != MAIN_REF:
        raise RecordError(f"the record was made on '{rec['event']}', not by a run on main")


def read_dir(directory):
    """(record fields, log text, {kept path: bytes}) of a record directory."""
    with open(os.path.join(directory, "record"), encoding="utf-8") as f:
        rec = parse(f.read())
    with open(os.path.join(directory, "log"), encoding="utf-8", errors="replace") as f:
        log = f.read()
    kept = {}
    for p in rec["files"]:
        full = os.path.join(directory, "files", p)
        if os.path.islink(full) or not os.path.isfile(full):
            raise RecordError(f"{p}, named in the record, is not among its files")
        with open(full, "rb") as f:
            kept[p] = f.read()
    return rec, log, kept
