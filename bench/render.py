# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/render.py
# ===============
#
# Prints a record written by bench/run.py as Markdown tables for
# publication:
#
#   python3 -I bench/render.py <record.json>
#
#   1. a banner when the record is a smoke run or a trial, with the
#      trial's reasons
#   2. the conditions: CPU, OS, virtualisation, frequency, priority,
#      placement, timer, revision and working-tree digest, sampling
#   3. latency and R per workload: workload, this implementation's median
#      latency, baseline, baseline median latency, R, variability, CPU,
#      revision; the strongest baseline of each workload (lowest median
#      latency) is marked
#   4. throughput and its R, when the run measured it, or a line saying it
#      was not measured
#   5. the workloads not run, with the reason
#   6. diagnostic rows of this library's testing build, and the paired cost
#      of the fault check (signing with it over signing without it)
#   7. maximum stack depth per operation
#   8. code size of the library
#   9. the identity of every build: this library's target, library digest,
#      compilers, flags and Jasmin compiler pins; each baseline's pin,
#      build options, compiler, flags and program digest
#  10. the semantic differences of each implementation (the record's notes)
#
# Times are medians, printed to three significant figures. R is this
# implementation's latency over the baseline's (for throughput, the
# baseline's rate over this implementation's), so lower is better in both.
# Variability gives the 95% sign-test interval of the median per-round
# ratio (the verdict rule of bench/stats.py), the range of the per-round
# ratios, the number of rounds, and the median relative interquartile
# range of the samples within a round.
#
# The output carries no host name, user name or path. The record holds
# none by construction (bench/run.py checks it on the measuring host); as
# a second guard the renderer refuses to print any cell that contains an
# absolute path, or a description of the machine that contains this host's
# or user's name, and exits with status 1 instead.

import getpass
import json
import re
import socket
import sys

OP_NAMES = {"keygen": "keygen", "sign": "sign (hedged)", "sign-det": "sign (deterministic)",
            "verify": "verify", "sign-unchecked": "sign (hedged), no check",
            "sign-det-unchecked": "sign (deterministic), no check"}
SUBJECT = "nirapod"
TESTING = "nirapod-testing"


class Failure(Exception):
    pass


# An absolute path: a slash that does not follow a word character (so not
# the one in "SHA2-512/256"), then a directory name and another slash.
ABSOLUTE_PATH = re.compile(r"(?<![\w.])/[\w.-]+/")


def forbidden():
    """Words no cell may contain: run.py's path placeholders."""
    return ["<root>", "<baselines>"]


def host_words():
    """This host's and this user's names, which no cell describing the
    machine may contain. They are not applied to implementation and set
    names, which come from this repository and may share a word with an
    account name."""
    return forbidden() + [n for n in (socket.gethostname().split(".")[0], getpass.getuser())
                          if len(n) >= 3]


def guard(text, words):
    if ABSOLUTE_PATH.search(text) or any(w.lower() in text.lower() for w in words):
        raise Failure("refusing to print a cell naming a path, host or user")
    return text


def duration(ns):
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("µs", 1e3)):
        if ns >= scale:
            return f"{ns / scale:.3g} {unit}"
    return f"{ns:.3g} ns"


def table(head, rows, words):
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(guard(str(c), words) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def banner(rec):
    if rec["kind"] == "smoke":
        return ("**Smoke run: these numbers check that the harness works. They are not "
                "a measurement and support no performance claim.**")
    if rec["kind"] == "trial":
        return ("**Trial run, not a measurement: " + "; ".join(rec.get("trial_reasons", []))
                + ". These numbers support no performance claim.**")
    return None


def revision_text(rev):
    if rev.get("matches_commit", True):
        return rev["commit"][:12]
    return f"{rev['commit'][:12]} + uncommitted changes (tree {rev['tree_sha256'][:12]})"


def r_cell(r):
    return f"{r['R']:.3f}" + (" (inconclusive)" if r["verdict"] == "inconclusive" else "")


def variability(r):
    ci = (f"95% CI {r['R_low']:.3f}-{r['R_high']:.3f}" if r.get("R_low") is not None
          else "no 95% CI (too few rounds)")
    return f"{ci}; range {r['R_min']:.3f}-{r['R_max']:.3f} over {r['rounds']} rounds"


def strongest(rows, median):
    """(set, op[, threads]) -> the baseline with the best median of rows."""
    best = {}
    for key, b, value in rows:
        if key not in best or median(value, best[key][1]):
            best[key] = (b, value)
    return {k: b for k, (b, _) in best.items()}


def conditions(rec, words):
    env, cfg, ids, timer = rec["environment"], rec["config"], rec["implementations"], \
        rec.get("timer", {})
    rev = ids[SUBJECT]["revision"]
    overhead = timer.get("overhead_ns", {})
    if isinstance(overhead, dict):
        clock = (f"{timer.get('timer', 'unknown')}, read overhead median "
                 f"{overhead.get('median', '?')} ns (range {overhead.get('min', '?')}-"
                 f"{overhead.get('max', '?')}) over {timer.get('processes', '?')} processes, "
                 f"step {timer.get('step_ns', {}).get('max', '?')} ns or less")
    else:
        clock = f"{timer.get('timer', 'unknown')}, overhead {overhead} ns"
    rows = [
        ["CPU", env.get("cpu", "unknown")],
        ["OS", f"{env.get('os', '')}, kernel {env.get('kernel', '')}"],
        ["Virtualisation", env.get("virtualisation", "unknown")],
        ["Frequency", json.dumps(env["frequency"]) if isinstance(env.get("frequency"), dict)
         else env.get("frequency", "unknown")],
        ["Priority (nice)", env.get("niceness", "unknown")],
        ["Placement", env.get("placement", "unknown")],
        ["Timer", clock],
        ["Revision", revision_text(rev)],
        ["Sampling", f"{cfg['rounds']} rounds x {cfg['samples']} samples after {cfg['warmup']} "
                     f"warm-up, implementation order rotating per round"],
        ["Input", f"{cfg['mlen']}-byte message, empty context"],
        ["Library variant", ", ".join(f"{s}: {v}" for s, v in
                                      sorted(ids[SUBJECT].get("selected_variant", {}).items()))],
    ]
    if "tree_sha256" in rev:
        rows.insert(8, ["Working tree", f"SHA-256 {rev['tree_sha256']}"
                        + (" (matches the commit)" if rev["matches_commit"] else
                           f", {len(rev['changes'])} paths differ from the commit")])
    for key, label in (("machine", None), ("cpus", "Logical CPUs"),
                       ("perf_cores", "Performance cores"),
                       ("efficiency_cores", "Efficiency cores")):
        if label and env.get(key):
            rows.insert(1, [label, env[key]])
    return table(["Condition", "Value"], rows, words)


def latency(rec, words):
    summary = {(r["name"], r["set"], r["op"]): r for r in rec["summary"]}
    cpu, revision = rec["environment"].get("cpu", "unknown"), \
        revision_text(rec["implementations"][SUBJECT]["revision"])
    best = strongest([((r["set"], r["op"]), r["baseline"],
                       summary[(r["baseline"], r["set"], r["op"])]["median_ns"])
                      for r in rec["ratios"]], lambda a, b: a < b)
    rows = []
    for r in rec["ratios"]:
        ours = summary[(SUBJECT, r["set"], r["op"])]
        base = summary[(r["baseline"], r["set"], r["op"])]
        mark = " (strongest)" if best.get((r["set"], r["op"])) == r["baseline"] else ""
        rows.append([f"{r['set']} {OP_NAMES[r['op']]}", duration(ours["median_ns"]),
                     r["baseline"] + mark, duration(base["median_ns"]), r_cell(r),
                     f"{variability(r)}; within-round {100 * ours['within_round_iqr_rel']:.1f}% "
                     f"/ {100 * base['within_round_iqr_rel']:.1f}%", cpu, revision])
    legend = ("R = this implementation's median latency / the baseline's, lower is better. "
              "A comparison is resolved only when the 95% sign-test interval of the median "
              "per-round ratio excludes 1, with at least 6 rounds; otherwise it is marked "
              "inconclusive.")
    return legend + "\n\n" + table(
        ["Workload", "This implementation (median latency)", "Baseline",
         "Baseline (median latency)", "R", "Variability", "CPU", "Revision"], rows, words)


def not_run_rows(rows, width, where):
    """The rows of a not-run list, each of which must end in its reason.

    bench/run.py records the reason bench.c gave as the last field of each
    row. A record written before it did, under the same schema, has rows one
    field shorter; that is refused by name rather than failing to unpack.
    """
    for r in rows:
        if len(r) != width or not r[-1]:
            raise Failure(f"{where}: row {r} has no reason field; the record predates it, "
                          "so re-run bench/run.py")
    return rows


def throughput(rec, words):
    tp = rec.get("throughput") or {}
    if not tp.get("summary"):
        return "Throughput: not measured in this run (bench/run.py --threads)."
    rate = {(r["name"], r["set"], r["op"], r["threads"]): r["median_ops_per_s"]
            for r in tp["summary"]}
    best = strongest([((r["set"], r["op"], r["threads"]), r["baseline"],
                       rate[(r["baseline"], r["set"], r["op"], r["threads"])])
                      for r in tp["ratios"]], lambda a, b: a > b)
    rows = [[f"{r['set']} {OP_NAMES[r['op']]}", r["threads"],
             f"{rate[(SUBJECT, r['set'], r['op'], r['threads'])]:.4g}",
             r["baseline"] + (" (strongest)" if best.get((r["set"], r["op"], r["threads"]))
                              == r["baseline"] else ""),
             f"{rate[(r['baseline'], r['set'], r['op'], r['threads'])]:.4g}", r_cell(r),
             variability(r)] for r in tp["ratios"]]
    own = [[f"{r['set']} {OP_NAMES[r['op']]}", r["threads"], f"{r['median_ops_per_s']:.4g}",
            f"{r['min_ops_per_s']:.4g}-{r['max_ops_per_s']:.4g}", r["rounds"]]
           for r in tp["summary"] if r["name"] == SUBJECT]
    parts = [f"Throughput: operations per second over all threads, each thread on its own "
             f"buffers, {rec['config'].get('duration_s')} s per operation and round. R = the "
             f"baseline's rate / this implementation's, lower is better.",
             table(["Workload", "Threads", "This implementation (median ops/s)", "Baseline",
                    "Baseline (median ops/s)", "R", "Variability"], rows, words)
             if rows else "No baseline offered a throughput comparison.",
             table(["Workload", "Threads", "This implementation (median ops/s)", "Range",
                    "Rounds"], own, words)]
    if tp.get("not_run"):
        parts.append(table(["Implementation", "Set", "Operation", "Threads", "Status"],
                           [[n, s, OP_NAMES.get(o, o), t, f"NOT RUN ({why})"]
                            for n, s, o, t, why in not_run_rows(tp["not_run"], 5,
                                                                  "throughput.not_run")],
                           words))
    return "\n\n".join(parts)


def diagnostics(rec, words):
    parts = []
    diag = [[f"{r['set']} {OP_NAMES[r['op']]}", r["variant"], duration(r["median_ns"])]
            for r in rec["summary"] if r["name"] == TESTING]
    if diag:
        parts.append("Testing build (same code; diagnostic, not the delivered API):\n\n" +
                     table(["Workload", "Variant", "Median latency"], diag, words))
    cost = [[f"{r['set']} {OP_NAMES[r['op']]}", f"{r['R']:.3f}" +
             (" (inconclusive)" if r["verdict"] == "inconclusive" else ""), variability(r)]
            for r in rec.get("fault_check", [])]
    if cost:
        parts.append("Cost of the fault check: signing with it / signing without it, paired "
                     "within each process of the testing build:\n\n" +
                     table(["Workload", "Ratio", "Variability"], cost, words))
    return parts


def builds(rec, words):
    ids = rec["implementations"]
    own = ids[SUBJECT]
    rev = own["revision"]
    lib = table(["This library", "Value"], [
        ["Revision", rev["commit"]],
        ["Working tree", rev.get("tree_sha256", "not recorded")],
        ["Target", own["target"]],
        ["Library SHA-256", own["library_sha256"]],
        ["C compiler", own["library_cc"]],
        ["C flags", own["library_cflags"]],
        ["Jasmin commit", own["jasmin_commit"]],
        ["Jasmin patch series SHA-256", own["jasmin_series_sha256"]],
        ["jasminc SHA-256", own["jasminc_sha256"]],
    ], words)
    rows = []
    for name in sorted(ids):
        for p in ids[name].get("programs", []):
            pin = p.get("pin", {})
            pin_text = (f"{pin.get('kind')} {pin.get('identity')}" if pin
                        else "this tree" if name.startswith(SUBJECT) else "not recorded")
            compiler = p["harness_cc"] + (f"; upstream {p['upstream_cc']}"
                                          if p.get("upstream_cc") and p["upstream_cc"] !=
                                          p["harness_cc"] else "")
            flags = f"harness {p['harness_cflags']}" + (f"; upstream {p['upstream_cflags']}"
                                                       if p.get("upstream_cflags") else "")
            build = p.get("build", "its own Makefile" if p.get("upstream_cflags") else
                          "this tree's build" if name.startswith(SUBJECT) else "not recorded")
            sets = p["sets"][0] if len(p["sets"]) == 1 else f"{len(p['sets'])} sets"
            rows.append([name, sets, pin_text, build, compiler, flags, p["program_sha256"]])
    return [lib, table(["Program", "Sets", "Pin", "Build", "Compiler", "Flags",
                        "Program SHA-256"], rows, words)]


def render(rec):
    words, machine = forbidden(), host_words()
    env = rec["environment"]
    for key in ("cpu", "os", "kernel", "virtualisation", "frequency", "placement"):
        guard(json.dumps(env.get(key, "")), machine)
    guard(json.dumps(rec.get("timer", {})), machine)
    parts = [b for b in [banner(rec)] if b]
    parts.append(conditions(rec, words))
    parts.append(latency(rec, words))
    parts.append(throughput(rec, words))
    if rec["not_run"]:
        parts.append(table(["Implementation", "Set", "Operation", "Status"],
                           [[n, s, OP_NAMES.get(o, o), f"NOT RUN ({why})"]
                            for n, s, o, why in not_run_rows(rec["not_run"], 4, "not_run")],
                           words))
    parts += diagnostics(rec, words)
    if rec["stack"]:
        deepest = {}
        for r in rec["stack"]:
            key = (r["name"], r["op"])
            if key not in deepest or r["stack_bytes"] > deepest[key][0]:
                deepest[key] = (r["stack_bytes"], r["lower_bound"])
        parts.append(table(["Implementation", "Operation",
                            "Maximum stack touched (bytes, over sets)"],
                           [[n, OP_NAMES[o], f"{'>= ' if lb else ''}{b}"]
                            for (n, o), (b, lb) in sorted(deepest.items())], words))
    t = rec["code_size"]["total"]
    parts.append(table(["Library", "Code", "Read-only data", "Data", "Zero-filled"],
                       [[rec["code_size"]["library"], t["code"], t["rodata"], t["data"],
                         t["bss"]]], words))
    parts += builds(rec, words)
    parts.append("\n".join(f"- {guard(k, words)}: {guard(v, words)}"
                           for k, v in sorted(rec["notes"].items())))
    return "\n\n".join(parts) + "\n"


def main(argv):
    if len(argv) != 2:
        print("usage: render.py <record.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[1]) as f:
            rec = json.load(f)
        if rec.get("schema") != "nirapod-slhdsa-bench/1":
            raise Failure("not a bench/run.py record of schema 1")
        sys.stdout.write(render(rec))
    except (Failure, OSError, KeyError, ValueError) as e:
        print(f"render: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
