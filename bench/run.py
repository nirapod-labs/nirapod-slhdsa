# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/run.py
# ============
#
# Measures this library and the baselines pinned in bench/baselines.lock on
# the same host, and writes one machine-readable record (JSON) with the
# observations, the statistics, R per workload and the identity of
# everything that ran. bench/render.py turns a record into the public
# table. docs/BENCHMARKS.md gives the method; this header gives the
# mechanics.
#
#   python3 -I bench/run.py [--baselines=DIR] --out=FILE [options]
#
# Steps:
#
#   1. Source state, before anything is built: the commit, and a digest of
#      the working tree (every tracked file and every untracked file git
#      does not ignore, by path, mode and SHA-256) next to the same digest
#      of the commit. When they differ, the changed paths are listed and
#      the record is a trial, not a measurement (--require-clean stops
#      instead).
#   2. Build. One benchmark program per implementation (bench/Makefile):
#      this library's public API, its testing build (for the variant
#      names and the diagnostic rows), and each baseline found under DIR.
#      sphincsplus selects its set at compile time, so it has one program
#      per variant and set. --no-build uses the programs already built.
#   3. Environment (bench/host.py). CPU, cores, memory, OS, kernel,
#      virtualisation, frequency policy, priority, load, compilers and
#      flags, and every revision: each baseline's pin and build options,
#      and the SHA-256 of the library and of every program. Nothing that
#      names the host, a user or a path is recorded: paths inside compiler
#      output and flags are replaced by <root> and <baselines>, and the
#      record is checked for this host's and user's names before it is
#      written.
#   4. Rounds. For each set, every implementation offering it runs once per
#      round, as its own process: warm-up calls, then --samples timed calls
#      of each operation (bench/bench.c). The order of implementations
#      rotates from round to round, so none always runs first or last.
#      Every process's timer line is kept.
#   5. Throughput, with --threads=LIST: the same rounds and rotation, each
#      process running T threads on distinct buffers for --duration
#      seconds per operation, for each T in LIST.
#   6. Stack. One painted call per operation, per implementation and set.
#   7. Code size of this library (bench/codesize.py).
#   8. Statistics (bench/stats.py): per implementation, set and operation,
#      the median of all samples and of each round, quartiles and the
#      spread within rounds; R per workload by paired median, judged by
#      the 95% sign-test interval of the median per-round ratio, with at
#      least stats.MIN_ROUNDS rounds; the same for throughput and for the
#      cost of this library's fault check.
#
# Kinds. --smoke is a short check that the harness works (two sets, two
# rounds, two samples); its record is a "smoke" record. Any other run is a
# "measurement" only when nothing in its conditions disqualifies it: the
# priority is not lowered, low-power mode is off, at least MIN_ROUNDS
# rounds ran, the tree matches its commit, the Jasmin compiler binary is
# identified, the programs are not older than their sources, and on Linux
# the processes are pinned (--cpu). Otherwise it is a "trial", with the
# reasons recorded; bench/render.py heads smoke and trial records as not
# being measurements.
#
# Status words: a workload that is not measured is NOT RUN, never a
# result, with the reason bench.c gave for it ("not offered", or "keeps
# state between calls" for a backend that cannot run on several threads).
# The record is written atomically (to FILE.partial, then renamed).

import argparse
import datetime
import getpass
import hashlib
import json
import os
import platform
import socket
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import codesize  # noqa: E402
import host  # noqa: E402
import revision as source  # noqa: E402
import stats  # noqa: E402

SCHEMA = "nirapod-slhdsa-bench/1"
SETS = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f"]
OPS = ["keygen", "sign", "sign-det", "verify"]
DIAG_OPS = ["sign-unchecked", "sign-det-unchecked"]
SMOKE_SETS = ["SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"]
SUBJECT = "nirapod"
TESTING = "nirapod-testing"

# The SPHINCS+ code's variants per architecture, and the family each serves.
SPX_VARIANTS = {
    "aarch64": [("ref", None), ("shake-a64", "SHAKE")],
    "x86_64": [("ref", None), ("sha2-avx2", "SHA2"), ("shake-avx2", "SHAKE")],
}

# Semantic differences from this library's workloads, recorded with every
# result and printed by the renderer. docs/BENCHMARKS.md explains them.
NOTES = {
    "nirapod": "public API; signing verifies the new signature before release "
               "(sign-unchecked rows isolate that cost); every call selects the hash "
               "variant from the CPU features; on AArch64 with FEAT_DIT, keygen and "
               "signing query FEAT_DIT and run with PSTATE.DIT set; keygen and signing "
               "clear their secret buffers and the registers they used",
    "openssl": "EVP interface; key and algorithm objects cached across calls; keygen "
               "includes creating its context by name and exporting both raw keys; hedged "
               "opt_rand passed in as test-entropy, not drawn from its DRBG; no DIT handling",
    "wolfssl": "wolfCrypt; key objects cached across calls; no DIT handling",
    "slhdsa-c": "direct calls into its public functions; no DIT handling",
    "sphincsplus": "FIPS 205 branch; one set per build; deterministic addrnd = PK.seed; "
                   "no DIT handling",
    "boringssl": "two sets only; hedged signing with its own randomness; no deterministic "
                 "signing; no DIT handling",
}


class Failure(Exception):
    pass


def say(msg):
    print(f"bench: {msg}", file=sys.stderr, flush=True)


def arch():
    m = platform.machine()
    if m in ("arm64", "aarch64"):
        return "aarch64"
    if m in ("x86_64", "amd64"):
        return "x86_64"
    raise Failure(f"unsupported machine {m}")


def out(cmd, cwd=None, check=True):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")
    except OSError as e:
        if check:
            raise Failure(f"{cmd[0]}: {e}") from None
        return ""
    if check and p.returncode != 0:
        raise Failure(f"{' '.join(cmd)} failed: {(p.stderr or p.stdout).strip()[-400:]}")
    return p.stdout.strip() if p.returncode == 0 else ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# Implementations ----------------------------------------------------------

def make_vars(impl):
    """The bench/Makefile variables of one implementation's program."""
    v = [f"IMPL={impl['impl']}"]
    if impl.get("baselines"):
        v.append(f"BASELINES={impl['baselines']}")
    for key in ("OPENSSL", "WOLFSSL", "SPX_VARIANT", "SPX_SET"):
        if key in impl:
            v.append(f"{key}={impl[key]}")
    return v


def make_print(impl, var):
    return out(["make", "-s", "--no-print-directory", "-C", HERE, *make_vars(impl),
                f"print-{var}"])


def implementations(baselines, sets):
    """Every program to build: dicts with a report name and make variables."""
    impls = [dict(name=SUBJECT, impl="nirapod", family="nirapod", sets=sets),
             dict(name="nirapod-testing", impl="nirapod-testing", family="nirapod",
                  sets=sets, diagnostic=True)]
    if not baselines:
        return impls

    def present(*parts):
        return os.path.isdir(os.path.join(baselines, *parts))

    for v in ("openssl-3.6.5", "openssl-4.0.3"):
        if present("out", v):
            impls.append(dict(name=v, impl="openssl", OPENSSL=v, family="openssl",
                              baselines=baselines, pin=v, sets=sets))
    if present("out", "wolfssl-5.9.4"):
        impls.append(dict(name="wolfssl-5.9.4", impl="wolfssl", WOLFSSL="wolfssl-5.9.4",
                          family="wolfssl", baselines=baselines, pin="wolfssl-5.9.4", sets=sets))
    if present("src", "slhdsa-c"):
        impls.append(dict(name="slhdsa-c", impl="slhdsa-c", family="slhdsa-c",
                          baselines=baselines, pin="slhdsa-c", sets=sets))
    if present("out", "boringssl"):
        two = [s for s in sets if s in ("SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f")]
        if two:
            impls.append(dict(name="boringssl", impl="boringssl", family="boringssl",
                              baselines=baselines, pin="boringssl", sets=two))
    if present("src", "sphincsplus"):
        for variant, family in SPX_VARIANTS[arch()]:
            for s in sets:
                if family and f"-{family}-" not in s:
                    continue
                impls.append(dict(name=f"sphincsplus-{variant}", impl="sphincsplus",
                                  SPX_VARIANT=variant, SPX_SET=s, family="sphincsplus",
                                  baselines=baselines, pin="sphincsplus", sets=[s]))
    return impls


def build(impls, skip):
    for impl in impls:
        impl["program"] = make_print(impl, "TARGET")
        if not skip:
            say(f"build {impl['name']} {' '.join(impl['sets']) if len(impl['sets']) == 1 else ''}")
            out(["make", "-s", "--no-print-directory", "-C", HERE, *make_vars(impl)])
        if not os.path.isfile(impl["program"]):
            raise Failure(f"{impl['name']}: program not built (run without --no-build)")
        impl["program_sha256"] = sha256(impl["program"])


# Environment and identity -------------------------------------------------

def scrub(text, baselines):
    """text with this tree's path and the baselines path replaced."""
    if baselines:
        text = text.replace(os.path.abspath(baselines), "<baselines>")
    return text.replace(ROOT, "<root>")


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def compiler(cc, baselines):
    first = out([cc, "--version"], check=False).splitlines()
    return scrub(first[0], baselines) if first else "unknown"


def lock_pins():
    pins = {}
    with open(os.path.join(HERE, "baselines.lock")) as f:
        for line in f:
            w = line.split()
            if w and w[0] in ("git", "archive"):
                pins[w[1]] = dict(kind=w[0], identity=w[-1])
    return pins


def identities(impls, baselines, revision):
    """Revision, build and compiler identity of every implementation."""
    pins = lock_pins()
    target = make_print(impls[0], "NIRAPOD_TARGET")
    lib = os.path.join(ROOT, "build", target, "lib", "libnirapod_slhdsa.a")
    cc = os.environ.get("CC", "cc")
    lib_flags = out(["make", "-s", "--no-print-directory", "-C", ROOT, "-f", "Makefile", "-f",
                     os.path.join(ROOT, "tests", "diff", "adapters", "print-var.mk"),
                     "print-CFLAGS"], check=False)
    # The compiler's identity: the pinned source and patch series it is built
    # from (toolchain/jasmin), and the binary's digest when JASMINC names it.
    pin = dict(line.split("=", 1) for line in read(os.path.join(ROOT, "toolchain", "jasmin",
                                                                "PIN")).splitlines()
               if "=" in line and not line.startswith("#"))
    jasminc = os.environ.get("JASMINC", "")
    ids = {SUBJECT: dict(revision=revision, target=target, library_sha256=sha256(lib),
                         library_cc=compiler(cc, baselines),
                         library_cflags=scrub(lib_flags, baselines),
                         jasmin_commit=pin.get("JASMIN_COMMIT", "unknown"),
                         jasmin_series_sha256=sha256(os.path.join(ROOT, "toolchain", "jasmin",
                                                                  "SERIES")),
                         jasminc_sha256=sha256(jasminc) if os.path.isfile(jasminc) else
                         "not recorded (JASMINC unset)")}
    for impl in impls:
        entry = dict(program_sha256=impl["program_sha256"],
                     harness_cc=compiler(make_print(impl, "CC"), baselines),
                     harness_cflags=scrub(make_print(impl, "HARNESS_CFLAGS"), baselines))
        if impl.get("pin"):
            entry["pin"] = pins.get(impl["pin"], {})
            stamp = read(os.path.join(baselines, "out", impl["pin"], ".nirapod-build"))
            if stamp:
                entry["build"] = scrub(stamp, baselines)
            if impl["impl"] in ("slhdsa-c", "sphincsplus"):
                entry["upstream_cc"] = compiler(make_print(impl, "UP_CC"), baselines)
                entry["upstream_cflags"] = scrub(make_print(impl, "UP_CFLAGS"), baselines)
        ids.setdefault(impl["name"], {}).setdefault("programs", []).append(
            dict(sets=impl["sets"], **entry))
    return ids


def stale_programs(impls):
    """Programs older than the harness sources or this library's archive."""
    inputs = [os.path.join(HERE, f) for f in os.listdir(HERE) if f.endswith((".c", ".h"))]
    inputs.append(os.path.join(HERE, "Makefile"))
    adapters = os.path.join(ROOT, "tests", "diff", "adapters")
    inputs += [os.path.join(adapters, f) for f in os.listdir(adapters)]
    newest = max(os.path.getmtime(p) for p in inputs if os.path.isfile(p))
    lib = os.path.join(ROOT, "build", make_print(impls[0], "NIRAPOD_TARGET"), "lib")
    newest_lib = max((os.path.getmtime(os.path.join(lib, f)) for f in os.listdir(lib)
                      if f.endswith(".a")), default=0) if os.path.isdir(lib) else 0
    return sorted({i["name"] for i in impls
                   if os.path.getmtime(i["program"]) < newest
                   or (i["family"] == "nirapod" and os.path.getmtime(i["program"]) < newest_lib)})


def timer_summary(timers):
    """The clock of every process: its name, overhead and step ranges, QoS."""
    if not timers:
        return {}
    def spread(key):
        v = [t[key] for t in timers]
        return dict(min=min(v), median=statistics.median(v), max=max(v))
    return dict(timer=timers[0]["timer"], processes=len(timers), overhead_ns=spread("overhead_ns"),
                step_ns=spread("step_ns"), qos=sorted({t.get("qos", "unknown") for t in timers}))


# Running ------------------------------------------------------------------

def run_program(impl, args, cpu):
    pre = None
    if cpu is not None:
        pre = lambda: os.sched_setaffinity(0, {cpu})  # noqa: E731
    p = subprocess.run([impl["program"], *args], capture_output=True, text=True,
                       preexec_fn=pre)
    if p.returncode != 0:
        raise Failure(f"{impl['name']} {' '.join(args)}: {p.stderr.strip()[-400:]}")
    return [json.loads(line) for line in p.stdout.splitlines() if line.strip()]


def variants(testing, cpu):
    return {r["set"]: r["variant"] for r in run_program(testing, ["--describe"], cpu)
            if "set" in r}


def rounds(impls, sets, cfg, each):
    """Calls each(impl, set, round, position) in rotating order per round."""
    for s in sets:
        group = [i for i in impls if s in i["sets"]]
        for r in range(cfg.rounds):
            k = r % len(group)
            for pos, impl in enumerate(group[k:] + group[:k]):
                each(impl, s, r, pos)
            say(f"{s}: round {r + 1}/{cfg.rounds}")


def measure(impls, sets, ops, cfg):
    """All latency rounds: list of observation dicts, plus the timer lines."""
    observations, timers = [], []

    def each(impl, s, r, pos):
        wanted = ops + (DIAG_OPS if impl.get("diagnostic") else [])
        args = [f"--set={s}", f"--ops={','.join(wanted)}", f"--warmup={cfg.warmup}",
                f"--samples={cfg.samples}", f"--mlen={cfg.mlen}"]
        for line in run_program(impl, args, cfg.cpu):
            if "timer" in line:
                timers.append(dict(impl=impl["name"], **line))
            elif "op" in line or line.get("status") == "unsupported":
                line.update(name=impl["name"], round=r, position=pos)
                observations.append(line)

    rounds(impls, sets, cfg, each)
    return observations, timers


def throughput(impls, sets, ops, cfg):
    """Throughput rounds for each thread count; processes are not pinned."""
    observations = []
    duration_ms = max(1, round(1000 * cfg.duration))

    def each(impl, s, r, pos):
        for t in cfg.threads:
            args = ["--throughput", f"--threads={t}", f"--duration-ms={duration_ms}",
                    f"--set={s}", f"--ops={','.join(ops)}", f"--warmup={cfg.warmup}",
                    f"--mlen={cfg.mlen}"]
            for line in run_program(impl, args, None):
                if "op" in line or line.get("status") == "unsupported":
                    line.update(name=impl["name"], round=r, position=pos, threads=t)
                    observations.append(line)

    rounds([i for i in impls if not i.get("diagnostic")], sets, cfg, each)
    return observations


def stack(impls, sets, ops, cpu):
    rows = []
    for s in sets:
        for impl in (i for i in impls if s in i["sets"]):
            wanted = ops + (DIAG_OPS if impl.get("diagnostic") else [])
            for line in run_program(impl, ["--stack", f"--set={s}", f"--ops={','.join(wanted)}"],
                                    cpu):
                if line.get("status") == "ok":
                    rows.append(dict(name=impl["name"], set=s, op=line["op"],
                                     stack_bytes=line["stack_bytes"],
                                     lower_bound=line["lower_bound"]))
    return rows


# The reasons bench.c gives for a row not run, its NOT_OFFERED and
# KEEPS_STATE. They are printed into a table cell as they are, so any other
# string is refused rather than recorded.
NOT_RUN_REASONS = ("not offered", "keeps state between calls")


def not_run(observations, *keys):
    """The rows not run, each once: (name, set, op, *keys, reason).

    The reason is the one bench.c printed for the row; a row without one, or
    with one bench.c does not print, is an error rather than a guess. A line
    that names no set or operation (a --variant the backend lacks) gets "*".
    """
    rows = set()
    for o in observations:
        if o.get("status") != "unsupported":
            continue
        where = f"{o['name']} {o.get('set', '*')} {o.get('op', '*')}"
        if not o.get("reason"):
            raise Failure(f"{where}: a row not run gives no reason")
        if o["reason"] not in NOT_RUN_REASONS:
            raise Failure(f"{where}: unknown reason {o['reason']!r} for a row not run "
                          f"(bench.c gives {' or '.join(map(repr, NOT_RUN_REASONS))})")
        rows.add((o["name"], o.get("set", "*"), o.get("op", "*"), *(o[k] for k in keys),
                  o["reason"]))
    return sorted(rows)


def disqualifiers(cfg, env, ids, stale):
    """Why a non-smoke run is a trial rather than a measurement."""
    why = []
    if env["niceness"] != 0:
        why.append(f"run at nice {env['niceness']}")
    if env.get("low_power_mode"):
        why.append("low-power mode on")
    if cfg.rounds < stats.MIN_ROUNDS:
        why.append(f"{cfg.rounds} rounds, fewer than {stats.MIN_ROUNDS}")
    rev = ids[SUBJECT]["revision"]
    if not rev["matches_commit"]:
        why.append(f"working tree differs from its commit ({len(rev['changes'])} paths)")
    if ids[SUBJECT]["jasminc_sha256"].startswith("not recorded"):
        why.append("Jasmin compiler binary not identified (JASMINC unset)")
    if stale:
        why.append(f"programs older than their sources: {', '.join(stale)}")
    if env["system"] == "Linux" and cfg.cpu is None:
        why.append("processes not pinned (--cpu)")
    return why


def private_words():
    """This host's and user's names, which no description of the machine
    or of the builds may contain."""
    return [n for n in (socket.gethostname().split(".")[0], getpass.getuser()) if len(n) >= 3]


def check_private(record):
    text = json.dumps(dict(environment=record["environment"], timer=record["timer"],
                           implementations=record["implementations"])).lower()
    hits = [w for w in private_words() if w.lower() in text]
    if hits or ROOT.lower() in text:
        raise Failure("the record would name this host, user or tree path; not written")


# Main ---------------------------------------------------------------------

def parse(argv):
    p = argparse.ArgumentParser(prog="run.py", description="Benchmark this library against "
                                "the pinned baselines (see the header of bench/run.py).")
    p.add_argument("--baselines", help="directory prepared by bench/baselines.py")
    p.add_argument("--out", required=True, help="record to write (JSON)")
    p.add_argument("--sets", default="all", help="comma-separated FIPS 205 set names, or all")
    p.add_argument("--impls", default="all",
                   help="comma-separated names to keep besides this library, or all")
    p.add_argument("--ops", default=",".join(OPS), help="subset of " + ",".join(OPS))
    p.add_argument("--rounds", type=int, default=9)
    p.add_argument("--samples", type=int, default=5, help="timed calls per operation and round")
    p.add_argument("--warmup", type=int, default=1, help="untimed calls before the samples")
    p.add_argument("--mlen", type=int, default=32, help="message length in bytes")
    p.add_argument("--cpu", type=int, help="Linux: pin each latency process to this CPU")
    p.add_argument("--threads", default="",
                   help="comma-separated thread counts for throughput (none by default)")
    p.add_argument("--duration", type=float, default=1.0,
                   help="seconds of calls per throughput operation and round")
    p.add_argument("--no-build", action="store_true", help="use the programs already built")
    p.add_argument("--no-stack", action="store_true", help="skip the stack probe")
    p.add_argument("--require-clean", action="store_true",
                   help="stop when the working tree differs from its commit")
    p.add_argument("--smoke", action="store_true",
                   help=f"harness check only: {','.join(SMOKE_SETS)}, 2 rounds, 2 samples")
    cfg = p.parse_args(argv)
    if cfg.smoke:
        cfg.rounds, cfg.samples, cfg.warmup = 2, 2, 1
        if cfg.sets == "all":
            cfg.sets = ",".join(SMOKE_SETS)
    cfg.sets = SETS if cfg.sets == "all" else cfg.sets.split(",")
    cfg.ops = cfg.ops.split(",")
    bad = [s for s in cfg.sets if s not in SETS] + [o for o in cfg.ops if o not in OPS]
    if bad:
        p.error(f"unknown set or operation: {' '.join(bad)}")
    if cfg.rounds < 1 or cfg.samples < 1 or cfg.warmup < 0:
        p.error("--rounds and --samples must be positive")
    try:
        cfg.threads = [int(t) for t in cfg.threads.split(",") if t]
    except ValueError:
        p.error("--threads takes comma-separated integers")
    if any(t < 1 or t > 256 for t in cfg.threads) or cfg.duration <= 0:
        p.error("--threads must be 1..256 and --duration positive")
    if cfg.cpu is not None and platform.system() != "Linux":
        p.error("--cpu is available on Linux only")
    return cfg


def placement(env, cfg, timer):
    if env["system"] == "Darwin":
        where = f"QoS user-interactive requested ({', '.join(timer.get('qos', []))}), no pinning"
    else:
        where = "not pinned" if cfg.cpu is None else f"pinned to CPU {cfg.cpu}"
    return where + ("; throughput threads not pinned" if cfg.threads else "")


def main(argv):
    cfg = parse(argv)
    try:
        revision = source.tree_state(ROOT)
        if cfg.require_clean and not revision["matches_commit"]:
            raise Failure(f"working tree differs from {revision['commit'][:12]}: "
                          + ", ".join(c["path"] for c in revision["changes"][:10]))
        impls = implementations(cfg.baselines and os.path.abspath(cfg.baselines), cfg.sets)
        if cfg.impls != "all":
            keep = set(cfg.impls.split(","))
            impls = [i for i in impls if i["family"] == "nirapod" or i["name"] in keep]
        build(impls, cfg.no_build)
        stale = stale_programs(impls) if cfg.no_build else []
        env = host.describe(arch(), cfg.cpu)
        ids = identities(impls, cfg.baselines, revision)
        ids[SUBJECT]["selected_variant"] = variants(impls[1], cfg.cpu)
        started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        observations, timers = measure(impls, cfg.sets, cfg.ops, cfg)
        tput = throughput(impls, cfg.sets, cfg.ops, cfg) if cfg.threads else []
        stacks = [] if cfg.no_stack else stack(impls, cfg.sets, cfg.ops, cfg.cpu)
        env["loadavg_end"] = os.getloadavg()
        timer = timer_summary(timers)
        env["placement"] = placement(env, cfg, timer)
        why = [] if cfg.smoke else disqualifiers(cfg, env, ids, stale)
        lib = os.path.join(ROOT, "build", ids[SUBJECT]["target"], "lib", "libnirapod_slhdsa.a")
        record = dict(
            schema=SCHEMA, kind="smoke" if cfg.smoke else ("trial" if why else "measurement"),
            trial_reasons=why, started=started,
            config=dict(sets=cfg.sets, ops=cfg.ops, rounds=cfg.rounds, samples=cfg.samples,
                        warmup=cfg.warmup, mlen=cfg.mlen, context_bytes=0, cpu=cfg.cpu,
                        order="rotating per round", threads=cfg.threads,
                        duration_s=cfg.duration if cfg.threads else None,
                        verdict=f"{int(100 * stats.LEVEL)}% sign-test interval of the median "
                                f"per-round ratio excludes 1; at least {stats.MIN_ROUNDS} rounds"),
            environment=env, timer=timer, timers=timers, implementations=ids,
            notes={k: v for k, v in NOTES.items() if any(i["family"] == k for i in impls)},
            observations=observations, summary=stats.summarise(observations),
            ratios=stats.ratios(observations, SUBJECT),
            fault_check=stats.fault_check_cost(observations, TESTING),
            throughput=dict(observations=tput, summary=stats.throughput_rows(tput),
                            ratios=stats.throughput_ratios(tput, SUBJECT),
                            not_run=not_run(tput, "threads")),
            not_run=not_run(observations), stack=stacks,
            code_size=dict(library="libnirapod_slhdsa.a", **codesize.library_size(lib)))
        check_private(record)
    except (Failure, codesize.Failure, source.Failure, OSError, ValueError) as e:
        say(str(e))
        return 1
    tmp = cfg.out + ".partial"
    os.makedirs(os.path.dirname(os.path.abspath(cfg.out)), exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(record, f, indent=1)
        f.write("\n")
    os.replace(tmp, cfg.out)
    say(f"wrote {cfg.out} ({record['kind']}, {len(observations)} observations)")
    for reason in why:
        say(f"trial: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
