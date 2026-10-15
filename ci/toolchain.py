# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/toolchain.py
# ===============
#
# The pinned toolchain in CI: its build keys, where a built one is found,
# and the checks on a built one. toolchain/build.sh builds it; the glue in
# ci/toolchain.sh installs packages, packs and unpacks it.
#
# Build keys. A built toolchain depends on its sources (every file under
# toolchain/) and on the host it was built on. Two keys per platform:
#
#   switch    the host identity, the options of toolchain/build.sh, what
#             `toolchain.sh prune` removes from a saved switch, and the
#             digests of every file under toolchain/ outside
#             toolchain/jasmin/, plus toolchain/jasmin/PIN
#   compiler  the switch key and the digests of every file under
#             toolchain/jasmin/ (pin, patch series, the expected
#             assumption and admit lists)
#
# The host identity is what the built binaries depend on: the operating
# system and its release, the machine, the C compiler, the C library, and
# the versions of the libraries the switch links (GMP, MPFR, PPL, PCRE2,
# zlib). Tools that only fetch or drive the build (git, curl, unzip, m4,
# pkg-config, bubblewrap) are left out, so that their updates in a runner
# image do not force a rebuild; opam is pinned by build.sh itself.
#
# Bundles. A run on main that built a toolchain uploads it as two
# artifacts, tc-switch-<platform>-<switch key> (the opam root, tar.zst)
# and tc-compiler-<platform>-<compiler key> (the binaries and the build
# record, tar.gz). Any run takes them only from runs of ci.yml on main
# (ci/store.py), and the binaries are checked against the build
# record of the same archive (`verify`). A pull request that changes the
# toolchain builds its own in the run, which no later run can take. Next
# to the compiler bundle, a run uploads tc-identity-<platform>-<compiler
# key>, the host identity it was built on: when a later run finds no
# bundle for its keys, it compares its own host identity with the newest
# one recorded on main and names the lines that differ.
#
# Warm runs. A runner image update changes the host identity, so the keys
# change and no bundle on main matches until a run on main builds one. The
# daily warm run of ci.yml on main (`warm`) resolves each platform's
# toolchain as a push to main would, and builds and stores only what is
# missing, so that pull requests find it.
#
# Usage, from the repository root:
#
#   toolchain.py keys PLATFORM
#       the host identity and both keys; to $GITHUB_OUTPUT switch-key=,
#       compiler-key=, switch-artifact=, compiler-artifact=,
#       identity-artifact=
#   toolchain.py find PLATFORM [IDENTITY]
#       the keys, then the newest runs on main with each bundle; to
#       $GITHUB_OUTPUT switch-run= and compiler-run= (empty when there is
#       none, or when the API cannot be read, which leads to a build), and
#       options=, the platform's options of toolchain/build.sh, which are in
#       the keys: the build uses the same value. With a bundle missing, the
#       lines of the host identity that differ from the newest one recorded
#       on main. Writes the host identity to the file IDENTITY, if given
#   toolchain.py warm PLATFORM
#       what a push to main would resolve on this platform (the toolchain
#       its checks need, from the registry and the tree), and whether runs
#       on main hold it for this host identity; to $GITHUB_OUTPUT need=
#       (none, compiler or switch) and build=true when a part is missing.
#       An API error fails, rather than building what may well be stored
#   toolchain.py verify compiler|switch
#       the binaries under toolchain/work are those the build record
#       (toolchain/work/logs/binaries.sha256) names, and jasminc, jasmin-ct
#       and jasmin2ec run; with the switch present, jasmin-checksafety runs
#       too (it loads the switch's abstract-domain libraries)
#   toolchain.py compare A B
#       two compiler archives of one platform describe the same compiler
#       (source identity, extracted OCaml, assumptions, admits, binaries,
#       test suites)
#   toolchain.py cold-compare PLATFORM ARCHIVE
#       ARCHIVE is a compiler built from scratch. Compare it with the
#       bundle of the same compiler key on main; without one, with the
#       newest bundle of the platform whose source identity is the same,
#       on what does not depend on the host (the binaries are then NOT
#       APPLICABLE); without either, INCONCLUSIVE, exit 1. Writes store=true
#       to $GITHUB_OUTPUT when the cold build may be stored (it passed, or
#       there was nothing to compare it with), store=false when it differs
#   toolchain.py agree DIR...
#       the build records (logs/ directories) of every platform: the same
#       extracted compiler from the same proofs and assumptions

import hashlib
import io
import json
import os
import platform as host_platform
import subprocess
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghapi  # noqa: E402
import key  # noqa: E402
import registry  # noqa: E402
import store  # noqa: E402

WORK = "toolchain/work"
TOOLS = ("jasminc", "jasmin-ct", "jasmin2ec", "jasmin-checksafety")
# What `toolchain.sh prune` removes before a switch is packed; a restored
# switch is never pruned again, so a change here must give a new switch key.
PRUNE = "root: download-cache; switch: .opam-switch/sources .opam-switch/build doc man"
LINUX_LIBS = ("libgmp-dev", "libmpfr-dev", "libppl-dev", "libpcre2-dev", "zlib1g-dev")
MACOS_LIBS = ("gmp", "mpfr", "ppl", "pcre2")
# Files of a build record; eclib-axioms.log only where EasyCrypt is built.
RECORD = ("provenance.txt", "assumptions.log", "admit-scan.log", "cil.sha256",
          "binaries.sha256", "switch.txt", "test-suites.txt")
RECORD_OPTIONAL = ("eclib-axioms.log",)
HOST_INDEPENDENT = ("cil.sha256", "assumptions.log", "admit-scan.log", "test-suites.txt")
CANDIDATES = 3
IDENTITY_FILE = "host-identity.txt"


class Failure(Exception):
    pass


def output(line):
    print(line)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(line + "\n")


def command(*cmd):
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise Failure(f"{' '.join(cmd)}: {e}") from None
    return out.strip().splitlines()[0] if out.strip() else ""


def host_identity():
    system, machine = host_platform.system(), host_platform.machine()
    lines = [f"platform {system}-{machine}", f"cc {command('cc', '--version')}"]
    if system == "Linux":
        with open("/etc/os-release", encoding="utf-8") as f:
            rel = dict(l.rstrip("\n").split("=", 1) for l in f if "=" in l)
        lines.append(f"os {rel.get('ID', '?').strip(chr(34))} {rel.get('VERSION_ID', '?').strip(chr(34))}")
        lines.append(f"libc {command('ldd', '--version')}")
        out = subprocess.run(["dpkg-query", "-W", "-f=${Package} ${Version}\\n", *LINUX_LIBS],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise Failure(f"dpkg-query: {out.stderr.strip()}")
        lines += sorted(f"package {l}" for l in out.stdout.splitlines())
    elif system == "Darwin":
        lines.append(f"os macOS {command('sw_vers', '-productVersion')} "
                     f"{command('sw_vers', '-buildVersion')}")
        out = subprocess.run(["brew", "list", "--versions", *MACOS_LIBS], capture_output=True,
                             text=True)
        if out.returncode != 0:
            raise Failure(f"brew list: {out.stderr.strip()}")
        lines += sorted(f"package {l}" for l in out.stdout.splitlines())
    else:
        raise Failure(f"unsupported host {system}")
    return lines


def build_keys(tree, options, identity):
    files = [p for p in tree.files if p.startswith("toolchain/")]
    switch_files = [p for p in files if not p.startswith("toolchain/jasmin/")]
    switch_files.append("toolchain/jasmin/PIN")
    compiler_files = [p for p in files if p.startswith("toolchain/jasmin/")]
    text = "\n".join(identity) + f"\noptions {options}\nprune {PRUNE}\n"
    switch = key.digest(tree, switch_files, b"") if switch_files else ""
    switch = hashlib.sha256((text + f"files {switch}\n").encode()).hexdigest()
    compiler = hashlib.sha256(f"switch {switch}\nfiles {key.digest(tree, compiler_files)}\n"
                              .encode()).hexdigest()
    return switch, compiler


def names(plat, switch, compiler):
    return f"tc-switch-{plat}-{switch}", f"tc-compiler-{plat}-{compiler}"


def identity_name(plat, compiler):
    return f"tc-identity-{plat}-{compiler}"


def identity_field(line):
    """The field a host identity line sets: its first word, and for a
    package also its name."""
    words = line.split()
    return " ".join(words[:2]) if words[:1] == ["package"] else (words[0] if words else "")


def identity_changes(stored, current):
    """The fields of two host identities (lists of lines) that differ, as
    lines of text; empty when they are the same."""
    def fields(lines):
        return {identity_field(l): l[len(identity_field(l)):].strip() for l in lines if l.strip()}
    a, b = fields(stored), fields(current)
    out = []
    for f in sorted(set(a) | set(b)):
        if f not in b:
            out.append(f"{f}: {a[f]} -> (absent)")
        elif f not in a:
            out.append(f"{f}: (absent) -> {b[f]}")
        elif a[f] != b[f]:
            out.append(f"{f}: {a[f]} -> {b[f]}")
    return out


def stored_identity(s, plat):
    """(run, lines) of the newest host identity recorded on main for PLAT,
    or None."""
    prefix = f"tc-identity-{plat}-"
    for run in s.runs():
        for a in s.artifacts(run):
            if a["name"].startswith(prefix):
                z = s.api.artifact_zip(a["id"])
                return run, z.read(IDENTITY_FILE).decode("utf-8").splitlines()
    return None


def explain_miss(s, plat, identity):
    """Print how this host identity differs from the newest one recorded on
    main. Diagnostic only: an error here is printed, never raised."""
    try:
        hit = stored_identity(s, plat)
    except (ghapi.ApiError, *store.DAMAGED) as e:
        print(f"host identity: the newest one on main could not be read ({e})")
        return
    if hit is None:
        print(f"host identity: no run on main has recorded one for {plat}")
        return
    run, stored = hit
    changes = identity_changes(stored, identity)
    if not changes:
        print(f"host identity: the same as run {run['id']}'s; the toolchain files or the "
              "build options differ")
        return
    print(f"host identity: differs from run {run['id']}'s ({run['created_at']}) in")
    for c in changes:
        print("  " + c)


def cmd_keys(plat, reg, tree):
    if plat not in reg["platforms"]:
        raise Failure(f"unknown platform {plat}")
    p = reg["platforms"][plat]
    if (host_platform.system(), host_platform.machine()) != (p["system"], p["machine"]):
        raise Failure(f"this host is not {plat}")
    identity = host_identity()
    switch, compiler = build_keys(tree, p["toolchain-options"], identity)
    sname, cname = names(plat, switch, compiler)
    print("host identity:")
    for l in identity:
        print("  " + l)
    output(f"switch-key={switch}")
    output(f"compiler-key={compiler}")
    output(f"switch-artifact={sname}")
    output(f"compiler-artifact={cname}")
    output(f"identity-artifact={identity_name(plat, compiler)}")
    return sname, cname, identity


def lookup(s, sname, cname):
    """{part: run id or ''} of the newest runs on main with each bundle."""
    runs = {"switch": "", "compiler": ""}
    for part, n in (("switch", sname), ("compiler", cname)):
        hit = s.find_artifact(n)
        if hit:
            runs[part] = str(hit[0]["id"])
            print(f"{part}: {n} in run {hit[0]['id']} ({hit[0]['event']}, {hit[0]['created_at']})")
        else:
            print(f"{part}: no run on main has {n}")
    return runs


def cmd_find(plat, reg, tree, identity_out=None):
    sname, cname, identity = cmd_keys(plat, reg, tree)
    if identity_out:
        with open(identity_out, "w", encoding="utf-8") as f:
            f.write("\n".join(identity) + "\n")
    try:
        s = store.Store(store.api_from_env())
        runs = lookup(s, sname, cname)
        if not runs["switch"] or not runs["compiler"]:
            explain_miss(s, plat, identity)
    except ghapi.ApiError as e:
        print(f"::warning::the toolchain bundles could not be looked up ({e}); they are built")
        runs = {"switch": "", "compiler": ""}
    output(f"switch-run={runs['switch']}")
    output(f"compiler-run={runs['compiler']}")
    output(f"options={reg['platforms'][plat]['toolchain-options']}")
    return 0


def main_need(reg, tree, plat):
    """The toolchain a push to main resolves on PLAT: the linux-x86_64
    toolchain job's (its checks and the proof shards), or the native job's."""
    import plan
    jobs = plan.jobs(reg, plan.compute(reg, tree))
    if plat == plan.X86:
        return jobs["x86"]
    native = jobs["native"][plat]
    return native["need"] if native["run"] else "none"


def cmd_warm(plat, reg, tree):
    need = main_need(reg, tree, plat)
    output(f"need={need}")
    if need == "none":
        print(f"warm: a run on main resolves no toolchain on {plat}")
        output("build=false")
        return 0
    sname, cname, identity = cmd_keys(plat, reg, tree)
    s = store.Store(store.api_from_env())
    runs = lookup(s, sname, cname)
    missing = [p for p in ("compiler", "switch")
               if not runs[p] and (p == "compiler" or need == "switch")]
    if not missing:
        print(f"warm: runs on main hold the {need} toolchain of this host identity; "
              "nothing to build")
        output("build=false")
        return 0
    explain_miss(s, plat, identity)
    print(f"warm: {' and '.join(missing)} missing on main; built and stored by this run")
    output("build=true")
    return 0


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def cmd_verify(need, work=WORK):
    if need not in ("compiler", "switch"):
        raise Failure(f"verify: need must be compiler or switch, not '{need}'")
    want = {}
    with open(os.path.join(work, "logs", "binaries.sha256"), encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                want[parts[1]] = parts[0]
    for b in TOOLS:
        path = os.path.join(work, "jasmin", "compiler", b)
        if b not in want:
            raise Failure(f"{b}: not in the build record")
        got = sha256_file(path)
        if got != want[b]:
            raise Failure(f"{b}: SHA-256 {got}, the build record says {want[b]}")
        if b == "jasmin-checksafety" and need != "switch":
            continue
        flag = "-version" if b == "jasminc" else "--version"
        if subprocess.run([path, flag], capture_output=True).returncode != 0:
            raise Failure(f"{b} does not run on this host")
    ran = [b for b in TOOLS if need == "switch" or b != "jasmin-checksafety"]
    print(f"verify: {', '.join(TOOLS)} are those of the build record; {', '.join(ran)} run")
    return 0


def source_identity(provenance):
    """The lines of provenance.txt that name the compiler source: pin, HEAD
    and tree of the patched Jasmin, the commits on the pin, the series."""
    out, block = [], False
    for line in provenance.splitlines():
        if line.startswith(("jasmin pin: ", "jasmin HEAD: ", "jasmin tree: ")):
            out.append(line)
            block = False
        elif line in ("commits on the pin:", "series (jasmin/SERIES):"):
            out.append(line)
            block = True
        elif line.startswith("  "):
            if block:
                out.append(line)
        else:
            block = False
    if not any(l.startswith("jasmin tree: ") for l in out):
        raise Failure("no patched-tree identity in the provenance record")
    return "\n".join(out) + "\n"


def read_record(source):
    """{file: text} of a build record: a logs/ directory, or a compiler
    archive (path or bytes) holding toolchain/work/logs/."""
    rec = {}
    if isinstance(source, str) and os.path.isdir(source):
        for f in RECORD + RECORD_OPTIONAL:
            p = os.path.join(source, f)
            if os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    rec[f] = fh.read()
    else:
        fileobj = io.BytesIO(source) if isinstance(source, bytes) else None
        with tarfile.open(name=None if fileobj else source, fileobj=fileobj, mode="r:gz") as tar:
            for f in RECORD + RECORD_OPTIONAL:
                try:
                    m = tar.getmember(f"{WORK}/logs/{f}")
                except KeyError:
                    continue
                if m.isfile():
                    rec[f] = tar.extractfile(m).read().decode("utf-8", errors="replace")
    missing = [f for f in RECORD if f not in rec]
    if missing:
        raise Failure(f"the build record lacks {', '.join(missing)}")
    return rec


def compare(a, b, files):
    """Lines of the comparison, and whether A and B agree on FILES and on
    the source identity."""
    lines, same = [], True
    pairs = [("compiler source (pin, series, patched tree)",
              source_identity(a["provenance.txt"]), source_identity(b["provenance.txt"]))]
    pairs += [(f, a.get(f), b.get(f)) for f in files]
    for what, x, y in pairs:
        if x == y:
            lines.append(f"  same: {what}")
        else:
            same = False
            lines.append(f"  DIFFERENT: {what}")
    return lines, same


def record_files(a, b, host=True):
    files = list(HOST_INDEPENDENT) + (["binaries.sha256"] if host else [])
    if "eclib-axioms.log" in a or "eclib-axioms.log" in b:
        files.append("eclib-axioms.log")
    return files


def cmd_compare(path_a, path_b):
    a, b = read_record(path_a), read_record(path_b)
    lines, same = compare(a, b, record_files(a, b))
    print("\n".join(lines))
    if not same:
        raise Failure("the two builds differ")
    return 0


def cmd_cold_compare(plat, archive, reg, tree):
    cold = read_record(archive)
    p = reg["platforms"][plat]
    switch, compiler = build_keys(tree, p["toolchain-options"], host_identity())
    sname, cname = names(plat, switch, compiler)
    s = store.Store(store.api_from_env())
    hit = s.find_artifact(cname)
    if hit:
        stored = read_record(bundle_archive(s.api, hit[1]))
        lines, same = compare(cold, stored, record_files(cold, stored))
        print(f"cold build against the bundle of the same key, run {hit[0]['id']}:")
        print("\n".join(lines))
        if not same:
            output("store=false")
            raise Failure("the cold build differs from the stored build of the same inputs")
        output("store=true")
        print("cold compare: PASS (same key)")
        return 0
    want = source_identity(cold["provenance.txt"])
    prefix = f"tc-compiler-{plat}-"
    seen = 0
    for run in s.runs():
        for a in s.artifacts(run):
            if not a["name"].startswith(prefix) or seen >= CANDIDATES:
                continue
            seen += 1
            stored = read_record(bundle_archive(s.api, a))
            if source_identity(stored["provenance.txt"]) != want:
                continue
            lines, same = compare(cold, stored, record_files(cold, stored, host=False))
            print(f"cold build against {a['name']} of run {run['id']}, the same toolchain "
                  "source on another host identity:")
            print("\n".join(lines))
            print("  NOT APPLICABLE: binaries.sha256 (another host identity)")
            if not same:
                output("store=false")
                raise Failure("the cold build differs from a stored build of the same source")
            output("store=true")
            print("cold compare: PASS (same source, host-independent parts)")
            return 0
    output("store=true")
    print("cold compare: INCONCLUSIVE, no stored build of this toolchain source to compare "
          "with; the cold build is stored for the next run")
    return 1


def bundle_archive(api, artifact):
    z = api.artifact_zip(artifact["id"])
    if "compiler.tar.gz" not in z.namelist():
        raise Failure(f"{artifact['name']}: no compiler.tar.gz")
    return z.read("compiler.tar.gz")


def cmd_agree(dirs, reg):
    n = len(reg["platforms"])
    if len(dirs) != n:
        raise Failure(f"expected the build records of {n} platforms, got {len(dirs)}")
    recs = [read_record(d) for d in dirs]
    same = True
    for d, r in zip(dirs[1:], recs[1:]):
        lines, ok = compare(recs[0], r, ("cil.sha256", "assumptions.log", "admit-scan.log"))
        print(f"{dirs[0]} against {d}:")
        print("\n".join(lines))
        same = same and ok
    if not same:
        raise Failure("the platforms built different compilers")
    print(f"agree: the same extracted compiler and assumptions on {n} platforms")
    return 0


def main(argv):
    try:
        if len(argv) == 3 and argv[1] in ("keys", "warm"):
            reg, tree = registry.load(), key.Tree()
            if argv[1] == "keys":
                cmd_keys(argv[2], reg, tree)
                return 0
            return cmd_warm(argv[2], reg, tree)
        if len(argv) in (3, 4) and argv[1] == "find":
            return cmd_find(argv[2], registry.load(), key.Tree(), argv[3] if len(argv) == 4 else None)
        if len(argv) == 3 and argv[1] == "verify":
            return cmd_verify(argv[2])
        if len(argv) == 4 and argv[1] == "compare":
            return cmd_compare(argv[2], argv[3])
        if len(argv) == 4 and argv[1] == "cold-compare":
            return cmd_cold_compare(argv[2], argv[3], registry.load(), key.Tree())
        if len(argv) >= 3 and argv[1] == "agree":
            return cmd_agree(argv[2:], registry.load())
    except (Failure, OSError, tarfile.TarError, ghapi.ApiError, key.KeyFailure,
            registry.RegistryError, json.JSONDecodeError) as e:
        print(f"toolchain.py: {e}", file=sys.stderr)
        return 1
    print("usage: toolchain.py keys|warm PLATFORM | find PLATFORM [IDENTITY] | "
          "verify compiler|switch | compare A B | "
          "cold-compare PLATFORM ARCHIVE | agree DIR...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
