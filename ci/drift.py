# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/drift.py
# ===========
#
# How far upstream Jasmin and EasyCrypt have moved from the pins under
# toolchain/ (.github/workflows/drift.yml). It prepares a scratch copy of
# toolchain/ with one pin moved to an upstream commit; the workflow then
# builds and tests that copy. Nothing here edits the repository's own
# toolchain/, and the scratch copy is a local repository that is never
# pushed.
#
# Usage, from the repository root:
#
#   drift.py setup
#       Check who started the run and what was asked for, from the
#       environment (EVENT, ACTOR, TRIGGERING_ACTOR, MAINTAINERS,
#       COMPONENT, JASMIN_REF, EASYCRYPT_REF, PLATFORMS, JASMIN_DROP), and
#       write to $GITHUB_OUTPUT which lanes run: jasmin=true|false,
#       easycrypt=true|false, jasmin-platforms, the JSON list of the
#       platforms the Jasmin lane builds on, and jasmin-drop, the patches
#       to leave out. A manual run by anyone but a
#       maintainer, an unknown component or platform set, or a ref in a
#       form `resolve` refuses, fails.
#   drift.py resolve COMPONENT REF DIR
#       COMPONENT is jasmin or easycrypt; REF a branch name, a commit (7 to
#       40 hexadecimal digits) or pull/<n>/head. Fetch the upstream
#       repository into DIR (blobless: file contents come when a checkout
#       needs them), check out the commit REF names, and print
#       commit=<full id> (also to $GITHUB_OUTPUT). An unknown or ambiguous
#       REF fails.
#   drift.py series UPSTREAM OUT [DROP...]
#       UPSTREAM is a checkout made by `resolve jasmin`. Try each patch of
#       toolchain/jasmin/SERIES, in order, on that commit, and classify it:
#
#         applies     it applies; it is kept, and the later patches are
#                     tried on top of it
#         upstream    it does not apply but its reverse does: upstream has
#                     it already; it is dropped
#         conflicts   neither: upstream changed the lines it touches. A
#                     patch that touches only the changelog (CHANGELOG.md,
#                     changes/) is dropped, marked "(changelog only)"; any
#                     other conflict means the series cannot be built on
#                     this commit
#         dropped     named in DROP (`patches/0001`, `patches-simd/0003`;
#                     an argument may hold several, separated by spaces):
#                     left out without being tried, to see whether the rest
#                     builds, for instance when upstream merged a patch in
#                     a changed form
#
#       Write the table to OUT/report.md and the job summary, then a scratch
#       copy of toolchain/ as OUT/tree/toolchain, in a git repository of
#       its own with one commit, in which JASMIN_COMMIT is the upstream
#       commit and SERIES lists the kept patches. With a conflict outside
#       the changelog, exit 1 after the report, without the copy.
#   drift.py easycrypt COMMIT OUT
#       The scratch copy with EASYCRYPT_COMMIT set to COMMIT, the Jasmin pin
#       and series unchanged.
#
# The copy is a repository with a commit so that toolchain/build.sh, which
# refuses uncommitted inputs, builds it as it builds the real toolchain/.
# Build it with WORK outside the copy.
#
# REF comes from the workflow's environment, never from its expression
# syntax inside a script, and is checked against the forms above before
# git sees it.

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# Commits made here have a fixed identity and are never signed or pushed.
IDENTITY = {"GIT_AUTHOR_NAME": "drift", "GIT_AUTHOR_EMAIL": "drift@invalid",
            "GIT_COMMITTER_NAME": "drift", "GIT_COMMITTER_EMAIL": "drift@invalid"}
GIT = ["git", "-c", "commit.gpgsign=false", "-c", "advice.detachedHead=false",
       "-c", "user.name=drift", "-c", "user.email=drift@invalid"]


class Failure(Exception):
    pass


def git(cwd, *args, check=True):
    r = subprocess.run(GIT + list(args), cwd=cwd, env=dict(os.environ, **IDENTITY),
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise Failure(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r


def output(line):
    print(line)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(line + "\n")


def summary(text):
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)


def entries(path):
    """Comment-free lines of an input file, as toolchain/build.sh reads them."""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].rstrip()
            if line:
                out.append(line)
    return out


def pin_value(path, var):
    values = [l.split("=", 1)[1] for l in entries(path) if l.startswith(var + "=")]
    if len(values) != 1:
        raise Failure(f"{path}: expected one {var}=..., found {len(values)}")
    return values[0]


def upstream_url(component, root=ROOT):
    if component == "jasmin":
        return pin_value(os.path.join(root, "toolchain", "jasmin", "PIN"), "JASMIN_URL")
    if component == "easycrypt":
        return pin_value(os.path.join(root, "toolchain", "easycrypt", "PIN"), "EASYCRYPT_URL")
    raise Failure(f"component must be jasmin or easycrypt, not '{component}'")


def platforms():
    """The platforms the Jasmin lane can build on, from the registry."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import registry
    reg = registry.load()
    return {name: {"platform": name, "runner": p["runner"], "options": p["toolchain-options"],
                   "jobs": p["jobs"]} for name, p in reg["platforms"].items()}


def cmd_setup(env):
    event = env.get("EVENT", "")
    maintainers = env.get("MAINTAINERS", "").split()
    if event == "workflow_dispatch":
        for who in (env.get("ACTOR", ""), env.get("TRIGGERING_ACTOR", "")):
            if who not in maintainers:
                raise Failure(f"a manual drift run is for maintainers ({', '.join(maintainers)}), "
                              f"not '{who}'")
        component = env.get("COMPONENT", "")
        platforms_wanted = env.get("PLATFORMS", "")
        refs = (env.get("JASMIN_REF", ""), env.get("EASYCRYPT_REF", ""))
        drop = env.get("JASMIN_DROP", "")
    elif event == "schedule":
        component, platforms_wanted, refs, drop = "both", "linux-x86_64", ("main", "main"), ""
    else:
        raise Failure(f"drift runs on a schedule or by hand, not on '{event}'")
    if component not in ("jasmin", "easycrypt", "both"):
        raise Failure(f"component must be jasmin, easycrypt or both, not '{component}'")
    known = platforms()
    if platforms_wanted == "all":
        chosen = list(known.values())
    elif platforms_wanted in known:
        chosen = [known[platforms_wanted]]
    else:
        raise Failure(f"platforms must be one platform or all, not '{platforms_wanted}'")
    jasmin, easycrypt = component in ("jasmin", "both"), component in ("easycrypt", "both")
    for name, ref, used in (("jasmin_ref", refs[0], jasmin), ("easycrypt_ref", refs[1], easycrypt)):
        if used and ref_kind(ref) is None:
            raise Failure(f"{name} '{ref}' is not a branch, a commit (7-40 hex) or pull/<n>/head")
    if not re.fullmatch(r"((patches|patches-simd)/[0-9]{4}( |$))*", drop):
        raise Failure(f"jasmin_drop '{drop}' is not a list of patches/NNNN or patches-simd/NNNN")
    output(f"jasmin={'true' if jasmin else 'false'}")
    output(f"jasmin-drop={drop}")
    output(f"easycrypt={'true' if easycrypt else 'false'}")
    output("jasmin-platforms=" + json.dumps(chosen, separators=(",", ":")))
    return 0


def ref_kind(ref):
    """commit, short, pull or branch; None for anything else, such as an
    option, a range or a revision expression."""
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return "commit"
    if re.fullmatch(r"[0-9a-f]{7,39}", ref):
        return "short"
    if re.fullmatch(r"pull/[1-9][0-9]{0,6}/head", ref):
        return "pull"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}", ref):
        return None
    if ".." in ref or "//" in ref or ref.endswith("/") or ref.endswith(".lock") \
            or "/." in ref or ref.startswith(("pull/", "refs/")):
        return None
    return "branch"


def cmd_resolve(component, ref, directory, root=ROOT):
    url = upstream_url(component, root)
    kind = ref_kind(ref)
    if kind is None:
        raise Failure(f"'{ref}' is not a branch, a commit (7-40 hex) or pull/<n>/head")
    if os.path.exists(directory):
        raise Failure(f"{directory} already exists")
    git(".", "init", "-q", directory)
    git(directory, "remote", "add", "origin", url)
    fetch = ["fetch", "-q", "--filter=blob:none", "origin"]
    if kind == "commit":
        git(directory, *fetch, ref)
        rev = "FETCH_HEAD"
    elif kind == "short":
        # An abbreviated id resolves only among fetched commits: every
        # branch, blobless.
        git(directory, *fetch, "+refs/heads/*:refs/remotes/origin/*")
        rev = ref
    elif kind == "pull":
        git(directory, *fetch, f"+refs/{ref}:refs/drift/target")
        rev = "refs/drift/target"
    else:
        git(directory, *fetch, f"+refs/heads/{ref}:refs/drift/target")
        rev = "refs/drift/target"
    r = git(directory, "rev-parse", "--verify", "-q", f"{rev}^{{commit}}", check=False)
    commit = r.stdout.strip()
    if r.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Failure(f"{component}: '{ref}' names no commit, or more than one")
    git(directory, "checkout", "-q", "--detach", commit)
    print(f"{component} {ref} is {commit} ({url})")
    output(f"commit={commit}")
    return 0


def patch_files(upstream, patch):
    r = git(upstream, "apply", "--numstat", patch, check=False)
    if r.returncode == 0:
        return [l.split("\t", 2)[2] for l in r.stdout.splitlines() if l.count("\t") >= 2]
    # git cannot read the patch against this tree: take the names from its
    # headers.
    with open(patch, encoding="utf-8", errors="replace") as f:
        return [l[6:].rstrip("\n") for l in f if l.startswith("+++ b/")]


def changelog_only(files):
    return bool(files) and all(f == "CHANGELOG.md" or f.startswith("changes/") for f in files)


def classify(upstream, patch):
    """applies, upstream, conflicts (changelog only) or conflicts; a patch
    that applies is applied with git am."""
    if git(upstream, "apply", "--check", patch, check=False).returncode == 0:
        git(upstream, "am", "-q", "--whitespace=nowarn", "--committer-date-is-author-date", patch)
        return "applies"
    if git(upstream, "apply", "--check", "-R", patch, check=False).returncode == 0:
        return "upstream"
    if changelog_only(patch_files(upstream, patch)):
        return "conflicts (changelog only)"
    return "conflicts"


def series(path):
    """(name, sha256) of each patch of a SERIES file, checked against its file."""
    out = []
    for line in entries(path):
        parts = line.split()
        if len(parts) != 2:
            raise Failure(f"{path}: malformed line '{line}'")
        name, digest = parts
        f = os.path.join(os.path.dirname(path), name)
        with open(f, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != digest:
                raise Failure(f"{name}: SHA-256 differs from SERIES")
        out.append((name, digest))
    return out


def copy_toolchain(out, root=ROOT):
    tree = os.path.join(out, "tree")
    if os.path.exists(tree):
        raise Failure(f"{tree} already exists")
    files = subprocess.run(["git", "ls-files", "-z", "--", "toolchain"], cwd=root,
                           check=True, capture_output=True).stdout.split(b"\0")
    for name in (f.decode() for f in files if f):
        dst = os.path.join(tree, name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(root, name), dst)
    git(".", "init", "-q", tree)
    return os.path.join(tree, "toolchain")


def commit_copy(out, message):
    tree = os.path.join(out, "tree")
    git(tree, "add", "-A")
    git(tree, "commit", "-q", "-m", message)
    head = git(tree, "rev-parse", "HEAD").stdout.strip()
    print(f"scratch toolchain: {tree}/toolchain ({head}, not pushed)")


def set_pin(path, var, value):
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    hits = [i for i, l in enumerate(lines) if l.startswith(var + "=")]
    if len(hits) != 1:
        raise Failure(f"{path}: expected one line {var}=..., found {len(hits)}")
    lines[hits[0]] = f"{var}={value}"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def cmd_series(upstream, out, root=ROOT, drop=()):
    base = git(upstream, "rev-parse", "--verify", "HEAD").stdout.strip()
    if git(upstream, "status", "--porcelain").stdout.strip():
        raise Failure(f"{upstream}: the checkout is not clean")
    os.makedirs(out, exist_ok=True)
    series_path = os.path.join(root, "toolchain", "jasmin", "SERIES")
    rows, kept, dropped, conflict = [], [], [], False
    for name, digest in series(series_path):
        if any(name.startswith(d + "-") for d in drop):
            status = "dropped"
        else:
            status = classify(upstream, os.path.join(root, "toolchain", "jasmin", name))
        rows.append((name, status))
        if status == "applies":
            kept.append((name, digest))
        elif status == "conflicts":
            conflict = True
        else:
            dropped.append(name)
    report = [f"### Jasmin drift: the patch series on upstream {base}", "",
              "| patch | on upstream |", "|---|---|"]
    report += [f"| {n} | {s} |" for n, s in rows]
    report += ["", f"Kept {len(kept)}, dropped {len(dropped)}."]
    if conflict:
        report += ["", "A patch conflicts outside the changelog: "
                       "the series cannot be built on this commit."]
    text = "\n".join(report) + "\n"
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write(text)
    print(text, end="")
    summary(text)
    if conflict:
        return 1
    t = copy_toolchain(out, root)
    set_pin(os.path.join(t, "jasmin", "PIN"), "JASMIN_COMMIT", base)
    for name in dropped:
        os.remove(os.path.join(t, "jasmin", name))
    with open(series_path, encoding="utf-8") as f:
        header = [l for l in f if l.split("#", 1)[0].strip() == ""]
    with open(os.path.join(t, "jasmin", "SERIES"), "w", encoding="utf-8") as f:
        f.writelines(header)
        f.writelines(f"{n} {d}\n" for n, d in kept)
    commit_copy(out, f"drift: series on Jasmin {base}")
    return 0


def cmd_easycrypt(commit, out, root=ROOT):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Failure(f"'{commit}' is not a full commit id")
    os.makedirs(out, exist_ok=True)
    t = copy_toolchain(out, root)
    set_pin(os.path.join(t, "easycrypt", "PIN"), "EASYCRYPT_COMMIT", commit)
    commit_copy(out, f"drift: EasyCrypt {commit}")
    text = (f"### EasyCrypt drift: upstream {commit}\n\n"
            "The toolchain is built with EasyCrypt at this commit and the pinned provers;\n"
            "the steps that follow check the Jasmin EasyCrypt library and the proofs.\n")
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write(text)
    summary(text)
    return 0


def main(argv):
    try:
        if len(argv) == 2 and argv[1] == "setup":
            return cmd_setup(os.environ)
        if len(argv) == 5 and argv[1] == "resolve":
            return cmd_resolve(argv[2], argv[3], argv[4])
        if len(argv) >= 4 and argv[1] == "series":
            return cmd_series(argv[2], argv[3], drop=[d for a in argv[4:] for d in a.split()])
        if len(argv) == 4 and argv[1] == "easycrypt":
            return cmd_easycrypt(argv[2], argv[3])
    except (Failure, OSError, subprocess.CalledProcessError) as e:
        print(f"drift.py: {e}", file=sys.stderr)
        return 1
    print("usage: drift.py setup | resolve COMPONENT REF DIR | series UPSTREAM OUT [DROP...] | easycrypt COMMIT OUT",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
