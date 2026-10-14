# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/lint.py
# ================
#
# Correctness checks of the repository's automation and metadata, run from
# the repository root:
#
#   - actionlint on the workflows under .github/workflows: syntax,
#     expressions, job dependencies, action inputs, and the shell scripts of
#     their run steps (through ShellCheck);
#   - zizmor on .github: security defects of workflows and of the
#     Dependabot configuration, such as template injection, unpinned
#     actions, credentials left in a checkout, dangerous triggers and
#     excessive permissions. Its default audits, offline; a finding is
#     either fixed or carries an ignore comment that says why it does not
#     apply;
#   - the rules of tools/ci/policy.py: no Actions cache, no secret, the
#     permissions each job may hold;
#   - ShellCheck on every tracked shell script (a *.sh file, or a file whose
#     first line names sh or bash), at severity "warning" and above: quoting
#     that splits or globs, unset variables, failing commands that are
#     ignored, and similar defects. The "info" and "style" levels are left
#     out; they are matters of taste, and this is not a style gate;
#   - a syntax check of every tracked Python script (*.py, or a python
#     first line).
#
# A further check, run on its own:
#
#   - REUSE lint: every file carries copyright and licence information, in
#     its header or in REUSE.toml, and every licence named has its text in
#     LICENSES/. It runs the reuse tool from the FSFE's container image,
#     pinned by the digest of its image index; the runtime pulls the image
#     by that digest and verifies the content against it.
#
# Usage: python3 -I tools/ci/lint.py [install DIR | reuse]
#
#   install DIR   download the pinned actionlint, ShellCheck and zizmor
#                 (Linux x86-64 release archives) into DIR/bin, after
#                 checking each archive against its SHA-256, and put
#                 DIR/bin on the PATH of the following workflow steps
#   reuse         REUSE lint in the pinned image (needs docker); the same
#                 check without docker is `reuse lint` with reuse 6.2.0
#   (no argument) the checks above, with the tools on PATH
#
# The versions in use are printed with the results. Any failure, a missing
# tool included, exits 1.

import ast
import hashlib
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

# name: (version, url, SHA-256 of the archive, member holding the binary)
TOOLS = {
    "actionlint": ("1.7.12",
                   "https://github.com/rhysd/actionlint/releases/download/v1.7.12/"
                   "actionlint_1.7.12_linux_amd64.tar.gz",
                   "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
                   "actionlint"),
    "shellcheck": ("0.11.0",
                   "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/"
                   "shellcheck-v0.11.0.linux.x86_64.tar.gz",
                   "b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6",
                   "shellcheck-v0.11.0/shellcheck"),
    "zizmor": ("1.30.1",
               "https://github.com/zizmorcore/zizmor/releases/download/v1.30.1/"
               "zizmor-x86_64-unknown-linux-gnu.tar.gz",
               "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a",
               "zizmor"),
}

# fsfe/reuse 6.2.0, OCI image index (linux/amd64 and linux/arm64).
REUSE_IMAGE = ("docker.io/fsfe/reuse@sha256:"
               "85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e")


class Failure(Exception):
    pass


def fetch(url, digest):
    with urllib.request.urlopen(url, timeout=120) as resp:
        data = resp.read()
    got = hashlib.sha256(data).hexdigest()
    if got != digest:
        raise Failure(f"{url}: SHA-256 {got}, expected {digest}")
    return data


def install(directory):
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise Failure("install: Linux x86-64 only")
    bindir = os.path.join(os.path.abspath(directory), "bin")
    os.makedirs(bindir, exist_ok=True)
    for name, (version, url, digest, member) in TOOLS.items():
        data = fetch(url, digest)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            info = tar.getmember(member)
            if not info.isfile():
                raise Failure(f"{url}: {member} is not a regular file")
            blob = tar.extractfile(info).read()
        dst = os.path.join(bindir, name)
        with open(dst, "wb") as f:
            f.write(blob)
        os.chmod(dst, 0o755)
        print(f"installed {name} {version}")
    if os.environ.get("GITHUB_PATH"):
        with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as f:
            f.write(bindir + "\n")
    return 0


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
    return [p.decode() for p in out.split(b"\0") if p]


def first_line(path):
    try:
        with open(path, "rb") as f:
            return f.readline().decode("utf-8", errors="replace").rstrip()
    except OSError:
        return ""


def is_shell(path):
    if path.endswith(".sh"):
        return True
    line = first_line(path)
    return line.startswith("#!") and (line.endswith("/sh") or line.endswith("/bash")
                                      or line.endswith("env bash") or line.endswith("env sh"))


def is_python(path):
    if path.endswith(".py"):
        return True
    line = first_line(path)
    return line.startswith("#!") and "python" in line


def tool(name):
    path = shutil.which(name)
    if not path:
        raise Failure(f"{name} is not on PATH")
    return path


def run(*cmd):
    r = subprocess.run(cmd)
    if r.returncode != 0:
        raise Failure(f"{os.path.basename(cmd[0])} failed (exit {r.returncode})")


def version(*cmd):
    out = subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()
    return out[0] if out else "?"


def checks():
    shellcheck, actionlint, zizmor = tool("shellcheck"), tool("actionlint"), tool("zizmor")
    sc_version = [l for l in subprocess.run([shellcheck, "--version"], capture_output=True,
                                            text=True).stdout.splitlines()
                  if l.startswith("version: ")]
    print(f"actionlint {version(actionlint, '-version')}, "
          f"shellcheck {sc_version[0][9:] if sc_version else '?'}, "
          f"{version(zizmor, '--version')}, Python {platform.python_version()}")
    run(actionlint, f"-shellcheck={shellcheck}", "-pyflakes=")
    print("actionlint: PASS")
    run(zizmor, "--offline", "--no-progress", "--config", ".github/zizmor.yml", ".github")
    print("zizmor: PASS")
    run(sys.executable, "-I", "tools/ci/policy.py")
    files = [f for f in tracked() if os.path.isfile(f)]
    shell = [f for f in files if is_shell(f)]
    if not shell:
        raise Failure("no shell scripts found")
    run(shellcheck, "-S", "warning", "-x", *shell)
    print(f"shellcheck: PASS ({len(shell)} files)")
    py = [f for f in files if is_python(f)]
    for f in py:
        with open(f, encoding="utf-8") as fh:
            try:
                ast.parse(fh.read(), f)
            except SyntaxError as e:
                raise Failure(f"{f}: {e}") from None
    print(f"python syntax: PASS ({len(py)} files)")
    return 0


# The container runs as the invoking user, so that git inside it, which
# reuse uses to list the files, accepts the ownership of the checkout.
def reuse():
    docker = tool("docker")
    base = [docker, "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
            "--volume", f"{os.getcwd()}:/data", "--workdir", "/data", REUSE_IMAGE]
    print(version(*base, "--version"))
    run(*base, "lint")
    return 0


def main(argv):
    try:
        if len(argv) == 1:
            return checks()
        if len(argv) == 3 and argv[1] == "install":
            return install(argv[2])
        if len(argv) == 2 and argv[1] == "reuse":
            return reuse()
    except (Failure, OSError, tarfile.TarError, KeyError, subprocess.CalledProcessError) as e:
        print(f"lint.py: {e}", file=sys.stderr)
        return 1
    print("usage: lint.py [install DIR | reuse]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
