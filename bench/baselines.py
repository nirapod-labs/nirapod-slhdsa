# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/baselines.py
# ==================
#
# Fetches, verifies and builds the independent SLH-DSA implementations
# pinned in bench/baselines.lock, for use as test oracles and benchmark
# baselines. None of them is compiled into the library.
#
#   python3 -I bench/baselines.py fetch  <workdir> [name...]
#       download and check every pin, or only the named ones
#   python3 -I bench/baselines.py build  <workdir> [name...]
#       build OpenSSL, wolfSSL and BoringSSL, or the named ones
#   python3 -I bench/baselines.py verify <workdir>
#       check the OpenPGP signatures and the upstream byte identity
#       recorded in the lock
#
# Layout under <workdir>:
#
#   src/<name>/   the checked source tree: a git checkout at the pinned
#                 commit, or the single top directory of the pinned archive
#   out/<name>/   OpenSSL, wolfSSL or BoringSSL install prefix (static)
#   log/          configure and build output
#
# slhdsa-c and sphincsplus need no build step here:
# tests/diff/adapters/adapters.mk compiles their sources with each
# project's own compiler flags.
#
# What a successful fetch establishes: every git tree is checked out at
# exactly the pinned commit with no tracked file modified and nothing else
# in it (untracked and ignored files are removed); every archive
# has exactly the pinned size and SHA-256, and its unpacked tree came from
# that archive (a stamp in the tree names the digest; a tree from another
# archive is removed, never reused). A file already present is checked
# again, never trusted. `verify` adds the provenance the digests alone do
# not give: OpenSSL's release signatures, and wolfSSL's SLH-DSA and hash
# sources byte-identical to its git tag.
#
# A build is reused only when its stamp names the same pinned source and
# the same configure options; otherwise the prefix is removed and the
# source unpacked again, so no build mixes two configurations.
#
# Any mismatch, failed download, failed command or missing tool ends the
# script with status 1 and a message naming the pin. Network access: the
# URLs in the lock, over HTTPS (git: the transport the URL names), and
# nothing else. Parallel build jobs: BASELINES_JOBS, default 2.

import hashlib
import http.client
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCK = os.path.join(ROOT, "bench", "baselines.lock")
STAMP_SOURCE = ".nirapod-source"
STAMP_BUILD = ".nirapod-build"
FIELDS = {"git": 3, "archive": 4, "openpgp": 4}


class Failure(Exception):
    pass


def say(msg):
    print(f"baselines: {msg}", flush=True)


def read_lock(path=LOCK):
    """The lock entries in file order: (kind, name, fields)."""
    entries = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            words = line.split()
            if not words or words[0].startswith("#"):
                continue
            kind, rest = words[0], words[1:]
            if kind == "sameas":
                ok = len(rest) >= 4
            else:
                ok = kind in FIELDS and len(rest) == FIELDS[kind]
            if not ok:
                raise Failure(f"{path}:{n}: malformed or unknown entry")
            entries.append((kind, rest[0], rest[1:]))
    return entries


def pin_of(entries, name):
    """(kind, fields) of the pin of name; its identity, the git commit or
    the archive digest, is the last field."""
    for kind, n, f in entries:
        if n == name and kind in ("git", "archive"):
            return kind, f
    raise Failure(f"{name}: not pinned in the lock")


def read_stamp(path):
    """The content of a stamp file, or "" when there is none."""
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(url, dest, check=None):
    """url to dest through dest.partial; HTTPS only, redirects included.

    check(path), when given, runs on the partial file and raises Failure to
    refuse it; only a download that completed and passed it is renamed to
    dest, so a refused or truncated transfer never sits at dest."""
    if not url.startswith("https://"):
        raise Failure(f"{url}: not an HTTPS URL")
    tmp = dest + ".partial"
    try:
        try:
            with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as out:
                if not r.geturl().startswith("https://"):
                    raise Failure(f"{url}: redirected off HTTPS to {r.geturl()}")
                shutil.copyfileobj(r, out, 1 << 20)
        except (OSError, http.client.HTTPException) as e:
            raise Failure(f"{url}: download failed: {e}") from None
        if check is not None:
            check(tmp)
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def run(cmd, cwd=None, log=None):
    """Run cmd; on failure raise with the log that holds its output."""
    try:
        if log is None:
            p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, errors="replace")
            out = p.stdout
        else:
            with open(log, "a") as lf:
                p = subprocess.run(cmd, cwd=cwd, stdout=lf, stderr=subprocess.STDOUT)
            out = f"see {log}"
    except OSError as e:
        raise Failure(f"{cmd[0]}: {e}") from None
    if p.returncode != 0:
        raise Failure(f"{' '.join(cmd)} failed (exit {p.returncode}): {out.strip()[-400:]}")
    return out


def fetch_git(work, name, url, commit):
    d = os.path.join(work, "src", name)
    if not os.path.isdir(os.path.join(d, ".git")):
        run(["git", "init", "-q", d])
        run(["git", "-C", d, "remote", "add", "origin", url])
    run(["git", "-C", d, "fetch", "-q", "--depth", "1", "origin", commit])
    run(["git", "-C", d, "checkout", "-q", "--detach", commit])
    head = run(["git", "-C", d, "rev-parse", "HEAD"]).strip()
    if head != commit:
        raise Failure(f"{name}: checkout is {head}, not {commit}")
    if run(["git", "-C", d, "status", "--porcelain", "--untracked-files=no"]).strip():
        raise Failure(f"{name}: tracked files modified in {d}")
    # The harness compiles every .c of a tree (tests/diff/adapters/adapters.mk),
    # and builds of earlier runs leave objects in it: remove everything git
    # does not track, ignored files included, so only the pinned sources stay.
    run(["git", "-C", d, "clean", "-q", "-ffdx"])
    if run(["git", "-C", d, "status", "--porcelain", "--ignored"]).strip():
        raise Failure(f"{name}: files outside the pinned commit remain in {d}")
    say(f"ok {name} {commit}")


def unpack(archive, into):
    """Extract into an empty directory, refusing links and paths outside it.

    zipfile drops the Unix mode bits a zip records, which a configure
    script needs to stay executable; they are restored (permission bits
    only) from each member's external attributes."""
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            base = os.path.realpath(into) + os.sep
            for info in z.infolist():
                target = os.path.realpath(os.path.join(into, info.filename))
                if not target.startswith(base):
                    raise Failure(f"{archive}: member {info.filename} leaves the tree")
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise Failure(f"{archive}: member {info.filename} is a link")
            for info in z.infolist():
                path = z.extract(info, into)
                mode = (info.external_attr >> 16) & 0o777
                if mode and not info.is_dir():
                    os.chmod(path, mode)
    else:
        with tarfile.open(archive, "r:gz") as t:
            t.extractall(into, filter="data")


def fetch_archive(work, name, url, size, digest):
    if url.endswith(".tar.gz"):
        ext = "tar.gz"
    elif url.endswith(".zip"):
        ext = "zip"
    else:
        raise Failure(f"{name}: unsupported archive type")
    path = os.path.join(work, "src", f"{name}.{ext}")

    def check(p):
        if os.path.getsize(p) != int(size):
            raise Failure(f"{name}: size mismatch")
        if sha256(p) != digest:
            raise Failure(f"{name}: SHA-256 mismatch")

    if os.path.isfile(path):
        check(path)
    else:
        download(url, path, check)

    tree = os.path.join(work, "src", name)
    stamp = os.path.join(tree, STAMP_SOURCE)
    if os.path.isdir(tree) and read_stamp(stamp) != digest:
        shutil.rmtree(tree)
    if not os.path.isdir(tree):
        tmp = tree + ".partial"
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        unpack(path, tmp)
        top = os.listdir(tmp)
        if len(top) != 1 or not os.path.isdir(os.path.join(tmp, top[0])):
            raise Failure(f"{name}: archive has no single top directory")
        os.replace(os.path.join(tmp, top[0]), tree)
        os.rmdir(tmp)
        with open(stamp, "w") as f:
            f.write(digest + "\n")
    say(f"ok {name} {digest}")


def cmd_fetch(work, entries, names):
    known = {n for k, n, _ in entries if k in ("git", "archive")}
    unknown = set(names) - known
    if unknown:
        raise Failure(f"not pinned in the lock: {' '.join(sorted(unknown))}")
    for kind, name, f in entries:
        if names and name not in names:
            continue
        if kind == "git":
            fetch_git(work, name, *f)
        elif kind == "archive":
            fetch_archive(work, name, *f)


# Builds -------------------------------------------------------------------

def jobs():
    return os.environ.get("BASELINES_JOBS", "2")


def up_to_date(work, entries, name, library, opts):
    """True when library exists and was built from the pin with opts.

    Otherwise the old prefix and build tree are removed and an archive's
    source is unpacked afresh, so a build never starts from a tree that a
    previous configuration has touched."""
    kind, f = pin_of(entries, name)
    want = f"src={f[-1]} opts={' '.join(opts)}"
    prefix = os.path.join(work, "out", name)
    if (os.path.isfile(os.path.join(prefix, library))
            and read_stamp(os.path.join(prefix, STAMP_BUILD)) == want):
        say(f"ok (built) {name}")
        return True, want
    shutil.rmtree(prefix, ignore_errors=True)
    shutil.rmtree(os.path.join(work, f"build-{name}"), ignore_errors=True)
    if kind == "archive":
        shutil.rmtree(os.path.join(work, "src", name), ignore_errors=True)
        fetch_archive(work, name, *f)
    return False, want


def stamp_build(work, name, want):
    prefix = os.path.join(work, "out", name)
    os.makedirs(prefix, exist_ok=True)
    with open(os.path.join(prefix, STAMP_BUILD), "w") as f:
        f.write(want + "\n")


def source_tree(work, name):
    src = os.path.join(work, "src", name)
    if not os.path.isdir(src):
        raise Failure(f"{name}: not fetched")
    return src


def build_openssl(work, entries, name):
    """Defaults for the host (assembly on, -O3); static, no docs or tests."""
    src = source_tree(work, name)
    prefix = os.path.join(work, "out", name)
    opts = ["no-shared", "no-docs", "no-tests"]
    done, want = up_to_date(work, entries, name, "lib/libcrypto.a", opts)
    if done:
        return
    log = os.path.join(work, "log", f"{name}.log")
    run(["./Configure", f"--prefix={prefix}", "--libdir=lib", *opts], cwd=src, log=log)
    with open(os.path.join(work, "log", f"{name}-configdata.txt"), "w") as out:
        subprocess.run(["perl", "configdata.pm", "--dump"], cwd=src, stdout=out,
                       stderr=subprocess.STDOUT, check=False)
    run(["make", f"-j{jobs()}"], cwd=src, log=log)
    run(["make", "install_sw"], cwd=src, log=log)
    stamp_build(work, name, want)
    say(f"ok built {name}")


def build_wolfssl(work, entries, name):
    """Static wolfCrypt (no TLS layer) with every SLH-DSA set, the pre-hash
    digests and the host's assembly: on x86-64 the Intel paths, chosen at
    run time by CPUID (AVX2 multi-way hashing among them); on AArch64 the
    SHA-256, SHA-512 and SHA-3 instructions."""
    src = source_tree(work, name)
    prefix = os.path.join(work, "out", name)
    machine = platform.machine()
    if machine in ("x86_64", "amd64"):
        asm = "--enable-intelasm"
    elif machine in ("arm64", "aarch64"):
        asm = "--enable-armasm=sha512-crypto"
    else:
        raise Failure(f"{name}: no assembly configuration for {machine}")
    opts = ["--enable-static", "--disable-shared", "--enable-cryptonly",
            "--enable-slhdsa=yes,sha2", "--enable-sha3", "--enable-shake128",
            "--enable-shake256", "--enable-sha224", "--enable-sha384", "--enable-sha512",
            asm, "--disable-examples", "--disable-crypttests"]
    done, want = up_to_date(work, entries, name, "lib/libwolfssl.a", opts)
    if done:
        return
    log = os.path.join(work, "log", f"{name}.log")
    run(["./configure", f"--prefix={prefix}", *opts], cwd=src, log=log)
    run(["make", f"-j{jobs()}"], cwd=src, log=log)
    run(["make", "install"], cwd=src, log=log)
    stamp_build(work, name, want)
    say(f"ok built {name} ({asm})")


def build_boringssl(work, entries, name):
    """The crypto library only, release build, BoringSSL's own assembly."""
    src = source_tree(work, name)
    prefix = os.path.join(work, "out", name)
    if shutil.which("cmake") is None:
        raise Failure(f"{name}: cmake not found")
    opts = ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=OFF"]
    done, want = up_to_date(work, entries, name, "lib/libcrypto.a", opts)
    if done:
        return
    log = os.path.join(work, "log", f"{name}.log")
    build = os.path.join(work, f"build-{name}")
    run(["cmake", "-S", src, "-B", build, *opts], log=log)
    run(["cmake", "--build", build, "--target", "crypto", "-j", jobs()], log=log)
    os.makedirs(os.path.join(prefix, "lib"), exist_ok=True)
    shutil.copy2(os.path.join(build, "libcrypto.a"), os.path.join(prefix, "lib", "libcrypto.a"))
    include = os.path.join(prefix, "include")
    if os.path.lexists(include):
        os.remove(include)
    os.symlink(os.path.join(src, "include"), include)
    stamp_build(work, name, want)
    say(f"ok built {name}")


def build_rule(name):
    if name.startswith("openssl-"):
        return build_openssl
    if name.startswith("wolfssl-"):
        return build_wolfssl
    if name == "boringssl":
        return build_boringssl
    return None


def cmd_build(work, entries, names):
    buildable = [n for k, n, _ in entries if k in ("git", "archive") and build_rule(n)]
    unknown = set(names) - set(buildable)
    if unknown:
        raise Failure(f"no build rule for: {' '.join(sorted(unknown))}")
    for name in names or buildable:
        build_rule(name)(work, entries, name)


# Provenance ---------------------------------------------------------------

def verify_openpgp(work, name, sig_url, primary, keys_url):
    """The archive's detached signature is valid and was made by a key whose
    primary fingerprint is the pinned one (VALIDSIG's last field)."""
    archive = os.path.join(work, "src", f"{name}.tar.gz")
    if not os.path.isfile(archive):
        raise Failure(f"{name}: not fetched")
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        download(sig_url, os.path.join(home, "sig.asc"))
        download(keys_url, os.path.join(home, "keys.asc"))
        # The import's status is not the evidence (a keyring may hold
        # expired keys); the VALIDSIG fingerprint below is.
        subprocess.run(["gpg", "--homedir", home, "--batch", "--quiet", "--import",
                        os.path.join(home, "keys.asc")], capture_output=True)
        # Status lines are ASCII; a user ID in them may not be UTF-8.
        p = subprocess.run(["gpg", "--homedir", home, "--batch", "--status-fd", "1",
                            "--verify", os.path.join(home, "sig.asc"), archive],
                           capture_output=True, text=True, errors="replace")
        signers = [line.split()[-1] for line in p.stdout.splitlines()
                   if line.split()[1:2] == ["VALIDSIG"]]
    if p.returncode != 0 or signers != [primary]:
        raise Failure(f"{name}: no valid signature by {primary}")
    say(f"ok signature {name} by {primary}")


def verify_sameas(work, name, url, commit, paths):
    tree = os.path.join(work, "src", name)
    with tempfile.TemporaryDirectory() as tmp:
        run(["git", "init", "-q", tmp])
        run(["git", "-C", tmp, "fetch", "-q", "--depth", "1", url, commit])
        for path in paths:
            p = subprocess.run(["git", "-C", tmp, "show", f"{commit}:{path}"],
                               capture_output=True)
            try:
                with open(os.path.join(tree, path), "rb") as f:
                    same = p.returncode == 0 and f.read() == p.stdout
            except OSError:
                same = False
            if not same:
                raise Failure(f"{name}: {path} differs from {commit}")
    say(f"ok {name} files identical to {commit}")


def cmd_verify(work, entries, names):
    if names:
        raise Failure("verify takes no names")
    if shutil.which("gpg") is None:
        raise Failure("verify: gpg not found")
    for kind, name, f in entries:
        if kind == "openpgp":
            verify_openpgp(work, name, *f)
        elif kind == "sameas":
            verify_sameas(work, name, f[0], f[1], f[2:])


COMMANDS = {"fetch": cmd_fetch, "build": cmd_build, "verify": cmd_verify}


def main(argv):
    if len(argv) < 3 or argv[1] not in COMMANDS:
        print("usage: baselines.py fetch|build|verify <workdir> [name...]", file=sys.stderr)
        return 2
    work = os.path.abspath(argv[2])
    for d in ("src", "out", "log"):
        os.makedirs(os.path.join(work, d), exist_ok=True)
    try:
        COMMANDS[argv[1]](work, read_lock(), argv[3:])
    except Failure as e:
        print(f"baselines: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
