# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/revision.py
# =================
#
# The source state a benchmark record names. A commit hash alone does not
# identify what was built when the working tree differs from it, and the
# top-level Makefile includes untracked *.mk fragments, so an untracked
# file can change the build. tree_state therefore records two digests:
#
#     tree_sha256          the working tree: every tracked file that is
#                          present and every untracked file that .gitignore
#                          does not exclude
#     commit_tree_sha256   the same computation over the files of HEAD
#
# Each digest is the SHA-256 of the entries "<mode> <content SHA-256>
# <path>" followed by a NUL byte, sorted by path; mode is 100644, 100755
# or 120000 (a symbolic link, hashed by its target) as git records it, and
# a submodule enters as its commit. The two are equal exactly when the
# files the build can see match the commit; otherwise "changes" lists
# each path that is modified, untracked or deleted, with its SHA-256.

import hashlib
import os
import subprocess


class Failure(Exception):
    pass


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git(root, *args, data=None):
    p = subprocess.run(["git", "-C", root, *args], input=data, capture_output=True)
    if p.returncode != 0:
        raise Failure(f"git {' '.join(args)} failed: {p.stderr.decode(errors='replace')[-300:]}")
    return p.stdout


def manifest_digest(entries):
    """SHA-256 of sorted (path, mode, content SHA-256) entries."""
    h = hashlib.sha256()
    for path in sorted(entries):
        mode, digest = entries[path]
        h.update(f"{mode} {digest} {path}\0".encode())
    return h.hexdigest()


def commit_entries(root, commit):
    """path -> (mode, content SHA-256) of every file of commit."""
    listing = [e for e in git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0") if e]
    entries, blobs = {}, []
    for e in listing:
        meta, path = e.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        if kind == "blob":
            blobs.append((path.decode(), mode, oid))
        else:
            entries[path.decode()] = (mode, oid)        # a submodule: its commit
    data = git(root, "cat-file", "--batch", data="".join(f"{o}\n" for _, _, o in blobs).encode())
    pos = 0
    for path, mode, _ in blobs:
        end = data.index(b"\n", pos)
        size = int(data[pos:end].split()[2])
        content = data[end + 1:end + 1 + size]
        entries[path] = (mode, hashlib.sha256(content).hexdigest())
        pos = end + 1 + size + 1
    return entries


def worktree_entries(root, committed):
    """path -> (mode, content SHA-256) of the working tree: every tracked
    file present and every untracked file .gitignore does not exclude."""
    paths = [p.decode() for p in git(root, "ls-files", "-z", "--cached", "--others",
                                     "--exclude-standard").split(b"\0") if p]
    entries = {}
    for path in sorted(set(paths)):
        full = os.path.join(root, path)
        if committed.get(path, ("",))[0] == "160000":
            entries[path] = committed[path]
        elif os.path.islink(full):
            entries[path] = ("120000", hashlib.sha256(os.readlink(full).encode()).hexdigest())
        elif os.path.isfile(full):
            mode = "100755" if os.stat(full).st_mode & 0o100 else "100644"
            entries[path] = (mode, sha256(full))
    return entries


def tree_state(root):
    """The commit, the working-tree digest, and what differs from the commit."""
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    committed = commit_entries(root, commit)
    current = worktree_entries(root, committed)
    changes = []
    for path in sorted(set(committed) | set(current)):
        if path not in current:
            changes.append(dict(path=path, state="deleted"))
        elif path not in committed:
            changes.append(dict(path=path, state="untracked", sha256=current[path][1]))
        elif current[path] != committed[path]:
            changes.append(dict(path=path, state="modified", mode=current[path][0],
                                sha256=current[path][1]))
    tree, at_commit = manifest_digest(current), manifest_digest(committed)
    return dict(commit=commit, tree_sha256=tree, commit_tree_sha256=at_commit,
                matches_commit=tree == at_commit, changes=changes)
