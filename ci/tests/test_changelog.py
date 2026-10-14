# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_changelog.py
# ==========================
#
# ci/changelog.py on a scratch repository: a base commit, a pull
# request head and the merge commit GitHub would build, with a local HTTP
# server in place of the GitHub API that answers the pull request query
# from a file. The labels are read when the check runs, so the same merge
# commit passes or fails with the labels of the moment, and an unreadable
# label list fails the check.

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

import fakeapi  # noqa: E402


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@invalid",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, env=env,
                          check=True, capture_output=True, text=True).stdout.strip()


class Changelog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.repo, "ci"))
        os.makedirs(os.path.join(self.repo, "changes"))
        os.makedirs(os.path.join(self.repo, "src"))
        for f in ("ci/changelog.py", "ci/ghapi.py", "ci/changes.sh",
                  "changes/README.md"):
            shutil.copy(os.path.join(ROOT, f), os.path.join(self.repo, f))
        with open(os.path.join(self.repo, "src", "a.jinc"), "w") as f:
            f.write("base\n")
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.api = fakeapi.Server()
        self.addCleanup(self.api.close)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def pull_request(self, files):
        """Commit FILES on a branch, then the merge into main, and check it out."""
        git(self.repo, "checkout", "-q", "-b", "pr", self.base)
        for path, text in files.items():
            full = os.path.join(self.repo, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write(text)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "change")
        head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "--detach", self.base)
        git(self.repo, "merge", "-q", "--no-ff", "-m", "merge", head)
        return head

    def run_check(self, head, labels):
        self.api.routes.clear()
        if labels is not None:
            self.api.routes["/repos/o/r/pulls/5"] = {
                "number": 5, "labels": [{"name": l} for l in labels]}
        env = dict(os.environ, GITHUB_API_URL=self.api.url, GH_TOKEN="t",
                   CI_EVENT="pull_request", CI_HEAD=head, CI_PR="5", GITHUB_REPOSITORY="o/r")
        env.pop("GITHUB_STEP_SUMMARY", None)
        return subprocess.run(["python3", "-I", "ci/changelog.py"], cwd=self.repo,
                              env=env, capture_output=True, text=True)

    def test_label_read_when_the_check_runs(self):
        head = self.pull_request({"src/a.jinc": "changed\n"})
        # Opened without the label: no entry, so the check fails.
        r = self.run_check(head, ["documentation"])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAIL", r.stdout)
        # The label is added: the same merge commit now passes, no push.
        r = self.run_check(head, ["documentation", "no-changelog"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("labelled no-changelog", r.stdout)
        # The label is removed again: it fails again.
        r = self.run_check(head, [])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_own_entry_passes_without_label(self):
        head = self.pull_request({"src/a.jinc": "changed\n",
                                  "changes/fixed/5-a-fix.md": "- Fixes a.\n"})
        r = self.run_check(head, [])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("with the entry changes/fixed/5-a-fix.md", r.stdout)

    def test_entry_under_another_number_does_not_count(self):
        head = self.pull_request({"src/a.jinc": "changed\n",
                                  "changes/fixed/4-a-fix.md": "- Fixes a.\n"})
        r = self.run_check(head, [])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_unwatched_change_passes(self):
        head = self.pull_request({"docs/x.md": "text\n"})
        r = self.run_check(head, [])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_unreadable_labels_fail(self):
        # An API error (HTTP 404 here) is never read as "no label", nor as
        # the label.
        head = self.pull_request({"src/a.jinc": "changed\n",
                                  "changes/fixed/5-a-fix.md": "- Fixes a.\n"})
        r = self.run_check(head, None)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_other_events_do_not_apply(self):
        env = dict(os.environ, CI_EVENT="push")
        env.pop("GITHUB_STEP_SUMMARY", None)
        r = subprocess.run(["python3", "-I", "ci/changelog.py"], cwd=self.repo,
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("NOT APPLICABLE", r.stdout)


if __name__ == "__main__":
    unittest.main()
