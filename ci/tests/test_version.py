# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_version.py
# ========================
#
# ci/version.py on copies of the header, CITATION.cff and CHANGELOG.md,
# with negative controls: the committed files agree; a copy whose
# CITATION.cff, version string or newest release heading disagrees with the
# macros fails, as do a missing, repeated or unknown macro, a non-decimal
# number, a malformed or repeated release heading, and a second `version`
# field. A tag passes only as "v" and the version, with a newest changelog
# section for it, and ci/source.py passes the tag's name on only for the
# push of a tag, an empty name included.

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import registry  # noqa: E402
import source  # noqa: E402
import version  # noqa: E402

ROOT = registry.ROOT
FILES = (version.HEADER, version.CITATION, version.CHANGELOG)


class Version(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for f in FILES:
            os.makedirs(os.path.join(self.tmp, os.path.dirname(f)), exist_ok=True)
            shutil.copy(os.path.join(ROOT, f), os.path.join(self.tmp, f))
        self.version, errors, _ = version.check(ROOT)
        self.assertEqual(errors, [])

    def edit(self, path, old, new, count=1):
        p = os.path.join(self.tmp, path)
        with open(p, encoding="utf-8") as f:
            text = f.read()
        self.assertIn(old, text)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text.replace(old, new, count))

    def errors(self, tag=None):
        return version.check(self.tmp, tag)[1]

    def release(self, v):
        """The release commit: a section for v under the introduction."""
        self.edit(version.CHANGELOG, "newest first.\n",
                  f"newest first.\n\n## v{v} - 2026-10-20\n\n### Added\n\n- Something.\n")

    def define(self, name):
        with open(os.path.join(self.tmp, version.HEADER), encoding="utf-8") as f:
            return re.search(rf"^#define NIRAPOD_SLHDSA_VERSION_{name} .*$", f.read(),
                             re.MULTILINE).group(0)

    def test_committed_files_agree(self):
        self.assertEqual(self.errors(), [])
        self.assertTrue(version.VERSION.match(self.version))

    def test_script_exit_status(self):
        script = os.path.join(ROOT, "ci/version.py")
        run = lambda *a: subprocess.run([sys.executable, "-I", script, *a], cwd=ROOT,
                                        capture_output=True, text=True).returncode
        self.assertEqual(run(), 0)
        self.assertEqual(run("--tag", "v0.0.0-not-this"), 1)
        self.assertEqual(run("--tag"), 2)

    def test_mismatched_citation_fails(self):
        self.edit(version.CITATION, f'version: "{self.version}"', 'version: "9.9.9"')
        self.assertTrue(any("CITATION.cff: version '9.9.9'" in e for e in self.errors()))

    def test_unquoted_citation_version_is_read(self):
        self.edit(version.CITATION, f'version: "{self.version}"', f"version: {self.version}")
        self.assertEqual(self.errors(), [])

    def test_second_citation_version_fails(self):
        self.edit(version.CITATION, "type: software\n",
                  f'type: software\nversion: "{self.version}"\n')
        self.assertTrue(any("2 top-level `version` fields" in e for e in self.errors()))

    def test_citation_without_version_fails(self):
        self.edit(version.CITATION, f'version: "{self.version}"\n', "")
        self.assertTrue(any("0 top-level `version` fields" in e for e in self.errors()))

    def test_string_disagreeing_with_numbers_fails(self):
        line = self.define("PATCH")
        self.edit(version.HEADER, line, line.rstrip("0123456789") + "7")
        self.assertTrue(any("disagrees with MAJOR, MINOR and PATCH" in e for e in self.errors()))

    def test_missing_macro_fails(self):
        self.edit(version.HEADER, self.define("MINOR") + "\n", "")
        self.assertTrue(any("VERSION_MINOR is not defined" in e for e in self.errors()))

    def test_repeated_macro_fails(self):
        line = self.define("MAJOR")
        self.edit(version.HEADER, line, line + "\n" + line)
        self.assertTrue(any("VERSION_MAJOR is defined again" in e for e in self.errors()))

    def test_unknown_macro_fails(self):
        line = self.define("MAJOR")
        self.edit(version.HEADER, line, line + "\n#define NIRAPOD_SLHDSA_VERSION_BUILD 3")
        self.assertTrue(any("VERSION_BUILD is not one of" in e for e in self.errors()))

    def test_non_decimal_number_fails(self):
        line = self.define("MAJOR")
        self.edit(version.HEADER, line, line.rstrip("0123456789") + "(0)")
        self.assertTrue(any("not a decimal number" in e for e in self.errors()))

    def test_pre_release_string_passes(self):
        line = self.define("STRING")
        self.edit(version.HEADER, line, line[:-1] + '-rc.1"')
        self.edit(version.CITATION, f'version: "{self.version}"',
                  f'version: "{self.version}-rc.1"')
        self.assertEqual(self.errors(), [])
        self.release(f"{self.version}-rc.1")
        self.assertEqual(self.errors(f"v{self.version}-rc.1"), [])

    def test_release_heading_must_match(self):
        self.release(self.version)
        self.assertEqual(self.errors(), [])
        self.edit(version.CHANGELOG, f"## v{self.version} -", "## v9.9.9 -")
        self.assertTrue(any("the newest release is v9.9.9" in e for e in self.errors()))

    def test_malformed_release_heading_fails(self):
        self.release(self.version)
        self.edit(version.CHANGELOG, " - 2026-10-20", " (2026-10-20)")
        self.assertTrue(any("is not '## vVERSION - YYYY-MM-DD'" in e for e in self.errors()))

    def test_repeated_release_heading_fails(self):
        self.release(self.version)
        self.release(self.version)
        self.assertTrue(any("a second section" in e for e in self.errors()))

    def test_tag_must_name_the_version(self):
        self.release(self.version)
        self.assertEqual(self.errors(f"v{self.version}"), [])
        for tag in (self.version, f"v{self.version}.1", "v9.9.9", ""):
            self.assertTrue(any(e.startswith("tag ") for e in self.errors(tag)), tag)

    def test_tag_without_changelog_section_fails(self):
        self.assertTrue(any("has no newest section" in e for e in self.errors(f"v{self.version}")))


class SourceStep(unittest.TestCase):
    """The command ci/source.py runs for the version check."""

    def command(self, env):
        ran = []
        env = dict({k: v for k, v in os.environ.items()
                    if k not in ("GITHUB_REF_TYPE", "GITHUB_REF_NAME")}, **env)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(source, "run", lambda cmd: ran.append(cmd) or True), \
                mock.patch("sys.stdout"):
            cwd = os.getcwd()
            os.chdir(ROOT)
            try:
                source.main(["source.py"])
            finally:
                os.chdir(cwd)
        return next(c[2:] for c in ran if c[2:3] == ["ci/version.py"])

    def test_tag_is_passed_on_a_tag_push_only(self):
        self.assertEqual(self.command({}), ["ci/version.py"])
        self.assertEqual(self.command({"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"}),
                         ["ci/version.py"])
        self.assertEqual(self.command({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v0.1.0"}),
                         ["ci/version.py", "--tag", "v0.1.0"])
        self.assertEqual(self.command({"GITHUB_REF_TYPE": "tag"}),
                         ["ci/version.py", "--tag", ""])


if __name__ == "__main__":
    unittest.main()
