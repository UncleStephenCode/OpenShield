#!/usr/bin/env python3
"""Stub-only provisioning tests; run inside a disposable Docker container."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).with_name("zypper-refresh.sh")
LEAP_PATH = "/distribution/leap/${releasever}/repo/oss/$basearch"


@unittest.skipUnless(Path("/.dockerenv").is_file(), "requires a disposable Docker container")
class ZypperRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="openshield-zypper-test.", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.alias = "openSUSE:repo-oss"
        self.repository = self.directory / (self.alias + ".repo")
        self.original = self.repository_text()
        self.repository.write_text(self.original)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.write_stub("zypper", """#!/bin/sh
set -eu
count=0
if [ -f "$STUB_DIRECTORY/count" ]; then read -r count < "$STUB_DIRECTORY/count"; fi
count=$((count + 1))
printf '%s\\n' "$count" > "$STUB_DIRECTORY/count"
printf '%s\\n' "$*" >> "$STUB_DIRECTORY/zypper.log"
cp "$STUB_REPOSITORY" "$STUB_DIRECTORY/snapshot-$count"
status=$(sed -n "${count}p" "$STUB_DIRECTORY/statuses")
[ -n "$status" ] || exit 99
if [ -n "${STUB_ERROR:-}" ]; then printf '%s\\n' "$STUB_ERROR" >&2; fi
exit "$status"
""")
        self.write_stub("sleep", """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_DIRECTORY/sleep.log"
""")
        self.environment = os.environ.copy()
        self.environment.update({
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "OPENSHIELD_E2E_TEST_ZYPPER_REPOS_DIR": str(self.directory),
            "STUB_DIRECTORY": str(self.directory),
            "STUB_REPOSITORY": str(self.repository),
        })

    @staticmethod
    def repository_text(origin="http://cdn.opensuse.org", path=LEAP_PATH):
        return (
            "[openSUSE:repo-oss]\n"
            "name=repo-oss (test)\n"
            "enabled=1\n"
            "autorefresh=1\n"
            "gpgcheck=1\n"
            "repo_gpgcheck=1\n"
            "pkg_gpgcheck=1\n"
            "priority=99\n"
            "  baseurl = " + origin + path + "  \n"
            "gpgkey=" + origin + path + "/repodata/repomd.xml.key\n"
        )

    def write_stub(self, name, content):
        stub = self.bin / name
        stub.write_text(content)
        stub.chmod(0o755)

    def run_helper(self, statuses=(0,), alias=None, error=None):
        (self.directory / "statuses").write_text("".join(str(status) + "\n" for status in statuses))
        environment = self.environment.copy()
        if error is not None:
            environment["STUB_ERROR"] = error
        return subprocess.run(
            ["sh", str(HELPER), self.alias if alias is None else alias],
            env=environment, text=True, capture_output=True, timeout=5,
        )

    def log(self, name):
        file = self.directory / (name + ".log")
        return file.read_text().splitlines() if file.exists() else []

    def test_upgrade_preserves_paths_variables_gpg_settings_and_permissions(self):
        self.repository.chmod(0o640)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.repository.read_text(), self.original.replace("http://", "https://"))
        self.assertEqual(self.repository.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.log("zypper"), ["--non-interactive refresh openSUSE:repo-oss"])
        self.assertEqual(self.log("sleep"), [])

    def test_https_input_is_idempotent(self):
        original = self.original.replace("http://", "https://")
        self.repository.write_text(original)
        before = self.repository.stat()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.repository.read_text(), original)
        self.assertEqual(self.repository.stat().st_ino, before.st_ino)
        self.assertEqual(self.repository.stat().st_mtime_ns, before.st_mtime_ns)

    def test_tumbleweed_download_origin_is_supported(self):
        self.alias = "repo-oss"
        self.repository = self.directory / "repo-oss.repo"
        original = self.repository_text("http://download.opensuse.org", "/tumbleweed/repo/oss/")
        self.repository.write_text(original)
        self.environment["STUB_REPOSITORY"] = str(self.repository)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.repository.read_text(), original.replace("http://", "https://"))

    def test_retries_switch_origins_and_force_fresh_metadata(self):
        result = self.run_helper((4, 4, 0))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log("sleep"), ["5", "10"])
        self.assertEqual(self.log("zypper"), [
            "--non-interactive refresh openSUSE:repo-oss",
            "--non-interactive refresh --force openSUSE:repo-oss",
            "--non-interactive refresh --force openSUSE:repo-oss",
        ])
        for attempt, origin in enumerate(("cdn.opensuse.org", "download.opensuse.org", "cdn.opensuse.org"), 1):
            snapshot = (self.directory / ("snapshot-" + str(attempt))).read_text()
            expected = self.original.replace("http://cdn.opensuse.org", "https://" + origin)
            self.assertEqual(snapshot, expected)

    def test_retryable_failure_stops_after_three_attempts(self):
        result = self.run_helper((4, 4, 4, 0))
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertEqual(len(self.log("zypper")), 3)
        self.assertEqual(self.log("sleep"), ["5", "10"])

    def test_nonretryable_signature_failure_is_returned_without_retry(self):
        result = self.run_helper((106, 0), error="Signature verification failed")
        self.assertEqual(result.returncode, 106, result.stderr)
        self.assertIn("Signature verification failed", result.stderr)
        self.assertEqual(self.log("zypper"), ["--non-interactive refresh openSUSE:repo-oss"])
        self.assertEqual(self.log("sleep"), [])

    def test_nonretryable_error_stops_immediately(self):
        result = self.run_helper((2, 0))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(len(self.log("zypper")), 1)
        self.assertEqual(self.log("sleep"), [])

    def test_tls_failure_is_not_accepted_or_bypassed(self):
        result = self.run_helper((4, 4, 4), error="SSL certificate verification failed")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("SSL certificate verification failed", result.stderr)
        for command in self.log("zypper"):
            self.assertNotIn("--no-gpg-checks", command)
            self.assertNotIn("--gpg-auto-import-keys", command)
            self.assertNotIn("ssl_verify", command)
        self.assertIn("repo_gpgcheck=1\n", self.repository.read_text())

    def test_unexpected_urls_fail_before_rewrite_or_refresh(self):
        for url in (
            "http://untrusted.example/repo",
            "http://cdn.opensuse.org.evil/repo",
            "ftp://cdn.opensuse.org/repo",
            "https://cdn.opensuse.org/repo?ssl_verify=no",
            "https://cdn.opensuse.org/repo#fragment",
        ):
            with self.subTest(url=url):
                original = self.repository_text(url, "")
                self.repository.write_text(original)
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.repository.read_text(), original)
                self.assertEqual(self.log("zypper"), [])

    def test_unexpected_gpgkey_fails_before_original_is_modified(self):
        original = self.original.replace("gpgkey=http://cdn.opensuse.org", "gpgkey=https://untrusted.example")
        self.repository.write_text(original)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.repository.read_text(), original)
        self.assertEqual(self.log("zypper"), [])

    def test_unexpected_alias_is_rejected(self):
        result = self.run_helper(alias="../../outside")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.repository.read_text(), self.original)
        self.assertEqual(self.log("zypper"), [])

    def test_symlink_repository_is_rejected(self):
        target = self.directory / "target.repo"
        self.repository.rename(target)
        self.repository.symlink_to(target)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), self.original)
        self.assertEqual(self.log("zypper"), [])


if __name__ == "__main__":
    unittest.main()
