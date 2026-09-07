#!/usr/bin/env python3
"""Offline release regressions using SYNTHETIC artifacts and fake GitHub state.

These tests prove validation/publication control flow, not successful builds,
package installation, firewall tests, performance, or an actual GitHub release.
No fixture generated here is suitable for publication as release evidence.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "packaging/ci/release-matrix.json"
VERSION = "0.0.0-offline-fixture"
TAG = "v" + VERSION
SOURCE_SHA = "a" * 40
TAG_REF_SHA = "b" * 40


def require_local_utilities() -> None:
    required = ("bash", "sh", "python3", "jq", "sha256sum", "stat", "sort", "grep",
                "find", "wc", "cmp", "mktemp", "dirname", "chmod", "rm")
    missing = [name for name in required
               if shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin") is None]
    if missing:
        raise AssertionError("offline release tests require local utilities: " + ", ".join(missing))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def workflow_script(step_name: str) -> str:
    """Read the actual literal bash block; fail if workflow structure changes."""
    lines = (ROOT / ".github/workflows/release.yml").read_text().splitlines()
    marker = "      - name: " + step_name
    positions = [index for index, line in enumerate(lines) if line == marker]
    if len(positions) != 1:
        raise AssertionError(f"expected exactly one workflow step: {step_name}")
    following = lines[positions[0] + 1:]
    for index, line in enumerate(following):
        if line == "        run: |":
            body = []
            for body_line in following[index + 1:]:
                if body_line and not body_line.startswith("          "):
                    break
                body.append(body_line[10:])
            script = "\n".join(body) + "\n"
            if not body or "${{" in script:
                raise AssertionError("workflow shell requires explicit test adaptation")
            return script
        if line.startswith("      - "):
            break
    raise AssertionError(f"no literal run block in {step_name}")


def zip_transport(source: Path, destination: Path) -> None:
    """Exercise a ZIP roundtrip and GitHub's documented outer mode 0644."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    stream.seek(0)
    with zipfile.ZipFile(stream) as archive:
        archive.extractall(destination)
    for path in destination.rglob("*"):
        if path.is_file():
            path.chmod(0o644)


def make_artifacts(directory: Path) -> None:
    matrix = json.loads(MATRIX.read_text())
    for row in matrix["binaries"]:
        binary_dir = directory / "binaries" / row["artifact_name"]
        binary_dir.mkdir(parents=True)
        archive_name = row["archive_template"].replace("{version}", VERSION)
        with tarfile.open(binary_dir / archive_name, "w:xz", preset=0) as archive:
            for name in ("openshield-daemon", "openshield-tui"):
                payload = f"SYNTHETIC TEST ONLY: {row['id']} {name}\n".encode()
                (binary_dir / name).write_bytes(payload)
                (binary_dir / name).chmod(0o755)
                member = tarfile.TarInfo(name)
                member.mode = 0o755
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

    extensions = {"deb": ".deb", "alpine": ".apk", "arch": ".pkg.tar.zst"}
    packages = {}
    for row in matrix["packages"]:
        package_dir = directory / "packages" / row["artifact_name"]
        package_dir.mkdir(parents=True)
        name = "synthetic-" + row["id"] + extensions.get(row["family"], ".rpm")
        package = package_dir / name
        package.write_bytes(f"SYNTHETIC TEST ONLY: {row['id']}\n".encode())
        packages[row["id"]] = package

    evidence = directory / "evidence"
    evidence.mkdir()
    for row in matrix["platforms"]:
        if row["arch"] not in matrix["runtime_test_arches"]:
            continue
        package = packages[row["package"]]
        record = {
            "schema_version": 1, "type": "package-install", "id": row["id"],
            "package": row["package"], "image": row["image"], "platform": row["platform"],
            "execution_mode": "x86-compat" if row["arch"] == "386" else "native",
            "package_asset": package.name, "package_sha256": sha256(package),
            "version": VERSION, "source_sha": SOURCE_SHA,
        }
        write_json(evidence / f"install-{row['id']}.json", record)
        for backend in ("nftables", "iptables"):
            firewall = {**record, "type": "firewall-e2e", "backend": backend,
                        "id": row["id"] + "-" + backend}
            write_json(evidence / f"firewall-{firewall['id']}.json", firewall)
    images = subprocess.check_output(
        [str(ROOT / "scripts/test-init-matrix.sh"), "images"], text=True,
    )
    write_json(evidence / "init-systems.json", {
        "schema_version": 1, "type": "init-systems", "id": "init-systems",
        "images": [dict(zip(("id", "image", "platform"), line.split("\t")))
                   for line in images.splitlines()],
        "script_sha256": sha256(ROOT / "scripts/test-init-matrix.sh"),
        "version": VERSION, "source_sha": SOURCE_SHA,
    })


class CandidatePipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        require_local_utilities()
        cls.temporary = tempfile.TemporaryDirectory(prefix="openshield-synthetic-release-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name)
        make_artifacts(cls.fixture / "built")
        zip_transport(cls.fixture / "built", cls.fixture / "artifacts")
        result = cls.assemble(cls.fixture / "artifacts", cls.fixture / "candidate")
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @staticmethod
    def assemble(artifacts: Path, output: Path) -> subprocess.CompletedProcess:
        return subprocess.run([
            sys.executable, str(ROOT / "scripts/assemble-release-candidate.py"),
            "--matrix", str(MATRIX), "--artifacts", str(artifacts),
            "--output", str(output), "--version", VERSION, "--tag", TAG,
            "--source-sha", SOURCE_SHA,
        ], capture_output=True, text=True, timeout=20)

    def setUp(self) -> None:
        self.temporary_case = tempfile.TemporaryDirectory(prefix="openshield-candidate-case-")
        self.addCleanup(self.temporary_case.cleanup)
        self.work = Path(self.temporary_case.name)
        self.candidate = self.work / "release"
        zip_transport(self.fixture / "candidate", self.candidate)

    def verify(self) -> subprocess.CompletedProcess:
        return subprocess.run([
            str(ROOT / "scripts/verify-release-candidate.sh"), str(self.candidate),
            VERSION, TAG, SOURCE_SHA, str(MATRIX),
        ], capture_output=True, text=True, timeout=20)

    def sealed_verify(self) -> subprocess.CompletedProcess:
        (self.work / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
        (self.work / "packaging").symlink_to(ROOT / "packaging", target_is_directory=True)
        return subprocess.run(
            ["bash", "-c", workflow_script("Verify the sealed release candidate")],
            cwd=self.work, env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "EXPECTED_CHECKSUM_MANIFEST_SHA256": sha256(self.fixture / "candidate/SHA256SUMS"),
                "SOURCE_SHA": SOURCE_SHA, "VERSION": VERSION, "TAG": TAG,
            }, capture_output=True, text=True, timeout=20,
        )

    def reseal_fixture(self) -> None:
        """Update only synthetic checksums, so semantic rejection is exercised."""
        entries = [f"{sha256(path)}  {path.name}\n"
                   for path in sorted(self.candidate.iterdir()) if path.name != "SHA256SUMS"]
        (self.candidate / "SHA256SUMS").write_text("".join(entries))

    def test_full_inventory_survives_both_zip_transports_and_sealed_verification(self) -> None:
        evidence = json.loads((self.candidate / "RELEASE-EVIDENCE.json").read_text())
        self.assertEqual(len(evidence["assets"]), 86)
        self.assertEqual(sum(item["kind"] == "binary" for item in evidence["assets"]), 43)
        self.assertEqual(sum(item["kind"] == "package" for item in evidence["assets"]), 43)
        self.assertEqual(len(evidence["package_install_results"]), 37)
        self.assertEqual(len(evidence["firewall_e2e_results"]), 74)
        self.assertEqual(len(list(self.candidate.iterdir())), 88)
        self.assertTrue(all(path.stat().st_mode & 0o7777 == 0o644 for path in self.candidate.iterdir()))
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.sealed_verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_assembler_rejects_missing_or_contradictory_runtime_evidence(self) -> None:
        for mode in ("missing", "wrong-source", "wrong-package"):
            with self.subTest(mode=mode):
                artifacts = self.work / mode
                shutil.copytree(self.fixture / "artifacts", artifacts)
                record_path = next((artifacts / "evidence").glob("firewall-*.json"))
                if mode == "missing":
                    record_path.unlink()
                    expected = "evidence inventory mismatch"
                else:
                    record = json.loads(record_path.read_text())
                    record["source_sha" if mode == "wrong-source" else "package_sha256"] = "0" * (40 if mode == "wrong-source" else 64)
                    write_json(record_path, record)
                    expected = "has unexpected"
                result = self.assemble(artifacts, self.work / (mode + "-output"))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_verifier_rejects_tampered_payload(self) -> None:
        package = next(self.candidate.glob("*.deb"))
        package.write_bytes(package.read_bytes() + b"tampered")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stdout)

    def test_verifier_rejects_incomplete_evidence_even_with_updated_checksums(self) -> None:
        path = self.candidate / "RELEASE-EVIDENCE.json"
        evidence = json.loads(path.read_text())
        evidence["firewall_e2e_results"].pop()
        write_json(path, evidence)
        self.reseal_fixture()
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("firewall evidence is incomplete or contradictory", result.stderr)

    def test_verifier_rejects_duplicate_checksum_entries(self) -> None:
        path = self.candidate / "SHA256SUMS"
        contents = path.read_text()
        path.write_text(contents + contents.splitlines()[0] + "\n")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate checksum entry", result.stderr)

    def test_sealed_step_rejects_rewritten_but_internally_consistent_candidate(self) -> None:
        package = next(self.candidate.glob("*.deb"))
        package.write_bytes(package.read_bytes() + b"substituted")
        evidence_path = self.candidate / "RELEASE-EVIDENCE.json"
        evidence = json.loads(evidence_path.read_text())
        for record in evidence["assets"]:
            if record["name"] == package.name:
                record.update(sha256=sha256(package), size=package.stat().st_size)
        for record in evidence["package_install_results"] + evidence["firewall_e2e_results"]:
            if record["package_asset"] == package.name:
                record["package_sha256"] = sha256(package)
        write_json(evidence_path, evidence)
        self.reseal_fixture()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.sealed_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the sealed upstream manifest", result.stdout)


class OfflinePublishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        require_local_utilities()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="openshield-offline-publish-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.release = self.work / "release"
        self.release.mkdir()
        for name in ("fixture-package.deb", "RELEASE-EVIDENCE.json", "SHA256SUMS"):
            (self.release / name).write_bytes(f"SYNTHETIC PUBLISH CONTROL-FLOW TEST: {name}\n".encode())
        self.bin = self.work / "bin"
        self.bin.mkdir()
        for command in ("git", "gh", "curl"):
            target = self.bin / command
            shutil.copyfile(ROOT / "tests/ci/release_publish_stub.py", target)
            target.chmod(0o755)
        # Only these local utilities are reachable. A newly introduced external
        # command fails instead of falling through to the developer's PATH.
        for command in ("jq", "sha256sum", "stat", "sort", "grep"):
            executable = shutil.which(command, path="/usr/bin:/bin")
            self.assertIsNotNone(executable, f"required local utility: {command}")
            (self.bin / command).symlink_to(executable)
        self.runner_temp = self.work / "runner-temp"
        self.runner_temp.mkdir()
        self.state_path = self.work / "fake-github.json"
        self.tag = "v0.0.0"
        self.state = {"release": None, "assets": [], "payloads": {}, "mutations": [],
                      "local_names": sorted(path.name for path in self.release.iterdir())}

    def marker(self) -> str:
        manifest = "".join(f"{path.name}\t{path.stat().st_size}\tsha256:{sha256(path)}\n"
                           for path in sorted(self.release.iterdir()))
        return (f"<!-- openshield-release:v1 tag-ref={TAG_REF_SHA} source={SOURCE_SHA} "
                f"manifest={hashlib.sha256(manifest.encode()).hexdigest()} -->")

    def existing_release(self, *, draft: bool = False, complete: bool = True) -> None:
        self.state["release"] = {
            "id": 101, "tag_name": self.tag, "body": self.marker(), "draft": draft,
            "prerelease": "-" in self.tag.split("+", 1)[0], "immutable": False,
            "upload_url": "https://uploads.github.com/repos/offline-fixture/openshield/releases/101/assets{?name,label}",
        }
        paths = sorted(self.release.iterdir())
        if not complete:
            paths = paths[:1]
        for index, path in enumerate(paths, 1001):
            self.state["assets"].append({
                "id": index, "name": path.name, "size": path.stat().st_size,
                "state": "uploaded", "digest": "sha256:" + sha256(path),
            })
            self.state["payloads"][str(index)] = base64.b64encode(path.read_bytes()).decode("ascii")

    def environment(self, repair: bool = False) -> dict[str, str]:
        # Deliberately do not inherit credentials, shell startup hooks or PATH.
        return {
            "PATH": str(self.bin), "LC_ALL": "C",
            "RUNNER_TEMP": str(self.runner_temp), "GITHUB_REPOSITORY": "offline-fixture/openshield",
            "GH_TOKEN": "offline-test-token", "TAG": self.tag,
            "SOURCE_SHA": SOURCE_SHA, "EXPECTED_TAG_REF_SHA": TAG_REF_SHA,
            "ALLOW_PUBLISHED_REPAIR": "true" if repair else "false",
            "OPENSHIELD_PUBLISH_STUB_STATE": str(self.state_path),
        }

    def publish(self, *, repair: bool = False) -> subprocess.CompletedProcess:
        write_json(self.state_path, self.state)
        result = subprocess.run(
            ["/bin/bash", "-c", workflow_script("Publish release safely")],
            cwd=self.work, env=self.environment(repair), capture_output=True, text=True, timeout=30,
        )
        self.state = json.loads(self.state_path.read_text())
        self.assertEqual(self.state.get("refusals", []), [], result.stdout + result.stderr)
        return result

    def assert_success(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.state["release"]["draft"])
        self.assertEqual(sorted(asset["name"] for asset in self.state["assets"]), self.state["local_names"])

    def assert_rejected(self, result: subprocess.CompletedProcess, message: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stdout + result.stderr)
        self.assertEqual(self.state["mutations"], [])

    def test_new_draft_is_uploaded_verified_and_published_then_idempotent(self) -> None:
        self.assert_success(self.publish())
        self.assertEqual(self.state["mutations"], ["create", *[
            "upload:" + name for name in self.state["local_names"]], "publish"])
        self.state["mutations"] = []
        self.assert_success(self.publish())
        self.assertEqual(self.state["mutations"], [])

    def test_owned_draft_resume_uploads_only_missing_assets(self) -> None:
        self.existing_release(draft=True, complete=False)
        existing_name = self.state["assets"][0]["name"]
        self.assert_success(self.publish())
        self.assertEqual(self.state["mutations"], [*[
            "upload:" + name for name in self.state["local_names"] if name != existing_name], "publish"])

    def test_published_repair_requires_authorization(self) -> None:
        self.existing_release(complete=False)
        self.assert_rejected(self.publish(), "not authorized to repair")
        self.assert_success(self.publish(repair=True))
        self.assertTrue(all(item.startswith("upload:") for item in self.state["mutations"]))

    def test_conflicting_remote_digest_never_overwrites(self) -> None:
        self.existing_release()
        self.state["assets"][0]["digest"] = "sha256:" + "0" * 64
        self.assert_rejected(self.publish(repair=True), "differs from the current build")

    def test_missing_digest_is_verified_by_downloading_bytes(self) -> None:
        self.existing_release()
        asset = self.state["assets"][0]
        asset["digest"] = None
        self.assert_success(self.publish())
        self.assertIn(asset["name"], self.state["downloads"])
        self.assertEqual(self.state["mutations"], [])

    def test_missing_digest_download_detects_same_size_corruption(self) -> None:
        self.existing_release()
        asset = self.state["assets"][0]
        asset["digest"] = None
        self.state["payloads"][str(asset["id"])] = base64.b64encode(b"x" * asset["size"]).decode("ascii")
        self.assert_rejected(self.publish(), "differs from the current build")

    def test_unowned_draft_is_rejected(self) -> None:
        self.existing_release(draft=True, complete=False)
        self.state["release"]["body"] = "Another draft"
        self.assert_rejected(self.publish(), "not owned by this source and asset manifest")

    def test_immutable_release_cannot_be_repaired(self) -> None:
        self.existing_release(complete=False)
        self.state["release"]["immutable"] = True
        self.assert_rejected(self.publish(repair=True), "Immutable release is missing")

    def test_tag_movement_before_upload_is_rejected(self) -> None:
        self.existing_release(draft=True, complete=False)
        self.state["move_tag_on_fetch"] = 2
        self.assert_rejected(self.publish(), "moved from")

    def test_release_identity_change_before_upload_is_rejected(self) -> None:
        self.existing_release(draft=True, complete=False)
        self.state["change_identity_on_lookup"] = 2
        self.assert_rejected(self.publish(), "identity changed during publication")

    def test_prerelease_draft_uses_prerelease_publication_flags(self) -> None:
        self.tag = "v0.0.0-rc.1"
        self.assert_success(self.publish())
        self.assertTrue(self.state["release"]["prerelease"])

    def test_stubs_refuse_unrecognized_external_operations(self) -> None:
        for command, arguments in (("git", ["push"]), ("gh", ["release", "delete", self.tag]),
                                   ("curl", ["https://example.invalid/"])):
            with self.subTest(command=command):
                write_json(self.state_path, self.state)
                result = subprocess.run([str(self.bin / command), *arguments],
                                        env=self.environment(), cwd=self.work,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 97)
                state = json.loads(self.state_path.read_text())
                self.assertTrue(state["refusals"])
                self.assertEqual(state["mutations"], [])


if __name__ == "__main__":
    unittest.main()
