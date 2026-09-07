#!/usr/bin/python3
"""Deny-by-default, filesystem-only substitutes for publish git/gh/curl calls.

Copied under each command name into a temporary test PATH. This helper never
starts subprocesses or opens a network connection. Its JSON records are fake
test state, never release evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import quote, unquote


class Refused(RuntimeError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def dispatch(command: str, args: list[str], state: dict) -> None:
    tag = os.environ["TAG"]
    repository = "offline-fixture/openshield"
    endpoint = f"repos/{repository}/releases/101"
    release = state["release"]

    if command == "git":
        ref = f"refs/tags/{tag}"
        if args == ["fetch", "--force", "--no-tags", "origin", f"{ref}:{ref}"]:
            state["fetches"] = state.get("fetches", 0) + 1
            return
        if args == ["rev-parse", ref]:
            moved = state.get("move_tag_on_fetch", 10**9) <= state.get("fetches", 0)
            print("f" * 40 if moved else os.environ["EXPECTED_TAG_REF_SHA"])
            return
        if args == ["rev-parse", ref + "^{commit}"]:
            print(os.environ["SOURCE_SHA"])
            return

    if command == "gh":
        if args[:2] == ["api", "graphql"]:
            query = (
                "query($owner:String!,$name:String!,$tag:String!)"
                "{repository(owner:$owner,name:$name)"
                "{release(tagName:$tag){id databaseId}}}"
            )
            require(args == [
                "api", "graphql", "-f", f"query={query}",
                "-f", "owner=offline-fixture", "-f", "name=openshield",
                "-f", f"tag={tag}",
            ], "unrecognized GraphQL request")
            state["lookups"] = state.get("lookups", 0) + 1
            identity = None
            if release is not None:
                changed = state.get("change_identity_on_lookup", 10**9) <= state["lookups"]
                identity = {"id": "changed" if changed else "fixture-node", "databaseId": 101}
            print(json.dumps({"data": {"repository": {"release": identity}}}))
            return
        if args == ["api", endpoint]:
            require(release is not None, "reading a nonexistent fixture release")
            print(json.dumps(release))
            return
        if args == ["api", endpoint + "/assets?per_page=100"]:
            print(json.dumps(state["assets"]))
            return
        if args[:3] == ["release", "create", tag]:
            require(release is None, "duplicate draft creation")
            require(len(args) >= 10, "incomplete draft creation")
            marker = args[7]
            expected = [
                "release", "create", tag, "--draft", "--verify-tag",
                "--generate-notes", "--notes", marker,
                "--title", f"OpenShield {tag}",
            ]
            prerelease = "-" in tag.split("+", 1)[0]
            if prerelease:
                expected.append("--prerelease")
            require(args == expected, "unrecognized draft creation options")
            state["release"] = {
                "id": 101, "tag_name": tag, "body": marker,
                "upload_url": f"https://uploads.github.com/{endpoint}/assets{{?name,label}}",
                "draft": True, "prerelease": prerelease, "immutable": False,
            }
            state["mutations"].append("create")
            return
        if args[:3] == ["api", "-H", "Accept: application/octet-stream"]:
            for asset in state["assets"]:
                asset_endpoint = f"repos/{repository}/releases/assets/{asset['id']}"
                if args == ["api", "-H", "Accept: application/octet-stream", asset_endpoint]:
                    sys.stdout.buffer.write(base64.b64decode(state["payloads"][str(asset["id"])]))
                    state.setdefault("downloads", []).append(asset["name"])
                    return
        if args[:3] == ["api", "--method", "PATCH"]:
            require(release is not None and release["draft"], "publishing a non-draft fixture")
            prerelease = "true" if release["prerelease"] else "false"
            latest = "false" if release["prerelease"] else "legacy"
            require(args == [
                "api", "--method", "PATCH", "-F", "draft=false",
                "-F", f"prerelease={prerelease}", "-f", f"make_latest={latest}", endpoint,
            ], "unrecognized release patch")
            release["draft"] = False
            state["mutations"].append("publish")
            return

    if command == "curl":
        require(release is not None, "upload without a fixture release")
        require(len(args) == 18, "unexpected curl argument count")
        source_argument, output_argument, url = args[14], args[16], args[17]
        prefix = f"https://uploads.github.com/{endpoint}/assets?name="
        require(url.startswith(prefix), "unrecognized upload URL")
        name = unquote(url[len(prefix):])
        require(quote(name, safe="~") == url[len(prefix):], "noncanonical upload name")
        require(name in state["local_names"], "upload outside the fixture inventory")
        require(source_argument == f"@release/{name}", "upload outside the fixture directory")
        require(output_argument == str(Path(os.environ["RUNNER_TEMP"]) / "openshield-release-upload-response.json"), "unexpected response path")
        require(args == [
            "--fail-with-body", "--silent", "--show-error", "--request", "POST",
            "--header", "Accept: application/vnd.github+json",
            "--header", "Authorization: Bearer offline-test-token",
            "--header", "Content-Type: application/octet-stream",
            "--header", "X-GitHub-Api-Version: 2026-03-10",
            "--data-binary", source_argument, "--output", output_argument, url,
        ], "unrecognized upload arguments")
        require(not any(asset["name"] == name for asset in state["assets"]), "attempted overwrite")
        data = (Path("release") / name).read_bytes()
        asset_id = max([asset["id"] for asset in state["assets"]] + [1000]) + 1
        asset = {
            "id": asset_id, "name": name, "size": len(data),
            "state": "uploaded", "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        }
        state["assets"].append(asset)
        state["payloads"][str(asset_id)] = base64.b64encode(data).decode("ascii")
        state["mutations"].append("upload:" + name)
        Path(output_argument).write_text(json.dumps(asset), encoding="utf-8")
        return

    raise Refused(f"unrecognized {command} invocation: {args!r}")


def main() -> int:
    state_path = Path(os.environ["OPENSHIELD_PUBLISH_STUB_STATE"])
    state = json.loads(state_path.read_text(encoding="utf-8"))
    command = Path(sys.argv[0]).name
    state.setdefault("calls", []).append([command, *sys.argv[1:]])
    try:
        dispatch(command, sys.argv[1:], state)
    except (Refused, KeyError, ValueError, OSError) as error:
        state.setdefault("refusals", []).append(str(error))
        print(f"offline publish stub refused: {error}", file=sys.stderr)
        return 97
    finally:
        state_path.write_text(json.dumps(state), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
