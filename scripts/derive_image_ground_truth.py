#!/usr/bin/env python3
"""Derive the container fixture's ground truth directly from the image, without any SBOM generator.

Installed Alpine packages come from the apk database (/lib/apk/db/installed); the Go toolchain
version comes from /usr/local/go/VERSION. With --check, exit non-zero when fixtures.json differs.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any

APK_DATABASE = "/lib/apk/db/installed"
GO_VERSION_FILE = "/usr/local/go/VERSION"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--image", help="local image reference; defaults to the fixture's image")
    parser.add_argument("--check", action="store_true", help="compare instead of printing")
    parser.add_argument("--write", action="store_true", help="update the config in place")
    return parser.parse_args()


def read_from_image(image: str, path: str) -> str:
    completed = subprocess.run(
        ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
         "--entrypoint", "cat", image, path],
        check=True, capture_output=True, text=True,
    )
    return completed.stdout


def parse_apk_database(text: str) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    name = version = ""
    for line in text.splitlines() + [""]:
        if not line.strip():
            if name and version:
                packages.append((name, version))
            name = version = ""
        elif line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:"):
            version = line[2:].strip()
    return sorted(packages)


def ground_truth(apk_text: str, go_version_text: str) -> list[dict[str, Any]]:
    expected = [
        {"name": name, "version": version, "relationship": "installed-os-package",
         "ecosystem": "apk", "gate": False}
        for name, version in parse_apk_database(apk_text)
    ]
    go_version = go_version_text.splitlines()[0].strip() if go_version_text.strip() else ""
    if go_version:
        expected.append({
            "name": "stdlib", "version": go_version.removeprefix("go"),
            "relationship": "go-toolchain", "ecosystem": "golang", "gate": False,
        })
    return expected


def main() -> int:
    args = parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    fixture = next(item for item in config["fixtures"] if item["kind"] == "image")
    image = args.image or fixture["image"]
    derived = ground_truth(
        read_from_image(image, APK_DATABASE), read_from_image(image, GO_VERSION_FILE)
    )
    if args.check:
        if fixture.get("expected_components") != derived:
            print("Container ground truth in fixtures.json does not match the image:", file=sys.stderr)
            print(json.dumps(derived, indent=2), file=sys.stderr)
            return 1
        print(f"Container ground truth matches the image ({len(derived)} components)")
        return 0
    if args.write:
        fixture["expected_components"] = derived
        args.config.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {len(derived)} ground-truth components to {args.config}")
        return 0
    print(json.dumps(derived, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
