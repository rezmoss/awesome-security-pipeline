#!/usr/bin/env python3
"""Publish a normalized SBOM benchmark result into reviewed repository history."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import sys
from typing import Any


DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=pathlib.Path)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--root", required=True, type=pathlib.Path)
    return parser.parse_args()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def tool_versions(result: dict[str, Any]) -> str:
    return ", ".join(f"{item['id']} {item['version']}" for item in result.get("tools") or [])


def render_index(root: pathlib.Path) -> str:
    history = root / "history"
    entries = []
    for data_path in sorted(history.glob("*.json"), reverse=True):
        result = load_json(data_path)
        date = str(result.get("run_date", data_path.stem))
        report_path = data_path.with_suffix(".md")
        fixture_count = len(result.get("fixtures") or [])
        run_count = sum(len(item.get("runs") or []) for item in result.get("fixtures") or [])
        entries.append(
            f"| {date} | {str(result.get('status', 'unknown')).upper()} | {fixture_count} / {run_count} "
            f"| {tool_versions(result)} | [report](history/{report_path.name}) | [JSON](history/{data_path.name}) |"
        )

    lines = [
        "# SBOM benchmark reports",
        "",
        "These are maintainer-reviewed monthly snapshots from the "
        "[SBOM compatibility benchmark](../../benchmarks/sbom/README.md). The suite still runs weekly; raw SBOMs "
        "and logs remain workflow artifacts for 90 days, while normalized monthly evidence is retained here.",
        "",
        "[Read the latest report](latest.md) · [Download the latest normalized JSON](latest.json)",
        "",
        "## History",
        "",
        "| Date | Status | Fixtures / tool runs | Tool versions | Report | Data |",
        "|---|---|---:|---|---|---|",
    ]
    lines.extend(entries or ["| — | No reviewed snapshots | 0 / 0 | — | — | — |"])
    lines.extend([
        "",
        "A passing snapshot means the configured commands completed, documents validated structurally, minimum "
        "inventory rules passed, and every configured identity was found. It is not a security certification, "
        "vulnerability assessment, license audit, or proof of complete component discovery.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    result = load_json(args.result)
    run_date = str(result.get("run_date", ""))
    if result.get("schema_version") != 1:
        raise ValueError("unsupported benchmark result schema")
    if not DATE_PATTERN.fullmatch(run_date):
        raise ValueError(f"invalid run date: {run_date!r}")
    if not args.report.is_file():
        raise ValueError(f"report not found: {args.report}")

    history = args.root / "history"
    history.mkdir(parents=True, exist_ok=True)
    dated_json = history / f"{run_date}.json"
    dated_report = history / f"{run_date}.md"

    shutil.copyfile(args.result, dated_json)
    shutil.copyfile(args.report, dated_report)
    shutil.copyfile(args.result, args.root / "latest.json")
    shutil.copyfile(args.report, args.root / "latest.md")
    (args.root / "README.md").write_text(render_index(args.root), encoding="utf-8")

    print(f"Published normalized snapshot for {run_date} with status {result['status']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"publication failed: {exc}", file=sys.stderr)
        sys.exit(1)
