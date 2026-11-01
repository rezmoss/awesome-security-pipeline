#!/usr/bin/env python3
"""Analyze benchmark SBOMs with sbomlyze and prepare sanitized copies for publication.

For every fixture and generator this records sbomlyze's NTIA / CISA 2025 / BSI TR-03183
minimum-element checks and, when the previous run's raw SBOM is available, a week-over-week
drift summary plus sbomlyze's self-contained HTML diff. sbomlyze is maintained by this
repository's maintainer, so ground-truth scoring stays in sbom_benchmark.py.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Any

DOCUMENTS = {
    "syft": "sbom.cdx.json",
    "trivy": "sbom.cdx.json",
    "cdxgen": "sbom.cdx.json",
    "microsoft-sbom-tool": "manifest/_manifest/spdx_2.2/manifest.spdx.json",
}
CHANGE_SAMPLE_LIMIT = 25


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=pathlib.Path)
    parser.add_argument("--raw-dir", required=True, type=pathlib.Path)
    parser.add_argument("--previous-raw-dir", type=pathlib.Path)
    parser.add_argument("--previous-run-date")
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--sbomlyze", default="sbomlyze")
    parser.add_argument(
        "--redact", action="append", default=[], metavar="PATH=PLACEHOLDER",
        help="replace an absolute runner path in published SBOMs",
    )
    return parser.parse_args()


def document_name(tool: str) -> str:
    return f"{tool}.spdx.json" if tool == "microsoft-sbom-tool" else f"{tool}.cdx.json"


def sanitized_copy(source: pathlib.Path, destination: pathlib.Path, redactions: list[tuple[str, str]]) -> None:
    text = source.read_text(encoding="utf-8", errors="replace")
    for path, placeholder in redactions:
        text = text.replace(path, placeholder)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def run_sbomlyze(binary: str, arguments: list[str], cwd: pathlib.Path) -> tuple[int, str, str]:
    completed = subprocess.run(
        [binary, *arguments, "--no-pager"],
        cwd=cwd, capture_output=True, text=True, check=False, timeout=300,
    )
    return completed.returncode, completed.stdout, completed.stderr.strip()


def compliance_summary(report: dict[str, Any]) -> dict[str, Any]:
    compliance = report.get("compliance") or {}
    standards = {}
    for key, value in compliance.items():
        if not isinstance(value, dict):
            continue
        standards[key] = {
            "standard": value.get("standard", key),
            "score": value.get("score"),
            "passed": value.get("passed"),
            "total": value.get("total"),
            "checks": [
                {
                    "id": check.get("id"),
                    "name": check.get("name"),
                    "passed": bool(check.get("passed")),
                    "details": check.get("details"),
                }
                for check in value.get("checks") or []
            ],
        }
    return {"overall_score": compliance.get("overall_score"), "standards": standards}


def change_sample(change: dict[str, Any]) -> dict[str, Any]:
    before = change.get("before") or {}
    after = change.get("after") or {}
    return {
        "name": change.get("name"),
        "before_version": before.get("version", ""),
        "after_version": after.get("version", ""),
        "drift": (change.get("drift") or {}).get("type", ""),
        "changes": change.get("changes") or [],
    }


def diff_summary(report: dict[str, Any]) -> dict[str, Any]:
    diff = report.get("diff") or {}
    changed = diff.get("changed") or []
    # Components without a PURL or CPE can be matched by a per-run random bom-ref, so an
    # unchanged component appears as removed and re-added. Net those out by name and version.
    def identity(item: dict[str, Any]) -> str:
        return f"{item.get('name')}@{item.get('version', '')}"

    added_ids = [identity(item) for item in diff.get("added") or []]
    removed_ids = [identity(item) for item in diff.get("removed") or []]
    churn = sorted(set(added_ids) & set(removed_ids))
    added = [item for item in added_ids if item not in churn]
    removed = [item for item in removed_ids if item not in churn]
    return {
        "added": len(added),
        "removed": len(removed),
        "reference_churn": len(churn),
        "changed": len(changed),
        "drift": diff.get("drift_summary") or {"version_drift": 0, "integrity_drift": 0, "metadata_drift": 0},
        "findings": [item.get("message", "") for item in (report.get("findings") or {}).get("findings") or []],
        "added_sample": added[:CHANGE_SAMPLE_LIMIT],
        "removed_sample": removed[:CHANGE_SAMPLE_LIMIT],
        "changed_sample": [change_sample(item) for item in changed[:CHANGE_SAMPLE_LIMIT]],
    }


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    result = json.loads(args.result.read_text(encoding="utf-8"))
    redactions = []
    for item in args.redact:
        path, _, placeholder = item.partition("=")
        if path:
            redactions.append((path, placeholder))
    redactions.sort(key=lambda pair: len(pair[0]), reverse=True)

    published = args.output_dir / "raw"
    html_dir = args.output_dir / "html"
    analysis: dict[str, Any] = {
        "run_date": result["run_date"],
        "previous_run_date": args.previous_run_date if args.previous_raw_dir else None,
        "runs": {},
        "errors": [],
    }
    code, stdout, _ = run_sbomlyze(args.sbomlyze, ["--version"], pathlib.Path.cwd())
    analysis["sbomlyze_version"] = stdout.splitlines()[0].strip() if code == 0 and stdout else "unknown"

    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary)
        for fixture in result["fixtures"]:
            for run in fixture["runs"]:
                tool = run["tool"]
                entry: dict[str, Any] = {"compliance": None, "diff": None, "errors": []}
                analysis["runs"].setdefault(fixture["id"], {})[tool] = entry
                source = args.raw_dir / fixture["id"] / tool / DOCUMENTS[tool]
                if not source.is_file():
                    entry["errors"].append("no generated document")
                    continue
                current_name = f"{tool}-{result['run_date']}.json"
                current = work / fixture["id"] / current_name
                sanitized_copy(source, current, redactions)
                sanitized_copy(source, published / fixture["id"] / document_name(tool), redactions)

                code, stdout, stderr = run_sbomlyze(
                    args.sbomlyze, [current_name, "--compliance", "--json"], current.parent
                )
                if code == 0:
                    entry["compliance"] = compliance_summary(json.loads(stdout))
                else:
                    entry["errors"].append(f"compliance exited with {code}: {stderr[:300]}")

                previous_source = (
                    args.previous_raw_dir / fixture["id"] / tool / DOCUMENTS[tool]
                    if args.previous_raw_dir else None
                )
                if not previous_source or not previous_source.is_file():
                    continue
                previous_name = f"{tool}-{args.previous_run_date or 'previous'}.json"
                sanitized_copy(previous_source, current.parent / previous_name, redactions)
                code, stdout, stderr = run_sbomlyze(
                    args.sbomlyze, [previous_name, current_name, "--json"], current.parent
                )
                if code not in (0, 1):
                    entry["errors"].append(f"diff exited with {code}: {stderr[:300]}")
                    continue
                entry["diff"] = diff_summary(json.loads(stdout))
                code, stdout, stderr = run_sbomlyze(
                    args.sbomlyze, [previous_name, current_name, "--format", "html"], current.parent
                )
                if code in (0, 1) and stdout.strip():
                    target = html_dir / fixture["id"] / f"{tool}.html"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(stdout, encoding="utf-8")
                    entry["diff"]["html"] = f"{fixture['id']}/{tool}.html"
                else:
                    entry["errors"].append(f"html diff exited with {code}: {stderr[:300]}")
    analysis["errors"] = [
        f"{fixture_id}/{tool}: {error}"
        for fixture_id, tools in analysis["runs"].items()
        for tool, entry in tools.items()
        for error in entry["errors"]
    ]
    return analysis


def main() -> int:
    args = parse_args()
    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True)
    analysis = analyze(args)
    with (args.output_dir / "sbomlyze.json").open("w", encoding="utf-8") as handle:
        json.dump(analysis, handle, indent=2, sort_keys=True)
        handle.write("\n")
    for error in analysis["errors"]:
        print(f"warning: {error}", file=sys.stderr)
    print(f"sbomlyze analysis written to {args.output_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"sbomlyze analysis failed: {exc}", file=sys.stderr)
        sys.exit(1)
