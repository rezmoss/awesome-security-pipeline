#!/usr/bin/env python3
"""Record a normalized SBOM benchmark run in the benchmark data branch.

The data branch keeps one compact JSON file per run (package-level inventory, scores, and
sbomlyze summaries). Raw SBOMs are not committed; the published site serves the latest set.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import sbom_benchmark  # noqa: E402

DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SUPPORTED_SCHEMAS = {1, 2}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=pathlib.Path)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--result", type=pathlib.Path)
    parser.add_argument("--sbomlyze", type=pathlib.Path)
    parser.add_argument(
        "--seed", type=pathlib.Path, action="append", default=[],
        help="legacy snapshot to import when the data branch has no run for that date",
    )
    return parser.parse_args()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def write_json(path: pathlib.Path, value: Any, indent: int | None = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        separators = None if indent else (",", ":")
        json.dump(value, handle, indent=indent, sort_keys=True, separators=separators)
        handle.write("\n")


def fixture_config(config: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any] | None:
    """Return the current fixture definition when it describes the same target as the run."""
    for item in config.get("fixtures") or []:
        if item["id"] != fixture.get("id"):
            continue
        target = item.get("path") or item.get("source_image")
        if fixture.get("target") in (None, target):
            return item
    return None


def compact(result: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Bring any supported snapshot to the compact schema-2 shape with ground-truth scores."""
    if result.get("schema_version") not in SUPPORTED_SCHEMAS:
        raise ValueError(f"unsupported benchmark result schema: {result.get('schema_version')}")
    compacted = json.loads(json.dumps(result))
    for fixture in compacted.get("fixtures") or []:
        definition = fixture_config(config, fixture)
        for run in fixture.get("runs") or []:
            components = run.get("components") or []
            if "inventory_only_counts" not in run:
                packages, counts, digest = sbom_benchmark.split_inventory(components)
                run["components"] = packages
                run["relationships"] = sbom_benchmark.package_relationships(
                    run.get("relationships") or [], packages
                )
                run["inventory_only_counts"] = counts
                run["inventory_only_digest"] = digest
                run.pop("change_from_previous", None)
            if definition and "score" not in run:
                run["score"] = sbom_benchmark.score_run(definition, run["components"])
                run["score"]["retroactive"] = True
            run.pop("log_tail", None)
    return compacted


def with_changes(runs: list[dict[str, Any]]) -> None:
    """Recompute package-level changes between consecutive runs (oldest first)."""
    previous: dict[str, Any] = {}
    for result in runs:
        for fixture in result.get("fixtures") or []:
            for run in fixture.get("runs") or []:
                old = sbom_benchmark.previous_run(previous, fixture["id"], run["tool"])
                run["change_from_previous"] = sbom_benchmark.change_from_previous(
                    run, old, bool(previous)
                )
        result["previous_run_date"] = previous.get("run_date")
        result["tool_changes"] = sbom_benchmark.tool_changes(result.get("tools") or [], previous)
        previous = result


def index_entry(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_date": result["run_date"],
        "status": result.get("status", "unknown"),
        "commit": result.get("commit"),
        "tools": {tool["id"]: tool["version"] for tool in result.get("tools") or []},
        "fixtures": len(result.get("fixtures") or []),
        "runs": sum(len(fixture.get("runs") or []) for fixture in result.get("fixtures") or []),
    }


DATA_README = """# SBOM benchmark data

Machine-written by `.github/workflows/sbom-benchmark.yml` on the default branch. Each file in
`runs/` is one weekly run in the compact normalized schema: package-level components,
ground-truth scores, file and cryptographic-asset counts with a digest, tool versions, and
asset digests. `runs/<date>.sbomlyze.json` holds sbomlyze minimum-element and drift summaries.

Do not edit by hand; the published report site is rebuilt from this branch.
"""


def main() -> int:
    args = parse_args()
    config = load_json(args.config)
    runs_dir = args.data_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    for seed in args.seed:
        legacy = load_json(seed)
        date = str(legacy.get("run_date", ""))
        if DATE_PATTERN.fullmatch(date) and not (runs_dir / f"{date}.json").exists():
            write_json(runs_dir / f"{date}.json", compact(legacy, config), indent=None)
            print(f"Imported legacy snapshot {date}")

    if args.result:
        result = load_json(args.result)
        date = str(result.get("run_date", ""))
        if not DATE_PATTERN.fullmatch(date):
            raise ValueError(f"invalid run date: {date!r}")
        write_json(runs_dir / f"{date}.json", compact(result, config), indent=None)
        if args.sbomlyze and args.sbomlyze.is_file():
            write_json(runs_dir / f"{date}.sbomlyze.json", load_json(args.sbomlyze), indent=None)
        print(f"Recorded run {date} with status {result.get('status')}")

    paths = sorted(path for path in runs_dir.glob("*.json") if DATE_PATTERN.fullmatch(path.stem))
    runs = [load_json(path) for path in paths]
    with_changes(runs)
    for path, result in zip(paths, runs):
        write_json(path, result, indent=None)
    write_json(args.data_dir / "index.json", {"runs": [index_entry(item) for item in reversed(runs)]})
    if runs:
        write_json(args.data_dir / "latest.json", runs[-1])
    (args.data_dir / "README.md").write_text(DATA_README, encoding="utf-8")
    print(f"Data branch holds {len(runs)} runs")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"publication failed: {exc}", file=sys.stderr)
        sys.exit(1)
