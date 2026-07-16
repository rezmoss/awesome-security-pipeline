#!/usr/bin/env python3
"""Run and normalize the repository's cross-tool SBOM benchmark."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import shlex
import subprocess
import sys
import time
import urllib.parse
from typing import Any


TOOLS = ("syft", "trivy", "cdxgen", "microsoft-sbom-tool")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--tool-metadata", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--previous", type=pathlib.Path)
    parser.add_argument("--run-date", default=dt.datetime.now(dt.timezone.utc).date().isoformat())
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "local"))
    parser.add_argument("--skip-kind", action="append", default=[])
    return parser.parse_args()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def display_command(command: list[str], repo_root: pathlib.Path, output_dir: pathlib.Path) -> str:
    replacements = path_replacements(repo_root, output_dir)
    rendered: list[str] = []
    for argument in command:
        clean = argument
        for source, replacement in replacements:
            clean = clean.replace(source, replacement)
        rendered.append(shlex.quote(clean))
    return " ".join(rendered)


def path_replacements(
    repo_root: pathlib.Path, output_dir: pathlib.Path
) -> list[tuple[str, str]]:
    candidates = {
        str(output_dir): "$OUTPUT_DIR",
        str(output_dir.resolve()): "$OUTPUT_DIR",
        str(repo_root): "$REPOSITORY",
        str(repo_root.resolve()): "$REPOSITORY",
    }
    return sorted(candidates.items(), key=lambda item: len(item[0]), reverse=True)


def sanitize_paths(value: str, repo_root: pathlib.Path, output_dir: pathlib.Path) -> str:
    clean = value
    for source, replacement in path_replacements(repo_root, output_dir):
        clean = clean.replace(source, replacement)
    return clean


def run_command(
    command: list[str],
    log_path: pathlib.Path,
    env: dict[str, str],
    timeout: int = 600,
) -> tuple[int, float, str | None]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    error: str | None = None
    return_code = 127
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                command,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
                check=False,
                timeout=timeout,
                text=True,
            )
        return_code = completed.returncode
    except FileNotFoundError as exc:
        error = str(exc)
        log_path.write_text(f"{error}\n", encoding="utf-8")
    except subprocess.TimeoutExpired:
        error = f"command timed out after {timeout} seconds"
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"\n{error}\n")
        return_code = 124
    return return_code, round(time.perf_counter() - started, 3), error


def log_tail(path: pathlib.Path, lines: int = 12) -> list[str]:
    if not path.exists():
        return []
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return content[-lines:]


def normalized_component(component: dict[str, Any], subject: bool = False) -> dict[str, Any]:
    purl = str(component.get("purl") or "")
    if not purl:
        for reference in component.get("externalRefs") or []:
            if str(reference.get("referenceType", "")).lower() == "purl":
                purl = str(reference.get("referenceLocator") or "")
                break
    decoded_purl = urllib.parse.unquote(purl)
    if "?" in decoded_purl:
        base, query = decoded_purl.split("?", 1)
        stable_qualifiers = [
            qualifier for qualifier in query.split("&")
            if not qualifier.lower().startswith("tag_id=")
        ]
        decoded_purl = base + (f"?{'&'.join(stable_qualifiers)}" if stable_qualifiers else "")
    return {
        "type": str(component.get("type") or ("package" if "SPDXID" in component else "unknown")),
        "name": str(component.get("name") or ""),
        "version": str(component.get("version") or component.get("versionInfo") or ""),
        "purl": decoded_purl,
        "subject": subject,
    }


def component_key(component: dict[str, Any]) -> str:
    if component.get("purl") and not component.get("subject"):
        return str(component["purl"]).lower()
    return "|".join(
        (
            str(component.get("type", "")).lower(),
            str(component.get("name", "")).lower(),
            str(component.get("version", "")).lower(),
            "subject" if component.get("subject") else "component",
        )
    )


def relationship_key(relationship: dict[str, Any]) -> str:
    source = relationship.get("from_purl") or (
        f"{relationship.get('from_name', '')}@{relationship.get('from_version', '')}"
    )
    target = relationship.get("to_purl") or (
        f"{relationship.get('to_name', '')}@{relationship.get('to_version', '')}"
    )
    return f"{source} {relationship.get('type', 'UNKNOWN')} {target}".lower()


def parse_document(path: pathlib.Path) -> dict[str, Any]:
    document = load_json(path)
    components: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    reference_map: dict[str, dict[str, Any]] = {}
    if document.get("bomFormat") == "CycloneDX":
        subject = (document.get("metadata") or {}).get("component")
        if isinstance(subject, dict):
            normalized = normalized_component(subject, subject=True)
            components.append(normalized)
            if subject.get("bom-ref"):
                reference_map[str(subject["bom-ref"])] = normalized
        for item in document.get("components") or []:
            if not isinstance(item, dict):
                continue
            normalized = normalized_component(item)
            components.append(normalized)
            if item.get("bom-ref"):
                reference_map[str(item["bom-ref"])] = normalized
        for dependency in document.get("dependencies") or []:
            source = reference_map.get(str(dependency.get("ref", "")))
            for target_ref in dependency.get("dependsOn") or []:
                target = reference_map.get(str(target_ref))
                if source and target:
                    relationships.append(normalized_relationship(source, target, "DEPENDS_ON"))
        specification = f"CycloneDX {document.get('specVersion', 'unknown')}"
        relationship_count = len(document.get("dependencies") or [])
        file_count = sum(1 for item in components if item["type"] == "file")
    elif str(document.get("spdxVersion", "")).startswith("SPDX-"):
        for item in document.get("packages") or []:
            if not isinstance(item, dict):
                continue
            normalized = normalized_component(
                item, subject=item.get("SPDXID") == "SPDXRef-RootPackage"
            )
            components.append(normalized)
            if item.get("SPDXID"):
                reference_map[str(item["SPDXID"])] = normalized
        for relationship in document.get("relationships") or []:
            source = reference_map.get(str(relationship.get("spdxElementId", "")))
            target = reference_map.get(str(relationship.get("relatedSpdxElement", "")))
            if source and target:
                relationships.append(
                    normalized_relationship(
                        source, target, str(relationship.get("relationshipType", "UNKNOWN"))
                    )
                )
        specification = str(document["spdxVersion"]).replace("SPDX-", "SPDX ")
        relationship_count = len(document.get("relationships") or [])
        file_count = len(document.get("files") or [])
    else:
        raise ValueError("document is neither CycloneDX JSON nor SPDX JSON")

    unique = {component_key(item): item for item in components if item["name"] or item["purl"]}
    normalized = sorted(
        unique.values(),
        key=lambda item: (item["name"].lower(), item["version"].lower(), item["purl"].lower()),
    )
    return {
        "specification": specification,
        "components": normalized,
        "relationships": sorted(
            relationships,
            key=lambda item: (
                item["from_name"].lower(), item["to_name"].lower(), item["type"]
            ),
        ),
        "component_count": len(normalized),
        "relationship_count": relationship_count,
        "dependency_edge_count": sum(
            1 for item in relationships if item["type"] == "DEPENDS_ON"
        ),
        "file_count": file_count,
    }


def normalized_relationship(
    source: dict[str, Any], target: dict[str, Any], relationship_type: str
) -> dict[str, Any]:
    return {
        "from_name": source["name"],
        "from_version": source["version"],
        "from_purl": source["purl"],
        "to_name": target["name"],
        "to_version": target["version"],
        "to_purl": target["purl"],
        "type": relationship_type,
    }


def expected_results(
    expected: list[dict[str, Any]], components: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    results = []
    for wanted in expected:
        name = str(wanted["name"])
        version = str(wanted["version"])
        found = any(
            item["name"].casefold() == name.casefold() and item["version"] == version
            for item in components
        )
        results.append({**wanted, "found": found})
    return results


def expected_relationship_results(
    expected: list[dict[str, Any]], relationships: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    results = []
    for wanted in expected:
        found = any(
            item["from_name"].casefold() == str(wanted["from_name"]).casefold()
            and item["from_version"] == str(wanted["from_version"])
            and item["to_name"].casefold() == str(wanted["to_name"]).casefold()
            and item["to_version"] == str(wanted["to_version"])
            and item["type"] == str(wanted["type"])
            for item in relationships
        )
        results.append({**wanted, "found": found})
    return results


def source_commands(
    tool: str,
    fixture: dict[str, Any],
    target: pathlib.Path,
    run_dir: pathlib.Path,
) -> tuple[list[str], pathlib.Path, pathlib.Path]:
    if tool == "syft":
        output = run_dir / "sbom.cdx.json"
        command = [
            "syft", "scan", f"dir:{target}", "--source-name", fixture["id"],
            "--source-version", "1.0.0", "-q", "-o", f"cyclonedx-json={output}",
        ]
        return command, output, target
    if tool == "trivy":
        output = run_dir / "sbom.cdx.json"
        command = [
            "trivy", "fs", "--quiet", "--format", "cyclonedx", "--output", str(output), str(target),
        ]
        return command, output, target
    if tool == "cdxgen":
        output = run_dir / "sbom.cdx.json"
        command = [
            "cdxgen", str(target), "--type", fixture["ecosystem"], "--spec-version", "1.6",
            "--no-install-deps", "--fail-on-error", "--output", str(output),
        ]
        return command, output, target

    manifest_root = run_dir / "manifest"
    manifest_root.mkdir(parents=True, exist_ok=True)
    output = manifest_root / "_manifest" / "spdx_2.2" / "manifest.spdx.json"
    command = [
        "sbom-tool", "generate", "-b", str(target), "-bc", str(target), "-m", str(manifest_root),
        "-pn", fixture["id"], "-pv", "1.0.0", "-ps", "rezmoss",
        "-nsb", "https://github.com/rezmoss/awesome-security-pipeline/sbom-benchmark",
        "-mi", "SPDX:2.2", "-t", str(run_dir / "telemetry.json"),
    ]
    return command, output, target


def image_commands(
    tool: str,
    fixture: dict[str, Any],
    run_dir: pathlib.Path,
) -> tuple[list[str], pathlib.Path, pathlib.Path]:
    image = str(fixture["image"])
    if tool == "syft":
        output = run_dir / "sbom.cdx.json"
        return ["syft", "scan", f"docker:{image}", "-q", "-o", f"cyclonedx-json={output}"], output, run_dir
    if tool == "trivy":
        output = run_dir / "sbom.cdx.json"
        return ["trivy", "image", "--quiet", "--format", "cyclonedx", "--output", str(output), image], output, run_dir
    if tool == "cdxgen":
        output = run_dir / "sbom.cdx.json"
        return [
            "cdxgen", image, "--type", "docker", "--spec-version", "1.6", "--no-install-deps",
            "--fail-on-error", "--output", str(output),
        ], output, run_dir

    drop = run_dir / "drop"
    components = run_dir / "components"
    manifest_root = run_dir / "manifest"
    for directory in (drop, components, manifest_root):
        directory.mkdir(parents=True, exist_ok=True)
    (drop / "image-reference.txt").write_text(f"{fixture['source_image']}\n", encoding="utf-8")
    output = manifest_root / "_manifest" / "spdx_2.2" / "manifest.spdx.json"
    command = [
        "sbom-tool", "generate", "-b", str(drop), "-bc", str(components), "-m", str(manifest_root),
        "-di", image, "-pn", fixture["id"], "-pv", "1.0.0", "-ps", "rezmoss",
        "-nsb", "https://github.com/rezmoss/awesome-security-pipeline/sbom-benchmark",
        "-mi", "SPDX:2.2", "-t", str(run_dir / "telemetry.json"),
    ]
    return command, output, drop


def validation_command(tool: str, document: pathlib.Path, validation_target: pathlib.Path) -> list[str]:
    if tool == "microsoft-sbom-tool":
        manifest_dir = document.parents[1]
        return [
            "sbom-tool", "validate", "-b", str(validation_target), "-m", str(manifest_dir),
            "-o", str(document.parent / "validation.json"), "-mi", "SPDX:2.2", "-n",
        ]
    parsed = load_json(document)
    version = str(parsed.get("specVersion", "1.7")).replace(".", "_")
    return [
        "cyclonedx", "validate", "--input-file", str(document),
        "--input-version", f"v{version}", "--fail-on-errors",
    ]


def previous_components(previous: dict[str, Any], fixture_id: str, tool: str) -> set[str]:
    for fixture in previous.get("fixtures") or []:
        if fixture.get("id") != fixture_id:
            continue
        for run in fixture.get("runs") or []:
            if run.get("tool") == tool:
                return {component_key(item) for item in run.get("components") or []}
    return set()


def previous_relationships(previous: dict[str, Any], fixture_id: str, tool: str) -> set[str]:
    for fixture in previous.get("fixtures") or []:
        if fixture.get("id") != fixture_id:
            continue
        for run in fixture.get("runs") or []:
            if run.get("tool") == tool:
                return {
                    relationship_key(item) for item in run.get("relationships") or []
                }
    return set()


def benchmark_fixture(
    fixture: dict[str, Any],
    repo_root: pathlib.Path,
    output_dir: pathlib.Path,
    base_env: dict[str, str],
    previous: dict[str, Any],
) -> dict[str, Any]:
    result = {key: value for key, value in fixture.items() if key not in {"path", "image"}}
    result["target"] = fixture.get("path") or fixture.get("source_image")
    result["runs"] = []

    for tool in TOOLS:
        run_dir = output_dir / "raw" / fixture["id"] / tool
        run_dir.mkdir(parents=True, exist_ok=True)
        if fixture["kind"] == "source":
            target = (repo_root / fixture["path"]).resolve()
            command, document, validation_target = source_commands(tool, fixture, target, run_dir)
        else:
            command, document, validation_target = image_commands(tool, fixture, run_dir)

        env = base_env.copy()
        cache_root = pathlib.Path(
            env.get("SBOM_BENCHMARK_CACHE_DIR", str(output_dir / "cache"))
        ).resolve()
        env["TRIVY_CACHE_DIR"] = str(cache_root / "trivy")
        env["DOTNET_BUNDLE_EXTRACT_BASE_DIR"] = str(cache_root / "dotnet")
        env["HOME"] = str(cache_root / "home")
        for directory in (
            pathlib.Path(env["TRIVY_CACHE_DIR"]),
            pathlib.Path(env["DOTNET_BUNDLE_EXTRACT_BASE_DIR"]),
            pathlib.Path(env["HOME"]),
        ):
            directory.mkdir(parents=True, exist_ok=True)
        generation_log = run_dir / "generation.log"
        return_code, duration, process_error = run_command(command, generation_log, env)
        run: dict[str, Any] = {
            "tool": tool,
            "status": "failed",
            "command": display_command(command, repo_root, output_dir),
            "duration_seconds": duration,
            "generation_exit_code": return_code,
            "validation": "not-run",
            "errors": [],
            "components": [],
            "component_count": 0,
            "relationship_count": 0,
            "dependency_edge_count": 0,
            "file_count": 0,
            "expected_components": [],
            "expected_relationships": [],
        }
        if process_error:
            run["errors"].append(process_error)
        if return_code != 0:
            run["errors"].append(f"generation exited with {return_code}")
        if not document.exists():
            run["errors"].append("generator did not create the expected document")
        else:
            run["output_bytes"] = document.stat().st_size
            run["output_sha256"] = sha256_file(document)
            try:
                parsed = parse_document(document)
                for component in parsed["components"]:
                    component["name"] = sanitize_paths(
                        component["name"], repo_root, output_dir
                    )
                for relationship in parsed["relationships"]:
                    relationship["from_name"] = sanitize_paths(
                        relationship["from_name"], repo_root, output_dir
                    )
                    relationship["to_name"] = sanitize_paths(
                        relationship["to_name"], repo_root, output_dir
                    )
                run.update(parsed)
            except (ValueError, json.JSONDecodeError, OSError) as exc:
                run["errors"].append(f"output parsing failed: {exc}")

        if document.exists() and not any(error.startswith("output parsing") for error in run["errors"]):
            validate = validation_command(tool, document, validation_target)
            validation_log = run_dir / "validation.log"
            validation_code, validation_duration, validation_error = run_command(validate, validation_log, env)
            run["validation_command"] = display_command(validate, repo_root, output_dir)
            run["validation_duration_seconds"] = validation_duration
            run["validation"] = "passed" if validation_code == 0 else "failed"
            if validation_error:
                run["errors"].append(validation_error)
            if validation_code != 0:
                run["errors"].append(f"validation exited with {validation_code}")

        run["expected_components"] = expected_results(
            fixture.get("expected_components") or [], run["components"]
        )
        missing = [item for item in run["expected_components"] if not item["found"]]
        if missing:
            wanted = ", ".join(f"{item['name']}@{item['version']}" for item in missing)
            run["errors"].append(f"missing expected components: {wanted}")
        run["expected_relationships"] = expected_relationship_results(
            fixture.get("expected_relationships") or [], run.get("relationships") or []
        )
        missing_relationships = [
            item for item in run["expected_relationships"] if not item["found"]
        ]
        if missing_relationships:
            wanted = ", ".join(
                f"{item['from_name']}@{item['from_version']} -> "
                f"{item['to_name']}@{item['to_version']} ({item['type']})"
                for item in missing_relationships
            )
            run["errors"].append(f"missing expected relationships: {wanted}")
        minimum = int(fixture.get("minimum_components", 0))
        if run["component_count"] < minimum:
            run["errors"].append(
                f"normalized component count {run['component_count']} is below minimum {minimum}"
            )

        current_keys = {component_key(item) for item in run["components"]}
        old_keys = previous_components(previous, fixture["id"], tool)
        current_relationships = {
            relationship_key(item) for item in run.get("relationships") or []
        }
        old_relationships = previous_relationships(previous, fixture["id"], tool)
        run["change_from_previous"] = {
            "added": sorted(current_keys - old_keys) if previous else [],
            "removed": sorted(old_keys - current_keys) if previous else [],
            "relationships_added": (
                sorted(current_relationships - old_relationships) if previous else []
            ),
            "relationships_removed": (
                sorted(old_relationships - current_relationships) if previous else []
            ),
        }
        if not run["errors"] and run["validation"] == "passed":
            run["status"] = "passed"
        else:
            run["log_tail"] = log_tail(generation_log) + log_tail(run_dir / "validation.log")
        result["runs"].append(run)
    return result


def render_report(result: dict[str, Any]) -> str:
    passed = result["status"] == "passed"
    lines = [
        f"# SBOM compatibility benchmark — {result['run_date']}",
        "",
        f"**Overall status:** {'PASS' if passed else 'FAIL'}  ",
        f"**Commit:** `{result['commit']}`  ",
        f"**Generated:** {result['generated_at']}  ",
        f"**Release policy:** `{result['release_policy']}`  ",
        f"**Tool releases resolved:** {result.get('tools_resolved_at') or 'not recorded'}",
        "",
        "## Tool releases",
        "",
        "| Tool | Version | Release asset SHA-256 | Verification |",
        "|---|---:|---|---|",
    ]
    for tool in result["tools"]:
        lines.append(
            f"| {tool['id']} | [{tool['version']}](https://github.com/{tool['repository']}/releases/tag/{tool['version']}) "
            f"| `{tool['sha256']}` | {tool['verification']} |"
        )

    lines.extend([
        "",
        "## Result summary",
        "",
        "| Fixture | Tool | Status | Format | Components | Dependency edges | Expected | Runtime | Change |",
        "|---|---|---|---|---:|---:|---:|---:|---|",
    ])
    for fixture in result["fixtures"]:
        for run in fixture["runs"]:
            expected = run.get("expected_components") or []
            found = sum(1 for item in expected if item["found"])
            expected_text = f"{found}/{len(expected)}" if expected else "n/a"
            change = run["change_from_previous"]
            change_text = (
                f"components +{len(change['added'])}/-{len(change['removed'])}; "
                f"edges +{len(change['relationships_added'])}/-{len(change['relationships_removed'])}"
                if result.get("previous_run_date") else "baseline"
            )
            lines.append(
                f"| `{fixture['id']}` | {run['tool']} | {'PASS' if run['status'] == 'passed' else 'FAIL'} "
                f"| {run.get('specification', 'none')} | {run['component_count']} | {run['dependency_edge_count']} "
                f"| {expected_text} | {run['duration_seconds']:.3f}s | {change_text} |"
            )

    if result.get("previous_run_date"):
        lines.extend([
            "",
            f"Changes compare normalized component identities with the reviewed snapshot from {result['previous_run_date']}. "
            "A count change is evidence to inspect, not automatically a regression.",
        ])

    lines.extend(["", "## Fixture details", ""])
    for fixture in result["fixtures"]:
        lines.extend([
            f"### {fixture['id']}",
            "",
            fixture["description"],
            "",
        ])
        expected = fixture.get("expected_components") or []
        if expected:
            lines.extend([
                "Expected identities: " + ", ".join(
                    f"`{item['name']}@{item['version']}` ({item['relationship']})" for item in expected
                ) + ".",
                "",
            ])
        expected_edges = fixture.get("expected_relationships") or []
        if expected_edges:
            lines.extend([
                "Expected dependency edges: " + ", ".join(
                    f"`{item['from_name']}@{item['from_version']} → "
                    f"{item['to_name']}@{item['to_version']}`" for item in expected_edges
                ) + ".",
                "",
            ])
        for run in fixture["runs"]:
            lines.extend([
                f"#### {run['tool']} — {'PASS' if run['status'] == 'passed' else 'FAIL'}",
                "",
                f"Command: `{run['command']}`",
                "",
            ])
            if run["errors"]:
                lines.append("Errors:")
                lines.append("")
                lines.extend(f"- {error}" for error in run["errors"])
                lines.append("")
            preview = run["components"][:12]
            if preview:
                lines.extend([
                    "Normalized inventory preview (the JSON result retains the complete inventory):",
                    "",
                    "| Type | Name | Version | PURL |",
                    "|---|---|---|---|",
                ])
                for component in preview:
                    lines.append(
                        f"| {component['type']} | `{component['name']}` | `{component['version'] or '—'}` "
                        f"| `{component['purl'] or '—'}` |"
                    )
                lines.append("")

    lines.extend([
        "## Interpretation limits",
        "",
        "- Component counts are not rankings; subjects, files, packages, and relationships are modeled differently.",
        "- Runtime is diagnostic data from one GitHub-hosted run, not a general performance benchmark.",
        "- Structural validation does not prove inventory completeness or identity accuracy.",
        "- The benchmark does not evaluate vulnerabilities, license correctness, or policy suitability.",
        "- Raw SBOMs and logs are retained with the workflow artifact; the normalized JSON is the durable comparison record.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo_root = pathlib.Path.cwd().resolve()
    config = load_json(args.config)
    metadata = load_json(args.tool_metadata)
    previous = load_json(args.previous) if args.previous and args.previous.exists() else {}
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise ValueError(
            f"output directory must be empty to prevent stale evidence: {args.output_dir}"
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)

    base_env = os.environ.copy()
    fixtures = []
    skipped = []
    for fixture in config.get("fixtures") or []:
        if fixture["kind"] in args.skip_kind:
            skipped.append(fixture["id"])
            continue
        fixtures.append(benchmark_fixture(fixture, repo_root, args.output_dir, base_env, previous))

    failed = [
        run
        for fixture in fixtures
        for run in fixture["runs"]
        if run["status"] != "passed"
    ]
    result = {
        "schema_version": 1,
        "run_date": args.run_date,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "commit": args.commit,
        "status": "failed" if failed else "passed",
        "release_policy": metadata.get("release_policy", "unknown"),
        "tools_resolved_at": metadata.get("resolved_at"),
        "environment": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "tools": metadata.get("tools") or [],
        "fixtures": fixtures,
        "skipped_fixtures": skipped,
        "previous_run_date": previous.get("run_date"),
    }
    write_json(args.output_dir / "result.json", result)
    (args.output_dir / "report.md").write_text(render_report(result), encoding="utf-8")
    print(f"SBOM benchmark status: {result['status']}")
    print(f"Machine-readable result: {args.output_dir / 'result.json'}")
    print(f"Readable report: {args.output_dir / 'report.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"benchmark failed before results were complete: {exc}", file=sys.stderr)
        sys.exit(2)
