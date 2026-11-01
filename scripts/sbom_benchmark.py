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
SCHEMA_VERSION = 2
# File and cryptographic-asset entries are retained as per-type counts plus a digest; they are
# real inventory, but they would otherwise drown package-level changes in every comparison.
INVENTORY_ONLY_TYPES = frozenset({"file", "cryptographic-asset"})


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


def normalize_version(version: str) -> str:
    """Compare versions without the cosmetic `v`/`go` prefixes generators disagree on."""
    clean = version.strip()
    for prefix in ("go", "v"):
        if clean.startswith(prefix) and clean[len(prefix):][:1].isdigit():
            return clean[len(prefix):]
    return clean


def identity_found(wanted: dict[str, Any], components: list[dict[str, Any]]) -> bool:
    name = str(wanted["name"]).casefold()
    version = normalize_version(str(wanted["version"]))
    return any(
        item["name"].casefold() == name and normalize_version(item["version"]) == version
        for item in components
        if not item.get("subject")
    )


def expected_results(
    expected: list[dict[str, Any]], components: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    return [{**wanted, "found": identity_found(wanted, components)} for wanted in expected]


def purl_type(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return ""
    return purl[4:].split("/", 1)[0].lower()


def is_inventory_only(component: dict[str, Any]) -> bool:
    return str(component.get("type", "")).lower() in INVENTORY_ONLY_TYPES


def split_inventory(
    components: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int], str]:
    """Return package-level components, per-type counts of the rest, and a digest of the rest."""
    packages = [item for item in components if not is_inventory_only(item)]
    others = [item for item in components if is_inventory_only(item)]
    counts: dict[str, int] = {}
    for item in others:
        counts[item["type"]] = counts.get(item["type"], 0) + 1
    digest = hashlib.sha256(
        "\n".join(sorted(component_key(item) for item in others)).encode("utf-8")
    ).hexdigest()
    return packages, dict(sorted(counts.items())), digest


def package_relationships(
    relationships: list[dict[str, Any]], packages: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Keep only edges whose endpoints are both package-level components."""
    known = {(item["name"], item["version"], item["purl"]) for item in packages}
    return [
        item for item in relationships
        if (item["from_name"], item["from_version"], item["from_purl"]) in known
        and (item["to_name"], item["to_version"], item["to_purl"]) in known
    ]


def score_run(fixture: dict[str, Any], components: list[dict[str, Any]]) -> dict[str, Any]:
    """Score a tool's package-level inventory against the fixture's independent ground truth."""
    packages = [
        item for item in components if not item.get("subject") and not is_inventory_only(item)
    ]
    # Operating-system and container entries describe the target, not an installed package.
    described = [
        item for item in packages
        if str(item.get("type", "")).lower() not in {"operating-system", "container"}
    ]
    expected = fixture.get("expected_components") or []
    found = [item for item in expected if identity_found(item, packages)]
    missed = [item for item in expected if not identity_found(item, packages)]
    scope = {value.lower() for value in fixture.get("complete_purl_types") or []}
    expected_names = {str(item["name"]).casefold() for item in expected}
    extra = sorted(
        {
            f"{item['name']}@{item['version']}"
            for item in packages
            if purl_type(item["purl"]) in scope and item["name"].casefold() not in expected_names
        }
    )
    return {
        "expected": len(expected),
        "found": len(found),
        "missed": [f"{item['name']}@{item['version']}" for item in missed],
        "extra": extra,
        "extra_scope": sorted(scope),
        "packages": len(packages),
        "missing_purl": sorted(
            f"{item['name']}@{item['version']}" if item["version"] else item["name"]
            for item in described
            if not item["purl"]
        ),
        "versionless": sorted(item["name"] for item in described if not item["version"]),
    }


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


def previous_run(previous: dict[str, Any], fixture_id: str, tool: str) -> dict[str, Any] | None:
    for fixture in previous.get("fixtures") or []:
        if fixture.get("id") != fixture_id:
            continue
        for run in fixture.get("runs") or []:
            if run.get("tool") == tool:
                return run
    return None


def package_keys(run: dict[str, Any] | None) -> set[str]:
    # Schema 1 snapshots stored every component; compare only the package-level subset.
    return {
        component_key(item)
        for item in (run or {}).get("components") or []
        if not is_inventory_only(item)
    }


def relationship_keys(run: dict[str, Any] | None) -> set[str]:
    return {relationship_key(item) for item in (run or {}).get("relationships") or []}


def inventory_counts(run: dict[str, Any] | None) -> dict[str, int]:
    if not run:
        return {}
    if "inventory_only_counts" in run:
        return dict(run["inventory_only_counts"])
    counts: dict[str, int] = {}
    for item in run.get("components") or []:
        if is_inventory_only(item):
            counts[item["type"]] = counts.get(item["type"], 0) + 1
    return counts


def change_from_previous(
    run: dict[str, Any], old: dict[str, Any] | None, has_previous: bool
) -> dict[str, Any]:
    if not has_previous:
        return {"baseline": True}
    current = package_keys(run)
    before = package_keys(old)
    current_edges = relationship_keys(run)
    before_edges = relationship_keys(old)
    old_counts = inventory_counts(old)
    new_counts = run.get("inventory_only_counts") or {}
    old_total = sum(old_counts.values())
    new_total = sum(new_counts.values())
    return {
        "baseline": old is None,
        "added": sorted(current - before),
        "removed": sorted(before - current),
        "relationships_added": sorted(current_edges - before_edges),
        "relationships_removed": sorted(before_edges - current_edges),
        "inventory_only_before": old_total,
        "inventory_only_after": new_total,
        "inventory_only_changed": (
            old is not None
            and (old_counts != new_counts or inventory_digest(old) != run.get("inventory_only_digest"))
        ),
    }


def inventory_digest(run: dict[str, Any]) -> str:
    if "inventory_only_digest" in run:
        return str(run["inventory_only_digest"])
    return split_inventory(run.get("components") or [])[2]


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
        missing = [
            item for item in run["expected_components"]
            if not item["found"] and item.get("gate", True)
        ]
        if missing:
            wanted = ", ".join(f"{item['name']}@{item['version']}" for item in missing)
            run["errors"].append(f"missing expected components: {wanted}")
        # Scored (non-gating) identities fail only when a tool loses one it found last run.
        old = previous_run(previous, fixture["id"], tool)
        if old is not None:
            old_components = old.get("components") or []
            lost = [
                item for item in run["expected_components"]
                if not item["found"]
                and not item.get("gate", True)
                and identity_found(item, old_components)
            ]
            if lost:
                wanted = ", ".join(f"{item['name']}@{item['version']}" for item in lost)
                run["errors"].append(f"lost ground-truth components found by the previous run: {wanted}")
        run["score"] = score_run(fixture, run["components"])
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

        packages, counts, digest = split_inventory(run["components"])
        run["components"] = packages
        run["relationships"] = package_relationships(run.get("relationships") or [], packages)
        run["inventory_only_counts"] = counts
        run["inventory_only_digest"] = digest
        run["change_from_previous"] = change_from_previous(run, old, bool(previous))
        if not run["errors"] and run["validation"] == "passed":
            run["status"] = "passed"
        else:
            run["log_tail"] = log_tail(generation_log) + log_tail(run_dir / "validation.log")
        result["runs"].append(run)
    return result


def status_text(run: dict[str, Any]) -> str:
    return "PASS" if run["status"] == "passed" else "FAIL"


def score_text(run: dict[str, Any]) -> str:
    score = run.get("score") or {}
    if not score.get("expected"):
        return "n/a"
    return f"{score['found']}/{score['expected']}"


def change_text(change: dict[str, Any]) -> str:
    if change.get("baseline"):
        return "baseline"
    parts = [f"packages +{len(change['added'])}/-{len(change['removed'])}"]
    if change.get("relationships_added") or change.get("relationships_removed"):
        parts.append(
            f"edges +{len(change['relationships_added'])}/-{len(change['relationships_removed'])}"
        )
    if change.get("inventory_only_changed"):
        parts.append(
            f"files/crypto {change['inventory_only_before']}→{change['inventory_only_after']}"
        )
    return "; ".join(parts)


def notable_differences(result: dict[str, Any], names: dict[str, str] | None = None) -> list[str]:
    notes = []
    for fixture in result["fixtures"]:
        for run in fixture["runs"]:
            score = run.get("score") or {}
            label = f"{(names or {}).get(run['tool'], run['tool'])} on `{fixture['id']}`"
            if score.get("missed"):
                notes.append(f"{label} missed {len(score['missed'])}: " + ", ".join(score["missed"]))
            if score.get("extra"):
                notes.append(
                    f"{label} reported {len(score['extra'])} {'/'.join(score['extra_scope'])} "
                    "package(s) that are not installed: " + ", ".join(score["extra"])
                )
            if score.get("missing_purl") and score.get("packages"):
                notes.append(
                    f"{label}: {len(score['missing_purl'])} of {score['packages']} packages have no package URL"
                )
            if score.get("versionless"):
                notes.append(f"{label}: {len(score['versionless'])} component(s) have no version")
    return notes


def render_report(result: dict[str, Any]) -> str:
    passed = result["status"] == "passed"
    tools = ", ".join(f"{tool['id']} {tool['version']}" for tool in result["tools"])
    lines = [
        f"# SBOM compatibility benchmark — {result['run_date']}",
        "",
        f"**Overall status:** {'PASS' if passed else 'FAIL'}  ",
        f"**Commit:** `{result['commit']}`  ",
        f"**Tools:** {tools}",
        "",
        "## Results at a glance",
        "",
        "Ground truth is read from the fixture itself (declared manifests, the lockfile, or the image's "
        "package database), never from a generator.",
        "",
        "| Fixture | Tool | Status | Format | Ground truth found | Extra | Packages | Files/crypto | Change |",
        "|---|---|---|---|---:|---:|---:|---:|---|",
    ]
    for fixture in result["fixtures"]:
        for run in fixture["runs"]:
            score = run.get("score") or {}
            lines.append(
                f"| `{fixture['id']}` | {run['tool']} | {status_text(run)} "
                f"| {run.get('specification', 'none')} | {score_text(run)} | {len(score.get('extra') or [])} "
                f"| {score.get('packages', 0)} | {sum((run.get('inventory_only_counts') or {}).values())} "
                f"| {change_text(run['change_from_previous'])} |"
            )
    notes = notable_differences(result)
    if notes:
        lines.extend(["", "## Notable differences", ""])
        lines.extend(f"- {note}" for note in notes)
    if result.get("tool_changes"):
        lines.extend(["", "## Tool upgrades since the previous run", ""])
        lines.extend(
            f"- {tool}: {change['before']} → {change['after']}"
            for tool, change in result["tool_changes"].items()
        )
    failures = [
        (fixture["id"], run) for fixture in result["fixtures"] for run in fixture["runs"]
        if run["status"] != "passed"
    ]
    if failures:
        lines.extend(["", "## Failures", ""])
        for fixture_id, run in failures:
            lines.append(f"- `{fixture_id}` / {run['tool']}: " + "; ".join(run["errors"]))
    if result.get("previous_run_date"):
        lines.extend([
            "",
            f"Changes compare package-level identities with the run from {result['previous_run_date']}; "
            "file and cryptographic-asset entries are compared as counts plus a digest.",
        ])
    lines.extend([
        "",
        "## Interpretation limits",
        "",
        "- Component counts are not rankings; subjects, files, packages, and relationships are modeled differently.",
        "- Structural validation does not prove inventory completeness or identity accuracy.",
        "- The benchmark does not evaluate vulnerabilities, license correctness, or policy suitability.",
        "",
    ])
    return "\n".join(lines)


def tool_changes(result_tools: list[dict[str, Any]], previous: dict[str, Any]) -> dict[str, Any]:
    before = {tool["id"]: tool["version"] for tool in previous.get("tools") or []}
    return {
        tool["id"]: {"before": before[tool["id"]], "after": tool["version"]}
        for tool in result_tools
        if tool["id"] in before and before[tool["id"]] != tool["version"]
    }


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
        "schema_version": SCHEMA_VERSION,
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
        "tool_changes": tool_changes(metadata.get("tools") or [], previous),
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
