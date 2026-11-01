#!/usr/bin/env python3
"""Weekly supply-chain report for every active tool in the catalog.

Subcommands:
  targets  read the active tools from tools/, resolve each project's latest release, and shard the list
  scan     fetch the manifests and lockfiles at each release tag, then run Syft, Grype, and sbomlyze
  publish  record the week's results in the data branch and compute changes from the previous week

Only dependency manifests and lockfiles are fetched (a blobless, sparse checkout). Test, fixture,
example, documentation, and vendored directories are excluded because security tools ship
deliberately vulnerable fixtures that would otherwise dominate the results.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import catalog  # noqa: E402
from scripts import supply_chain_checks as checks  # noqa: E402

SCHEMA_VERSION = 1
MANIFESTS = (
    "go.mod", "go.sum", "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lock", "requirements*.txt", "pyproject.toml", "poetry.lock", "Pipfile",
    "Pipfile.lock", "uv.lock", "pdm.lock", "setup.py", "setup.cfg", "Cargo.toml", "Cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock", "*.gemspec", "packages.lock.json", "*.csproj", "packages.config",
    "Package.resolved", "mix.lock", "pubspec.lock", "*.opam", "conanfile.txt", "conan.lock",
)
WORKFLOW_FILE = re.compile(r"^(\.github/workflows/[^/]+\.ya?ml|(.*/)?action\.ya?ml)$")
EXCLUDED_DIRECTORIES = frozenset({
    "test", "tests", "testdata", "test-data", "__tests__", "spec", "fixtures", "fixture", "integration",
    "e2e", "examples", "example", "docs", "doc", "vendor", "node_modules", "third_party", "benchmark",
    "benchmarks", "samples", "sample", "testing", "mocks",
})
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
FETCH_TIMEOUT = 600
TOOL_TIMEOUT = 600


# ----- helpers ---------------------------------------------------------------------------

def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: pathlib.Path, value: Any, indent: int | None = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=indent, sort_keys=True, separators=None if indent else (",", ":"))
        handle.write("\n")


def run(command: list[str], cwd: pathlib.Path | None = None, timeout: int = TOOL_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


def gh_api(endpoint: str) -> Any:
    completed = run(["gh", "api", "-H", "Accept: application/vnd.github+json", endpoint], timeout=60)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip()[:300] or f"gh api {endpoint} failed")
    return json.loads(completed.stdout)


def project_id(repository: str) -> str:
    return repository.replace("/", "__")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


# ----- targets ---------------------------------------------------------------------------

def active_catalog(tools_dir: pathlib.Path) -> list[dict[str, str]]:
    """Active catalog entries from tools/*.json, with the category path of their first listing."""
    tools = catalog.load_tools(tools_dir)
    categories = catalog.load_categories(tools_dir)
    entries = []
    for tool in tools.values():
        if (tool.get("automated") or {}).get("section", "active") != "active":
            continue
        listing = tool["listing"]
        first = listing["categories"][0]
        entries.append({
            "repository": listing["repository"],
            "name": listing["name"],
            "description": first["description"].rstrip("."),
            "category": " › ".join(item["title"] for item in catalog.category_path(categories, first["category"])),
        })
    return sorted(entries, key=lambda item: item["repository"].lower())


def resolve_release(target: dict[str, str], tag_patterns: dict[str, Any]) -> dict[str, Any]:
    resolved: dict[str, Any] = dict(target)
    repository = gh_api(f"repos/{target['repository']}")
    resolved["canonical"] = repository.get("full_name", target["repository"])
    resolved["archived"] = bool(repository.get("archived"))
    preference = tag_patterns.get(target["repository"])
    try:
        if preference:
            pattern = re.compile(preference["pattern"])
            releases = [
                item for item in gh_api(f"repos/{target['repository']}/releases?per_page=100")
                if not item.get("draft") and not item.get("prerelease") and pattern.search(item["tag_name"])
            ]
            if not releases:
                raise RuntimeError(f"no release matches {preference['pattern']}")
            release = max(releases, key=lambda item: item.get("published_at") or "")
            resolved["tag_pattern"] = preference["pattern"]
        else:
            release = gh_api(f"repos/{target['repository']}/releases/latest")
        resolved.update(ref=release["tag_name"], ref_kind="release", released_at=release.get("published_at"))
        resolved["assets"] = [
            {key: asset.get(key) for key in ("name", "size", "digest", "browser_download_url")}
            for asset in release.get("assets") or []
        ]
    except RuntimeError:
        resolved.update(ref=repository["default_branch"], ref_kind="default-branch", released_at=None)
    return resolved


def command_targets(args: argparse.Namespace) -> int:
    entries = active_catalog(args.tools)
    if args.only:
        wanted = {item.lower() for item in args.only}
        entries = [item for item in entries if item["repository"].lower() in wanted]
    if args.limit:
        entries = entries[: args.limit]
    tag_patterns = load_json(args.tag_patterns).get("projects", {}) if args.tag_patterns.is_file() else {}
    targets = []
    for entry in entries:
        try:
            targets.append(resolve_release(entry, tag_patterns))
        except (RuntimeError, KeyError, json.JSONDecodeError) as exc:
            targets.append({**entry, "ref": None, "ref_kind": "unresolved", "error": str(exc)})
    shards = [targets[index:: args.shards] for index in range(args.shards)]
    write_json(args.output, {"generated_at": utc_now(), "targets": targets, "shards": shards})
    matrix = [index for index, shard in enumerate(shards) if shard]
    print(json.dumps(matrix))
    return 0


# ----- scan ------------------------------------------------------------------------------

def wanted_path(path: str) -> bool:
    if WORKFLOW_FILE.match(path):
        return True
    parts = path.split("/")
    if any(part.lower() in EXCLUDED_DIRECTORIES for part in parts[:-1]):
        return False
    return any(fnmatch.fnmatch(parts[-1], pattern) for pattern in MANIFESTS)


def fetch_manifests(repository: str, ref: str, destination: pathlib.Path) -> tuple[str, list[str]]:
    """Fetch only manifests and lockfiles at `ref`; return the commit and the selected paths."""
    url = f"https://github.com/{repository}.git"
    clone = run(
        ["git", "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout",
         "--branch", ref, url, str(destination)],
        timeout=FETCH_TIMEOUT,
    )
    if clone.returncode != 0:
        raise RuntimeError(f"clone failed: {clone.stderr.strip()[:300]}")
    commit = run(["git", "rev-parse", "HEAD"], cwd=destination).stdout.strip()
    listing = run(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=destination)
    paths = [path for path in listing.stdout.splitlines() if wanted_path(path)]
    if paths:
        sparse = subprocess.run(
            ["git", "sparse-checkout", "set", "--no-cone", "--stdin"], cwd=destination,
            input="".join(f"/{path}\n" for path in paths), text=True, capture_output=True,
            timeout=120, check=False,
        )
        if sparse.returncode != 0:
            raise RuntimeError(f"sparse checkout failed: {sparse.stderr.strip()[:300]}")
        checkout = run(["git", "checkout", "--quiet", "HEAD"], cwd=destination, timeout=FETCH_TIMEOUT)
        if checkout.returncode != 0:
            raise RuntimeError(f"checkout failed: {checkout.stderr.strip()[:300]}")
    shutil.rmtree(destination / ".git", ignore_errors=True)
    return commit, paths


def component_licenses(component: dict[str, Any]) -> list[str]:
    names = []
    for item in component.get("licenses") or []:
        if "expression" in item:
            names.append(str(item["expression"]))
        license_ = item.get("license") or {}
        if license_.get("id") or license_.get("name"):
            names.append(str(license_.get("id") or license_.get("name")))
    return sorted(set(names))


def component_location(component: dict[str, Any]) -> str:
    for prop in component.get("properties") or []:
        if prop.get("name") == "syft:location:0:path":
            return str(prop.get("value", "")).lstrip("/")
    return ""


def ecosystem(purl: str) -> str:
    return purl[4:].split("/", 1)[0].lower() if purl.startswith("pkg:") else "unknown"


def normalize_sbom(document: dict[str, Any]) -> list[dict[str, Any]]:
    components = {}
    for item in document.get("components") or []:
        if item.get("type") == "file":
            continue
        purl = str(item.get("purl") or "")
        entry = {
            "name": str(item.get("name") or ""),
            "version": str(item.get("version") or ""),
            "purl": purl.split("?", 1)[0],
            "ecosystem": ecosystem(purl),
            "licenses": component_licenses(item),
            "location": component_location(item),
        }
        key = entry["purl"] or f"{entry['ecosystem']}:{entry['name']}@{entry['version']}"
        if not entry["name"]:
            continue
        existing = components.get(key)
        if existing is None:
            components[key] = entry
            continue
        # The same package can be declared by several lockfiles, not all of which carry a
        # license; merge them so the result does not depend on the order Syft reports them.
        existing["licenses"] = sorted(set(existing["licenses"]) | set(entry["licenses"]))
        existing["location"] = min(filter(None, (existing["location"], entry["location"])), default="")
    return sorted(components.values(), key=lambda item: (item["ecosystem"], item["name"].lower(), item["version"]))


def normalize_grype(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = {}
    for match in report.get("matches") or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        aliases = sorted({
            str(item.get("id")) for item in match.get("relatedVulnerabilities") or [] if item.get("id")
        } - {str(vulnerability.get("id"))})
        fix = vulnerability.get("fix") or {}
        entry = {
            "id": str(vulnerability.get("id", "")),
            "aliases": aliases,
            "severity": str(vulnerability.get("severity") or "Unknown"),
            "package": str(artifact.get("name", "")),
            "version": str(artifact.get("version", "")),
            "ecosystem": ecosystem(str(artifact.get("purl") or "")),
            "fixed_in": list(fix.get("versions") or []),
            "fix_state": str(fix.get("state") or "unknown"),
            "url": str(vulnerability.get("dataSource") or ""),
            "location": str(((artifact.get("locations") or [{}])[0]).get("path", "")).lstrip("/"),
        }
        findings[(entry["id"], entry["package"], entry["version"])] = entry
    order = {name: index for index, name in enumerate(SEVERITIES)}
    return sorted(findings.values(), key=lambda item: (order.get(item["severity"], 99), item["package"], item["id"]))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for item in findings:
        counts[item["severity"] if item["severity"] in counts else "Unknown"] += 1
    return counts


def tool_version(binary: str, arguments: list[str]) -> str:
    try:
        completed = run([binary, *arguments], timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    output = completed.stdout + "\n" + completed.stderr
    for pattern in (r"govulncheck@v(\S+)", r"(?:GitVersion|Version|version)[:\s]+v?(\d+\.\d+\.\d+\S*)",
                    r"\bv?(\d+\.\d+\.\d+)\b"):
        match = re.search(pattern, output)
        if match:
            return match.group(1)
    return "unknown"


def compliance_summary(report: dict[str, Any]) -> dict[str, Any]:
    result = {"overall_score": (report.get("compliance") or {}).get("overall_score"), "standards": {}}
    for key, value in (report.get("compliance") or {}).items():
        if isinstance(value, dict):
            result["standards"][key] = {
                "score": value.get("score"), "passed": value.get("passed"), "total": value.get("total"),
                "failed_checks": [check.get("name") for check in value.get("checks") or [] if not check.get("passed")],
            }
    return result


def sbomlyze_diff(binary: str, previous: pathlib.Path, current: pathlib.Path, html_target: pathlib.Path) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary)
        shutil.copyfile(previous, work / "previous.cdx.json")
        shutil.copyfile(current, work / "current.cdx.json")
        completed = run([binary, "previous.cdx.json", "current.cdx.json", "--json", "--no-pager"], cwd=work)
        if completed.returncode not in (0, 1) or not completed.stdout.strip():
            return None
        report = json.loads(completed.stdout)
        diff = report.get("diff") or {}
        summary = {
            "added": len(diff.get("added") or []),
            "removed": len(diff.get("removed") or []),
            "changed": len(diff.get("changed") or []),
            "drift": diff.get("drift_summary") or {},
            "findings": [item.get("message", "") for item in (report.get("findings") or {}).get("findings") or []],
        }
        if summary["added"] or summary["removed"] or summary["changed"]:
            page = run([binary, "previous.cdx.json", "current.cdx.json", "--format", "html", "--no-pager"], cwd=work)
            if page.returncode in (0, 1) and page.stdout.strip():
                html_target.parent.mkdir(parents=True, exist_ok=True)
                html_target.write_text(page.stdout, encoding="utf-8")
                summary["html"] = html_target.name
        return summary


def redact(path: pathlib.Path, replacements: dict[str, str]) -> None:
    """Remove runner-local paths from a published report."""
    text = path.read_text(encoding="utf-8")
    for source in sorted(replacements, key=len, reverse=True):
        text = text.replace(source, replacements[source])
    path.write_text(text, encoding="utf-8")


def check(summary: dict[str, Any], name: str, function: Any, *arguments: Any) -> Any:
    """Run one optional check; a failure is recorded without stopping the project scan."""
    try:
        return function(*arguments)
    except Exception as exc:  # noqa: BLE001 - every check is best effort
        summary["errors"].append(f"{name} failed: {exc}")
        return None


def release_checks(target: dict[str, Any], summary: dict[str, Any], work: pathlib.Path) -> None:
    asset = checks.select_linux_asset(target.get("assets") or [], target["repository"])
    file = None
    if asset:
        file = work / asset["name"]
        checks.download(asset["browser_download_url"], file)
        binaries = checks.extract_binaries(file, work / "extracted")
        is_go = any(path.endswith("go.mod") for path in summary.get("manifests") or [])
        for binary in binaries if is_go else []:
            result = checks.govulncheck_binary(binary)
            if result:
                summary["go_binary"] = {**result, "asset": asset["name"]}
                break
        if is_go and "go_binary" not in summary:
            summary["go_binary_note"] = (
                f"{asset['name']} could not be analyzed: no Go build information "
                "(the binary may be compressed, for example with UPX, or not built with Go)"
            )
    summary["release_integrity"] = checks.release_integrity(target, asset, file, work)


def scan_target(target: dict[str, Any], output: pathlib.Path, previous_dir: pathlib.Path | None, sbomlyze: str,
                scorecard_cli: bool = False) -> dict[str, Any]:
    pid = project_id(target["repository"])
    directory = output / pid
    directory.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "id": pid, **{key: target.get(key) for key in (
            "repository", "name", "description", "category", "ref", "ref_kind", "released_at", "archived")},
        "scanned_at": utc_now(), "errors": [],
    }
    if not target.get("ref"):
        summary["errors"].append(target.get("error") or "release could not be resolved")
        return summary
    with tempfile.TemporaryDirectory() as temporary:
        source = pathlib.Path(temporary) / "source"
        try:
            summary["commit"], paths = fetch_manifests(target["repository"], target["ref"], source)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            summary["errors"].append(str(exc))
            return summary
        summary["manifests"] = paths
        source_paths = {str(source.resolve()): "", str(source): ""}
        sbom = directory / "sbom.cdx.json"
        syft = run(["syft", "scan", f"dir:{source}", "--source-name", target["repository"],
                    "--source-version", target["ref"], "-q", "-o", f"cyclonedx-json={sbom}"])
        if syft.returncode != 0 or not sbom.is_file():
            summary["errors"].append(f"syft failed: {syft.stderr.strip()[:300]}")
            return summary
        osv = check(summary, "osv-scanner", checks.osv_scan, source) or {}
        if osv.get("error"):
            summary["errors"].append(osv["error"])
        workflows = check(summary, "zizmor", checks.zizmor_audit, source)
        if workflows and workflows.get("error"):
            summary["errors"].append(workflows["error"])
            workflows = None
        summary["workflow_audit"] = workflows
    redact(sbom, {**source_paths, str(pathlib.Path.home()): "$HOME"})
    document = load_json(sbom)
    summary["components"] = normalize_sbom(document)

    grype_report = directory / "grype.json"
    grype = run(["grype", f"sbom:{sbom}", "-q", "-o", "json", "--file", str(grype_report)])
    if grype.returncode != 0 or not grype_report.is_file():
        summary["errors"].append(f"grype failed: {grype.stderr.strip()[:300]}")
        summary["vulnerabilities"] = None
    else:
        redact(grype_report, {str(directory.resolve()): ".", str(directory): ".", str(pathlib.Path.home()): "$HOME"})
        summary["vulnerabilities"] = normalize_grype(load_json(grype_report))

    summary["osv"] = checks.cross_reference(summary["vulnerabilities"], osv)
    if summary["osv"].get("available"):
        summary["osv"]["osv_only"] = summary["osv"]["osv_only"][:100]
    if target.get("ref_kind") == "release":
        with tempfile.TemporaryDirectory() as temporary:
            check(summary, "release checks", release_checks, target, summary, pathlib.Path(temporary))
    checks.annotate_reachability(summary["vulnerabilities"], summary.get("go_binary"))
    if summary.get("go_binary"):
        summary["go_binary"].pop("modules", None)
    scorecard = check(summary, "scorecard", checks.scorecard, target["repository"], scorecard_cli)
    summary["scorecard"] = scorecard if scorecard and not scorecard.get("error") else None
    if scorecard and scorecard.get("error"):
        summary["scorecard_note"] = scorecard["error"]

    compliance = run([sbomlyze, str(sbom), "--compliance", "--json", "--no-pager"])
    if compliance.returncode == 0 and compliance.stdout.strip():
        summary["compliance"] = compliance_summary(json.loads(compliance.stdout))
    previous = previous_dir / pid / "sbom.cdx.json" if previous_dir else None
    if previous and previous.is_file():
        summary["sbomlyze_diff"] = sbomlyze_diff(sbomlyze, previous, sbom, directory / "sbomlyze-diff.html")
    write_json(directory / "summary.json", summary)
    return summary


def command_scan(args: argparse.Namespace) -> int:
    plan = load_json(args.targets)
    shard = plan["shards"][args.shard]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    tools = {
        "syft": tool_version("syft", ["version"]),
        "grype": tool_version("grype", ["version"]),
        "osv-scanner": tool_version("osv-scanner", ["--version"]),
        "govulncheck": tool_version("govulncheck", ["-version"]),
        "zizmor": tool_version("zizmor", ["--version"]),
        "scorecard": tool_version("scorecard", ["version"]),
        "cosign": tool_version("cosign", ["version"]),
        "slsa-verifier": tool_version("slsa-verifier", ["version"]),
        "sbomlyze": tool_version(args.sbomlyze, ["--version"]),
    }
    db = run(["grype", "db", "status", "-o", "json"], timeout=120)
    if db.returncode == 0 and db.stdout.strip():
        status = json.loads(db.stdout)
        tools["grype_db_built"] = status.get("built")
    results = []
    budget = args.scorecard_cli_limit
    for target in shard:
        print(f"scanning {target['repository']} @ {target.get('ref')}", flush=True)
        allow_cli = budget > 0
        try:
            results.append(scan_target(target, args.output_dir, args.previous_dir, args.sbomlyze, allow_cli))
            if allow_cli and (results[-1].get("scorecard") or {}).get("source") == "scorecard-cli":
                budget -= 1
        except Exception as exc:  # one project must not stop the shard
            results.append({"id": project_id(target["repository"]), **target, "errors": [f"scan crashed: {exc}"]})
        if results[-1]["errors"]:
            print(f"  errors: {results[-1]['errors']}", flush=True)
    write_json(args.output_dir / f"shard-{args.shard}.json", {"tools": tools, "projects": results})
    return 0


# ----- publish ---------------------------------------------------------------------------

def package_key(item: dict[str, Any]) -> str:
    return f"{item['ecosystem']}:{item['name']}".lower()


def finding_key(item: dict[str, Any]) -> str:
    return f"{item['id']}|{item['package']}".lower()


def changes(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    if not previous or previous.get("components") is None or current.get("components") is None:
        return {"baseline": True}
    def versions(components: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
        grouped: dict[str, dict[str, dict[str, Any]]] = {}
        for item in components:
            grouped.setdefault(package_key(item), {})[item["version"]] = item
        return grouped

    before, after = versions(previous["components"]), versions(current["components"])
    added, removed, upgraded, licensed = [], [], [], []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key, {}), after.get(key, {})
        if len(old) == 1 and len(new) == 1 and set(old) != set(new):
            (old_item,), (new_item,) = old.values(), new.values()
            upgraded.append({"package": new_item["name"], "ecosystem": new_item["ecosystem"],
                             "from": old_item["version"], "to": new_item["version"]})
            continue
        added.extend(f"{item['name']}@{version}" for version, item in sorted(new.items()) if version not in old)
        removed.extend(f"{item['name']}@{version}" for version, item in sorted(old.items()) if version not in new)
        for version in sorted(set(old) & set(new)):
            if old[version].get("licenses") != new[version].get("licenses"):
                licensed.append({"package": new[version]["name"], "from": old[version]["licenses"],
                                 "to": new[version]["licenses"]})
    result: dict[str, Any] = {
        "baseline": False,
        "release_changed": previous.get("ref") != current.get("ref"),
        "previous_ref": previous.get("ref"),
        "added": added,
        "removed": removed,
        "upgraded": upgraded,
        "license_changes": licensed,
    }
    if previous.get("vulnerabilities") is not None and current.get("vulnerabilities") is not None:
        old = {finding_key(item): item for item in previous["vulnerabilities"]}
        new = {finding_key(item): item for item in current["vulnerabilities"]}
        result["new_vulnerabilities"] = [new[key] for key in sorted(set(new) - set(old))]
        result["resolved_vulnerabilities"] = [old[key] for key in sorted(set(old) - set(new))]
    drift = (current.get("sbomlyze_diff") or {}).get("drift") or {}
    result["integrity_drift"] = int(drift.get("integrity_drift") or 0)
    before_score = (previous.get("scorecard") or {}).get("score")
    after_score = (current.get("scorecard") or {}).get("score")
    if isinstance(before_score, (int, float)) and isinstance(after_score, (int, float)) and abs(before_score - after_score) >= 0.1:
        result["scorecard"] = {"from": before_score, "to": after_score}
    before_verdict = (previous.get("release_integrity") or {}).get("verdict")
    after_verdict = (current.get("release_integrity") or {}).get("verdict")
    if before_verdict and after_verdict and before_verdict != after_verdict:
        result["release_integrity"] = {"from": before_verdict, "to": after_verdict}
    if previous.get("workflow_audit") is not None and current.get("workflow_audit") is not None:
        def workflow_keys(project: dict[str, Any]) -> set[str]:
            return {f"{item['rule']}|{item['file']}|{item['note']}" for item in project["workflow_audit"]["findings"]}
        result["workflow_new"] = len(workflow_keys(current) - workflow_keys(previous))
        result["workflow_resolved"] = len(workflow_keys(previous) - workflow_keys(current))
    if previous.get("go_binary") and current.get("go_binary"):
        def in_binary(project: dict[str, Any]) -> set[str]:
            return {item["id"] for item in project["go_binary"]["findings"] if item["level"] == "symbol"}
        result["in_binary_new"] = sorted(in_binary(current) - in_binary(previous))
        result["in_binary_resolved"] = sorted(in_binary(previous) - in_binary(current))
    result["any"] = bool(
        result["release_changed"] or result["added"] or result["removed"] or result["upgraded"]
        or result["license_changes"] or result.get("new_vulnerabilities") or result.get("resolved_vulnerabilities")
        or result["integrity_drift"] or result.get("scorecard") or result.get("release_integrity")
        or result.get("workflow_new") or result.get("in_binary_new")
    )
    return result


def history_entry(date: str, project: dict[str, Any]) -> dict[str, Any]:
    change = project.get("changes") or {}
    vulns = project.get("vulnerabilities")
    return {
        "date": date,
        "ref": project.get("ref"),
        "commit": project.get("commit"),
        "dependencies": len(project.get("components") or []) if project.get("components") is not None else None,
        "vulnerabilities": severity_counts(vulns) if vulns is not None else None,
        "fixable": sum(1 for item in vulns or [] if item.get("fixed_in")) if vulns is not None else None,
        "added": len(change.get("added") or []),
        "removed": len(change.get("removed") or []),
        "upgraded": len(change.get("upgraded") or []),
        "new_vulnerabilities": len(change.get("new_vulnerabilities") or []),
        "resolved_vulnerabilities": len(change.get("resolved_vulnerabilities") or []),
        "release_changed": bool(change.get("release_changed")),
        "osv_confirmed": (project.get("osv") or {}).get("confirmed"),
        "osv_only": len((project.get("osv") or {}).get("osv_only") or []) if (project.get("osv") or {}).get("available") else None,
        "in_binary": in_binary_counts(project.get("go_binary")),
        "go_version": (project.get("go_binary") or {}).get("go_version"),
        "workflow": workflow_counts(project.get("workflow_audit")),
        "scorecard": (project.get("scorecard") or {}).get("score"),
        "release_integrity": (project.get("release_integrity") or {}).get("verdict"),
        "errors": project.get("errors") or [],
    }


def in_binary_counts(go: dict[str, Any] | None) -> dict[str, int] | None:
    if not go:
        return None
    symbols = [item for item in go["findings"] if item["level"] == "symbol"]
    return {
        "total": len(symbols),
        "stdlib": sum(1 for item in symbols if item["module"] == "stdlib"),
        "dependencies": sum(1 for item in symbols if item["module"] != "stdlib"),
    }


def workflow_counts(audit: dict[str, Any] | None) -> dict[str, int] | None:
    if audit is None:
        return None
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for item in audit.get("findings") or []:
        if item["severity"] in counts:
            counts[item["severity"]] += 1
    return {**counts, "files": audit.get("files", 0)}


def command_publish(args: argparse.Namespace) -> int:
    projects_dir = args.data_dir / "projects"
    runs_dir = args.data_dir / "runs"
    shards = sorted(args.shards_dir.glob("**/shard-*.json"))
    if not shards:
        raise ValueError(f"no shard results in {args.shards_dir}")
    tools: dict[str, Any] = {}
    week = []
    for shard_path in shards:
        shard = load_json(shard_path)
        tools.update(shard.get("tools") or {})
        for project in shard["projects"]:
            path = projects_dir / f"{project['id']}.json"
            stored = load_json(path) if path.is_file() else {}
            previous = stored.get("latest")
            if project.get("components") is None and previous:
                # A failed scan keeps last week's inventory visible and is marked as failed.
                project = {**previous, "errors": project.get("errors"), "scanned_at": project.get("scanned_at"), "stale": True}
                project["changes"] = {"baseline": False, "any": False, "scan_failed": True}
            else:
                if not project.get("scorecard") and previous and previous.get("scorecard"):
                    # Scorecard CLI runs are rate limited; keep the last result until it is refreshed.
                    project["scorecard"] = {**previous["scorecard"], "carried_forward": True}
                project["changes"] = changes(previous, project)
            history = [item for item in stored.get("history") or [] if item["date"] != args.date]
            history.append(history_entry(args.date, project))
            history.sort(key=lambda item: item["date"])
            write_json(path, {"latest": project, "history": history, "updated": args.date})
            week.append({
                **history[-1], "id": project["id"], "repository": project["repository"], "name": project.get("name"),
                "category": project.get("category"), "ref_kind": project.get("ref_kind"),
                "released_at": project.get("released_at"), "stale": bool(project.get("stale")),
                "compliance": (project.get("compliance") or {}).get("standards"),
                "change_any": bool((project.get("changes") or {}).get("any")),
                "integrity_drift": (project.get("changes") or {}).get("integrity_drift", 0),
            })
    week.sort(key=lambda item: item["repository"].lower())
    write_json(runs_dir / f"{args.date}.json", {
        "schema_version": SCHEMA_VERSION, "date": args.date, "generated_at": utc_now(),
        "commit": args.commit, "tools": tools, "projects": week,
    }, indent=None)
    dates = sorted(path.stem for path in runs_dir.glob("*.json"))
    write_json(args.data_dir / "index.json", {"runs": list(reversed(dates)), "latest": dates[-1]})
    (args.data_dir / "README.md").write_text(
        "# Supply-chain report data\n\nMachine-written by `.github/workflows/supply-chain-report.yml`. "
        "`projects/<owner>__<repo>.json` holds the latest inventory, findings, and weekly history for one "
        "catalog project; `runs/<date>.json` summarizes one weekly run. Do not edit by hand.\n",
        encoding="utf-8",
    )
    print(f"Recorded {len(week)} projects for {args.date}")
    return 0


# ----- entry point -----------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    targets = commands.add_parser("targets")
    targets.add_argument("--tools", type=pathlib.Path, default=pathlib.Path("tools"))
    targets.add_argument("--shards", type=int, default=8)
    targets.add_argument("--tag-patterns", type=pathlib.Path,
                         default=pathlib.Path("benchmarks/supply-chain/release-tags.json"))
    targets.add_argument("--limit", type=int, default=0)
    targets.add_argument("--only", action="append", default=[])
    targets.add_argument("--output", type=pathlib.Path, required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--targets", type=pathlib.Path, required=True)
    scan.add_argument("--shard", type=int, required=True)
    scan.add_argument("--output-dir", type=pathlib.Path, required=True)
    scan.add_argument("--previous-dir", type=pathlib.Path)
    scan.add_argument("--sbomlyze", default="sbomlyze")
    scan.add_argument("--scorecard-cli-limit", type=int, default=1,
                      help="projects per shard that may fall back to the Scorecard CLI (API-rate bound)")
    publish = commands.add_parser("publish")
    publish.add_argument("--shards-dir", type=pathlib.Path, required=True)
    publish.add_argument("--data-dir", type=pathlib.Path, required=True)
    publish.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).date().isoformat())
    publish.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "local"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return {"targets": command_targets, "scan": command_scan, "publish": command_publish}[args.command](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"supply-chain report failed: {exc}", file=sys.stderr)
        sys.exit(1)
