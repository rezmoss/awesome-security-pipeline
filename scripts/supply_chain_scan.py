#!/usr/bin/env python3
"""Weekly supply-chain report for every active tool in the catalog.

Subcommands:
  targets   read the active tools from tools/, resolve each project's latest release, and shard the list
  scan      fetch the manifests and lockfiles at each release tag, then run Syft, Grype, and sbomlyze
  publish   record the week's results in the data branch and compute changes from the previous week
  baseline  print the run that produced the previous week's data, for drift comparison
  verify    check the data branch: recomputation, checksums, append-only history, and attestations

Only dependency manifests and lockfiles are fetched (a blobless, sparse checkout). Test, fixture,
example, documentation, and vendored directories are excluded because security tools ship
deliberately vulnerable fixtures that would otherwise dominate the results.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
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

SCHEMA_VERSION = 2
WORKFLOW_PATH = ".github/workflows/supply-chain-report.yml"
GO_VULN_INDEX = "https://vuln.go.dev/index/db.json"
CHECKSUMS_FILE = "SHA256SUMS"
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


def release_checks(target: dict[str, Any], summary: dict[str, Any], work: pathlib.Path, evidence: pathlib.Path) -> None:
    asset = checks.select_linux_asset(target.get("assets") or [], target["repository"])
    file = None
    if asset:
        file = work / asset["name"]
        checks.download(asset["browser_download_url"], file)
        binaries = checks.extract_binaries(file, work / "extracted")
        is_go = any(path.endswith("go.mod") for path in summary.get("manifests") or [])
        for binary in binaries if is_go else []:
            result = checks.govulncheck_binary(binary, evidence / "govulncheck.json")
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
        osv = check(summary, "osv-scanner", checks.osv_scan, source, directory / "osv-scanner.json") or {}
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
            check(summary, "release checks", release_checks, target, summary, pathlib.Path(temporary), directory)
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
    environment = scan_environment(args.shard)
    tools["grype_db_built"] = (environment.get("grype_db") or {}).get("built")
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
    environment["finished_at"] = utc_now()
    write_json(args.output_dir / f"shard-{args.shard}.json", {"tools": tools, "environment": environment, "projects": results})
    return 0


def grype_database() -> dict[str, Any]:
    """What `grype db status` reports, plus our own hash of the database file that was used."""
    completed = run(["grype", "db", "status", "-o", "json"], timeout=120)
    if completed.returncode != 0 or not completed.stdout.strip():
        return {"error": completed.stderr.strip()[:200] or "grype db status failed"}
    status = json.loads(completed.stdout)
    result = {key: status.get(key) for key in ("schemaVersion", "built", "from", "valid") if status.get(key) is not None}
    path = pathlib.Path(str(status.get("path") or ""))
    database = path / "vulnerability.db" if path.is_dir() else path
    if status.get("path") and database.is_file():
        result["sha256"] = checks.sha256(database)
    return result


def go_vulnerability_database() -> dict[str, Any]:
    try:
        return {"url": "https://vuln.go.dev", "modified": checks.fetch_json(GO_VULN_INDEX).get("modified")}
    except Exception as exc:  # noqa: BLE001 - provenance is best effort
        return {"url": "https://vuln.go.dev", "error": str(exc)[:200]}


def scan_environment(shard: int) -> dict[str, Any]:
    """Where and against which databases this shard ran, recorded with the results."""
    return {
        "shard": shard,
        "started_at": utc_now(),
        "runner": {key: os.environ.get(name) for key, name in (
            ("os", "ImageOS"), ("image_version", "ImageVersion"), ("name", "RUNNER_NAME"), ("arch", "RUNNER_ARCH"))
            if os.environ.get(name)},
        "grype_db": grype_database(),
        "go_vulndb": go_vulnerability_database(),
        # OSV-Scanner has no local snapshot in this mode: each project is queried live against osv.dev.
        "osv": {"mode": "live osv.dev API", "url": "https://api.osv.dev"},
    }


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
    card = project.get("scorecard") or {}
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
        "scorecard": card.get("score"),
        "scorecard_source": ("carried-forward" if card.get("carried_forward") else card.get("source")) if card else None,
        "scorecard_date": card.get("date") if card else None,
        "scorecard_note": project.get("scorecard_note") if not card else None,
        "release_integrity": (project.get("release_integrity") or {}).get("verdict"),
        "errors": project.get("errors") or [],
    }


def run_row(project: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    """One project's row in runs/<date>.json; `verify` recomputes it from the project file."""
    return {
        **entry, "id": project["id"], "repository": project["repository"], "name": project.get("name"),
        "category": project.get("category"), "ref_kind": project.get("ref_kind"),
        "released_at": project.get("released_at"), "stale": bool(project.get("stale")),
        "compliance": (project.get("compliance") or {}).get("standards"),
        "change_any": bool((project.get("changes") or {}).get("any")),
        "integrity_drift": (project.get("changes") or {}).get("integrity_drift", 0),
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


def run_provenance(args: argparse.Namespace) -> dict[str, Any]:
    """The workflow run that produced this data, from the standard GitHub Actions environment."""
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID")
    attempt = int(os.environ.get("GITHUB_RUN_ATTEMPT") or 1)
    event = os.environ.get("GITHUB_EVENT_NAME", "local")
    reason = args.reason or ("scheduled weekly scan" if event == "schedule" else f"{event} run")
    if attempt > 1:
        reason += f" (re-run attempt {attempt})"
    return {
        "repository": repository or None,
        "workflow": WORKFLOW_PATH,
        "id": int(run_id) if run_id else None,
        "attempt": attempt,
        "url": f"{server}/{repository}/actions/runs/{run_id}/attempts/{attempt}" if run_id and repository else None,
        "event": event,
        "commit": args.commit,
        "ref": os.environ.get("GITHUB_REF"),
        "reason": reason,
    }


def git(data_dir: pathlib.Path, *arguments: str, check: bool = True) -> str:
    completed = run(["git", "-C", str(data_dir), *arguments], timeout=120)
    if check and completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(arguments[:2])} failed: {completed.stderr.strip()[:200]}")
    return completed.stdout


def is_git_repository(path: pathlib.Path) -> bool:
    return run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"], timeout=30).stdout.strip() == "true"


def show_json(data_dir: pathlib.Path, commit: str, path: str) -> Any:
    completed = run(["git", "-C", str(data_dir), "show", f"{commit}:{path}"], timeout=120)
    return json.loads(completed.stdout) if completed.returncode == 0 and completed.stdout.strip() else None


def previous_week_commit(data_dir: pathlib.Path, date: str) -> str | None:
    """The newest data commit whose latest run is older than `date`, so re-runs compare with last week."""
    if not is_git_repository(data_dir):
        return None
    for commit in git(data_dir, "rev-list", "--first-parent", "HEAD", check=False).split():
        index = show_json(data_dir, commit, "index.json") or {}
        if index.get("latest") and index["latest"] < date:
            return commit
    return None


def write_checksums(data_dir: pathlib.Path) -> None:
    lines = [f"{checks.sha256(path)}  {path.relative_to(data_dir).as_posix()}" for path in data_files(data_dir)]
    (data_dir / CHECKSUMS_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


def data_files(data_dir: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        path for path in data_dir.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(data_dir).parts and path.name != CHECKSUMS_FILE
    )


def command_publish(args: argparse.Namespace) -> int:
    projects_dir = args.data_dir / "projects"
    runs_dir = args.data_dir / "runs"
    shards = sorted(args.shards_dir.glob("**/shard-*.json"))
    if not shards:
        raise ValueError(f"no shard results in {args.shards_dir}")
    provenance = run_provenance(args)
    run_file = runs_dir / f"{args.date}.json"
    superseded = None
    if run_file.is_file():
        # A second run for the same week replaces the first; the replaced record is kept.
        old = load_json(run_file)
        old_run = (old.get("provenance") or {}).get("run") or {}
        name = (f"{old_run['id']}-{old_run.get('attempt', 1)}" if old_run.get("id")
                else "unrecorded-" + re.sub(r"[^0-9T]", "", str(old.get("generated_at") or "")))
        superseded = runs_dir / "superseded" / args.date / f"{name}.json"
        superseded.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(run_file, superseded)
    baseline_commit = previous_week_commit(args.data_dir, args.date) if superseded else None
    tools: dict[str, Any] = {}
    environments = []
    week = []
    for shard_path in shards:
        shard = load_json(shard_path)
        tools.update(shard.get("tools") or {})
        if shard.get("environment"):
            environments.append(shard["environment"])
        for project in shard["projects"]:
            path = projects_dir / f"{project['id']}.json"
            stored = load_json(path) if path.is_file() else {}
            previous = stored.get("latest")
            if stored.get("updated") == args.date:
                # Same-week re-run: compare with the previous week, not with the run being replaced.
                prior = show_json(args.data_dir, baseline_commit, f"projects/{project['id']}.json") if baseline_commit else None
                previous = (prior or {}).get("latest") if baseline_commit else previous
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
            week.append(run_row(project, history[-1]))
    week.sort(key=lambda item: item["repository"].lower())
    environments.sort(key=lambda item: item.get("shard", 0))
    write_json(run_file, {
        "schema_version": SCHEMA_VERSION, "date": args.date, "generated_at": utc_now(),
        "commit": args.commit, "tools": tools, "projects": week,
        "provenance": {"run": provenance, "shards": environments},
        "evidence_release": args.evidence_release,
        "supersedes": superseded.relative_to(args.data_dir).as_posix() if superseded else None,
    }, indent=None)
    dates = sorted(path.stem for path in runs_dir.glob("*.json"))
    replaced = {
        directory.name: sorted(item.relative_to(args.data_dir).as_posix() for item in directory.glob("*.json"))
        for directory in sorted((runs_dir / "superseded").glob("*")) if directory.is_dir()
    }
    write_json(args.data_dir / "index.json", {"runs": list(reversed(dates)), "latest": dates[-1], "superseded": replaced})
    (args.data_dir / "README.md").write_text(
        "# Supply-chain report data\n\nMachine-written by `.github/workflows/supply-chain-report.yml`. "
        "`projects/<owner>__<repo>.json` holds the latest inventory, findings, and weekly history for one "
        "catalog project; `runs/<date>.json` summarizes one weekly run, including the workflow run, commit, "
        "runner image, and vulnerability databases that produced it. When a week is re-run, the replaced "
        "summary is kept under `runs/superseded/<date>/`. `SHA256SUMS` lists every file; each file is covered "
        "by a GitHub artifact attestation from the workflow (`gh attestation verify <file> --repo "
        f"{provenance['repository'] or '<owner>/<repo>'}`). Do not edit by hand: history is append-only and checked by "
        "`scripts/supply_chain_scan.py verify`.\n",
        encoding="utf-8",
    )
    write_checksums(args.data_dir)
    print(f"Recorded {len(week)} projects for {args.date}" + (f" (superseding {superseded.name})" if superseded else ""))
    return 0


# ----- baseline --------------------------------------------------------------------------

def command_baseline(args: argparse.Namespace) -> int:
    """Print the previous week's canonical run, for downloading its SBOMs."""
    result: dict[str, Any] = {"date": None, "run_id": None, "generated_at": None}
    index_path = args.data_dir / "index.json"
    if index_path.is_file():
        earlier = [date for date in load_json(index_path).get("runs") or [] if date < args.date]
        if earlier:
            previous = load_json(args.data_dir / "runs" / f"{earlier[0]}.json")
            result.update(date=earlier[0], generated_at=previous.get("generated_at"),
                          run_id=((previous.get("provenance") or {}).get("run") or {}).get("id"))
    print(json.dumps(result))
    return 0


# ----- verify ----------------------------------------------------------------------------

HISTORY_KEYS = ("ref", "commit", "dependencies", "vulnerabilities", "fixable", "added", "removed", "upgraded",
                "new_vulnerabilities", "resolved_vulnerabilities", "release_changed", "scorecard", "errors")


def verify_tree(data_dir: pathlib.Path) -> list[str]:
    """Problems in one checkout of the data branch; an empty list means it is consistent."""
    problems = []
    runs_dir = data_dir / "runs"
    index = load_json(data_dir / "index.json")
    dates = sorted(path.stem for path in runs_dir.glob("*.json"))
    if index.get("runs") != list(reversed(dates)) or index.get("latest") != (dates[-1] if dates else None):
        problems.append("index.json does not match the run files")
    projects = {path.stem: load_json(path) for path in sorted((data_dir / "projects").glob("*.json"))}
    for date in dates:
        run_data = load_json(runs_dir / f"{date}.json")
        if run_data.get("date") != date:
            problems.append(f"runs/{date}.json records date {run_data.get('date')}")
        for row in run_data.get("projects") or []:
            stored = projects.get(row["id"])
            entry = next((item for item in (stored or {}).get("history") or [] if item["date"] == date), None)
            if entry is None:
                problems.append(f"runs/{date}.json lists {row['id']} but its project history has no {date} entry")
                continue
            if date == dates[-1] and stored.get("updated") == date:
                expected = run_row(stored["latest"], entry)
                if row != expected:
                    keys = sorted(key for key in set(row) | set(expected) if row.get(key) != expected.get(key))
                    problems.append(f"runs/{date}.json row for {row['id']} differs from the project file: {', '.join(keys)}")
            else:
                keys = [key for key in HISTORY_KEYS if key in entry and row.get(key) != entry.get(key)]
                if keys:
                    problems.append(f"runs/{date}.json row for {row['id']} differs from its history entry: {', '.join(keys)}")
    for directory, files in (index.get("superseded") or {}).items():
        for name in files:
            if not (data_dir / name).is_file():
                problems.append(f"index.json lists missing superseded run {name}")
    checksums = data_dir / CHECKSUMS_FILE
    if checksums.is_file():
        listed = {}
        for line in checksums.read_text(encoding="utf-8").splitlines():
            digest, _, name = line.partition("  ")
            listed[name] = digest
        actual = {path.relative_to(data_dir).as_posix(): path for path in data_files(data_dir)}
        for name in sorted(set(listed) ^ set(actual)):
            problems.append(f"{CHECKSUMS_FILE} {'lists missing' if name in listed else 'does not list'} {name}")
        for name in sorted(set(listed) & set(actual)):
            if checks.sha256(actual[name]) != listed[name]:
                problems.append(f"{name} does not match its {CHECKSUMS_FILE} digest")
    return problems


def verify_step(data_dir: pathlib.Path, before: str, after: str) -> list[str]:
    """Rules for one data commit: only the newest week may be replaced, and nothing may be deleted."""
    problems = []
    short = after[:12]
    latest = (show_json(data_dir, before, "index.json") or {}).get("latest") or ""
    archived = run(["git", "-C", str(data_dir), "cat-file", "-e", f"{after}:{CHECKSUMS_FILE}"], timeout=30).returncode == 0
    for line in git(data_dir, "diff", "--name-status", "--no-renames", before, after).splitlines():
        status, _, path = line.partition("\t")
        if path in ("index.json", "README.md", CHECKSUMS_FILE):
            continue
        if status == "A":
            name = pathlib.PurePosixPath(path)
            if name.parent.as_posix() == "runs" and latest and name.stem < latest:
                problems.append(f"{short} adds {path}, which is older than the newest week ({latest})")
            continue
        if status == "D":
            problems.append(f"{short} deletes {path}")
        elif path.startswith("runs/superseded/"):
            problems.append(f"{short} modifies superseded run {path}")
        elif path.startswith("runs/"):
            date = pathlib.PurePosixPath(path).stem
            if date != latest:
                problems.append(f"{short} rewrites {path}, which is older than the newest week ({latest})")
            elif archived and not (show_json(data_dir, after, "runs/" + date + ".json") or {}).get("supersedes"):
                problems.append(f"{short} replaces {path} without keeping the replaced run")
        elif path.startswith("projects/"):
            old = {item["date"]: item for item in (show_json(data_dir, before, path) or {}).get("history") or []}
            new = {item["date"]: item for item in (show_json(data_dir, after, path) or {}).get("history") or []}
            for date in sorted(old):
                if date != latest and old[date] != new.get(date):
                    problems.append(f"{short} rewrites the {date} history of {path}")
    return problems


def verify_history(data_dir: pathlib.Path, anchors: list[str]) -> tuple[list[str], int]:
    problems = []
    if git(data_dir, "rev-list", "--merges", "HEAD").strip():
        problems.append("the data branch contains merge commits")
    commits = git(data_dir, "rev-list", "--first-parent", "--reverse", "HEAD").split()
    for before, after in zip(commits, commits[1:]):
        problems.extend(verify_step(data_dir, before, after))
    for tag in anchors:
        # Every evidence release pins a data commit; a rewritten branch would no longer contain it.
        if run(["git", "-C", str(data_dir), "merge-base", "--is-ancestor", tag, "HEAD"], timeout=30).returncode != 0:
            problems.append(f"release tag {tag} is not in the data branch history")
    return problems, len(commits)


def verify_attestation(path: pathlib.Path, repository: str) -> str | None:
    completed = run(["gh", "attestation", "verify", str(path), "--repo", repository,
                     "--signer-workflow", f"{repository}/{WORKFLOW_PATH}"], timeout=120)
    return None if completed.returncode == 0 else (completed.stderr.strip().splitlines() or ["failed"])[-1][:300]


def command_verify(args: argparse.Namespace) -> int:
    problems = verify_tree(args.data_dir)
    print(f"tree: {len(problems)} problem(s)")
    if args.history:
        anchors = git(args.data_dir, "tag", "--list", "report-*").split()
        found, count = verify_history(args.data_dir, anchors)
        problems.extend(found)
        print(f"history: {count} commit(s), {len(anchors)} release anchor(s), {len(found)} problem(s)")
    if args.attestations:
        checksums = args.data_dir / CHECKSUMS_FILE
        latest = (load_json(args.data_dir / "index.json").get("latest") or "")
        legacy = not (load_json(args.data_dir / "runs" / f"{latest}.json").get("provenance") if latest else None)
        if not checksums.is_file() and legacy:
            print(f"attestation: skipped, the newest week ({latest}) predates attestation")
        elif not checksums.is_file():
            problems.append(f"no {CHECKSUMS_FILE}, but the newest week records provenance")
        elif error := verify_attestation(checksums, args.repository):
            problems.append(f"{CHECKSUMS_FILE} attestation did not verify: {error}")
        else:
            print(f"attestation: {CHECKSUMS_FILE} verified for {args.repository}")
    for problem in problems:
        print(f"  - {problem}")
    return 1 if problems else 0


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
    publish.add_argument("--reason", default="", help="why this run was started, recorded with its provenance")
    publish.add_argument("--evidence-release", default=None, help="tag of the release holding this run's raw evidence")
    baseline = commands.add_parser("baseline")
    baseline.add_argument("--data-dir", type=pathlib.Path, required=True)
    baseline.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).date().isoformat())
    verify = commands.add_parser("verify")
    verify.add_argument("--data-dir", type=pathlib.Path, required=True)
    verify.add_argument("--history", action="store_true", help="check every data commit (needs full git history)")
    verify.add_argument("--attestations", action="store_true", help="verify the SHA256SUMS attestation with gh")
    verify.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "rezmoss/awesome-security-pipeline"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return {"targets": command_targets, "scan": command_scan, "publish": command_publish,
            "baseline": command_baseline, "verify": command_verify}[args.command](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"supply-chain report failed: {exc}", file=sys.stderr)
        sys.exit(1)
