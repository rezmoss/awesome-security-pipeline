#!/usr/bin/env python3
"""Weekly supply-chain report for every active tool in the catalog.

Subcommands:
  targets   read the active tools from tools/, resolve each project's latest release, and shard the list
  scan      fetch the manifests and lockfiles at each release tag, then run Syft, Grype, and sbomlyze
  publish   record the week's results in the data branch and compute changes from the previous week
  enrich    download the CISA KEV catalog and FIRST EPSS scores applied to matches at publish time
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
from scripts import enrichment  # noqa: E402
from scripts import site_exports  # noqa: E402
from scripts import supply_chain_checks as checks  # noqa: E402

SCHEMA_VERSION = 5
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
# Compound names such as integration-tests, test-fixtures, functional-tests, server-mock, gotestdata.
EXCLUDED_DIRECTORY_PATTERN = re.compile(
    r"(^|[-_.])(tests?|testdata|testing|fixtures?|mocks?|e2e|examples?|samples?|benchmarks?)($|[-_.])|testdata$",
    re.IGNORECASE,
)
# A GitHub Action referenced by an exact release; a moving tag or branch (v4, release/v1) has no fixed version.
EXACT_ACTION_VERSION = re.compile(r"v?\d+\.\d+\.\d+")
# npm versions that point at the repository itself rather than the registry.
LOCAL_NPM_VERSION = re.compile(r"^(file|link|workspace|portal|git\+|git|https?):", re.IGNORECASE)
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


def run(command: list[str], cwd: pathlib.Path | None = None, timeout: int = TOOL_TIMEOUT,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
                          env={**os.environ, **env} if env else None)


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

def excluded_directory(name: str) -> bool:
    return name.lower() in EXCLUDED_DIRECTORIES or bool(EXCLUDED_DIRECTORY_PATTERN.search(name))


def wanted_path(path: str) -> bool:
    parts = path.split("/")
    if path.startswith(".github/workflows/") and WORKFLOW_FILE.match(path):
        return True
    if any(excluded_directory(part) for part in parts[:-1]):
        return False
    return bool(WORKFLOW_FILE.match(path)) or any(fnmatch.fnmatch(parts[-1], pattern) for pattern in MANIFESTS)


def lockfile_aliases(source: pathlib.Path) -> dict[str, str]:
    """Copy each npm-shrinkwrap.json without a package-lock.json beside it, which Syft does not read, to
    package-lock.json (the same format); return the copies' paths mapped to the original names."""
    aliases = {}
    for shrinkwrap in sorted(source.rglob("npm-shrinkwrap.json")):
        lock = shrinkwrap.with_name("package-lock.json")
        if not lock.exists():
            shutil.copyfile(shrinkwrap, lock)
            aliases[lock.relative_to(source).as_posix()] = shrinkwrap.relative_to(source).as_posix()
    return aliases


def local_npm_packages(source: pathlib.Path) -> set[str]:
    """Names of the npm packages the repository itself defines: they are never installed from the registry,
    so a registry advisory for the same name (for example malware published under it) does not apply."""
    names = set()
    for manifest in source.rglob("package.json"):
        try:
            name = json.loads(manifest.read_text(encoding="utf-8")).get("name")
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(name, str) and name:
            names.add(name)
    return names


def excluded_match(entry: dict[str, Any], local_packages: set[str]) -> str | None:
    """Why a Grype match does not identify an installed version, or None when it does."""
    if entry["ecosystem"] == "github" and not EXACT_ACTION_VERSION.fullmatch(entry["version"]):
        return "action reference to a moving tag or branch"
    if entry["ecosystem"] == "npm" and (LOCAL_NPM_VERSION.match(entry["version"]) or entry["package"] in local_packages):
        return "package defined in the repository itself"
    return None


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


def normalize_grype(report: dict[str, Any], local_packages: set[str] | None = None,
                    excluded: dict[str, int] | None = None) -> list[dict[str, Any]]:
    findings, skipped = {}, {}
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
            "purl": str(artifact.get("purl") or "").split("?", 1)[0],
            "fixed_in": list(fix.get("versions") or []),
            "fix_state": str(fix.get("state") or "unknown"),
            "url": str(vulnerability.get("dataSource") or ""),
            "summary": " ".join(str(vulnerability.get("description") or "").split())[:300],
            "locations": sorted({str(item.get("path", "")).lstrip("/") for item in artifact.get("locations") or []} - {""}),
        }
        key = (entry["id"], entry["ecosystem"], entry["package"], entry["version"])
        reason = excluded_match(entry, local_packages or set())
        if reason:
            skipped[key] = reason
            continue
        existing = findings.get(key)
        if existing:
            # Grype reports one match per lockfile that declares the version; keep every location so the
            # result does not depend on the order of the matches.
            entry["aliases"] = sorted(set(existing["aliases"]) | set(entry["aliases"]))
            entry["locations"] = sorted(set(existing["locations"]) | set(entry["locations"]))
        findings[key] = entry
    if excluded is not None:
        for reason in skipped.values():
            excluded[reason] = excluded.get(reason, 0) + 1
    for entry in findings.values():
        entry["location"] = entry["locations"][0] if entry["locations"] else ""
    order = {name: index for index, name in enumerate(SEVERITIES)}
    return sorted(findings.values(), key=lambda item: (order.get(item["severity"], 99), item["package"], item["id"],
                                                      item["ecosystem"], item["version"]))


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


def sbomlyze_occurrences(diff: dict[str, Any], aliases_before: dict[str, str], aliases_after: dict[str, str]) -> dict[str, Any]:
    """The parts of sbomlyze's diff the report shows, per occurrence (package × lockfile). sbomlyze does the
    matching, version ordering, and hash comparison; this only reshapes its output and maps lockfile aliases back."""
    def place(path: str, aliases: dict[str, str]) -> str:
        path = str(path or "").lstrip("/")
        return aliases.get(path, path)

    def package(item: dict[str, Any], aliases: dict[str, str]) -> dict[str, Any]:
        return {"name": str(item.get("name") or ""), "ecosystem": ecosystem(str(item.get("purl") or "")),
                "version": str(item.get("version") or ""),
                "location": place((item.get("locations") or [""])[0], aliases),
                "locations": sorted(place(path, aliases) for path in item.get("locations") or [])}

    result: dict[str, Any] = {
        "added": [package(item, aliases_after) for item in diff.get("added") or [] if item.get("type") != "file"],
        "removed": [package(item, aliases_before) for item in diff.get("removed") or [] if item.get("type") != "file"],
        "version_changes": [], "integrity_changes": [], "metadata_changes": [], "license_changes": [],
        "moved": [{"name": item.get("name"), "version": item.get("version"),
                   "from": place(item.get("from"), aliases_before), "to": place(item.get("to"), aliases_after)}
                  for item in diff.get("moved") or []],
        "version_set_changes": [{"name": item.get("name"), "location": place(item.get("location"), aliases_after),
                                 "removed_versions": item.get("removed_versions") or [],
                                 "added_versions": item.get("added_versions") or []}
                                for item in diff.get("version_set_changes") or []],
        "file_changes": [{"path": place(item.get("path"), aliases_after), "owners": item.get("owners") or []}
                         for item in diff.get("file_changes") or []],
        "files_added": [place(item.get("path"), aliases_after) for item in diff.get("files_added") or []],
        "files_removed": [place(item.get("path"), aliases_before) for item in diff.get("files_removed") or []],
        "owned_file_drift": [{"name": item.get("name"), "version": item.get("version"),
                              "location": place(item.get("location"), aliases_after),
                              "files": [entry.get("path") for entry in item.get("files") or []]}
                             for item in diff.get("owned_file_drift") or []],
        "source_change": diff.get("source_change"),
        "digest_coverage": diff.get("digest_coverage"),
        "file_coverage": diff.get("file_coverage"),
    }
    for item in diff.get("changed") or []:
        before, after, drift = item.get("before") or {}, item.get("after") or {}, item.get("drift") or {}
        common = {"name": str(item.get("name") or after.get("name") or ""),
                  "ecosystem": ecosystem(str(after.get("purl") or before.get("purl") or "")),
                  "location": place(item.get("location"), aliases_after)}
        if drift.get("type") == "version":
            result["version_changes"].append({**common, "from": drift.get("version_from"), "to": drift.get("version_to"),
                                              "direction": drift.get("direction") or "unknown",
                                              "level": drift.get("level") or "unknown"})
        elif drift.get("type") == "integrity":
            changes = (drift.get("hash_changes") or {}).get("changed") or {}
            result["integrity_changes"].append({**common, "version": after.get("version"), "kinds": sorted(changes),
                                                "hashes": changes})
        else:
            result["metadata_changes"].append({**common, "version": after.get("version"), "changes": item.get("changes") or []})
        if drift.get("licenses_diff"):
            result["license_changes"].append({**common, "version_from": before.get("version"), "version_to": after.get("version"),
                                              "from": sorted(before.get("licenses") or []), "to": sorted(after.get("licenses") or []),
                                              "diff": drift["licenses_diff"]})
    return result


def sbomlyze_change(diff: dict[str, Any]) -> bool:
    """Whether sbomlyze reports any difference, including file-only and source-only changes."""
    return any(diff.get(key) for key in ("added", "removed", "changed", "moved", "file_changes", "files_added",
                                         "files_removed", "owned_file_drift", "source_change"))


def sbomlyze_diff(binary: str, previous: pathlib.Path, current: pathlib.Path, html_target: pathlib.Path,
                  raw_target: pathlib.Path | None = None, aliases_before: dict[str, str] | None = None,
                  aliases_after: dict[str, str] | None = None, baseline: dict[str, Any] | None = None) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary)
        shutil.copyfile(previous, work / "previous.cdx.json")
        shutil.copyfile(current, work / "current.cdx.json")
        completed = run([binary, "previous.cdx.json", "current.cdx.json", "--json", "--no-pager"], cwd=work)
        if completed.returncode not in (0, 1) or not completed.stdout.strip():
            return None
        if raw_target is not None:
            raw_target.write_text(completed.stdout.strip() + "\n", encoding="utf-8")
        report = json.loads(completed.stdout)
        diff = report.get("diff") or {}
        summary = {
            "added": len(diff.get("added") or []),
            "removed": len(diff.get("removed") or []),
            "changed": len(diff.get("changed") or []),
            "drift": diff.get("drift_summary") or {},
            "findings": [item.get("message", "") for item in (report.get("findings") or {}).get("findings") or []],
            "previous_sbom_sha256": checks.sha256(previous),
            "sbom_sha256": checks.sha256(current),
            "baseline": baseline or {},
        }
        # 0.7.1+ always reports digest coverage for a pair with packages; without it the fields below mean
        # something else (0.6.x counted file entries as integrity drift).
        summary["contract"] = "sbomlyze-diff-0.7" if "digest_coverage" in diff or not sbomlyze_change(diff) else "unsupported"
        if summary["contract"] != "unsupported":
            summary["occurrences"] = sbomlyze_occurrences(diff, aliases_before or {}, aliases_after or {})
        if sbomlyze_change(diff):
            page = run([binary, "previous.cdx.json", "current.cdx.json", "--format", "html", "--no-pager"], cwd=work)
            if page.returncode in (0, 1) and page.stdout.strip():
                html_target.parent.mkdir(parents=True, exist_ok=True)
                html_target.write_text(page.stdout, encoding="utf-8")
                summary["html"] = html_target.name
            else:
                summary["html_error"] = f"sbomlyze --format html exited with {page.returncode}"
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
                scorecard_cli: bool = False, baseline_run: dict[str, Any] | None = None) -> dict[str, Any]:
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
        local_packages = local_npm_packages(source)
        summary["local_packages"] = sorted(local_packages)
        osv = check(summary, "osv-scanner", checks.osv_scan, source, directory / "osv-scanner.json") or {}
        if osv.get("error"):
            summary["errors"].append(osv["error"])
        lock_aliases = lockfile_aliases(source)
        sbom = directory / "sbom.cdx.json"
        # Syft skips npm devDependencies by default; every other ecosystem includes development dependencies.
        syft = run(["syft", "scan", f"dir:{source}", "--source-name", target["repository"],
                    "--source-version", target["ref"], "-q", "-o", f"cyclonedx-json={sbom}"],
                   env={"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"})
        if syft.returncode != 0 or not sbom.is_file():
            summary["errors"].append(f"syft failed: {syft.stderr.strip()[:300]}")
            return summary
        workflows = check(summary, "zizmor", checks.zizmor_audit, source)
        if workflows and workflows.get("error"):
            summary["errors"].append(workflows["error"])
            workflows = None
        summary["workflow_audit"] = workflows
    redact(sbom, {**source_paths, str(pathlib.Path.home()): "$HOME"})
    document = load_json(sbom)
    summary["components"] = normalize_sbom(document)
    for item in summary["components"]:
        item["location"] = lock_aliases.get(item["location"], item["location"])

    grype_report = directory / "grype.json"
    grype = run(["grype", f"sbom:{sbom}", "-q", "-o", "json", "--file", str(grype_report)])
    if grype.returncode != 0 or not grype_report.is_file():
        summary["errors"].append(f"grype failed: {grype.stderr.strip()[:300]}")
        summary["vulnerabilities"] = None
    else:
        redact(grype_report, {str(directory.resolve()): ".", str(directory): ".", str(pathlib.Path.home()): "$HOME"})
        excluded: dict[str, int] = {}
        summary["vulnerabilities"] = normalize_grype(load_json(grype_report), local_packages, excluded)
        for item in summary["vulnerabilities"]:
            item["locations"] = sorted(lock_aliases.get(path, path) for path in item["locations"])
            item["location"] = item["locations"][0] if item["locations"] else ""
        if excluded:
            summary["excluded_matches"] = excluded

    summary["osv"] = checks.cross_reference(summary["vulnerabilities"], osv)
    if summary["vulnerabilities"] is not None:
        earlier = previous_dir / pid / "summary.json" if previous_dir else None
        since = str(load_json(earlier).get("scanned_at") or "") if earlier and earlier.is_file() else ""
        summary["osv_api"] = check(summary, "OSV API lookup", checks.osv_api_lookup, summary["vulnerabilities"],
                                   directory / "osv-api.json", since)
    if target.get("ref_kind") == "release":
        with tempfile.TemporaryDirectory() as temporary:
            check(summary, "release checks", release_checks, target, summary, pathlib.Path(temporary), directory)
    checks.annotate_reachability(summary["vulnerabilities"], summary.get("go_binary"))
    if summary.get("go_binary"):
        # The module list is in govulncheck.json; the project file keeps only the findings.
        summary["go_binary"].pop("modules", None)
        summary["go_binary"].pop("module_versions", None)
    scorecard = check(summary, "scorecard", checks.scorecard, target["repository"], scorecard_cli)
    summary["scorecard"] = scorecard if scorecard and not scorecard.get("error") else None
    if scorecard and scorecard.get("error"):
        summary["scorecard_note"] = scorecard["error"]

    compliance = run([sbomlyze, str(sbom), "--compliance", "--json", "--no-pager"])
    if compliance.returncode == 0 and compliance.stdout.strip():
        summary["compliance"] = compliance_summary(json.loads(compliance.stdout))
    summary["sbom_sha256"] = checks.sha256(sbom)
    summary["lock_aliases"] = lock_aliases
    previous = previous_dir / pid / "sbom.cdx.json" if previous_dir else None
    if previous and previous.is_file():
        earlier = previous.with_name("summary.json")
        aliases_before = (load_json(earlier).get("lock_aliases") if earlier.is_file() else None) or lock_aliases
        summary["sbomlyze_diff"] = sbomlyze_diff(sbomlyze, previous, sbom, directory / "sbomlyze-diff.html",
                                                 directory / "sbomlyze-diff.json", aliases_before, lock_aliases,
                                                 baseline_run)
    write_json(directory / "summary.json", summary)
    return summary


# ----- replay ----------------------------------------------------------------------------

RAW_FILES = ("sbom.cdx.json", "grype.json", "osv-scanner.json", "govulncheck.json", "osv-api.json")


def inferred_aliases(summary: dict[str, Any]) -> dict[str, str]:
    """Lockfile aliases of a scan recorded before they were kept: an npm-shrinkwrap.json without a
    package-lock.json beside it was read as package-lock.json."""
    manifests = set(summary.get("manifests") or [])
    aliases = {}
    for path in manifests:
        if path.rsplit("/", 1)[-1] == "npm-shrinkwrap.json":
            lock = path[: -len("npm-shrinkwrap.json")] + "package-lock.json"
            if lock not in manifests:
                aliases[lock] = path
    return aliases


def replay_project(summary: dict[str, Any], evidence: pathlib.Path, output: pathlib.Path, previous_dir: pathlib.Path | None,
                   sbomlyze: str, baseline_run: dict[str, Any] | None, osv_api_live: bool = False) -> dict[str, Any]:
    """Re-derive one project's summary from its raw evidence files, without the network (except an OSV API lookup
    when asked for one, which is recorded with its own time). Release verification, Scorecard, and workflow results
    are taken from the original summary: they come from upstream services, not from these files."""
    result = json.loads(json.dumps(summary))
    directory = output / summary["id"]
    directory.mkdir(parents=True, exist_ok=True)
    for name in RAW_FILES:
        if (evidence / name).is_file():
            shutil.copyfile(evidence / name, directory / name)
    sbom = directory / "sbom.cdx.json"
    if summary.get("components") is None or not sbom.is_file():
        write_json(directory / "summary.json", result)
        return result
    aliases = summary.get("lock_aliases") if summary.get("lock_aliases") is not None else inferred_aliases(summary)
    result["lock_aliases"] = aliases
    result["components"] = normalize_sbom(load_json(sbom))
    for item in result["components"]:
        item["location"] = aliases.get(item["location"], item["location"])
    result["sbom_sha256"] = checks.sha256(sbom)

    grype = directory / "grype.json"
    if summary.get("vulnerabilities") is not None and grype.is_file():
        excluded: dict[str, int] = {}
        rows = normalize_grype(load_json(grype), set(summary.get("local_packages") or []), excluded)
        if "local_packages" not in summary:
            # Scans before the local package names were kept: those exclusions are the npm rows it did not record.
            kept = {(item["id"], item["package"], item["version"]) for item in summary["vulnerabilities"]}
            rows = [item for item in rows if item["ecosystem"] != "npm" or (item["id"], item["package"], item["version"]) in kept]
            excluded = dict(summary.get("excluded_matches") or {})
        for item in rows:
            item["locations"] = sorted(aliases.get(path, path) for path in item["locations"])
            item["location"] = item["locations"][0] if item["locations"] else ""
        result["vulnerabilities"] = rows
        result.pop("excluded_matches", None)
        if excluded:
            result["excluded_matches"] = excluded
    osv_file = directory / "osv-scanner.json"
    osv = (checks.parse_osv_report(load_json(osv_file), [], (summary.get("osv") or {}).get("warning"))
           if osv_file.is_file() and (summary.get("osv") or {}).get("available") else {})
    result["osv"] = checks.cross_reference(result.get("vulnerabilities"), osv)
    if (directory / "osv-api.json").is_file():
        result["osv_api"] = checks.apply_osv_api(result.get("vulnerabilities"), load_json(directory / "osv-api.json"))
    elif osv_api_live and result.get("vulnerabilities") is not None:
        earlier = previous_dir / summary["id"] / "summary.json" if previous_dir else None
        since = str(load_json(earlier).get("scanned_at") or "") if earlier and earlier.is_file() else ""
        result["osv_api"] = checks.osv_api_lookup(result["vulnerabilities"], directory / "osv-api.json", since)

    stream = directory / "govulncheck.json"
    if summary.get("go_binary") and stream.is_file():
        objects = checks.json_stream(stream.read_text(encoding="utf-8"))
        modules = next((item["SBOM"] for item in objects if "SBOM" in item), {}).get("modules") or []
        go = {**summary["go_binary"], "findings": checks.govulncheck_findings(objects),
              "modules": [module.get("path") for module in modules],
              "module_versions": {module.get("path"): module.get("version") or "" for module in modules if module.get("path")}}
        checks.annotate_reachability(result.get("vulnerabilities"), go)
        go.pop("modules", None)
        go.pop("module_versions", None)
        result["go_binary"] = go
    else:
        checks.annotate_reachability(result.get("vulnerabilities"), result.get("go_binary"))

    compliance = run([sbomlyze, str(sbom), "--compliance", "--json", "--no-pager"])
    if compliance.returncode == 0 and compliance.stdout.strip():
        result["compliance"] = compliance_summary(json.loads(compliance.stdout))
    result.pop("sbomlyze_diff", None)
    previous = previous_dir / summary["id"] / "sbom.cdx.json" if previous_dir else None
    if previous and previous.is_file():
        earlier = previous.with_name("summary.json")
        before = load_json(earlier) if earlier.is_file() else {}
        aliases_before = before.get("lock_aliases") if before.get("lock_aliases") is not None else inferred_aliases(before) if before else aliases
        result["sbomlyze_diff"] = sbomlyze_diff(sbomlyze, previous, sbom, directory / "sbomlyze-diff.html",
                                                directory / "sbomlyze-diff.json", aliases_before, aliases, baseline_run)
    write_json(directory / "summary.json", result)
    return result


def command_replay(args: argparse.Namespace) -> int:
    """Rebuild shard results from an evidence bundle (one shard, or all), for a corrected publication of a recorded
    week and for the accuracy check."""
    shard_files = sorted(args.evidence_dir.glob("supply-chain-shard-*/shard-*.json"))
    if args.shard is not None:
        shard_files = [path for path in shard_files if path.stem == f"shard-{args.shard}"]
    if not shard_files:
        raise ValueError(f"no shard results in {args.evidence_dir}")
    baseline_run = ({"run_id": str(args.previous_run_id), "attempt": str(args.previous_run_attempt or "")}
                    if args.previous_run_id else None)
    for shard_file in shard_files:
        shard = load_json(shard_file)
        # One shard (a workflow job) writes straight into its output directory, like `scan`.
        output = args.output_dir if args.shard is not None else args.output_dir / shard_file.parent.name
        projects = [replay_project(summary, shard_file.parent / summary["id"], output, args.previous_dir, args.sbomlyze,
                                   baseline_run, args.osv_api) for summary in shard["projects"]]
        tools = {**(shard.get("tools") or {}), "sbomlyze": tool_version(args.sbomlyze, ["--version"])}
        environment = {**(shard.get("environment") or {}),
                       "replay": {"at": utc_now(), "from": args.source or str(args.evidence_dir), "osv_api": bool(args.osv_api)}}
        write_json(output / shard_file.name, {"tools": tools, "environment": environment, "projects": projects}, indent=None)
        print(f"replayed {shard_file.parent.name}: {len(projects)} projects", flush=True)
    return 0


# ----- accuracy audit ----------------------------------------------------------------------

DERIVED_KEYS = ("components", "vulnerabilities", "go_binary", "osv", "osv_api", "sbom_sha256")
# Added at publish from the KEV/EPSS snapshots, not derived from the scan files.
ENRICHMENT_KEYS = ("kev", "kev_cves", "kev_snapshot", "epss", "epss_date")


def without_enrichment(value: Any) -> Any:
    if isinstance(value, list):
        return [without_enrichment(item) for item in value]
    if isinstance(value, dict):
        return {key: without_enrichment(item) for key, item in value.items() if key not in ENRICHMENT_KEYS}
    return value


def first_difference(expected: Any, actual: Any, path: str = "") -> str:
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            if expected.get(key) != actual.get(key):
                return first_difference(expected.get(key), actual.get(key), f"{path}.{key}")
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return f"{path}: {len(expected)} entries expected, {len(actual)} recorded"
        for index, (left, right) in enumerate(zip(expected, actual)):
            if left != right:
                return first_difference(left, right, f"{path}[{index}]")
    return f"{path}: expected {json.dumps(expected)[:160]}, recorded {json.dumps(actual)[:160]}"


def audit_shards(shards_dir: pathlib.Path, previous_dir: pathlib.Path | None, sbomlyze: str) -> list[str]:
    """Re-derive every project from its raw files and compare with the recorded summary: a lossy or
    order-dependent normalization, or a summary that does not match its evidence, is reported."""
    problems = []
    with tempfile.TemporaryDirectory() as temporary:
        for shard_file in sorted(shards_dir.glob("**/shard-*.json")):
            for summary in load_json(shard_file)["projects"]:
                if summary.get("components") is None:
                    continue
                baseline = (summary.get("sbomlyze_diff") or {}).get("baseline") or None
                replayed = replay_project(summary, shard_file.parent / summary["id"], pathlib.Path(temporary), previous_dir,
                                          sbomlyze, baseline)
                for key in DERIVED_KEYS:
                    if without_enrichment(replayed.get(key)) != without_enrichment(summary.get(key)):
                        problems.append(f"{summary['id']} {key} does not match its raw evidence: "
                                        + first_difference(without_enrichment(replayed.get(key)), without_enrichment(summary.get(key)), key))
                expected = (replayed.get("sbomlyze_diff") or {}).get("occurrences")
                if expected != (summary.get("sbomlyze_diff") or {}).get("occurrences"):
                    problems.append(f"{summary['id']} sbomlyze occurrences differ from a re-run of sbomlyze: "
                                    + first_difference(expected, (summary.get("sbomlyze_diff") or {}).get("occurrences"), "occurrences"))
    return problems


def audit_publication(data_dir: pathlib.Path, shards_dir: pathlib.Path, date: str) -> list[str]:
    """Check the published week against the shard results it was built from: inventories and findings carried
    over unchanged, dependency changes equal to sbomlyze's occurrences, and history counts equal to the lists."""
    problems = []
    for shard_file in sorted(shards_dir.glob("**/shard-*.json")):
        for summary in load_json(shard_file)["projects"]:
            path = data_dir / "projects" / f"{summary['id']}.json"
            if not path.is_file():
                problems.append(f"{summary['id']} has no project file")
                continue
            stored = load_json(path)
            latest, entry = stored["latest"], next((item for item in stored.get("history") or [] if item["date"] == date), None)
            if entry is None:
                problems.append(f"{summary['id']} has no history entry for {date}")
                continue
            if summary.get("components") is None:
                continue
            for key in DERIVED_KEYS:
                if without_enrichment(latest.get(key)) != without_enrichment(summary.get(key)):
                    problems.append(f"{summary['id']} published {key} differs from the scan: "
                                    + first_difference(without_enrichment(summary.get(key)), without_enrichment(latest.get(key)), key))
            change = latest.get("changes") or {}
            if change.get("dependency_state") == "ok":
                found = summary["sbomlyze_diff"]["occurrences"]
                if change.get("version_changes") != found["version_changes"]:
                    problems.append(f"{summary['id']} version changes differ from sbomlyze's")
                directions = len(change.get("upgraded") or []) + len(change.get("downgraded") or []) + len(change.get("unknown_direction") or [])
                if directions != len(found["version_changes"]):
                    problems.append(f"{summary['id']} upgrades + downgrades + unknown ({directions}) != version changes ({len(found['version_changes'])})")
                for key in ("added", "removed"):
                    if len(change.get(key) or []) != len(found[key]):
                        problems.append(f"{summary['id']} {key}: {len(change.get(key) or [])} published, sbomlyze reports {len(found[key])}")
            for key, state in (("added", "dependency_state"), ("removed", "dependency_state"), ("upgraded", "dependency_state"),
                               ("downgraded", "dependency_state"), ("new_vulnerabilities", "advisory_state"),
                               ("resolved_vulnerabilities", "advisory_state")):
                if key in entry and change.get("method") and entry[key] != count(change, key, state):
                    problems.append(f"{summary['id']} history {key} = {entry[key]}, change lists give {count(change, key, state)}")
    return problems


def command_audit(args: argparse.Namespace) -> int:
    if args.data_dir and args.date:
        recorded = load_json(args.data_dir / "runs" / f"{args.date}.json").get("schema_version") or 0
        if recorded < SCHEMA_VERSION:
            # Weeks recorded by an earlier method keep their record; the audit applies from schema 5.
            print(f"audit: {args.date} was recorded with schema {recorded} (before {SCHEMA_VERSION}); not applicable")
            return 0
    problems = []
    if args.sbomlyze:
        problems += audit_shards(args.shards_dir, args.previous_dir, args.sbomlyze)
    if args.data_dir:
        problems += audit_publication(args.data_dir, args.shards_dir, args.date)
    for problem in problems:
        print(problem)
    print(f"audit: {len(problems)} problem(s)")
    return 1 if problems else 0


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
    baseline_run = ({"run_id": str(args.previous_run_id), "attempt": str(args.previous_run_attempt or "")}
                    if args.previous_run_id else None)
    results = []
    budget = args.scorecard_cli_limit
    for target in shard:
        print(f"scanning {target['repository']} @ {target.get('ref')}", flush=True)
        allow_cli = budget > 0
        try:
            results.append(scan_target(target, args.output_dir, args.previous_dir, args.sbomlyze, allow_cli, baseline_run))
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

def finding_key(item: dict[str, Any]) -> str:
    return f"{item['id']}|{item['package']}".lower()


CHANGE_METHOD = "sbomlyze-occurrence-v1"


def dependency_baseline(previous: dict[str, Any], current: dict[str, Any], context: dict[str, Any]) -> str | None:
    """Why sbomlyze's diff cannot be used as this week's dependency changes, or None when it compares the same
    SBOM that the stored previous week was built from."""
    diff = current.get("sbomlyze_diff")
    if previous.get("stale"):
        return "last week's scan failed, so there is no SBOM from last week to compare with"
    if not diff:
        return "last week's SBOM was not available to compare with"
    if diff.get("contract") != "sbomlyze-diff-0.7" or "occurrences" not in diff:
        return "the SBOM comparison was made with an sbomlyze version the report does not support"
    if previous.get("sbom_sha256"):
        if previous["sbom_sha256"] != diff.get("previous_sbom_sha256"):
            return "the SBOM compared with is not the one last week's report was built from"
        return None
    # Weeks recorded before SBOM digests: the SBOMs must come from the run that recorded last week.
    run_id = str((diff.get("baseline") or {}).get("run_id") or "")
    if not run_id or run_id != str(context.get("previous_run_id") or ""):
        return "the SBOM compared with does not come from the run that recorded last week"
    return None


def advisory_keys(previous: dict[str, Any], current: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """Source matches of both weeks grouped by (advisory, ecosystem, package), with advisory ids that are aliases of
    each other (in either week) treated as one advisory."""
    parent: dict[str, str] = {}

    def find(value: str) -> str:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    items = [*(previous.get("vulnerabilities") or []), *(current.get("vulnerabilities") or [])]
    for item in items:
        for alias in item.get("aliases") or []:
            parent[find(alias)] = find(item["id"])
    groups: dict[str, set[str]] = {}
    for value in list(parent) + [item["id"] for item in items]:
        groups.setdefault(find(value), set()).add(value)
    canonical = {root: site_exports.canonical_id(members) for root, members in groups.items()}

    def grouped(project: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for item in project.get("vulnerabilities") or []:
            key = f"{canonical[find(item['id'])]}|{item.get('ecosystem', '')}|{item['package']}".lower()
            result.setdefault(key, []).append(item)
        return result

    return grouped(previous), grouped(current)


def advisory_dates(item: dict[str, Any]) -> dict[str, str]:
    api = item.get("osv_api") or {}
    published = item.get("osv_published") or (api.get("published") if api.get("state") == "confirmed" else "") or ""
    modified = item.get("osv_modified") or (api.get("modified") if api.get("state") == "confirmed" else "") or ""
    return {key: value for key, value in (("published", published), ("modified", modified)) if value}


def new_advisory(item: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """A new match with why it is new: the package version was already there (so the advisory, or its data, is
    what changed), the package changed version, or the package is new."""
    inventory = {(component["ecosystem"], component["name"].lower()): set() for component in previous.get("components") or []}
    for component in previous.get("components") or []:
        inventory[(component["ecosystem"], component["name"].lower())].add(component["version"])
    versions = inventory.get((item.get("ecosystem", ""), item["package"].lower()))
    reason = ("unchanged version" if versions and item["version"] in versions
              else "changed version" if versions else "new package")
    since = str(previous.get("scanned_at") or "")
    dates = advisory_dates(item)
    detail = {"reason": reason, **dates}
    if since and dates.get("published", "") >= since:
        detail["advisory"] = "published since last scan"
    elif since and dates.get("modified", "") >= since:
        detail["advisory"] = "updated since last scan"
    return {**item, "new": detail}


def kev_listed(item: dict[str, Any]) -> set[str]:
    return set(item.get("kev_cves") or ([item["kev"]["cve"]] if item.get("kev") else []))


def changes(previous: dict[str, Any] | None, current: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """This week compared with the previous recorded week. `context` holds run-level facts from publish:
    `previous_run_id`, `kev_previous` and `kev_current` (CVE id sets of the two KEV snapshots)."""
    context = context or {}
    if not previous or previous.get("components") is None or current.get("components") is None:
        if context.get("previous_unavailable"):
            return {"baseline": False, "any": False, "unavailable": context["previous_unavailable"],
                    "dependency_state": "unavailable", "advisory_state": "unavailable"}
        return {"baseline": True}
    result: dict[str, Any] = {
        "baseline": False,
        "method": CHANGE_METHOD,
        "release_changed": previous.get("ref") != current.get("ref"),
        "previous_ref": previous.get("ref"),
        "added": [], "removed": [], "upgraded": [], "downgraded": [], "unknown_direction": [], "license_changes": [],
    }
    reason = dependency_baseline(previous, current, context)
    diff = current.get("sbomlyze_diff") or {}
    if reason:
        result.update(dependency_state="unavailable", dependency_reason=reason, integrity_drift=None)
    else:
        found = diff["occurrences"]
        result.update(
            dependency_state="ok",
            dependency_baseline={"sbom_sha256": diff.get("previous_sbom_sha256"), **(diff.get("baseline") or {})},
            added=[f"{item['name']}@{item['version']}" for item in found["added"]],
            removed=[f"{item['name']}@{item['version']}" for item in found["removed"]],
            added_detail=found["added"], removed_detail=found["removed"],
            version_changes=found["version_changes"],
            moved=found["moved"], version_set_changes=found["version_set_changes"],
            file_changes=[item["path"] for item in found["file_changes"]],
            integrity_changes=found["integrity_changes"], metadata_changes=found["metadata_changes"],
            integrity_drift=len(found["integrity_changes"]),
            digest_coverage=found.get("digest_coverage"),
            distinct_version_changes=(diff.get("drift") or {}).get("distinct_version_changes"),
        )
        for item in found["version_changes"]:
            entry = {"package": item["name"], "ecosystem": item["ecosystem"], "from": item["from"], "to": item["to"],
                     "location": item["location"], "direction": item["direction"], "level": item["level"]}
            key = {"upgrade": "upgraded", "downgrade": "downgraded"}.get(item["direction"], "unknown_direction")
            result[key].append(entry)
        result["license_changes"] = [{"package": item["name"], "ecosystem": item["ecosystem"], "location": item["location"],
                                      "version_from": item["version_from"], "version_to": item["version_to"],
                                      "from": item["from"], "to": item["to"], "diff": item["diff"]}
                                     for item in found["license_changes"]]
    if previous.get("vulnerabilities") is not None and current.get("vulnerabilities") is not None:
        old, new = advisory_keys(previous, current)
        result["advisory_state"] = "ok"
        result["new_vulnerabilities"] = [new_advisory(item, previous) for key in sorted(set(new) - set(old)) for item in new[key]]
        result["resolved_vulnerabilities"] = [item for key in sorted(set(old) - set(new)) for item in old[key]]
        # Distinct (advisory, package); the lists above have one entry per affected package version.
        result["new_advisories"] = len(set(new) - set(old))
        result["resolved_advisories"] = len(set(old) - set(new))
        result["still_affected_version_changed"] = [
            {"id": new[key][0]["id"], "package": new[key][0]["package"], "ecosystem": new[key][0].get("ecosystem"),
             "from": sorted({item["version"] for item in old[key]}), "to": sorted({item["version"] for item in new[key]})}
            for key in sorted(set(old) & set(new))
            if {item["version"] for item in old[key]} != {item["version"] for item in new[key]}]
    else:
        result["advisory_state"] = "unavailable"
        result["advisory_reason"] = ("this week's vulnerability scan failed" if current.get("vulnerabilities") is None
                                     else "last week's vulnerability scan failed")
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
    if site_exports.all_matches(current) and any("kev" in item for item in site_exports.all_matches(previous)):
        # Only once last week was checked against KEV too; otherwise every listed match would look new.
        # Includes govulncheck-only findings in the shipped binary.
        earlier = {finding_key(item): item for item in site_exports.all_matches(previous)}
        before_ids, after_ids = context.get("kev_previous"), context.get("kev_current")
        if before_ids is not None and after_ids is not None:
            # CVEs CISA added between the two snapshots; a new match for a CVE that was already listed is a new
            # vulnerability, not a KEV status change, and is listed separately.
            added = set(after_ids) - set(before_ids)
            result["kev_method"] = "snapshot difference"
            result["kev_new"] = [item for item in site_exports.all_matches(current) if kev_listed(item) & added]
            result["kev_new_match"] = [item for item in site_exports.all_matches(current)
                                       if kev_listed(item) and not kev_listed(item) & added and finding_key(item) not in earlier]
        else:
            # Without last week's snapshot: a match counts if CISA listed it since last week's scan.
            since = (previous.get("scanned_at") or "")[:10]
            result["kev_method"] = "date added since last scan"
            result["kev_new"] = [
                item for item in site_exports.all_matches(current)
                if item.get("kev") and not (earlier.get(finding_key(item)) or {}).get("kev")
                and (finding_key(item) in earlier or (item["kev"].get("date_added") or "") >= since)
            ]
    result["any"] = bool(
        result["release_changed"] or result["added"] or result["removed"] or result["upgraded"] or result["downgraded"]
        or result["unknown_direction"] or result["license_changes"] or result.get("file_changes") or result.get("moved")
        or result.get("integrity_drift") or result.get("new_vulnerabilities") or result.get("resolved_vulnerabilities")
        or result.get("scorecard") or result.get("release_integrity") or result.get("workflow_new")
        or result.get("workflow_resolved") or result.get("in_binary_new") or result.get("in_binary_resolved")
        or result.get("kev_new") or result.get("kev_new_match")
    )
    return result


def count(change: dict[str, Any], key: str, state: str) -> int | None:
    return None if change.get(state) == "unavailable" else len(change.get(key) or [])


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
        "vulnerable_packages": len({(item["package"], item["version"]) for item in vulns or []}) if vulns is not None else None,
        "kev": sum(1 for item in vulns or [] if item.get("kev")) if vulns is not None and any("kev" in item for item in vulns) else None,
        "kev_new": len(change.get("kev_new") or []),
        "kev_new_match": len(change.get("kev_new_match") or []),
        # An unavailable comparison is null, never 0.
        "added": count(change, "added", "dependency_state"),
        "removed": count(change, "removed", "dependency_state"),
        "upgraded": count(change, "upgraded", "dependency_state"),
        "downgraded": count(change, "downgraded", "dependency_state"),
        "unknown_direction": count(change, "unknown_direction", "dependency_state"),
        "license_changes": count(change, "license_changes", "dependency_state"),
        "file_changes": count(change, "file_changes", "dependency_state"),
        "moved": count(change, "moved", "dependency_state"),
        "new_vulnerabilities": count(change, "new_vulnerabilities", "advisory_state"),
        "new_advisories": change.get("new_advisories"),
        "resolved_advisories": change.get("resolved_advisories"),
        "resolved_vulnerabilities": count(change, "resolved_vulnerabilities", "advisory_state"),
        "in_binary_new": len(change.get("in_binary_new") or []),
        "in_binary_resolved": len(change.get("in_binary_resolved") or []),
        "workflow_new": change.get("workflow_new"),
        "workflow_resolved": change.get("workflow_resolved"),
        "dependency_state": change.get("dependency_state"),
        "advisory_state": change.get("advisory_state"),
        "method": change.get("method"),
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
        "last_success_at": project.get("last_success_at") or project.get("scanned_at"),
    }


def in_binary_counts(go: dict[str, Any] | None) -> dict[str, int] | None:
    if not go:
        return None
    symbols = [item for item in go["findings"] if item["level"] == "symbol"]
    return {
        # Distinct advisories; `records` counts advisory × module × version.
        "total": len(site_exports.binary_advisories(go)),
        "stdlib": len(site_exports.binary_advisories(go, "stdlib")),
        "dependencies": len(site_exports.binary_advisories(go, "dependencies")),
        "records": len(symbols),
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


PROJECT_FIELDS = {"id": str, "repository": str, "errors": list}


def incomplete_week(shard_paths: list[pathlib.Path], plan: dict[str, Any]) -> list[str]:
    """Why these shard results are not a complete scan of the planned targets; empty when they are."""
    problems = []
    expected_shards = {index for index, shard in enumerate(plan.get("shards") or []) if shard}
    found_shards = {}
    for path in shard_paths:
        match = re.fullmatch(r"shard-(\d+)\.json", path.name)
        if not match or int(match.group(1)) in found_shards:
            problems.append(f"unexpected or duplicate shard file {path.name}")
            continue
        found_shards[int(match.group(1))] = path
    problems += [f"shard {index} has no results" for index in sorted(expected_shards - set(found_shards))]
    problems += [f"shard {index} was not planned" for index in sorted(set(found_shards) - expected_shards)]
    planned = [target["repository"] for shard in plan.get("shards") or [] for target in shard]
    seen: dict[str, int] = {}
    for index, path in sorted(found_shards.items()):
        try:
            projects = load_json(path)["projects"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems.append(f"shard {index} is unreadable: {exc}")
            continue
        for project in projects:
            missing = [name for name, kind in PROJECT_FIELDS.items() if not isinstance(project.get(name), kind)]
            if missing or not (project.get("errors") or isinstance(project.get("components"), list)):
                problems.append(f"shard {index}: malformed result for {project.get('repository')!r} ({', '.join(missing) or 'no components and no error'})")
            seen[project.get("repository")] = seen.get(project.get("repository"), 0) + 1
    problems += [f"{name} has no result" for name in planned if name not in seen]
    problems += [f"{name} appears {count} times" for name, count in seen.items() if count > 1]
    problems += [f"{name} was not a planned target" for name in seen if name not in planned]
    return problems


def command_publish(args: argparse.Namespace) -> int:
    projects_dir = args.data_dir / "projects"
    runs_dir = args.data_dir / "runs"
    shards = sorted(args.shards_dir.glob("**/shard-*.json"))
    if not shards:
        raise ValueError(f"no shard results in {args.shards_dir}")
    if args.targets:
        problems = incomplete_week(shards, load_json(args.targets))
        if problems:
            # Nothing has been written yet: the previous week stays current.
            raise ValueError("incomplete scan, not published:\n  " + "\n  ".join(problems[:50]))
    index_file = args.data_dir / "index.json"
    latest = load_json(index_file).get("latest") if index_file.is_file() else None
    if latest and args.date < latest:
        raise ValueError(f"{args.date} is earlier than the latest recorded week {latest}; history is append-only")
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
    context = enrichment.load(args.enrichment_dir)
    previous_dates = sorted(path.stem for path in runs_dir.glob("*.json") if path.stem < args.date)
    previous_run = load_json(runs_dir / f"{previous_dates[-1]}.json") if previous_dates else {}
    kev_previous = ((previous_run.get("provenance") or {}).get("enrichment") or {}).get("kev") or {}
    comparison = {
        "previous_run_id": ((previous_run.get("provenance") or {}).get("run") or {}).get("id"),
        # Weeks recorded before the CVE list was kept: read last week's snapshot from its evidence bundle.
        "kev_previous": (set(kev_previous["cve_ids"]) if kev_previous.get("cve_ids") is not None
                         else set(enrichment.snapshot_ids(args.previous_enrichment_dir) or []) or None
                         if args.previous_enrichment_dir else None),
        "kev_current": set(context["kev"]) if context and context.get("kev") is not None else None,
    }
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
            project_context = dict(comparison)
            if stored.get("updated") == args.date:
                # Same-week re-run: compare with the previous week, never with the run being replaced.
                prior = show_json(args.data_dir, baseline_commit, f"projects/{project['id']}.json") if baseline_commit else None
                previous = (prior or {}).get("latest")
                if previous is None and any(item["date"] < args.date for item in stored.get("history") or []):
                    project_context["previous_unavailable"] = "last week's record is not in this copy of the data (no Git history)"
            if project.get("components") is None and previous:
                # A failed scan keeps last week's inventory visible and is marked as failed.
                project = {**previous, "errors": project.get("errors"), "scanned_at": project.get("scanned_at"), "stale": True,
                           "last_success_at": previous.get("last_success_at") or previous.get("scanned_at")}
                project["changes"] = {"baseline": False, "any": False, "scan_failed": True,
                                      "dependency_state": "unavailable", "advisory_state": "unavailable"}
                enrichment.annotate(project.get("vulnerabilities"), context)
                enrichment.annotate((project.get("go_binary") or {}).get("findings"), context)
            else:
                enrichment.annotate(project.get("vulnerabilities"), context)
                enrichment.annotate((project.get("go_binary") or {}).get("findings"), context)
                if not project.get("scorecard") and previous and previous.get("scorecard"):
                    # Scorecard CLI runs are rate limited; keep the last result until it is refreshed.
                    project["scorecard"] = {**previous["scorecard"], "carried_forward": True}
                project["changes"] = changes(previous, project, project_context)
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
        "provenance": {"run": provenance, "shards": environments, "enrichment": enrichment.provenance(context)},
        "evidence_release": args.evidence_release,
        "derivation": args.derivation,
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


# ----- enrich ----------------------------------------------------------------------------

def command_enrich(args: argparse.Namespace) -> int:
    metadata = enrichment.fetch(args.output_dir)
    for key in ("kev", "epss"):
        entry = metadata[key]
        print(f"{key}: " + (f"failed ({entry['error']})" if "error" in entry else f"{entry.get('version')} ({entry.get('count')} entries)"))
    return 0


# ----- baseline --------------------------------------------------------------------------

def command_baseline(args: argparse.Namespace) -> int:
    """Print the previous week's canonical run, for downloading its SBOMs."""
    result: dict[str, Any] = {"date": None, "run_id": None, "generated_at": None, "attempt": None, "evidence_release": None}
    index_path = args.data_dir / "index.json"
    if index_path.is_file():
        earlier = [date for date in load_json(index_path).get("runs") or [] if date < args.date]
        if earlier:
            previous = load_json(args.data_dir / "runs" / f"{earlier[0]}.json")
            run_info = (previous.get("provenance") or {}).get("run") or {}
            result.update(date=earlier[0], generated_at=previous.get("generated_at"), run_id=run_info.get("id"),
                          attempt=run_info.get("attempt"), evidence_release=previous.get("evidence_release"))
    print(json.dumps(result))
    return 0


# ----- verify ----------------------------------------------------------------------------

HISTORY_KEYS = ("ref", "commit", "dependencies", "vulnerabilities", "fixable", "added", "removed", "upgraded",
                "downgraded", "unknown_direction", "file_changes", "new_vulnerabilities", "resolved_vulnerabilities",
                "dependency_state", "advisory_state", "method", "release_changed", "scorecard", "errors")


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
                if (run_data.get("schema_version") or 0) < 5:
                    # Rows recorded before schema 5 have no last-success time.
                    expected.pop("last_success_at", None)
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
    scan.add_argument("--previous-run-id", help="workflow run the previous SBOMs were downloaded from")
    scan.add_argument("--previous-run-attempt", help="attempt of that run")
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
    publish.add_argument("--previous-enrichment-dir", type=pathlib.Path, default=None,
                         help="last week's KEV/EPSS snapshot, when its run record predates the stored CVE list")
    publish.add_argument("--derivation", default=None, help="why this week is published again, e.g. a replay from evidence")
    publish.add_argument("--enrichment-dir", type=pathlib.Path, help="output of `enrich` (CISA KEV and EPSS snapshots)")
    publish.add_argument("--targets", type=pathlib.Path,
                         help="output of `targets`; publishing fails unless every planned target has exactly one result")
    replay = commands.add_parser("replay", help="rebuild shard results offline from an evidence bundle")
    replay.add_argument("--evidence-dir", type=pathlib.Path, required=True, help="an extracted evidence bundle")
    replay.add_argument("--output-dir", type=pathlib.Path, required=True)
    replay.add_argument("--shard", type=int, default=None)
    replay.add_argument("--previous-dir", type=pathlib.Path, help="last week's project directories (for the SBOM diff)")
    replay.add_argument("--previous-run-id")
    replay.add_argument("--previous-run-attempt")
    replay.add_argument("--sbomlyze", default="sbomlyze")
    replay.add_argument("--osv-api", action="store_true", help="also query the OSV API (recorded with its own time)")
    replay.add_argument("--source", help="where the evidence came from, recorded with the replay")
    audit = commands.add_parser("audit", help="check results against their raw evidence and the published data")
    audit.add_argument("--shards-dir", type=pathlib.Path, required=True)
    audit.add_argument("--previous-dir", type=pathlib.Path)
    audit.add_argument("--sbomlyze", help="re-derive from raw files (needs the scanners' sbomlyze); omit to check publication only")
    audit.add_argument("--data-dir", type=pathlib.Path)
    audit.add_argument("--date")
    enrich = commands.add_parser("enrich")
    enrich.add_argument("--output-dir", type=pathlib.Path, required=True)
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
    return {"targets": command_targets, "scan": command_scan, "publish": command_publish, "enrich": command_enrich,
            "baseline": command_baseline, "verify": command_verify, "replay": command_replay,
            "audit": command_audit}[args.command](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"supply-chain report failed: {exc}", file=sys.stderr)
        sys.exit(1)
