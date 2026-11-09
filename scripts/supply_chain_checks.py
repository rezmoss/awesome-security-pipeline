"""Per-project checks for the weekly supply-chain report, beyond the SBOM itself.

- OSV-Scanner: a second vulnerability database, used to confirm Grype matches.
- govulncheck: which Go advisories have vulnerable code compiled into the released binary.
- zizmor: security audit of the project's GitHub Actions workflows.
- OpenSSF Scorecard: repository security practices.
- Cosign, slsa-verifier, and GitHub attestations: whether the release can be verified.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any

TIMEOUT = 600
MAX_ASSET_BYTES = 400 * 1024 * 1024
SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com/{repository}"
SCORECARD_MAX_AGE_DAYS = 30
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
NON_BINARY = re.compile(
    r"(\.(sig|pem|cert|crt|asc|sbom|spdx|json|jsonl|txt|md|sha256|sha512|sha1|md5|deb|rpm|apk|msi|exe|dmg|pkg|"
    r"whl|gem|jar|nupkg|vsix|bundle|att|sigstore)$)|checksums|sha256sums|provenance|attestation|source|src",
    re.IGNORECASE,
)
LINUX = re.compile(r"linux", re.IGNORECASE)
AMD64 = re.compile(r"amd64|x86[_-]?64|x64|64bit|64-bit", re.IGNORECASE)
NOT_AMD64 = re.compile(r"arm|aarch|386|i686|x32|ppc|s390|riscv|mips|loong", re.IGNORECASE)
ARCHIVE = re.compile(r"\.(tar\.gz|tgz|tar\.xz|txz|zip)$", re.IGNORECASE)
CHECKSUMS = re.compile(r"checksums?|sha256sums|\.sha256$", re.IGNORECASE)
SBOM_ASSET = re.compile(r"\.sbom|spdx|cyclonedx|\.cdx|sbom\.json", re.IGNORECASE)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], cwd: pathlib.Path | None = None, timeout: int = TIMEOUT, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, env=env)


def json_stream(text: str) -> list[dict[str, Any]]:
    """Parse concatenated JSON objects (govulncheck's streaming output)."""
    decoder = json.JSONDecoder()
    objects, index = [], 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        value, index = decoder.raw_decode(text, index)
        objects.append(value)
    return objects


def cvss_bucket(score: str | float | None) -> str:
    try:
        value = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "Unknown"
    if value >= 9:
        return "Critical"
    if value >= 7:
        return "High"
    if value >= 4:
        return "Medium"
    if value > 0:
        return "Low"
    return "Unknown"


# ----- OSV-Scanner --------------------------------------------------------------------

def strip_paths(text: str, paths: list[str]) -> str:
    for path in sorted(paths, key=len, reverse=True):
        text = text.replace(path, "")
    return text


def osv_scan(source: pathlib.Path, raw: pathlib.Path | None = None) -> dict[str, Any]:
    # --all-packages lists every package OSV-Scanner read, with or without advisories, so a match it did not
    # report can be told apart from a package it did not check.
    completed = run(["osv-scanner", "scan", "source", "-r", str(source), "--format", "json", "--all-packages",
                     "--no-call-analysis=all"])
    output = completed.stdout.strip()
    if raw is not None and output:
        # Kept as evidence; runner-local paths are removed so the file is reproducible to read.
        raw.write_text(strip_paths(output, [str(source.resolve()) + "/", str(source) + "/"]) + "\n", encoding="utf-8")
    if not output.startswith("{"):
        if completed.returncode == 128:  # no supported packages found: nothing was checked
            return {"groups": [], "packages": []}
        if completed.returncode == 0:
            return {"groups": []}
        return {"error": f"osv-scanner exited with {completed.returncode}: {completed.stderr.strip()[-300:]}"}
    report = json.loads(output)
    warning = None
    if completed.returncode not in (0, 1):
        # Some manifests could not be resolved (for example a Maven parent POM); keep the rest.
        detail = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else str(completed.returncode)
        for path in (str(source.resolve()), str(source)):
            detail = detail.replace(path + "/", "").replace(path, "").replace(path.lstrip("/") + "/", "")
        warning = f"osv-scanner could not resolve every manifest: {detail[:200]}"
    return parse_osv_report(report, [str(source.resolve()) + "/", str(source) + "/"], warning)


def parse_osv_report(report: dict[str, Any], roots: list[str], warning: str | None = None) -> dict[str, Any]:
    """Advisory groups and, for reports made with --all-packages, every package OSV-Scanner read. A report without
    a package lacking advisories was made without --all-packages: its package list says nothing about coverage."""
    groups, packages = [], []
    for result in report.get("results") or []:
        path = strip_paths(str((result.get("source") or {}).get("path", "")), roots).lstrip("/")
        for package in result.get("packages") or []:
            info = package.get("package") or {}
            vulns = {vuln.get("id"): vuln for vuln in package.get("vulnerabilities") or []}
            packages.append({"path": path, "ecosystem": str(info.get("ecosystem", "")), "name": str(info.get("name", "")),
                             "version": str(info.get("version", "")),
                             # A lockfile entry without a registry URL is treated as a local package and not queried.
                             "local": "source=LOCAL" in str(info.get("purl", ""))})
            for group in package.get("groups") or []:
                ids = set(group.get("ids") or [])
                for identifier in list(ids):
                    ids |= set((vulns.get(identifier) or {}).get("aliases") or [])
                ids |= set(group.get("aliases") or [])
                records = [vulns[identifier] for identifier in group.get("ids") or [] if identifier in vulns]
                groups.append({
                    "ids": sorted(ids),
                    "package": str(info.get("name", "")),
                    "version": str(info.get("version", "")),
                    "ecosystem": str(info.get("ecosystem", "")),
                    "severity": cvss_bucket(group.get("max_severity")),
                    "score": group.get("max_severity") or "",
                    "path": path,
                    "published": min((str(item.get("published")) for item in records if item.get("published")), default=""),
                    "modified": max((str(item.get("modified")) for item in records if item.get("modified")), default=""),
                })
    complete = any(not item.get("groups") for result in report.get("results") or [] for item in result.get("packages") or [])
    result = {"groups": groups, "packages": packages if complete or not packages else None}
    if warning:
        result["warning"] = warning
    return result


# Grype's package types (from the purl) and the OSV ecosystem names OSV-Scanner reports.
OSV_ECOSYSTEMS = {
    "golang": "Go", "pypi": "PyPI", "npm": "npm", "cargo": "crates.io", "maven": "Maven", "github": "GitHub Actions",
    "gem": "RubyGems", "composer": "Packagist", "nuget": "NuGet", "pub": "Pub", "hex": "Hex", "swift": "SwiftURL",
}


def package_identity(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    """(OSV ecosystem, package name, version) normalized so the two scanners' spellings compare equal."""
    ecosystem = OSV_ECOSYSTEMS.get(ecosystem, ecosystem)
    name = name.lower()
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name)
    elif ecosystem == "Maven":
        name = name.rsplit(":", 1)[-1]  # Grype reports the artifact id, OSV group:artifact
    version = version.lower().removeprefix("v")
    # 3.7 and 3.7.0 are the same release (PEP 440, SemVer tooling); drop trailing zero components.
    version = re.sub(r"^(\d+(?:\.\d+)*?)(?:\.0+)+(?=$|[-+])", r"\1", version)
    return ecosystem, name, version


def cross_reference(grype: list[dict[str, Any]] | None, osv: dict[str, Any]) -> dict[str, Any]:
    """Mark Grype findings confirmed by OSV and list OSV-only advisories. A confirmation needs the same advisory
    (id or alias), ecosystem, package, and version: one package at two versions is two separate matches."""
    groups = osv.get("groups")
    if grype is None or groups is None:
        return {"available": False}
    matched_groups = set()
    identities_by_group = [package_identity(group.get("ecosystem", ""), group["package"], group.get("version", ""))
                           for group in groups]
    packages = osv.get("packages")
    read_paths = {item["path"] for item in packages or []}
    listed: dict[tuple[str, tuple[str, str, str]], bool] = {}
    for item in packages or []:
        key = (item["path"], package_identity(item["ecosystem"], item["name"], item["version"]))
        listed[key] = listed.get(key, False) or not item["local"]
    for finding in grype:
        identities = {finding["id"], *finding.get("aliases", [])}
        package = package_identity(finding.get("ecosystem", ""), finding["package"], finding.get("version", ""))
        finding["osv_confirmed"] = False
        for index, group in enumerate(groups):
            if identities & set(group["ids"]) and identities_by_group[index] == package:
                finding["osv_confirmed"] = True
                matched_groups.add(index)
                if group.get("modified"):
                    finding["osv_published"] = group.get("published", "")
                    finding["osv_modified"] = group["modified"]
        if packages is not None:
            finding["osv_coverage"] = osv_coverage(finding, package, read_paths, listed)
    only = [group for index, group in enumerate(groups) if index not in matched_groups]
    result = {
        "available": True,
        "warning": osv.get("warning"),
        "advisories": len(groups),
        "confirmed": sum(1 for finding in grype if finding.get("osv_confirmed")),
        "osv_only": only,
    }
    if packages is not None:
        states: dict[str, int] = {}
        for finding in grype:
            state = finding["osv_coverage"]["state"]
            states[state] = states.get(state, 0) + 1
        result["coverage"] = states
    return result


COVERAGE_ORDER = ("confirmed", "not reported", "not checked")


def osv_coverage(finding: dict[str, Any], package: tuple[str, str, str], read_paths: set[str],
                 listed: dict[tuple[str, tuple[str, str, str]], bool]) -> dict[str, Any]:
    """Whether OSV-Scanner checked this match: confirmed it, checked the package without reporting this advisory, or
    did not check it (the file is not one it reads, or the lockfile entry has no registry source)."""
    if finding.get("osv_confirmed"):
        return {"state": "confirmed"}
    reasons = []
    for path in finding.get("locations") or [finding.get("location", "")]:
        if path not in read_paths:
            reasons.append(f"{path}: not read by OSV-Scanner")
        elif (path, package) not in listed:
            reasons.append(f"{path}: package not listed by OSV-Scanner")
        elif not listed[(path, package)]:
            reasons.append(f"{path}: entry has no registry source, so OSV-Scanner did not query it")
        else:
            return {"state": "not reported", "path": path}
    return {"state": "not checked", "reasons": reasons}


OSV_API = "https://api.osv.dev/v1"


def osv_api_query(name: str, ecosystem: str, purl: str) -> tuple[str, str] | None:
    """(OSV ecosystem, package name) for the OSV API, or None for an ecosystem OSV does not cover."""
    osv_ecosystem = OSV_ECOSYSTEMS.get(ecosystem)
    if not osv_ecosystem:
        return None
    if osv_ecosystem == "Maven" and purl.startswith("pkg:maven/"):
        group, _, artifact = purl[len("pkg:maven/"):].split("@", 1)[0].partition("/")
        name = f"{urllib.parse.unquote(group)}:{urllib.parse.unquote(artifact)}" if artifact else name
    return osv_ecosystem, name


def post_json(url: str, body: Any, timeout: int = 60) -> Any:
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https endpoint
        return json.load(response)


def osv_api_lookup(grype: list[dict[str, Any]] | None, raw: pathlib.Path | None = None, since: str = "",
                   batch: int = 500) -> dict[str, Any]:
    """Ask the OSV API about every Grype match OSV-Scanner did not confirm: an extra, separately labelled source.
    Records modified since `since` (the previous scan) are fetched in full for their dates. Requests and responses
    are written to `raw` so the result can be replayed without the network."""
    findings = [item for item in grype or [] if not item.get("osv_confirmed")]
    queries, owners = [], []
    for item in findings:
        target = osv_api_query(item["package"], item.get("ecosystem", ""), item.get("purl", ""))
        if target is None:
            item["osv_api"] = {"state": "unsupported ecosystem"}
            continue
        query = {"package": {"ecosystem": target[0], "name": target[1]}, "version": item["version"]}
        if query not in queries:
            queries.append(query)
        owners.append((item, queries.index(query)))
    evidence: dict[str, Any] = {"url": f"{OSV_API}/querybatch", "queried_at": utc_now(), "queries": queries,
                                "results": [], "records": {}}
    try:
        for start in range(0, len(queries), batch):
            evidence["results"] += post_json(f"{OSV_API}/querybatch", {"queries": queries[start:start + batch]})["results"]
        for index, result in enumerate(evidence["results"]):
            token = result.get("next_page_token")
            while token:  # more than one page of advisories for one package version
                page = post_json(f"{OSV_API}/querybatch", {"queries": [{**queries[index], "page_token": token}]})["results"][0]
                result["vulns"] = (result.get("vulns") or []) + (page.get("vulns") or [])
                token = page.get("next_page_token")
            result.pop("next_page_token", None)
        recent = sorted({vuln["id"] for result in evidence["results"] for vuln in result.get("vulns") or []
                         if since and str(vuln.get("modified", "")) >= since})
        for identifier in recent:
            record = fetch_json(f"{OSV_API}/vulns/{urllib.parse.quote(identifier)}")
            evidence["records"][identifier] = {key: record.get(key) for key in ("id", "aliases", "published", "modified")}
    except Exception as exc:  # noqa: BLE001 - the API is an optional extra source
        evidence["error"] = str(exc)[:300]
    if raw is not None:
        raw.write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return apply_osv_api(grype, evidence)


def apply_osv_api(grype: list[dict[str, Any]] | None, evidence: dict[str, Any]) -> dict[str, Any]:
    """Mark matches from recorded OSV API responses (also used to replay them)."""
    results = evidence.get("results") or []
    states: dict[str, int] = {}
    for item in grype or []:
        if item.get("osv_confirmed") or (item.get("osv_api") or {}).get("state") == "unsupported ecosystem":
            continue
        target = osv_api_query(item["package"], item.get("ecosystem", ""), item.get("purl", ""))
        query = {"package": {"ecosystem": target[0], "name": target[1]}, "version": item["version"]} if target else None
        if query is None:
            item["osv_api"] = {"state": "unsupported ecosystem"}
        elif evidence.get("error") or query not in evidence.get("queries", []) or len(results) <= evidence["queries"].index(query):
            item["osv_api"] = {"state": "error"}
        else:
            vulns = results[evidence["queries"].index(query)].get("vulns") or []
            identities = {item["id"], *item.get("aliases", [])}
            hits = [vuln for vuln in vulns if vuln.get("id") in identities]
            hits += [vuln for vuln in vulns if vuln not in hits
                     and identities & set((evidence["records"].get(vuln.get("id")) or {}).get("aliases") or [])]
            if hits:
                record = evidence["records"].get(hits[0]["id"]) or {}
                item["osv_api"] = {"state": "confirmed", "id": hits[0]["id"],
                                   "modified": record.get("modified") or hits[0].get("modified", ""),
                                   "published": record.get("published") or ""}
            else:
                item["osv_api"] = {"state": "not reported", "advisories": len(vulns)}
        states[item["osv_api"]["state"]] = states.get(item["osv_api"]["state"], 0) + 1
    return {"available": not evidence.get("error"), "queried_at": evidence.get("queried_at"), "states": states,
            **({"error": evidence["error"]} if evidence.get("error") else {})}


# ----- zizmor -------------------------------------------------------------------------

def zizmor_audit(source: pathlib.Path) -> dict[str, Any]:
    workflows = [path for path in source.rglob("*.y*ml") if ".github/workflows" in path.as_posix() or path.name.startswith("action.")]
    if not workflows:
        return {"findings": [], "files": 0}
    completed = run(["zizmor", "--offline", "--format", "json", "--min-confidence", "medium", "--no-progress", str(source)])
    if not completed.stdout.strip().startswith("["):
        return {"error": f"zizmor exited with {completed.returncode}: {completed.stderr.strip()[-300:]}"}
    findings = []
    prefixes = (str(source).rstrip("/") + "/", str(source.resolve()).rstrip("/") + "/")
    for item in json.loads(completed.stdout):
        location = (item.get("locations") or [{}])[0]
        key = ((location.get("symbolic") or {}).get("key") or {}).get("Local") or {}
        path = str(key.get("verbatim_path") or key.get("given_path") or "")
        for prefix in prefixes:
            path = path.removeprefix(prefix)
        row = (((location.get("concrete") or {}).get("location") or {}).get("start_point") or {}).get("row")
        findings.append({
            "rule": item.get("ident", ""),
            "description": item.get("desc", ""),
            "url": item.get("url", ""),
            "severity": (item.get("determinations") or {}).get("severity", "Unknown"),
            "confidence": (item.get("determinations") or {}).get("confidence", "Unknown"),
            "file": path,
            "line": row + 1 if isinstance(row, int) else None,
            "note": (location.get("symbolic") or {}).get("annotation", ""),
        })
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    findings.sort(key=lambda item: (order.get(item["severity"], 9), item["file"], item["line"] or 0))
    return {"findings": findings, "files": len(workflows)}


# ----- release assets -----------------------------------------------------------------

OTHER_OS = re.compile(r"darwin|macos|mac-|osx|windows|win64|win32|freebsd|openbsd|netbsd|solaris|illumos|android", re.IGNORECASE)


def select_linux_asset(assets: list[dict[str, Any]], repository: str) -> dict[str, Any] | None:
    """Pick the release file a Linux amd64 user would download (archive or raw binary)."""
    name = repository.split("/", 1)[1].lower()
    usable = [
        asset for asset in assets
        if not NON_BINARY.search(asset["name"]) and not OTHER_OS.search(asset["name"])
        and not NOT_AMD64.search(asset["name"]) and 0 < int(asset.get("size") or 0) <= MAX_ASSET_BYTES
    ]
    tiers = (
        [asset for asset in usable if LINUX.search(asset["name"]) and AMD64.search(asset["name"])],
        [asset for asset in usable if LINUX.search(asset["name"])],  # e.g. kube-linter-linux
        [asset for asset in usable if AMD64.search(asset["name"])],  # e.g. tracee-x86_64.v1.tar.gz
    )
    for candidates in tiers:
        if candidates:
            return sorted(candidates, key=lambda asset: (signature_files(assets, asset["name"]) is None,
                                                         name not in asset["name"].lower(), "musl" in asset["name"].lower(),
                                                         not ARCHIVE.search(asset["name"]), len(asset["name"])))[0]
    return None


def download(url: str, destination: pathlib.Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "awesome-security-pipeline-supply-chain-report"})
    with urllib.request.urlopen(request, timeout=300) as response, destination.open("wb") as handle:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ASSET_BYTES:
                raise RuntimeError("asset exceeds size limit")
            handle.write(chunk)


def fetch_json(url: str, timeout: int = 30) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": "awesome-security-pipeline-supply-chain-report"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_binaries(archive: pathlib.Path, destination: pathlib.Path) -> list[pathlib.Path]:
    destination.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                target = (destination / member.filename).resolve()
                if destination.resolve() in target.parents and not member.is_dir():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(bundle.read(member))
    elif ARCHIVE.search(name):
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter="data")
    else:
        (destination / archive.name).write_bytes(archive.read_bytes())
    binaries = []
    for path in sorted(destination.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.stat().st_size > 512 * 1024:
            with path.open("rb") as handle:
                if handle.read(4) == b"\x7fELF":
                    binaries.append(path)
    return sorted(binaries, key=lambda path: -path.stat().st_size)[:3]


# ----- govulncheck --------------------------------------------------------------------

LEVELS = {"symbol": 3, "package": 2, "module": 1}


def govulncheck_binary(binary: pathlib.Path, raw: pathlib.Path | None = None) -> dict[str, Any] | None:
    completed = run(["govulncheck", "-mode=binary", "-format", "json", str(binary)])
    if completed.returncode != 0 or not completed.stdout.strip():
        return None  # not a Go binary, or analysis failed
    objects = json_stream(completed.stdout)
    sbom = next((item["SBOM"] for item in objects if "SBOM" in item), {})
    if not sbom.get("go_version"):
        return None
    if raw is not None:
        raw.write_text(strip_paths(completed.stdout, [str(binary.parent.resolve()) + "/", str(binary.parent) + "/"]), encoding="utf-8")
    config = next((item["config"] for item in objects if "config" in item), {})
    return {
        "binary": binary.name,
        "go_version": sbom.get("go_version"),
        "main_module": (sbom.get("roots") or [""])[0] if sbom.get("roots") else "",
        "modules": [module.get("path") for module in sbom.get("modules") or []],
        "module_versions": {module.get("path"): module.get("version") or "" for module in sbom.get("modules") or []
                            if module.get("path")},
        "findings": govulncheck_findings(objects),
        "db": config.get("db", ""),
        "db_last_modified": config.get("db_last_modified", ""),
    }


def govulncheck_findings(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One record per advisory, module, and version at the highest level govulncheck reached for it: an advisory can
    affect several modules in one binary (for example the standard library and golang.org/x/net)."""
    advisories = {item["osv"]["id"]: item["osv"] for item in objects if "osv" in item}
    levels: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in objects:
        finding = item.get("finding")
        if not finding:
            continue
        frame = (finding.get("trace") or [{}])[0]
        level = "symbol" if frame.get("function") else "package" if frame.get("package") else "module"
        key = (finding["osv"], frame.get("module", ""), frame.get("version", ""))
        current = levels.get(key)
        if current is None or LEVELS[level] > LEVELS[current["level"]]:
            levels[key] = {"level": level, "module": key[1], "version": key[2], "fixed_version": finding.get("fixed_version", "")}
    findings = []
    for (identifier, _, _), detail in levels.items():
        advisory = advisories.get(identifier, {})
        findings.append({
            "id": identifier,
            "aliases": sorted(advisory.get("aliases") or []),
            "summary": advisory.get("summary", ""),
            **detail,
            "published": advisory.get("published", ""),
            "modified": advisory.get("modified", ""),
        })
    findings.sort(key=lambda item: (-LEVELS[item["level"]], item["module"] != "stdlib", item["module"], item["id"], item["version"]))
    return findings


IN_BINARY = {"symbol": "vulnerable code in binary", "package": "package in binary", "module": "module in binary"}


def go_version(version: str) -> str:
    """v1.2.3 (modules) and go1.26.5 (the standard library in Grype) compare as 1.2.3 and 1.26.5."""
    return version.removeprefix("v").removeprefix("go")


def annotate_reachability(grype: list[dict[str, Any]] | None, go: dict[str, Any] | None) -> None:
    """Tell each Go Grype match whether its vulnerable code is in the released binary. govulncheck evidence counts
    only for the same advisory, module, and version; a module built at another version is reported as such."""
    if not grype or not go:
        return
    versions = go.get("module_versions")
    if versions is None:  # recorded before module versions were kept
        versions = {path: None for path in go.get("modules") or []}
    by_identity: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in go["findings"]:
        for identity in (finding["id"], *finding["aliases"]):
            key = (identity, finding["module"], go_version(finding.get("version", "")))
            current = by_identity.get(key)
            if current is None or LEVELS[finding["level"]] > LEVELS[current["level"]]:
                by_identity[key] = finding
    for finding in grype:
        if finding.get("ecosystem") != "golang":
            continue
        finding.pop("binary_version", None)
        version = go_version(finding.get("version", ""))
        hits = [by_identity[key] for key in ((i, finding["package"], version) for i in (finding["id"], *finding.get("aliases", [])))
                if key in by_identity]
        if hits:
            finding["in_binary"] = IN_BINARY[max(hits, key=lambda hit: LEVELS[hit["level"]])["level"]]
        elif finding["package"] not in versions:
            finding["in_binary"] = "not in released binary"
        elif versions[finding["package"]] is not None and go_version(versions[finding["package"]]) != version:
            finding["in_binary"] = "different version in binary"
            finding["binary_version"] = versions[finding["package"]]
        else:
            finding["in_binary"] = "vulnerable code not in binary"


# ----- release integrity --------------------------------------------------------------

def asset_by_name(assets: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((asset for asset in assets if asset["name"] == name), None)


def key_based_bundle(path: pathlib.Path) -> bool:
    try:
        material = json.loads(path.read_text(encoding="utf-8")).get("verificationMaterial") or {}
    except (OSError, json.JSONDecodeError, AttributeError):
        return False
    return "publicKey" in material and not ({"certificate", "x509CertificateChain"} & set(material))


def cosign_verify(blob: pathlib.Path, signature: dict[str, pathlib.Path], repository: str) -> dict[str, Any]:
    if "bundle" in signature and key_based_bundle(signature["bundle"]):
        return {"status": "key-signature", "detail": "signed with the project's own key; the public key is not checked"}
    identity = f"^https://github\\.com/{re.escape(repository)}/"
    command = ["cosign", "verify-blob", "--certificate-oidc-issuer", GITHUB_ISSUER,
               "--certificate-identity-regexp", identity]
    if "bundle" in signature:
        command += ["--bundle", str(signature["bundle"])]
    else:
        command += ["--signature", str(signature["sig"]), "--certificate", str(signature["cert"])]
    completed = run([*command, str(blob)], timeout=180)
    if completed.returncode == 0:
        return {"status": "verified", "identity": f"GitHub Actions workflow in {repository}"}
    loose = [part if part != identity else ".*" for part in command]
    loose[loose.index("--certificate-oidc-issuer")] = "--certificate-oidc-issuer-regexp"
    loose[loose.index(GITHUB_ISSUER)] = ".*"
    if run([*loose, str(blob)], timeout=180).returncode == 0:
        return {"status": "signed-other-identity", "detail": "valid Sigstore signature from an identity outside this repository's GitHub workflows"}
    return {"status": "failed", "error": completed.stderr.strip()[-300:]}


def certificate_identity(signature: dict[str, pathlib.Path]) -> str | None:
    """The signer named in a Sigstore certificate (subject alternative name), for example a workflow URL or an
    email; None for key signatures or when the certificate cannot be read."""
    try:
        if "bundle" in signature:
            material = json.loads(signature["bundle"].read_text(encoding="utf-8")).get("verificationMaterial") or {}
            raw = (material.get("certificate") or {}).get("rawBytes") \
                or ((material.get("x509CertificateChain") or {}).get("certificates") or [{}])[0].get("rawBytes")
            if not raw:
                return None
            data, form = base64.b64decode(raw), "DER"
        elif "cert" in signature:
            data, form = signature["cert"].read_bytes(), "PEM"
            if b"BEGIN CERTIFICATE" not in data:
                data = base64.b64decode(data)  # cosign writes the PEM base64-encoded
        else:
            return None
    except (OSError, ValueError, TypeError, AttributeError, IndexError):
        return None
    completed = subprocess.run(["openssl", "x509", "-inform", form, "-noout", "-ext", "subjectAltName"],
                               input=data, capture_output=True, timeout=30, check=False)
    lines = [line.strip() for line in completed.stdout.decode("utf-8", "replace").splitlines()[1:] if line.strip()]
    return ", ".join(lines)[:200] or None


def signature_files(assets: list[dict[str, Any]], name: str) -> dict[str, str] | None:
    for suffix in ("-keyless.sigstore.json", ".keyless.sigstore.json", ".sigstore.json", ".bundle", ".sigstore"):
        if asset_by_name(assets, name + suffix):
            return {"bundle": name + suffix}
    if asset_by_name(assets, name + ".sig"):
        for suffix in (".pem", ".cert", ".crt"):
            if asset_by_name(assets, name + suffix):
                return {"sig": name + ".sig", "cert": name + suffix}
        return {"key_signature": name + ".sig"}
    return None


def release_integrity(target: dict[str, Any], asset: dict[str, Any] | None, file: pathlib.Path | None, work: pathlib.Path) -> dict[str, Any]:
    assets = target.get("assets") or []
    repository = target["repository"]
    result: dict[str, Any] = {
        "assets": len(assets),
        "checksums_published": any(CHECKSUMS.search(item["name"]) for item in assets),
        "sbom_published": any(SBOM_ASSET.search(item["name"]) for item in assets),
        "signatures_published": any(re.search(r"\.(sig|sigstore\.json|bundle|asc)$", item["name"]) for item in assets),
        "provenance_published": any(item["name"].endswith(".intoto.jsonl") for item in assets),
        "methods": [],
    }
    if not assets:
        result["verdict"] = "no-assets"
        return result
    if not asset or not file:
        result["verdict"] = "no-linux-binary"
        return result
    result["asset"] = asset["name"]
    actual = sha256(file)
    expected = str(asset.get("digest") or "").removeprefix("sha256:")
    result["digest_matches_github"] = (actual == expected) if expected else None

    def fetch(name: str) -> pathlib.Path:
        path = work / name
        if not path.exists():
            download(asset_by_name(assets, name)["browser_download_url"], path)
        return path

    # 1. Sigstore signature on the asset itself, or on a checksums file that lists it.
    signed = signature_files(assets, asset["name"])
    covered_by = asset["name"]
    if not signed:
        signature_suffixes = (".sig", ".pem", ".cert", ".sigstore.json", ".bundle", ".sigstore")
        for checksum in (item for item in assets if CHECKSUMS.search(item["name"]) and not item["name"].endswith(signature_suffixes)):
            files = signature_files(assets, checksum["name"])
            if files:
                text = fetch(checksum["name"]).read_text(encoding="utf-8", errors="replace")
                if re.search(rf"^{actual}\s+\*?{re.escape(asset['name'])}\s*$", text, re.MULTILINE):
                    signed, covered_by = files, checksum["name"]
                    break
    if signed and "key_signature" in signed:
        result["methods"].append({"method": "cosign", "status": "key-signature", "detail": "signed with a key; public key not checked"})
    elif signed:
        try:
            paths = {key: fetch(value) for key, value in signed.items()}
            outcome = cosign_verify(fetch(covered_by) if covered_by != asset["name"] else file, paths, repository)
            outcome["covers"] = "asset" if covered_by == asset["name"] else f"checksums file {covered_by}"
            if outcome["status"] in ("verified", "signed-other-identity"):
                outcome["signer"] = certificate_identity(paths)
            result["methods"].append({"method": "cosign", **outcome})
        except (urllib.error.URLError, OSError, subprocess.TimeoutExpired) as exc:
            result["methods"].append({"method": "cosign", "status": "failed", "error": str(exc)})

    # 2. SLSA provenance.
    provenance = next((item["name"] for item in assets if item["name"] in (asset["name"] + ".intoto.jsonl", "multiple.intoto.jsonl")), None) \
        or next((item["name"] for item in assets if item["name"].endswith(".intoto.jsonl")), None)
    if provenance:
        try:
            completed = run(["slsa-verifier", "verify-artifact", str(file), "--provenance-path", str(fetch(provenance)),
                             "--source-uri", f"github.com/{repository}", "--source-tag", target["ref"]], timeout=180)
            result["methods"].append({"method": "slsa-verifier", "status": "verified" if completed.returncode == 0 else "failed",
                                      "error": "" if completed.returncode == 0 else completed.stderr.strip()[-300:]})
        except (urllib.error.URLError, OSError, subprocess.TimeoutExpired) as exc:
            result["methods"].append({"method": "slsa-verifier", "status": "failed", "error": str(exc)})

    # 3. GitHub attestations: build provenance (signed by the project's workflow) and
    # immutable-release attestations (signed by GitHub when the release was published).
    listing = run(["gh", "api", f"repos/{repository}/attestations/sha256:{actual}", "--jq",
                   "[.attestations[].bundle.dsseEnvelope.payload]"], timeout=60)
    predicates: set[str] = set()
    if listing.returncode == 0 and listing.stdout.strip().startswith("["):
        for payload in json.loads(listing.stdout):
            try:
                predicates.add(json.loads(base64.b64decode(payload)).get("predicateType", ""))
            except (ValueError, TypeError):
                continue
    build = sorted(item for item in predicates if "release/" not in item and item)
    if build:
        statuses = []
        for predicate in build:
            completed = run(["gh", "attestation", "verify", str(file), "--repo", repository, "--predicate-type", predicate], timeout=180)
            statuses.append(completed.returncode == 0)
        result["methods"].append({"method": "github-attestation", "status": "verified" if any(statuses) else "failed",
                                  "predicates": build})
    if any("in-toto.io/attestation/release/" in item for item in predicates):
        completed = run(["gh", "release", "verify-asset", target["ref"], str(file), "-R", repository], timeout=180)
        result["methods"].append({"method": "github-immutable-release", "status": "verified" if completed.returncode == 0 else "failed",
                                  "detail": "GitHub attests the file is unchanged since the release was published"})

    result.update(integrity_dimensions(result["methods"]))
    result["verdict"] = integrity_verdict(result)
    return result


SIGNATURE_STATES = {"verified": "own-workflow", "signed-other-identity": "other-identity", "key-signature": "key-unchecked",
                    "failed": "failed"}


def integrity_dimensions(methods: list[dict[str, Any]]) -> dict[str, Any]:
    """Each kind of release evidence on its own, because they prove different things: build provenance says how and
    from what source the file was built; a signature says who signed it; an immutable release only says the file has
    not changed since it was published."""
    def state(names: tuple[str, ...]) -> str | None:
        found = [item["status"] for item in methods if item["method"] in names]
        return "verified" if "verified" in found else ("failed" if found else None)

    cosign = next((item for item in methods if item["method"] == "cosign"), None)
    immutable = state(("github-immutable-release",))
    return {
        "build_provenance": state(("slsa-verifier", "github-attestation")),
        "signature": SIGNATURE_STATES.get(cosign["status"], cosign["status"]) if cosign else None,
        "signer": (cosign or {}).get("signer"),
        "immutable_release": None if immutable is None else immutable == "verified",
    }


def integrity_verdict(result: dict[str, Any]) -> str:
    """One label for tables and badges. *verified* needs build provenance or a signature from one of the project's
    own GitHub Actions workflows; an immutable release alone is reported as *immutable*, not verified."""
    if result.get("verdict") in ("no-assets", "no-linux-binary"):
        return result["verdict"]
    dimensions = {**integrity_dimensions(result.get("methods") or []),
                  **{key: result[key] for key in ("build_provenance", "signature", "immutable_release") if key in result}}
    if dimensions["build_provenance"] == "verified" or dimensions["signature"] == "own-workflow":
        return "verified"
    if dimensions["signature"] in ("other-identity", "key-unchecked"):
        return "signed"
    if dimensions["immutable_release"]:
        return "immutable"
    if result.get("methods"):
        return "unverified"
    return "checksums-only" if result.get("checksums_published") else "none"


# ----- OpenSSF Scorecard --------------------------------------------------------------

def scorecard(repository: str, allow_cli: bool) -> dict[str, Any]:
    """Prefer the OpenSSF public dataset; fall back to the Scorecard CLI while the weekly budget lasts."""
    try:
        request = urllib.request.Request(SCORECARD_API.format(repository=repository), headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
        date = str(data.get("date", ""))[:10]
        age = (dt.date.today() - dt.date.fromisoformat(date)).days if date else None
        if age is not None and age <= SCORECARD_MAX_AGE_DAYS:
            return summarize_scorecard(data, "openssf-api")
        reason = (f"the OpenSSF public dataset entry is {age} days old (limit {SCORECARD_MAX_AGE_DAYS})"
                  if age is not None else "the OpenSSF public dataset entry has no date")
    except urllib.error.HTTPError as exc:
        reason = ("the project is not in the OpenSSF public dataset" if exc.code == 404
                  else f"the OpenSSF API returned HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError) as exc:
        reason = f"the OpenSSF API could not be reached ({getattr(exc, 'reason', exc)})"
    except (json.JSONDecodeError, ValueError):
        reason = "the OpenSSF API returned an unreadable response"
    if not allow_cli:
        return {"error": f"{reason}; the Scorecard CLI fallback was skipped because this shard's weekly budget was used"}
    token = os.environ.get("SCORECARD_TOKEN") or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return {"error": f"{reason}; no token is available for the Scorecard CLI fallback"}
    completed = run(["scorecard", f"--repo=github.com/{repository}", "--format=json"], timeout=600,
                    env={**os.environ, "GITHUB_AUTH_TOKEN": token})
    if completed.returncode != 0 or not completed.stdout.strip():
        detail = completed.stderr.strip().splitlines()[-1][:200] if completed.stderr.strip() else "no output"
        return {"error": f"{reason}; the Scorecard CLI fallback failed (exit {completed.returncode}: {detail})"}
    return summarize_scorecard(json.loads(completed.stdout), "scorecard-cli")


def summarize_scorecard(data: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "score": data.get("score"),
        "date": str(data.get("date", ""))[:10],
        "version": (data.get("scorecard") or {}).get("version", ""),
        "source": source,
        "checks": sorted(
            ({"name": item.get("name"), "score": item.get("score"), "reason": item.get("reason", "")}
             for item in data.get("checks") or []),
            key=lambda item: (item["score"] if isinstance(item["score"], (int, float)) and item["score"] >= 0 else 99, item["name"]),
        ),
    }
