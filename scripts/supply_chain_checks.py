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

def osv_scan(source: pathlib.Path) -> dict[str, Any]:
    completed = run(["osv-scanner", "scan", "source", "-r", str(source), "--format", "json", "--no-call-analysis=all"])
    output = completed.stdout.strip()
    if not output.startswith("{"):
        if completed.returncode in (0, 128):  # 128: no supported packages found
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
    groups = []
    for result in report.get("results") or []:
        for package in result.get("packages") or []:
            info = package.get("package") or {}
            aliases_by_id = {
                vuln.get("id"): set(vuln.get("aliases") or []) for vuln in package.get("vulnerabilities") or []
            }
            for group in package.get("groups") or []:
                ids = set(group.get("ids") or [])
                for identifier in list(ids):
                    ids |= aliases_by_id.get(identifier, set())
                ids |= set(group.get("aliases") or [])
                groups.append({
                    "ids": sorted(ids),
                    "package": str(info.get("name", "")),
                    "version": str(info.get("version", "")),
                    "ecosystem": str(info.get("ecosystem", "")),
                    "severity": cvss_bucket(group.get("max_severity")),
                    "score": group.get("max_severity") or "",
                })
    return {"groups": groups, "warning": warning} if warning else {"groups": groups}


def cross_reference(grype: list[dict[str, Any]] | None, osv: dict[str, Any]) -> dict[str, Any]:
    """Mark Grype findings confirmed by OSV and count OSV-only advisories."""
    groups = osv.get("groups")
    if grype is None or groups is None:
        return {"available": False}
    matched_groups = set()
    for finding in grype:
        identities = {finding["id"], *finding.get("aliases", [])}
        finding["osv_confirmed"] = False
        for index, group in enumerate(groups):
            if identities & set(group["ids"]) and group["package"].lower() == finding["package"].lower():
                finding["osv_confirmed"] = True
                matched_groups.add(index)
    only = [group for index, group in enumerate(groups) if index not in matched_groups]
    return {
        "available": True,
        "warning": osv.get("warning"),
        "advisories": len(groups),
        "confirmed": sum(1 for finding in grype if finding.get("osv_confirmed")),
        "osv_only": only,
    }


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


def govulncheck_binary(binary: pathlib.Path) -> dict[str, Any] | None:
    completed = run(["govulncheck", "-mode=binary", "-format", "json", str(binary)])
    if completed.returncode != 0 or not completed.stdout.strip():
        return None  # not a Go binary, or analysis failed
    objects = json_stream(completed.stdout)
    sbom = next((item["SBOM"] for item in objects if "SBOM" in item), {})
    if not sbom.get("go_version"):
        return None
    advisories = {item["osv"]["id"]: item["osv"] for item in objects if "osv" in item}
    levels: dict[str, dict[str, Any]] = {}
    for item in objects:
        finding = item.get("finding")
        if not finding:
            continue
        frame = (finding.get("trace") or [{}])[0]
        level = "symbol" if frame.get("function") else "package" if frame.get("package") else "module"
        current = levels.get(finding["osv"])
        if current is None or LEVELS[level] > LEVELS[current["level"]]:
            levels[finding["osv"]] = {
                "level": level, "module": frame.get("module", ""), "version": frame.get("version", ""),
                "fixed_version": finding.get("fixed_version", ""),
            }
    findings = []
    for identifier, detail in levels.items():
        advisory = advisories.get(identifier, {})
        findings.append({
            "id": identifier,
            "aliases": sorted(advisory.get("aliases") or []),
            "summary": advisory.get("summary", ""),
            **detail,
        })
    findings.sort(key=lambda item: (-LEVELS[item["level"]], item["module"] != "stdlib", item["module"], item["id"]))
    return {
        "binary": binary.name,
        "go_version": sbom.get("go_version"),
        "main_module": (sbom.get("roots") or [""])[0] if sbom.get("roots") else "",
        "modules": [module.get("path") for module in sbom.get("modules") or []],
        "findings": findings,
    }


def annotate_reachability(grype: list[dict[str, Any]] | None, go: dict[str, Any] | None) -> None:
    """Tell each Go Grype match whether its vulnerable code is in the released binary."""
    if not grype or not go:
        return
    modules = set(go.get("modules") or [])
    by_identity: dict[str, dict[str, Any]] = {}
    for finding in go["findings"]:
        for identity in (finding["id"], *finding["aliases"]):
            by_identity[identity] = finding
    for finding in grype:
        if finding.get("ecosystem") != "golang":
            continue
        hit = next((by_identity[i] for i in (finding["id"], *finding.get("aliases", [])) if i in by_identity), None)
        if hit:
            finding["in_binary"] = {"symbol": "vulnerable code in binary", "package": "package in binary",
                                    "module": "module in binary"}[hit["level"]]
        elif finding["package"] not in modules:
            finding["in_binary"] = "not in released binary"
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

    statuses = [item["status"] for item in result["methods"]]
    if "verified" in statuses:
        result["verdict"] = "verified"
    elif {"key-signature", "signed-other-identity"} & set(statuses):
        result["verdict"] = "signed"
    elif statuses:
        result["verdict"] = "unverified"
    elif result["checksums_published"]:
        result["verdict"] = "checksums-only"
    else:
        result["verdict"] = "none"
    return result


# ----- OpenSSF Scorecard --------------------------------------------------------------

def scorecard(repository: str, allow_cli: bool) -> dict[str, Any]:
    try:
        request = urllib.request.Request(SCORECARD_API.format(repository=repository), headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
        date = str(data.get("date", ""))[:10]
        age = (dt.date.today() - dt.date.fromisoformat(date)).days if date else 999
        if age <= SCORECARD_MAX_AGE_DAYS:
            return summarize_scorecard(data, "openssf-api")
    except (urllib.error.URLError, json.JSONDecodeError, ValueError, TimeoutError):
        data = None
    if not allow_cli:
        return {"error": "not in the OpenSSF dataset this week; run budget exhausted"}
    token = os.environ.get("SCORECARD_TOKEN") or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return {"error": "no token available for the Scorecard CLI"}
    completed = run(["scorecard", f"--repo=github.com/{repository}", "--format=json"], timeout=600,
                    env={**os.environ, "GITHUB_AUTH_TOKEN": token})
    if completed.returncode != 0 or not completed.stdout.strip():
        return {"error": f"scorecard exited with {completed.returncode}: {completed.stderr.strip()[-300:]}"}
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
