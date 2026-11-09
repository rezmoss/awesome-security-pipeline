"""Exploitation context for matched advisories: CISA KEV and FIRST EPSS.

`fetch` runs in a read-only job and writes the two upstream files plus `enrichment.json` (where they
came from, their versions, and digests). `publish` only reads that directory; a failed download is
recorded and leaves matches without `kev`/`epss` keys, which the site shows as "not checked".
"""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import pathlib
from typing import Any

from scripts import supply_chain_checks as checks

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_FILE = "kev.json"
EPSS_FILE = "epss_scores.csv.gz"
METADATA_FILE = "enrichment.json"


def cve_ids(item: dict[str, Any]) -> list[str]:
    return sorted({value for value in [item.get("id", ""), *(item.get("aliases") or [])] if value.startswith("CVE-")})


def fetch(output: pathlib.Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    metadata: dict[str, Any] = {"fetched_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()}
    for key, url, name in (("kev", KEV_URL, KEV_FILE), ("epss", EPSS_URL, EPSS_FILE)):
        entry: dict[str, Any] = {"url": url, "file": name}
        try:
            checks.download(url, output / name)
            entry["sha256"] = checks.sha256(output / name)
            entry.update(describe_kev(output / name) if key == "kev" else describe_epss(output / name))
        except Exception as exc:  # noqa: BLE001 - enrichment is optional; the scan must not fail on it
            (output / name).unlink(missing_ok=True)
            entry = {"url": url, "error": str(exc)[:200]}
        metadata[key] = entry
    (output / METADATA_FILE).write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


def describe_kev(path: pathlib.Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("KEV feed has no vulnerabilities list")
    return {"version": data.get("catalogVersion"), "released": data.get("dateReleased"), "count": len(data["vulnerabilities"])}


def epss_rows(path: pathlib.Path) -> tuple[dict[str, str], csv.DictReader]:
    text = gzip.decompress(path.read_bytes()).decode("utf-8")
    first, _, rest = text.partition("\n")
    header = dict(part.split(":", 1) for part in first.lstrip("#").split(",") if ":" in part) if first.startswith("#") else {}
    return header, csv.DictReader(io.StringIO(rest if first.startswith("#") else text))


def describe_epss(path: pathlib.Path) -> dict[str, Any]:
    header, rows = epss_rows(path)
    count = sum(1 for row in rows if row.get("cve", "").startswith("CVE-"))
    if not count:
        raise ValueError("EPSS file has no scores")
    return {"version": header.get("model_version"), "released": header.get("score_date"), "count": count}


def load(directory: pathlib.Path | None) -> dict[str, Any] | None:
    """KEV and EPSS lookups plus provenance; None when no enrichment directory was given."""
    if not directory or not (directory / METADATA_FILE).is_file():
        return None
    metadata = json.loads((directory / METADATA_FILE).read_text(encoding="utf-8"))
    result: dict[str, Any] = {"metadata": metadata, "kev": None, "epss": None}
    if "error" not in metadata.get("kev", {}) and (directory / KEV_FILE).is_file():
        feed = json.loads((directory / KEV_FILE).read_text(encoding="utf-8"))
        result["kev"] = {item["cveID"]: {"date_added": item.get("dateAdded")} for item in feed["vulnerabilities"] if item.get("cveID")}
    if "error" not in metadata.get("epss", {}) and (directory / EPSS_FILE).is_file():
        _, rows = epss_rows(directory / EPSS_FILE)
        result["epss"] = {row["cve"]: (float(row["epss"]), float(row["percentile"])) for row in rows if row.get("cve", "").startswith("CVE-")}
    return result


def annotate(vulnerabilities: list[dict[str, Any]] | None, data: dict[str, Any] | None) -> None:
    """Add `kev` and `epss` to each match; a source that was not loaded leaves its key absent."""
    if not vulnerabilities or not data:
        return
    for item in vulnerabilities:
        ids = cve_ids(item)
        if data.get("kev") is not None:
            listed = [data["kev"][cve] | {"cve": cve} for cve in ids if cve in data["kev"]]
            item["kev"] = min(listed, key=lambda entry: entry.get("date_added") or "") if listed else None
            # Every listed CVE alias (`kev` is the earliest) and the catalog version that was checked.
            item["kev_cves"] = sorted(entry["cve"] for entry in listed)
            item["kev_snapshot"] = (data["metadata"].get("kev") or {}).get("version")
        if data.get("epss") is not None:
            scored = [(data["epss"][cve], cve) for cve in ids if cve in data["epss"]]
            if scored:
                (score, percentile), cve = max(scored)
                item["epss"] = {"score": score, "percentile": percentile, "cve": cve}
            else:
                item["epss"] = None
            item["epss_date"] = (data["metadata"].get("epss") or {}).get("released")


def provenance(data: dict[str, Any] | None) -> dict[str, Any] | None:
    if not data:
        return None
    metadata = data["metadata"]
    result = {key: metadata.get(key) for key in ("fetched_at", "kev", "epss")}
    if data.get("kev") is not None:
        # The full CVE list lets next week tell which CVEs CISA added, without the old snapshot file.
        ids = sorted(data["kev"])
        result["kev"] = {**(result["kev"] or {}), "cve_ids": ids,
                         "cve_ids_sha256": hashlib.sha256("\n".join(ids).encode()).hexdigest()}
    return result


def snapshot_ids(directory: pathlib.Path | None) -> list[str] | None:
    """CVE ids in a stored KEV snapshot (an evidence bundle's supply-chain-enrichment directory)."""
    data = load(directory)
    return sorted(data["kev"]) if data and data.get("kev") is not None else None
