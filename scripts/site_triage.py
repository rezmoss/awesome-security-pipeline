"""Week-over-week triage for the report: which changes are comparable, which got worse, and the per-week events
the overview uses for "since your last visit"."""

from __future__ import annotations

import re
from typing import Any, Callable

from scripts import supply_chain_checks as checks

SEVERE = ("Critical", "High")
SCORE_DROP = 0.5
VERDICT_NAMES = {
    "verified": "verified", "signed": "signed", "immutable": "immutable release only", "unverified": "did not verify",
    "checksums-only": "checksums only", "none": "no checksums or signatures", "no-linux-binary": "no Linux binary",
    "no-assets": "no release files",
}
METHOD_NAMES = {"cosign": "Cosign signature", "slsa-verifier": "SLSA provenance", "github-attestation": "GitHub attestation",
                "github-immutable-release": "immutable release"}
EVIDENCE_NAMES = {"build_provenance": "build provenance", "signature": "own-workflow signature", "immutable_release": "immutable release"}


def name_of(entry: dict[str, Any]) -> str:
    return entry.get("name") or entry["repository"]


def score_delta(previous: dict[str, Any] | None, row: dict[str, Any]) -> float | None:
    """The Scorecard change between two weekly rows, or None when the two scores are not comparable: either one is
    missing, they come from different sources, one was carried forward, or either week's scan failed."""
    if not previous:
        return None
    before, after = previous.get("scorecard"), row.get("scorecard")
    if not isinstance(before, (int, float)) or not isinstance(after, (int, float)):
        return None
    source = row.get("scorecard_source")
    if not source or source == "carried-forward" or source != previous.get("scorecard_source"):
        return None
    if row.get("stale") or previous.get("stale") or row.get("errors") or previous.get("errors"):
        return None
    return round(after - before, 1)


def score_change_reason(previous: dict[str, Any] | None, row: dict[str, Any]) -> str | None:
    """Why two recorded scores that differ are not compared."""
    if not previous or not isinstance(previous.get("scorecard"), (int, float)) or not isinstance(row.get("scorecard"), (int, float)):
        return None
    if previous["scorecard"] == row["scorecard"] or score_delta(previous, row) is not None:
        return None
    if "carried-forward" in (row.get("scorecard_source"), previous.get("scorecard_source")):
        return "carried forward"
    if row.get("scorecard_source") != previous.get("scorecard_source"):
        return "source changed"
    return "scan failed"


def canonical(item: dict[str, Any], aliases: dict[str, str]) -> str:
    return aliases.get(item["id"]) or next((aliases[value] for value in item.get("aliases") or [] if value in aliases), item["id"])


def severe_pairs(change: dict[str, Any], aliases: dict[str, str]) -> set[tuple[str, str]]:
    """Distinct (advisory, package) pairs new this week with Critical or High severity."""
    if not change or change.get("baseline"):
        return set()
    return {(canonical(item, aliases), item["package"]) for item in change.get("new_vulnerabilities") or []
            if item.get("severity") in SEVERE}


def new_by_advisory(projects: list[dict[str, Any]], aliases: dict[str, str]) -> list[dict[str, Any]]:
    """New advisories this week, one entry per advisory with every tool and package it newly matches;
    most severe first, then the most tools."""
    order = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
    grouped: dict[str, dict[str, Any]] = {}
    for project in projects:
        change = project.get("changes") or {}
        if change.get("baseline"):
            continue
        for item in change.get("new_vulnerabilities") or []:
            key = canonical(item, aliases)
            record = grouped.setdefault(key, {"id": key, "severity": "Unknown", "packages": set(), "tools": {}, "item": item})
            severity = item.get("severity") if item.get("severity") in order else "Unknown"
            if order.index(severity) < order.index(record["severity"]):
                record["severity"] = severity
            record["packages"].add(item["package"])
            record["tools"][project["repository"]] = project
    return sorted(grouped.values(), key=lambda record: (order.index(record["severity"]), -len(record["tools"]), record["id"]))


def binary_new_by_advisory(projects: list[dict[str, Any]], aliases: dict[str, str]) -> list[dict[str, Any]]:
    """Advisories whose vulnerable code is newly in a released Go binary, with the tools it is in; most tools first."""
    grouped: dict[str, dict[str, Any]] = {}
    for project in projects:
        change = project.get("changes") or {}
        if change.get("baseline"):
            continue
        for identifier in change.get("in_binary_new") or []:
            key = aliases.get(identifier, identifier)
            grouped.setdefault(key, {"id": key, "tools": {}})["tools"][project["repository"]] = project
    return sorted(grouped.values(), key=lambda record: (-len(record["tools"]), record["id"]))


def failed_methods(integrity: dict[str, Any] | None) -> list[str]:
    """Release checks that ran and failed, including ones hidden by another check that verified."""
    return sorted({item["method"] for item in (integrity or {}).get("methods") or [] if item.get("status") == "failed"})


def evidence_of(integrity: dict[str, Any] | None) -> dict[str, Any] | None:
    if not integrity or integrity.get("verdict") in (None, "no-assets", "no-linux-binary"):
        return None
    dimensions = checks.release_dimensions(integrity)
    return {key: dimensions.get(key) for key in EVIDENCE_NAMES}


def evidence_lost(previous: dict[str, Any] | None, current: dict[str, Any] | None) -> list[str]:
    """Kinds of release evidence that verified last week and do not verify this week. Weeks recorded before evidence
    was kept per kind give no comparison."""
    if not previous or not current:
        return []
    lost = []
    if previous.get("build_provenance") == "verified" and current.get("build_provenance") != "verified":
        lost.append("build provenance")
    if previous.get("signature") == "own-workflow" and current.get("signature") != "own-workflow":
        lost.append("own-workflow signature")
    if previous.get("immutable_release") is True and current.get("immutable_release") is not True:
        lost.append("immutable release")
    return lost


def run_revision(run: dict[str, Any]) -> str:
    """Identifies one recorded report: a same-date re-run replaces the report and gets a new revision."""
    info = (run.get("provenance") or {}).get("run") or {}
    if info.get("id"):
        return f"{info['id']}-{info.get('attempt', 1)}"
    return re.sub(r"[^0-9T]", "", str(run.get("generated_at") or "")) or str(run.get("date"))


def row_anchor(entry: dict[str, Any]) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(entry["id"]).lower()).strip("-")


def row_events(previous: dict[str, Any] | None, row: dict[str, Any], verdict_change: tuple[str, str] | None = None) -> list[str]:
    """One tool's changes in one week, from its weekly rows, as short phrases. A null count was not compared and is
    left out rather than shown as zero."""
    events = []
    if row.get("errors"):
        events.append("scan failed")
    if row.get("release_changed"):
        events.append(f"new release {row.get('ref')}")
    new = row.get("new_advisories") if row.get("new_advisories") is not None else row.get("new_vulnerabilities")
    if new:
        severe = row.get("new_severe")
        events.append(f"{new} new advisor{'y' if new == 1 else 'ies'}"
                      + (f" ({severe} Critical/High)" if severe else "" if severe is not None else " (severity not recorded)"))
    resolved = row.get("resolved_advisories") if row.get("resolved_advisories") is not None else row.get("resolved_vulnerabilities")
    if resolved:
        events.append(f"{resolved} resolved")
    if row.get("kev_new"):
        events.append(f"{row['kev_new']} newly in CISA KEV")
    if row.get("kev_new_match"):
        events.append(f"{row['kev_new_match']} new match{'es' if row['kev_new_match'] != 1 else ''} for CVEs already in CISA KEV")
    if row.get("in_binary_new"):
        events.append(f"{row['in_binary_new']} new in binary")
    if row.get("in_binary_resolved"):
        events.append(f"{row['in_binary_resolved']} removed from binary")
    if row.get("binary_analysis"):
        events.append("binary analyzed again" if (row["binary_analysis"] or {}).get("to") == "analyzed" else "binary not analyzed")
    delta = score_delta(previous, row)
    if delta:
        events.append(f"Scorecard {previous['scorecard']:.1f} → {row['scorecard']:.1f}")
    elif score_change_reason(previous, row):
        events.append(f"Scorecard {previous['scorecard']:.1f} → {row['scorecard']:.1f} (not compared: {score_change_reason(previous, row)})")
    if verdict_change:
        events.append(f"release {VERDICT_NAMES.get(verdict_change[0], verdict_change[0])} → "
                      f"{VERDICT_NAMES.get(verdict_change[1], verdict_change[1])}")
    elif previous and previous.get("release_integrity") and row.get("release_integrity") \
            and previous["release_integrity"] != row["release_integrity"]:
        events.append(f"release {VERDICT_NAMES.get(previous['release_integrity'], previous['release_integrity'])} → "
                      f"{VERDICT_NAMES.get(row['release_integrity'], row['release_integrity'])}")
    failed = (row.get("release_evidence") or {}).get("failed")
    if failed:
        events.append("release check failed: " + ", ".join(METHOD_NAMES.get(item, item) for item in failed))
    lost = evidence_lost((previous or {}).get("release_evidence"), row.get("release_evidence"))
    if lost:
        events.append("release evidence lost: " + ", ".join(lost))
    dependencies = sum(row.get(key) or 0 for key in ("added", "removed", "upgraded", "downgraded", "unknown_direction"))
    if dependencies:
        events.append(f"{dependencies} dependency change{'s' if dependencies != 1 else ''}")
    if row.get("workflow_new"):
        events.append(f"{row['workflow_new']} new workflow finding{'s' if row['workflow_new'] != 1 else ''}")
    if row.get("workflow_resolved"):
        events.append(f"{row['workflow_resolved']} workflow finding{'s' if row['workflow_resolved'] != 1 else ''} resolved")
    for key, one, many in (("license_changes", "license change", "license changes"),
                           ("file_changes", "manifest or workflow file changed", "manifest or workflow files changed"),
                           ("moved", "package moved between lockfiles", "packages moved between lockfiles"),
                           ("integrity_drift", "package hash change", "package hash changes")):
        if row.get(key):
            events.append(f"{row[key]} {one if row[key] == 1 else many}")
    # A comparison that could not be made is noted, but on its own does not mark the tool as changed.
    if events:
        events += [f"{kind} changes unavailable" for kind, key in (("dependency", "dependency_state"), ("advisory", "advisory_state"))
                   if row.get(key) == "unavailable"]
    return events


def week_events(runs: list[dict[str, Any]], method_change: Callable[[str], Any],
                latest_verdicts: dict[str, tuple[str, str]] | None = None) -> dict[str, Any]:
    """Per week after the first: each tool's change phrases, keyed by its overview row id, and which tools joined or
    left the report. `latest_verdicts` gives the newest week's release verdict changes as the scan recorded them
    (the newest rows are relabelled with the current verdict definition; older rows are not)."""
    weeks = []
    for index in range(1, len(runs)):
        before = {row["repository"]: row for row in runs[index - 1].get("projects") or []}
        rows = runs[index].get("projects") or []
        latest = index == len(runs) - 1
        events = {}
        for row in rows:
            previous = before.get(row["repository"])
            if previous is None:
                events[row_anchor(row)] = "added to the report"
                continue
            if latest and latest_verdicts is not None:
                phrases = row_events({**previous, "release_integrity": None}, row, latest_verdicts.get(row["repository"]))
            else:
                phrases = row_events(previous, row)
            if phrases:
                events[row_anchor(row)] = "; ".join(phrases)
        current = {row["repository"]: row for row in rows}
        weeks.append({
            "date": runs[index]["date"],
            "revision": run_revision(runs[index]),
            "method_change": bool(method_change(runs[index]["date"])),
            "events": events,
            "added": sorted(name_of(row) for name, row in current.items() if name not in before),
            # Tools that left the catalog are not named on current pages; their pages remain under History.
            "removed": sum(1 for name in before if name not in current),
        })
    return {
        "first": runs[0]["date"] if runs else None,
        "latest": {"date": runs[-1]["date"], "revision": run_revision(runs[-1])} if runs else None,
        "weeks": weeks,
    }


def card_delta(before: float | int | None, after: float | int | None, digits: int = 0) -> str:
    """'+3', '−12', '±0' or '' when either side is missing."""
    if not isinstance(before, (int, float)) or not isinstance(after, (int, float)):
        return ""
    value = round(after - before, digits) if digits else int(after - before)
    if not value:
        return "±0"
    text = f"{abs(value):.{digits}f}" if digits else str(abs(value))
    return ("+" if value > 0 else "−") + text
