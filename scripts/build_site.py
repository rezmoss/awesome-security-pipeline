#!/usr/bin/env python3
"""Build the GitHub Pages site for the weekly supply-chain report.

Pages: an overview table of every catalog project, one page per project with full details
and history, and a page per week.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import shutil
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import site_sections as sections  # noqa: E402
from scripts.supply_chain_scan import SEVERITIES, severity_counts  # noqa: E402

SHOWN_SEVERITIES = ("Critical", "High", "Medium", "Low")
STANDARD_NAMES = {"ntia": "NTIA 2021", "cisa": "CISA 2025", "bsi_tr03183": "BSI TR-03183"}
STYLE = """
:root{--fg:#1f2328;--muted:#59636e;--bg:#fff;--panel:#f6f8fa;--line:#d1d9e0;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--link:#0969da}
@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--muted:#9198a1;--bg:#0d1117;--panel:#151b23;--line:#3d444d;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--link:#4493f8}}
*{box-sizing:border-box}body{margin:0;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg)}
a{color:var(--link)}header,main,footer{max-width:1120px;margin:0 auto;padding:0 20px}
header{padding-top:28px}nav{display:flex;gap:16px;flex-wrap:wrap;font-size:15px;margin:8px 0 0}
h1{font-size:30px;margin:0 0 4px}h2{font-size:22px;margin:36px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}h3{font-size:18px;margin:24px 0 8px}
.lede{color:var(--muted);margin:4px 0 0;max-width:820px}.meta{color:var(--muted);font-size:14px}
table{border-collapse:collapse;width:100%;margin:8px 0 4px;font-size:15px}th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
th{background:var(--panel);font-weight:600}td.num,th.num{text-align:right;white-space:nowrap}.scroll{overflow-x:auto}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--panel);padding:1px 4px;border-radius:4px;word-break:break-word}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}
.banner{border:1px solid var(--bad);background:var(--panel);padding:12px 16px;border-radius:6px;margin:18px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:16px 0}
.card{border:1px solid var(--line);border-radius:8px;padding:14px 16px;background:var(--panel)}.card h3{margin:0 0 4px;font-size:17px}
.card .big{font-size:24px;font-weight:700}.small{font-size:14px;color:var(--muted)}ul.tight{margin:6px 0;padding-left:20px}
details{margin:8px 0}summary{cursor:pointer;font-weight:600}.note{border-left:3px solid var(--line);padding:4px 12px;color:var(--muted);margin:12px 0}
footer{margin-top:48px;padding-bottom:40px;border-top:1px solid var(--line);color:var(--muted);font-size:14px}
"""
VULNERABILITY_NOTE = (
    "Vulnerabilities are known advisories that Grype matches against the dependencies declared in each "
    "project's release source (manifests and lockfiles, including development and build dependencies). "
    "A match does not mean the tool is exploitable: the vulnerable code may be unused, test-only, or not "
    "shipped in the released binary."
)
SCOPE_NOTE = (
    "Each project is scanned at its latest GitHub release tag (or its default branch when it publishes no "
    "releases). Only dependency manifests and lockfiles are fetched; test, fixture, example, documentation, "
    "and vendored directories are excluded because security tools ship deliberately vulnerable fixtures."
)
EXTRA_STYLE = """
.sev-Critical{color:#fff;background:#a40e26}.sev-High{color:#fff;background:#cf222e}.sev-Medium{color:#1f2328;background:#f2cc60}.sev-Low{color:#1f2328;background:#d1d9e0}
.pill{display:inline-block;min-width:1.8em;padding:0 6px;border-radius:10px;text-align:center;font-size:13px;font-weight:600}
.zero{color:var(--muted)}td.change{font-size:14px}tr.changed td:first-child{border-left:3px solid var(--warn)}
"""


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def ordered_standards(standards: dict[str, Any]) -> list[tuple[str, Any]]:
    order = list(STANDARD_NAMES)
    return sorted(standards.items(), key=lambda item: order.index(item[0]) if item[0] in order else len(order))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--repository", default="rezmoss/awesome-security-pipeline")
    parser.add_argument("--supply-chain-data", type=pathlib.Path)
    parser.add_argument("--supply-chain-artifacts", type=pathlib.Path, help="scan shard output for the latest week")
    return parser.parse_args()


def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def project_path(repository: str) -> str:
    return f"projects/{repository}/"


def pill(severity: str, count: int) -> str:
    if not count:
        return '<span class="pill zero">0</span>'
    return f'<span class="pill sev-{esc(severity)}" title="{esc(severity)}">{count}</span>'


def badge(severity: str, text: str | None = None) -> str:
    return f'<span class="pill sev-{esc(severity)}">{esc(text or severity)}</span>'


def change_summary(change: dict[str, Any]) -> str:
    if not change or change.get("baseline"):
        return "first scan"
    if change.get("scan_failed"):
        return "scan failed; showing last good scan"
    parts = []
    if change.get("release_changed"):
        parts.append(f"new release (was {change.get('previous_ref')})")
    for key, label in (("added", "added"), ("removed", "removed"), ("upgraded", "upgraded")):
        if change.get(key):
            parts.append(f"{len(change[key])} {label}")
    if change.get("new_vulnerabilities"):
        parts.append(f"{len(change['new_vulnerabilities'])} new advisories")
    if change.get("resolved_vulnerabilities"):
        parts.append(f"{len(change['resolved_vulnerabilities'])} resolved")
    if change.get("license_changes"):
        parts.append(f"{len(change['license_changes'])} license changes")
    if change.get("integrity_drift"):
        parts.append(f"{change['integrity_drift']} hash changes without a version change")
    if change.get("in_binary_new"):
        parts.append(f"{len(change['in_binary_new'])} new vulnerable functions in binary")
    if change.get("in_binary_resolved"):
        parts.append(f"{len(change['in_binary_resolved'])} removed from binary")
    if change.get("workflow_new"):
        parts.append(f"{change['workflow_new']} new workflow findings")
    if change.get("scorecard"):
        parts.append(f"Scorecard {change['scorecard']['from']} → {change['scorecard']['to']}")
    if change.get("release_integrity"):
        parts.append(f"release {change['release_integrity']['from']} → {change['release_integrity']['to']}")
    return "; ".join(parts) or "no change"


class ReportSite:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.repository = args.repository
        self.out = args.output
        data = args.supply_chain_data
        self.runs: list[dict[str, Any]] = []
        self.projects: dict[str, dict[str, Any]] = {}
        if data and (data / "runs").is_dir():
            self.runs = [load_json(path) for path in sorted((data / "runs").glob("*.json"))]
            for path in sorted((data / "projects").glob("*.json")):
                stored = load_json(path)
                self.projects[stored["latest"]["repository"]] = stored
        self.latest = self.runs[-1] if self.runs else None

    def page(self, title: str, depth: int, body: str, description: str) -> str:
        root = "../" * depth
        repo = f"https://github.com/{self.repository}"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(description)}">
<link rel="stylesheet" href="{root}style.css">
</head>
<body>
<header>
<nav aria-label="Report"><a href="{root}index.html">All projects</a><a href="{root}history/index.html">History</a><a href="{root}data/index.json">Data</a><a href="{repo}">Repository</a></nav>
</header>
<main>
{body}
</main>
<footer>
<p>{esc(SCOPE_NOTE)}</p>
<p>{esc(VULNERABILITY_NOTE)}</p>
<p>Generated by <a href="{repo}/blob/main/.github/workflows/supply-chain-report.yml">the weekly supply-chain workflow</a> in <a href="{repo}">{esc(self.repository)}</a> with Syft, Grype, and sbomlyze. sbomlyze is developed by this repository's maintainer and is used for SBOM diffs and minimum-element checks.</p>
</footer>
</body>
</html>
"""

    def write(self, relative: str, content: str) -> None:
        target = self.out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def tools_line(self, run: dict[str, Any]) -> str:
        tools = run.get("tools") or {}
        parts = [f"Syft {tools.get('syft', '?')}", f"Grype {tools.get('grype', '?')}"]
        if tools.get("grype_db_built"):
            parts.append(f"vulnerability database built {str(tools['grype_db_built'])[:10]}")
        if tools.get("sbomlyze"):
            parts.append(str(tools["sbomlyze"]))
        return " · ".join(esc(part) for part in parts)

    # ----- overview ----------------------------------------------------------------------
    def project_table(self, entries: list[dict[str, Any]], depth: int) -> str:
        root = "../" * depth
        rows = []
        for entry in entries:
            vulns = entry.get("vulnerabilities")
            counts = "".join(f"<td class=\"num\">{pill(s, (vulns or {}).get(s, 0))}</td>" for s in SHOWN_SEVERITIES) if vulns else (
                '<td colspan="4" class="small">not scanned</td>'
            )
            fixable = entry.get("fixable")
            change = (self.projects.get(entry["repository"]) or {}).get("latest", {}).get("changes") if depth == 0 else None
            summary = change_summary(change) if change is not None else self.history_change_text(entry)
            ref = esc(entry.get("ref") or "—")
            if entry.get("ref_kind") == "default-branch":
                ref += ' <span class="small">(branch)</span>'
            status = ""
            if entry.get("errors"):
                status = ' <span class="bad" title="' + esc("; ".join(entry["errors"])) + '">scan error</span>'
            in_binary = entry.get("in_binary")
            binary = (f'<span class="{"bad" if in_binary["total"] else "ok"}" title="{esc(entry.get("go_version") or "")}">{in_binary["total"]}</span>'
                      if in_binary else '<span class="zero">—</span>')
            workflow = entry.get("workflow")
            workflow_cell = (pill("High", workflow["High"]) if workflow and workflow["High"] else
                             ('<span class="pill zero">0</span>' if workflow else '<span class="zero">—</span>'))
            score = entry.get("scorecard")
            score_cell = f"{score:.1f}" if isinstance(score, (int, float)) else '<span class="zero">—</span>'
            rows.append(
                f"<tr class=\"{'changed' if entry.get('change_any') else ''}\">"
                f"<td><a href=\"{root}{project_path(entry['repository'])}index.html\">{esc(entry.get('name') or entry['repository'])}</a>"
                f"<div class=\"small\">{esc(entry.get('category') or '')}</div></td>"
                f"<td>{ref}{status}</td>"
                f"<td class=\"num\">{entry['dependencies'] if entry.get('dependencies') is not None else '—'}</td>"
                f"{counts}<td class=\"num\">{fixable if fixable is not None else '—'}</td>"
                f"<td class=\"num\">{binary}</td><td class=\"num\">{score_cell}</td><td class=\"num\">{workflow_cell}</td>"
                f"<td class=\"small\">{sections.verdict_cell(entry.get('release_integrity'))}</td>"
                f"<td class=\"change\">{esc(summary)}</td></tr>"
            )
        return (
            '<div class="scroll"><table><thead><tr><th>Project</th><th>Version scanned</th>'
            '<th class="num">Dependencies</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th>'
            '<th class="num">Low</th><th class="num" title="Advisories with a fixed version available">Fixable</th>'
            '<th class="num" title="Go tools: advisories with vulnerable functions compiled into the released binary (govulncheck)">In binary</th>'
            '<th class="num" title="OpenSSF Scorecard, 0 to 10">Scorecard</th>'
            '<th class="num" title="High-severity GitHub Actions workflow findings (zizmor)">Workflow</th>'
            '<th title="Release signature, provenance, or attestation verified">Release</th>'
            '<th>Change since last week</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>"
            + '<p class="small"><strong>In binary</strong>: Go tools only, advisories whose vulnerable functions are compiled into the '
            "released Linux binary. <strong>Scorecard</strong>: OpenSSF repository practices out of 10. <strong>Workflow</strong>: high-severity "
            "GitHub Actions findings from zizmor. <strong>Release</strong>: whether the Linux release file's signature, SLSA provenance, or "
            "GitHub attestation verifies against the project's own workflows.</p>"
        )

    @staticmethod
    def history_change_text(entry: dict[str, Any]) -> str:
        parts = []
        if entry.get("release_changed"):
            parts.append("new release")
        for key, label in (("added", "added"), ("removed", "removed"), ("upgraded", "upgraded"),
                           ("new_vulnerabilities", "new advisories"), ("resolved_vulnerabilities", "resolved")):
            if entry.get(key):
                parts.append(f"{entry[key]} {label}")
        return "; ".join(parts) or "no change"

    def this_week(self) -> str:
        latest = [stored["latest"] for stored in self.projects.values()]
        releases, new_vulns, resolved, deps, drift, failed = [], [], [], [], [], []
        binary, workflows, scores, integrity = [], [], [], []
        for project in sorted(latest, key=lambda item: item["repository"].lower()):
            change = project.get("changes") or {}
            link = f'<a href="{project_path(project["repository"])}index.html">{esc(project.get("name") or project["repository"])}</a>'
            if change.get("scan_failed") or project.get("errors"):
                failed.append(f"{link}: {esc('; '.join(project.get('errors') or []))}")
            if change.get("baseline"):
                continue
            if change.get("release_changed"):
                releases.append(f"{link} {esc(change.get('previous_ref'))} → {esc(project.get('ref'))}")
            for item in change.get("new_vulnerabilities") or []:
                new_vulns.append((SEVERITIES.index(item["severity"]) if item["severity"] in SEVERITIES else 99,
                                  f"{link}: {badge(item['severity'], item['severity'][0])} "
                                  f"<code>{esc(item['id'])}</code> in <code>{esc(item['package'])}@{esc(item['version'])}</code>"))
            if change.get("resolved_vulnerabilities"):
                resolved.append(f"{link}: {len(change['resolved_vulnerabilities'])}")
            count = len(change.get("added") or []) + len(change.get("removed") or []) + len(change.get("upgraded") or [])
            if count:
                deps.append(f"{link}: +{len(change.get('added') or [])} / −{len(change.get('removed') or [])} / ↑{len(change.get('upgraded') or [])}")
            if change.get("integrity_drift"):
                drift.append(f"{link}: {change['integrity_drift']}")
            if change.get("in_binary_new") or change.get("in_binary_resolved"):
                binary.append(f"{link}: +{len(change.get('in_binary_new') or [])} / −{len(change.get('in_binary_resolved') or [])}")
            if change.get("workflow_new") or change.get("workflow_resolved"):
                workflows.append(f"{link}: +{change.get('workflow_new', 0)} / −{change.get('workflow_resolved', 0)}")
            if change.get("scorecard"):
                scores.append(f"{link}: {change['scorecard']['from']} → {change['scorecard']['to']}")
            if change.get("release_integrity"):
                integrity.append(f"{link}: {esc(change['release_integrity']['from'])} → {esc(change['release_integrity']['to'])}")
        if all(not item.get("changes") or item["changes"].get("baseline") for item in latest):
            return ('<h2 id="this-week">This week</h2><p>This is the first weekly scan, so there is nothing to compare yet. '
                    "From next week this section lists new releases, dependency changes, new and resolved advisories, changes in "
                    "released binaries, release verification, Scorecard, and workflow findings, and drift.</p>"
                    + (f"<h3>Scan problems</h3><ul>{''.join(f'<li>{item}</li>' for item in failed)}</ul>" if failed else ""))
        new_vulns.sort(key=lambda pair: pair[0])
        groups = [
            ("New releases", releases), ("New advisories", [text for _, text in new_vulns]),
            ("Resolved advisories", resolved), ("Dependency changes (+added / −removed / ↑upgraded)", deps),
            ("Vulnerable functions in released binaries (+new / −removed)", binary),
            ("Release verification changed", integrity), ("OpenSSF Scorecard changed", scores),
            ("Workflow findings (+new / −resolved)", workflows),
            ("Hash changed without a version change (sbomlyze integrity drift)", drift), ("Scan problems", failed),
        ]
        parts = ['<h2 id="this-week">This week</h2>']
        for title, items in groups:
            if not items:
                continue
            shown = items[:40]
            more = f"<li>… and {len(items) - 40} more</li>" if len(items) > 40 else ""
            parts.append(f"<h3>{esc(title)} ({len(items)})</h3><ul>{''.join(f'<li>{item}</li>' for item in shown)}{more}</ul>")
        if len(parts) == 1:
            parts.append("<p>No project changed this week.</p>")
        return "\n".join(parts)

    def overview(self) -> None:
        if not self.latest:
            body = "<h1>Weekly supply-chain report</h1><p>No scans have been recorded yet.</p>"
        else:
            run = self.latest
            entries = run["projects"]
            totals = {s: sum((item.get("vulnerabilities") or {}).get(s, 0) for item in entries) for s in SHOWN_SEVERITIES}
            with_findings = sum(1 for item in entries if any((item.get("vulnerabilities") or {}).get(s) for s in ("Critical", "High")))
            go_tools = [item for item in entries if item.get("in_binary")]
            go_vulnerable = sum(1 for item in go_tools if item["in_binary"]["total"])
            with_assets = [item for item in entries if item.get("release_integrity") not in (None, "no-assets", "no-linux-binary")]
            verified = sum(1 for item in with_assets if item.get("release_integrity") == "verified")
            scores = sorted(item["scorecard"] for item in entries if isinstance(item.get("scorecard"), (int, float)))
            median = scores[len(scores) // 2] if scores else None
            body = (
                "<h1>Weekly supply-chain report for open-source security tools</h1>"
                f'<p class="lede">Every week, each of the {len(entries)} active tools in the '
                f'<a href="https://github.com/{esc(self.repository)}">Awesome Security Pipeline</a> catalog is scanned at its latest release: '
                "its dependencies and known vulnerabilities, which vulnerable code actually ships in its binary, whether the release can be "
                "verified, how its repository and CI are secured, and what changed since the previous week.</p>"
                f'<p class="meta">Week of {esc(run["date"])} · <a href="#how-it-works">How this report is made</a> · '
                f'<a href="data/runs/{esc(run["date"])}.json">JSON</a></p>'
                '<div class="cards">'
                f'<div class="card"><div class="big">{len(entries)}</div><div class="small">projects scanned, {sum(item.get("dependencies") or 0 for item in entries)} declared dependencies</div></div>'
                f'<div class="card"><div class="big">{totals["Critical"]} / {totals["High"]}</div><div class="small">critical / high advisories matched in {with_findings} projects</div></div>'
                f'<div class="card"><div class="big">{go_vulnerable} / {len(go_tools)}</div><div class="small">Go tools ship vulnerable functions in their release binary</div></div>'
                f'<div class="card"><div class="big">{verified} / {len(with_assets)}</div><div class="small">Linux releases verifiable by signature, provenance, or attestation</div></div>'
                f'<div class="card"><div class="big">{median if median is not None else "—"}</div><div class="small">median OpenSSF Scorecard ({len(scores)} scored)</div></div>'
                "</div>"
                + self.this_week()
                + '<h2 id="projects">All projects</h2>'
                + f'<p class="small">{esc(VULNERABILITY_NOTE)} Rows marked on the left changed since last week. Select a project for its full inventory, advisories, and history.</p>'
                + self.project_table(entries, depth=0)
                + sections.pipeline_section(run.get("tools") or {}, len(entries))
            )
        self.write("index.html", self.page(
            "Weekly supply-chain report for open-source security tools", 0, body,
            "Weekly SBOMs, known-vulnerability matches, and dependency drift for every tool in the Awesome Security Pipeline catalog.",
        ))

    # ----- project pages ------------------------------------------------------------------
    def project_page(self, repository: str, stored: dict[str, Any]) -> None:
        project = stored["latest"]
        depth = 3
        root = "../" * depth
        change = project.get("changes") or {}
        vulns = project.get("vulnerabilities")
        components = project.get("components") or []
        counts = severity_counts(vulns) if vulns is not None else None
        fixable = sum(1 for item in vulns or [] if item.get("fixed_in"))
        ref = project.get("ref") or "—"
        ref_link = (
            f'<a href="https://github.com/{esc(repository)}/releases/tag/{esc(ref)}">{esc(ref)}</a>'
            if project.get("ref_kind") == "release" else f"{esc(ref)} (default branch; no releases published)"
        )
        parts = [
            f"<h1>{esc(project.get('name') or repository)}</h1>",
            f'<p class="lede">{esc(project.get("description") or "")}</p>',
            f'<p class="meta"><a href="https://github.com/{esc(repository)}">{esc(repository)}</a> · {esc(project.get("category") or "")} · '
            f"scanned {ref_link}"
            + (f" (released {esc(str(project.get('released_at'))[:10])})" if project.get("released_at") else "")
            + (f" · commit <code>{esc(str(project.get('commit'))[:12])}</code>" if project.get("commit") else "")
            + f" · last scan {esc(str(project.get('scanned_at') or '')[:10])}</p>",
        ]
        if project.get("errors"):
            parts.append('<div class="banner"><strong class="bad">The latest scan failed.</strong> '
                         + esc("; ".join(project["errors"]))
                         + (" Showing the last successful scan." if project.get("stale") else "") + "</div>")
        cards = [
            f'<div class="card"><div class="big">{len(components)}</div><div class="small">declared dependencies</div></div>',
            f'<div class="card"><div class="big">{(counts or {}).get("Critical", 0)} / {(counts or {}).get("High", 0)}</div><div class="small">critical / high advisories</div></div>'
            if counts is not None else '<div class="card"><div class="big">—</div><div class="small">vulnerability scan unavailable</div></div>',
            f'<div class="card"><div class="big">{fixable}</div><div class="small">advisories with a fixed version</div></div>',
        ]
        go = project.get("go_binary")
        if go:
            symbols = sum(1 for item in go["findings"] if item["level"] == "symbol")
            cards.append(f'<div class="card"><div class="big">{symbols}</div><div class="small">advisories with vulnerable code in the {esc(go["go_version"])} binary</div></div>')
        card = project.get("scorecard") or {}
        cards.append(f'<div class="card"><div class="big">{esc(card.get("score", "—"))}</div><div class="small">OpenSSF Scorecard (of 10)</div></div>')
        cards.append(f'<div class="card"><div class="big">{sections.verdict_cell((project.get("release_integrity") or {}).get("verdict"))}</div><div class="small">release verification</div></div>')
        parts.append(f'<div class="cards">{"".join(cards)}</div>')
        parts.append(self.project_changes(change))
        parts.append(self.project_vulnerabilities(vulns))
        parts.append(sections.osv_section(project.get("osv")))
        parts.append(sections.reachability_section(go, vulns, project.get("go_binary_note")))
        parts.append(sections.release_section(project.get("release_integrity"), repository))
        parts.append(sections.scorecard_section(project.get("scorecard"), project.get("scorecard_note"), repository))
        parts.append(sections.workflow_section(project.get("workflow_audit"), repository, project.get("ref") or "HEAD"))
        parts.append(self.project_dependencies(components))
        parts.append(self.project_history(stored.get("history") or []))
        parts.append(self.project_compliance(project.get("compliance") or {}))
        downloads = []
        directory = self.out / project_path(repository)
        for name, label in (("sbom.cdx.json", "CycloneDX SBOM"), ("grype.json", "Grype report"), ("sbomlyze-diff.html", "sbomlyze diff from last week")):
            if (directory / name).is_file():
                downloads.append(f'<a href="{name}">{label}</a>')
        manifests = project.get("manifests") or []
        parts.append(
            '<h2 id="evidence">Evidence</h2>'
            + (f"<p>Downloads for this week: {' · '.join(downloads)}</p>" if downloads else "")
            + f"<details><summary>{len(manifests)} manifests and lockfiles scanned</summary><p>"
            + ", ".join(f"<code>{esc(path)}</code>" for path in manifests) + "</p></details>"
            + f'<p class="small"><a href="{root}data/projects/{esc(project["id"])}.json">Full JSON for this project</a></p>'
        )
        parts.append(sections.pipeline_section((self.latest or {}).get("tools") or {}, len((self.latest or {}).get("projects") or [])))
        self.write(f"{project_path(repository)}index.html", self.page(
            f"{project.get('name') or repository} supply-chain report", depth, "\n".join(parts),
            f"Weekly SBOM, known vulnerabilities, and dependency history for {repository}.",
        ))

    @staticmethod
    def project_changes(change: dict[str, Any]) -> str:
        if not change or change.get("baseline"):
            return '<h2 id="changes">Changes since last week</h2><p>First scan; changes appear from next week.</p>'
        if change.get("scan_failed"):
            return '<h2 id="changes">Changes since last week</h2><p>The scan failed this week, so no comparison was made.</p>'
        parts = ['<h2 id="changes">Changes since last week</h2>', f"<p>{esc(change_summary(change))}.</p>"]
        if change.get("upgraded"):
            rows = "".join(
                f"<tr><td><code>{esc(item['package'])}</code></td><td>{esc(item['ecosystem'])}</td><td><code>{esc(item['from'])}</code></td><td><code>{esc(item['to'])}</code></td></tr>"
                for item in change["upgraded"]
            )
            parts.append(f"<h3>Version changes ({len(change['upgraded'])})</h3><div class=\"scroll\"><table><thead><tr><th>Package</th><th>Ecosystem</th><th>From</th><th>To</th></tr></thead><tbody>{rows}</tbody></table></div>")
        for key, title in (("added", "Added"), ("removed", "Removed")):
            if change.get(key):
                parts.append(f"<h3>{title} ({len(change[key])})</h3><p>" + ", ".join(f"<code>{esc(item)}</code>" for item in change[key]) + "</p>")
        for key, title in (("new_vulnerabilities", "New advisories"), ("resolved_vulnerabilities", "Resolved advisories")):
            if change.get(key):
                parts.append(f"<h3>{title} ({len(change[key])})</h3><ul>" + "".join(
                    f"<li>{badge(item['severity'], item['severity'][0])} <code>{esc(item['id'])}</code> in <code>{esc(item['package'])}@{esc(item['version'])}</code></li>"
                    for item in change[key]) + "</ul>")
        if change.get("license_changes"):
            parts.append("<h3>License changes</h3><ul>" + "".join(
                f"<li><code>{esc(item['package'])}</code>: {esc(', '.join(item['from']) or 'none')} → {esc(', '.join(item['to']) or 'none')}</li>"
                for item in change["license_changes"]) + "</ul>")
        if change.get("integrity_drift"):
            parts.append(f'<p class="warn">sbomlyze found {change["integrity_drift"]} component(s) whose hash changed without a version change. '
                         "Review the sbomlyze diff below.</p>")
        return "\n".join(parts)

    @staticmethod
    def project_vulnerabilities(vulns: list[dict[str, Any]] | None) -> str:
        if vulns is None:
            return '<h2 id="vulnerabilities">Known vulnerabilities</h2><p>The vulnerability scan did not complete this week.</p>'
        if not vulns:
            return '<h2 id="vulnerabilities">Known vulnerabilities</h2><p class="ok">No known advisories matched the declared dependencies.</p>'
        rows = []
        for item in vulns:
            link = f'<a href="{esc(item["url"])}">{esc(item["id"])}</a>' if item.get("url") else esc(item["id"])
            aliases = f'<div class="small">{esc(", ".join(item["aliases"]))}</div>' if item.get("aliases") else ""
            fixed = esc(", ".join(item.get("fixed_in") or [])) or '<span class="small">no fix listed</span>'
            osv = '<span class="ok" title="Also reported by OSV-Scanner">✓</span>' if item.get("osv_confirmed") else '<span class="zero">—</span>'
            shipped = item.get("in_binary")
            shipped_cell = (f'<span class="{"bad" if shipped in ("vulnerable code in binary", "package in binary") else "zero"}">{esc(shipped)}</span>'
                            if shipped else '<span class="zero">—</span>')
            rows.append(
                f"<tr><td>{badge(item['severity'])}</td><td>{link}{aliases}</td>"
                f"<td><code>{esc(item['package'])}</code><div class=\"small\">{esc(item['ecosystem'])}</div></td><td><code>{esc(item['version'])}</code></td>"
                f"<td>{fixed}</td><td class=\"num\">{osv}</td><td class=\"small\">{shipped_cell}</td>"
                f"<td class=\"small\"><code>{esc(item.get('location') or '')}</code></td></tr>"
            )
        return (
            f'<h2 id="vulnerabilities">Known vulnerabilities ({len(vulns)})</h2>'
            f'<p class="small">{esc(VULNERABILITY_NOTE)} <strong>OSV</strong>: also reported by OSV-Scanner. '
            "<strong>Released binary</strong>: for Go tools, whether govulncheck found the vulnerable code in the shipped Linux binary.</p>"
            '<div class="scroll"><table><thead><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Version</th><th>Fixed in</th>'
            '<th>OSV</th><th>Released binary</th><th>Declared in</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>"
        )

    @staticmethod
    def project_dependencies(components: list[dict[str, Any]]) -> str:
        if not components:
            return '<h2 id="dependencies">Dependencies</h2><p>No dependencies were found in the scanned manifests.</p>'
        groups: dict[str, list[dict[str, Any]]] = {}
        for item in components:
            groups.setdefault(item["ecosystem"], []).append(item)
        licenses: dict[str, int] = {}
        for item in components:
            for name in item.get("licenses") or ["unknown"]:
                licenses[name] = licenses.get(name, 0) + 1
        parts = [
            f'<h2 id="dependencies">Dependencies ({len(components)})</h2>',
            "<p>By ecosystem: " + ", ".join(f"{esc(name)} {len(items)}" for name, items in sorted(groups.items(), key=lambda kv: -len(kv[1]))) + ".</p>",
            '<p class="small">Licenses (as declared in the SBOM): ' + ", ".join(
                f"{esc(name)} {count}" for name, count in sorted(licenses.items(), key=lambda kv: -kv[1])[:15]) + ".</p>",
        ]
        for name, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            rows = "".join(
                f"<tr><td><code>{esc(item['name'])}</code></td><td><code>{esc(item['version'] or '—')}</code></td>"
                f"<td class=\"small\">{esc(', '.join(item.get('licenses') or []))}</td><td class=\"small\"><code>{esc(item.get('location') or '')}</code></td></tr>"
                for item in items
            )
            parts.append(
                f"<details><summary>{esc(name)} ({len(items)})</summary><div class=\"scroll\"><table><thead><tr><th>Name</th><th>Version</th><th>License</th><th>Declared in</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></div></details>"
            )
        return "\n".join(parts)

    @staticmethod
    def project_history(history: list[dict[str, Any]]) -> str:
        rows = []
        for item in reversed(history):
            vulns = item.get("vulnerabilities")
            counts = "".join(f"<td class=\"num\">{pill(s, (vulns or {}).get(s, 0))}</td>" for s in SHOWN_SEVERITIES) if vulns else '<td colspan="4">—</td>'
            changes = []
            if item.get("release_changed"):
                changes.append("new release")
            for key, label in (("added", "+"), ("removed", "−"), ("upgraded", "↑")):
                if item.get(key):
                    changes.append(f"{label}{item[key]}")
            if item.get("new_vulnerabilities"):
                changes.append(f"{item['new_vulnerabilities']} new advisories")
            if item.get("resolved_vulnerabilities"):
                changes.append(f"{item['resolved_vulnerabilities']} resolved")
            if item.get("errors"):
                changes.append("scan error")
            rows.append(
                f"<tr><td><a href=\"../../../history/{esc(item['date'])}/index.html\">{esc(item['date'])}</a></td><td>{esc(item.get('ref') or '—')}</td>"
                f"<td class=\"num\">{item['dependencies'] if item.get('dependencies') is not None else '—'}</td>{counts}<td>{esc(' · '.join(changes) or '—')}</td></tr>"
            )
        return (
            '<h2 id="history">History</h2>'
            '<div class="scroll"><table><thead><tr><th>Week</th><th>Version</th><th class="num">Dependencies</th><th class="num">Critical</th>'
            '<th class="num">High</th><th class="num">Medium</th><th class="num">Low</th><th>Changes</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>"
        )

    @staticmethod
    def project_compliance(compliance: dict[str, Any]) -> str:
        standards = compliance.get("standards") or {}
        if not standards:
            return ""
        rows = "".join(
            f"<tr><td>{esc(STANDARD_NAMES.get(key, key))}</td><td class=\"num\">{value.get('score')}</td><td class=\"num\">{value.get('passed')}/{value.get('total')}</td>"
            f"<td class=\"small\">{esc(', '.join(value.get('failed_checks') or []) or 'none')}</td></tr>"
            for key, value in ordered_standards(standards)
        )
        return (
            '<h2 id="minimum-elements">SBOM minimum elements</h2>'
            '<p class="small">Scored by sbomlyze on the generated source SBOM. A source SBOM usually lacks supplier and hash data, '
            "so these scores mostly reflect what the project's manifests declare.</p>"
            f'<table><thead><tr><th>Standard</th><th class="num">Score</th><th class="num">Checks passed</th><th>Failed checks</th></tr></thead><tbody>{rows}</tbody></table>'
        )

    # ----- history ------------------------------------------------------------------------
    def history(self) -> None:
        rows = []
        for run in reversed(self.runs):
            entries = run["projects"]
            releases = sum(1 for item in entries if item.get("release_changed"))
            new = sum(item.get("new_vulnerabilities") or 0 for item in entries)
            resolved = sum(item.get("resolved_vulnerabilities") or 0 for item in entries)
            changed = sum(1 for item in entries if item.get("change_any"))
            rows.append(
                f"<tr><td><a href=\"{esc(run['date'])}/index.html\">{esc(run['date'])}</a></td><td class=\"num\">{len(entries)}</td>"
                f"<td class=\"num\">{changed}</td><td class=\"num\">{releases}</td><td class=\"num\">{new}</td><td class=\"num\">{resolved}</td>"
                f"<td><a href=\"../data/runs/{esc(run['date'])}.json\">JSON</a></td></tr>"
            )
            body = (
                f"<h1>Supply-chain report: week of {esc(run['date'])}</h1>"
                f'<p class="meta">{self.tools_line(run)} · <a href="../../data/runs/{esc(run["date"])}.json">JSON</a></p>'
                + self.project_table(entries, depth=2)
            )
            self.write(f"history/{run['date']}/index.html", self.page(
                f"Supply-chain report {run['date']}", 2, body, f"Supply-chain scan of security tools for the week of {run['date']}."))
        body = (
            "<h1>Weekly history</h1>"
            '<div class="scroll"><table><thead><tr><th>Week</th><th class="num">Projects</th><th class="num">Changed</th>'
            '<th class="num">New releases</th><th class="num">New advisories</th><th class="num">Resolved</th><th>Data</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>"
        )
        self.write("history/index.html", self.page("Supply-chain report history", 1, body, "Weekly history of the supply-chain report."))

    # ----- assets -------------------------------------------------------------------------
    def assets(self) -> None:
        self.write("style.css", STYLE.strip() + "\n" + EXTRA_STYLE.strip() + "\n" + sections.PIPELINE_STYLE.strip() + "\n")
        (self.out / ".nojekyll").write_text("", encoding="utf-8")
        data = self.args.supply_chain_data
        if data and data.is_dir():
            for sub in ("runs", "projects"):
                if (data / sub).is_dir():
                    shutil.copytree(data / sub, self.out / "data" / sub, dirs_exist_ok=True)
            if (data / "index.json").is_file():
                shutil.copyfile(data / "index.json", self.out / "data" / "index.json")
        artifacts = self.args.supply_chain_artifacts
        if artifacts and artifacts.is_dir():
            for summary in artifacts.glob("**/summary.json"):
                repository = load_json(summary).get("repository")
                if not repository or repository not in self.projects:
                    continue
                target = self.out / project_path(repository)
                target.mkdir(parents=True, exist_ok=True)
                for name in ("sbom.cdx.json", "grype.json", "sbomlyze-diff.html"):
                    if (summary.parent / name).is_file():
                        shutil.copyfile(summary.parent / name, target / name)

    def build(self) -> None:
        self.assets()
        self.overview()
        for repository, stored in self.projects.items():
            self.project_page(repository, stored)
        self.history()


def main() -> int:
    args = parse_args()
    if args.output.exists():
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True)
    ReportSite(args).build()
    print(f"Site written to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"site build failed: {exc}", file=sys.stderr)
        sys.exit(1)
