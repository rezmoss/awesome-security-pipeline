#!/usr/bin/env python3
"""Build the GitHub Pages site for the weekly supply-chain report.

Pages: an overview table of every catalog project, one page per project with full details
and history, one page per matched advisory, a page per week, how to verify the data, and every
manual correction. Also writes CSV exports, Atom feeds, and shields.io badge endpoints.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import shutil
import sys
import urllib.parse
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import catalog  # noqa: E402
from scripts import site_exports as exports  # noqa: E402
from scripts import site_sections as sections  # noqa: E402
from scripts.supply_chain_scan import CHECKSUMS_FILE, SEVERITIES, WORKFLOW_PATH, severity_counts  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Grype's Negligible is shown with Unknown so that every match is counted in exactly one column.
SHOWN_SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
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
CONTEXT_NOTE = (
    "KEV: listed in the CISA Known Exploited Vulnerabilities catalog. EPSS: FIRST's estimated probability of "
    "exploitation in the next 30 days. Both describe the vulnerability in general, not its exploitability through "
    "this tool; a match in a workflow file refers to a GitHub Action, not to shipped code."
)
NO_FIX = '<span class="small">no fix listed</span>'
ZERO = '<span class="zero">0</span>'
SCOPE_NOTE = (
    "Each project is scanned at its latest GitHub release tag (or its default branch when it publishes no "
    "releases). Only dependency manifests and lockfiles are fetched; test, fixture, example, documentation, "
    "and vendored directories are excluded because security tools ship deliberately vulnerable fixtures."
)
EXTRA_STYLE = """
.sev-Critical{color:#fff;background:#a40e26}.sev-High{color:#fff;background:#cf222e}.sev-Medium{color:#1f2328;background:#f2cc60}.sev-Low{color:#1f2328;background:#d1d9e0}
.pill{display:inline-block;min-width:1.8em;padding:0 6px;border-radius:10px;text-align:center;font-size:13px;font-weight:600}
.zero{color:var(--muted)}td.change{font-size:14px;min-width:180px}tr.changed td:first-child{border-left:3px solid var(--warn)}
header,main,footer{max-width:1600px}
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
    parser.add_argument("--site-url", help="public base URL for feeds and badges (default: the repository's GitHub Pages URL)")
    parser.add_argument("--supply-chain-data", type=pathlib.Path)
    parser.add_argument("--supply-chain-artifacts", type=pathlib.Path, help="scan shard output for the latest week")
    parser.add_argument("--tools", type=pathlib.Path, default=ROOT / "tools")
    parser.add_argument("--tag-patterns", type=pathlib.Path, default=ROOT / "benchmarks/supply-chain/release-tags.json")
    parser.add_argument("--corrections", type=pathlib.Path, default=ROOT / "benchmarks/supply-chain/corrections.json")
    return parser.parse_args()


def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def project_path(repository: str) -> str:
    return f"projects/{repository}/"


def anchor(*parts: Any) -> str:
    """A stable fragment id, for example adv-ghsa-xxxx-golang-org-x-net."""
    return re.sub(r"[^a-z0-9]+", "-", "-".join(str(part) for part in parts).lower()).strip("-")


def pill(severity: str, count: int) -> str:
    if not count:
        return '<span class="pill zero">0</span>'
    return f'<span class="pill sev-{esc(severity)}" title="{esc(severity)}">{count}</span>'


def badge(severity: str, text: str | None = None) -> str:
    severity = severity if severity in SHOWN_SEVERITIES else "Unknown"
    return f'<span class="pill sev-{esc(severity)}">{esc(text or severity)}</span>'


def shown_counts(counts: dict[str, int] | None) -> dict[str, int]:
    counts = counts or {}
    shown = {level: counts.get(level, 0) for level in SHOWN_SEVERITIES}
    shown["Unknown"] += counts.get("Negligible", 0)
    return shown


def count_cells(counts: dict[str, int]) -> str:
    return "".join(f"<td class=\"num\">{pill(level, value)}</td>" for level, value in shown_counts(counts).items())


def kev_cell(item: dict[str, Any]) -> str:
    if "kev" not in item:
        return '<span class="zero" title="not checked this week">—</span>'
    kev = item["kev"]
    if not kev:
        return '<span class="zero">no</span>'
    return f'<span class="pill kev" title="{esc(kev.get("cve"))} added to CISA KEV {esc(kev.get("date_added"))}">KEV</span>'


def epss_text(epss: dict[str, Any] | None) -> str:
    if not epss:
        return "—"
    return f"{epss['score'] * 100:.1f}%"


def epss_cell(item: dict[str, Any]) -> str:
    epss = item.get("epss")
    if not epss:
        return '<td class="num" data-sort="-1"><span class="zero">—</span></td>'
    return (f'<td class="num" data-sort="{epss["score"]}" title="{esc(epss.get("cve"))}: percentile '
            f'{epss["percentile"] * 100:.0f}">{epss_text(epss)}</td>')


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
    if change.get("kev_new"):
        parts.append(f"{len(change['kev_new'])} newly in CISA KEV")
    return "; ".join(parts) or "no change"


SCORECARD_SOURCES = {"openssf-api": ("", "OpenSSF public dataset"), "scorecard-cli": ("*", "Scorecard CLI run by this workflow"),
                     "carried-forward": ("†", "carried forward from an earlier week")}


def advisory_anchor(item: dict[str, Any]) -> str:
    return anchor("adv", item["id"], item["package"], item.get("version", ""))


def scorecard_cell(entry: dict[str, Any]) -> str:
    score = entry.get("scorecard")
    if not isinstance(score, (int, float)):
        reason = entry.get("scorecard_note") or "no Scorecard result recorded"
        return f'<span class="zero" title="{esc(reason)}">—</span>'
    marker, label = SCORECARD_SOURCES.get(entry.get("scorecard_source") or "", ("", "source not recorded"))
    title = label + (f", assessed {entry['scorecard_date']}" if entry.get("scorecard_date") else "")
    return f'<span title="{esc(title)}">{score:.1f}{marker}</span>'


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
        self.index = load_json(data / "index.json") if data and (data / "index.json").is_file() else {}
        owner, _, name = self.repository.partition("/")
        self.site_url = (args.site_url or f"https://{owner.lower()}.github.io/{name}/").rstrip("/") + "/"
        self.corrections = load_json(args.corrections) if args.corrections.is_file() else {}
        self.disputes = {
            exports.dispute_key(entry["repository"], entry["advisory"], entry.get("package", "")): entry
            for entry in self.corrections.get("disputes") or []
        }
        latest_projects = [stored["latest"] for stored in self.projects.values()]
        self.advisories, self.aliases = exports.group_advisories(latest_projects)
        self.superseded = {
            path.relative_to(data).as_posix(): load_json(path) for path in sorted((data / "runs" / "superseded").glob("*/*.json"))
        } if data and (data / "runs" / "superseded").is_dir() else {}

    def provenance_line(self, run: dict[str, Any] | None, root: str) -> str:
        if not run:
            return ""
        repo = f"https://github.com/{self.repository}"
        info = (run.get("provenance") or {}).get("run") or {}
        commit = str(run.get("commit") or info.get("commit") or "")
        commit_link = (f'<a href="{repo}/tree/{esc(commit)}"><code>{esc(commit[:7])}</code></a>'
                       if re.fullmatch(r"[0-9a-f]{40}", commit) else esc(commit or "unknown"))
        if info.get("id"):
            produced = (f'Data for {esc(run["date"])} produced by <a href="{esc(info["url"])}">run #{esc(info["id"])}</a> '
                        f"(attempt {esc(info.get('attempt', 1))}, {esc(info.get('event'))}) of "
                        f'<a href="{repo}/blob/{esc(commit)}/{WORKFLOW_PATH}">the workflow</a> at commit {commit_link}')
        else:
            produced = (f"Data for {esc(run['date'])} produced at commit {commit_link}; this week predates "
                        "run-level provenance, which is recorded from 2026-11-08")
        return (f'<p>{produced}, generated {esc(str(run.get("generated_at") or "")[:16].replace("T", " "))} UTC. '
                f'<a href="{root}verify/index.html">Verify the data</a> · <a href="{root}corrections/index.html">Corrections</a></p>')

    def page(self, title: str, depth: int, body: str, description: str, run: dict[str, Any] | None = None,
             feed: str | None = None, index: bool = True) -> str:
        root = "../" * depth
        repo = f"https://github.com/{self.repository}"
        provenance = self.provenance_line(run or self.latest, root)
        head = "" if index else '<meta name="robots" content="noindex">\n'
        head += f'<link rel="alternate" type="application/atom+xml" title="{esc(title)}" href="{esc(feed)}">\n' if feed else ""
        head += f'<link rel="alternate" type="application/atom+xml" title="Weekly supply-chain report" href="{root}feed.xml">\n' 
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(description)}">
<link rel="stylesheet" href="{root}style.css">
{head}</head>
<body>
<header>
<nav aria-label="Report"><a href="{root}index.html">All projects</a><a href="{root}advisories/index.html">Advisories</a><a href="{root}history/index.html">History</a><a href="{root}verify/index.html">Verify</a><a href="{root}corrections/index.html">Corrections</a><a href="{root}data/index.html">Data</a><a href="{root}feed.xml">Feed</a><a href="{repo}">Repository</a></nav>
</header>
<main>
{body}
</main>
<footer>
{provenance}
<p>{esc(SCOPE_NOTE)}</p>
<p>{esc(VULNERABILITY_NOTE)}</p>
<p>{esc(CONTEXT_NOTE)} KEV data: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA</a>. EPSS data: <a href="https://www.first.org/epss/">FIRST</a>.</p>
<p>Generated by <a href="{repo}/blob/main/.github/workflows/supply-chain-report.yml">the weekly supply-chain workflow</a> in <a href="{repo}">{esc(self.repository)}</a> with Syft, Grype, and sbomlyze. sbomlyze is developed by this repository's maintainer and is used for SBOM diffs and minimum-element checks.</p>
</footer>
<script src="{root}report.js" defer></script>
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
    def project_extras(self, entry: dict[str, Any], depth: int) -> tuple[Any, Any]:
        """Vulnerable-package and KEV counts; weeks recorded before these fields fall back to the project file."""
        packages, kev = entry.get("vulnerable_packages"), entry.get("kev")
        project = (self.projects.get(entry["repository"]) or {}).get("latest") or {}
        vulns = project.get("vulnerabilities")
        if depth == 0 and vulns is not None:
            if packages is None:
                packages = len({(item["package"], item["version"]) for item in vulns})
            if kev is None and any("kev" in item for item in vulns):
                kev = sum(1 for item in vulns if item.get("kev"))
        return packages, kev

    def project_table(self, entries: list[dict[str, Any]], depth: int) -> str:
        root = "../" * depth
        rows = []
        for entry in entries:
            vulns = entry.get("vulnerabilities")
            columns = len(SHOWN_SEVERITIES)
            if not vulns:
                counts = f'<td colspan="{columns}" class="small">not scanned</td>'
            elif entry.get("dependencies") == 0:
                # Zero matches against zero dependencies is not a clean result.
                counts = f'<td colspan="{columns}" class="small">no dependencies found to match</td>'
            else:
                counts = count_cells(vulns)
            fixable = entry.get("fixable")
            packages, kev = self.project_extras(entry, depth)
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
            score_cell = scorecard_cell(entry)
            score = entry.get("scorecard")
            flags = "".join(f" data-{name}" for name, on in (
                ("changed", entry.get("change_any")), ("binary", in_binary and in_binary["total"]), ("kev", kev),
                ("critical", vulns and (vulns.get("Critical") or vulns.get("High")))) if on)
            kev_text = (f'<span class="pill kev" title="matches in CISA KEV">{kev}</span>' if kev else
                        ('<span class="pill zero">0</span>' if kev is not None else '<span class="zero">—</span>'))
            rows.append(
                f"<tr id=\"{esc(anchor(entry['id']))}\" class=\"{'changed' if entry.get('change_any') else ''}\"{flags}>"
                f"<td data-sort=\"{esc((entry.get('name') or entry['repository']).lower())}\"><a href=\"{root}{project_path(entry['repository'])}index.html\">{esc(entry.get('name') or entry['repository'])}</a>"
                f"<div class=\"small\">{esc(entry.get('category') or '')}</div></td>"
                f"<td>{ref}{status}</td>"
                f"<td class=\"num\">{entry['dependencies'] if entry.get('dependencies') is not None else '—'}</td>"
                f"{counts}<td class=\"num\">{packages if packages is not None else '—'}</td>"
                f"<td class=\"num\">{fixable if fixable is not None else '—'}</td>"
                f"<td class=\"num\">{kev_text}</td>"
                f"<td class=\"num\">{binary}</td><td class=\"num\" data-sort=\"{score if isinstance(score, (int, float)) else -1}\">{score_cell}</td>"
                f"<td class=\"num\">{workflow_cell}</td>"
                f"<td class=\"small\">{sections.verdict_cell(entry.get('release_integrity'))}</td>"
                f"<td class=\"change\">{esc(summary)}</td></tr>"
            )
        table_id = "projects-table" if depth == 0 else "week-table"
        return (
            f'<div class="controls" data-controls="{table_id}" hidden><input type="search" placeholder="Filter projects" aria-label="Filter projects">'
            '<label><input type="checkbox" data-flag="changed"> changed this week</label>'
            '<label><input type="checkbox" data-flag="critical"> critical or high</label>'
            '<label><input type="checkbox" data-flag="kev"> in CISA KEV</label>'
            '<label><input type="checkbox" data-flag="binary"> vulnerable code in binary</label>'
            '<span class="count small"></span></div>'
            f'<div class="scroll"><table class="sortable" id="{table_id}"><thead><tr><th>Project</th><th>Version scanned</th>'
            '<th class="num">Dependencies</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th>'
            '<th class="num">Low</th><th class="num" title="Unknown or negligible severity">Unknown</th>'
            '<th class="num" title="Distinct package versions with at least one matched advisory">Vulnerable packages</th>'
            '<th class="num" title="Advisories with a fixed version available">Fixable</th>'
            '<th class="num" title="Matched advisories listed in the CISA Known Exploited Vulnerabilities catalog">KEV</th>'
            '<th class="num" title="Go tools: advisories with vulnerable functions compiled into the released binary (govulncheck)">In binary</th>'
            '<th class="num" title="OpenSSF Scorecard, 0 to 10">Scorecard</th>'
            '<th class="num" title="High-severity GitHub Actions workflow findings (zizmor)">Workflow</th>'
            '<th title="Release signature, provenance, or attestation verified">Release</th>'
            '<th data-nosort>Change since last week</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>"
            + '<p class="small"><strong>Critical … Unknown</strong>: advisory matches (one advisory can match several packages). '
            "<strong>Vulnerable packages</strong>: distinct package versions with a match, roughly the number of upgrades that clear "
            "the list. <strong>KEV</strong>: matches listed in the CISA Known Exploited Vulnerabilities catalog (— means not checked "
            "that week). <strong>In binary</strong>: Go tools only, advisories whose vulnerable functions are compiled into the "
            "released Linux binary. <strong>Scorecard</strong>: OpenSSF repository practices out of 10; * marks a score from the "
            "Scorecard CLI run by this workflow, † a score carried forward from an earlier week (hover for source and date, or for why "
            "a score is missing). <strong>Workflow</strong>: high-severity "
            "GitHub Actions findings from zizmor. <strong>Release</strong>: whether the Linux release file's signature, SLSA provenance, or "
            "GitHub attestation verifies against the project's own workflows. Select a column heading to sort.</p>"
        )

    @staticmethod
    def history_change_text(entry: dict[str, Any]) -> str:
        parts = []
        if entry.get("release_changed"):
            parts.append("new release")
        for key, label in (("added", "added"), ("removed", "removed"), ("upgraded", "upgraded"),
                           ("new_vulnerabilities", "new advisories"), ("resolved_vulnerabilities", "resolved"),
                           ("kev_new", "newly in CISA KEV")):
            if entry.get(key):
                parts.append(f"{entry[key]} {label}")
        return "; ".join(parts) or "no change"

    def this_week(self) -> str:
        latest = [stored["latest"] for stored in self.projects.values()]
        releases, new_vulns, resolved, deps, drift, failed = [], [], [], [], [], []
        binary, workflows, scores, integrity, kev = [], [], [], [], []
        for project in sorted(latest, key=lambda item: item["repository"].lower()):
            change = project.get("changes") or {}
            page = f'{project_path(project["repository"])}index.html'
            name = esc(project.get("name") or project["repository"])
            link = f'<a href="{page}#changes">{name}</a>'
            if change.get("scan_failed") or project.get("errors"):
                failed.append(f"{link}: {esc('; '.join(project.get('errors') or []))}")
            if change.get("baseline"):
                continue
            if change.get("release_changed"):
                releases.append(f"{link} {esc(change.get('previous_ref'))} → {esc(project.get('ref'))}")
            for item in change.get("new_vulnerabilities") or []:
                new_vulns.append((SEVERITIES.index(item["severity"]) if item["severity"] in SEVERITIES else 99,
                                  f"{link}: {badge(item['severity'], item['severity'][0])} "
                                  f"{self.advisory_link(item, 0)} "
                                  f"in <code>{esc(item['package'])}@{esc(item['version'])}</code>"))
            for item in change.get("kev_new") or []:
                kev.append(f"{link}: {self.advisory_link(item, 0)} ({esc((item.get('kev') or {}).get('cve'))}, added "
                           f"{esc((item.get('kev') or {}).get('date_added'))}) in <code>{esc(item['package'])}@{esc(item['version'])}</code>")
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
            ("Newly listed in CISA KEV", kev),
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
            totals = {s: sum(shown_counts(item.get("vulnerabilities"))[s] for item in entries) for s in SHOWN_SEVERITIES}
            with_findings = sum(1 for item in entries if any((item.get("vulnerabilities") or {}).get(s) for s in ("Critical", "High")))
            serious = [record for record in self.advisories.values() if record["severity"] in ("Critical", "High")]
            kev_checked = any(record["kev_checked"] for record in self.advisories.values())
            in_kev = [record for record in self.advisories.values() if record["kev"]]
            shipped = [record for record in self.advisories.values() if record["shipped"]]
            kev_card = (
                f'<div class="card"><div class="big">{len(in_kev)}</div><div class="small">matched advisories in the '
                f'<a href="advisories/index.html#kev">CISA KEV catalog</a>, {sum(1 for record in in_kev if record["shipped"])} of them '
                "with vulnerable code in a shipped binary</div></div>"
                if kev_checked else "")
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
                f'<a href="data/runs/{esc(run["date"])}.json">JSON</a> · <a href="data/projects.csv">CSV</a> · '
                '<a href="feed.xml">Atom feed</a></p>'
                '<div class="cards">'
                f'<div class="card"><div class="big">{len(entries)}</div><div class="small">projects scanned, {sum(item.get("dependencies") or 0 for item in entries)} declared dependencies</div></div>'
                f'<div class="card"><div class="big">{totals["Critical"]} / {totals["High"]}</div><div class="small">critical / high matches in {with_findings} projects '
                f'({len(serious)} distinct <a href="advisories/index.html">advisories</a>; {sum(totals.values())} matches of any severity)</div></div>'
                + kev_card +
                f'<div class="card"><div class="big">{len(shipped)}</div><div class="small">advisories with vulnerable code shipped in a release binary, '
                f"across {go_vulnerable} of {len(go_tools)} analyzed Go tools</div></div>"
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

    def evidence_release(self, run: dict[str, Any] | None) -> str:
        tag = (run or {}).get("evidence_release")
        if not tag:
            return ""
        return f'<a href="https://github.com/{esc(self.repository)}/releases/tag/{esc(tag)}">release <code>{esc(tag)}</code></a>'

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
        source = ("carried forward from " + str(card.get("date") or "an earlier week") if card.get("carried_forward")
                  else SCORECARD_SOURCES.get(card.get("source") or "", ("", ""))[1]) if card else "no result this week"
        cards.append(f'<div class="card"><div class="big">{esc(card.get("score", "—"))}</div><div class="small">OpenSSF Scorecard (of 10); {esc(source)}</div></div>')
        cards.append(f'<div class="card"><div class="big">{sections.verdict_cell((project.get("release_integrity") or {}).get("verdict"))}</div><div class="small">release verification</div></div>')
        parts.append(f'<div class="cards">{"".join(cards)}</div>')
        parts.append(self.project_changes(change))
        parts.append(self.project_vulnerabilities(project))
        parts.append(sections.osv_section(project.get("osv")))
        parts.append(sections.reachability_section(go, vulns, project.get("go_binary_note")))
        parts.append(sections.release_section(project.get("release_integrity"), repository))
        parts.append(sections.scorecard_section(project.get("scorecard"), project.get("scorecard_note"), repository))
        parts.append(sections.workflow_section(project.get("workflow_audit"), repository, project.get("ref") or "HEAD"))
        parts.append(self.project_dependencies(components))
        parts.append(self.project_history(stored.get("history") or [], project["id"]))
        parts.append(self.project_compliance(project.get("compliance") or {}))
        downloads = []
        directory = self.out / project_path(repository)
        for name, label in (("sbom.cdx.json", "CycloneDX SBOM"), ("grype.json", "Grype report"), ("sbomlyze-diff.html", "sbomlyze diff from last week")):
            if (directory / name).is_file():
                downloads.append(f'<a href="{name}">{label}</a>')
        manifests = project.get("manifests") or []
        release = self.evidence_release(self.latest)
        if project.get("stale"):
            permanent = ""
        elif release:
            permanent = (f"<p>Permanent copy of the raw SBOM, Grype, OSV-Scanner, and govulncheck output and release checks: "
                         f"{release}, folder <code>supply-chain-shard-*/{esc(project['id'])}/</code>.</p>")
        else:
            permanent = ('<p class="small">Raw evidence for this week is kept as a workflow artifact for 90 days; '
                         "permanent evidence releases start with the 2026-11-08 scan.</p>")
        parts.append(
            '<h2 id="evidence">Evidence</h2>'
            + (f"<p>Downloads for this week: {' · '.join(downloads)}</p>" if downloads else "")
            + permanent
            + f"<details><summary>{len(manifests)} manifests and lockfiles scanned</summary><p>"
            + ", ".join(f"<code>{esc(path)}</code>" for path in manifests) + "</p></details>"
            + f'<p class="small"><a href="{root}data/projects/{esc(project["id"])}.json">Full JSON for this project</a> · '
            '<a href="feed.xml">Atom feed of weekly changes</a></p>'
        )
        parts.append(self.project_badges(repository, project))
        parts.append(sections.pipeline_section((self.latest or {}).get("tools") or {}, len((self.latest or {}).get("projects") or [])))
        self.write(f"{project_path(repository)}index.html", self.page(
            f"{project.get('name') or repository} supply-chain report", depth, "\n".join(parts),
            f"Weekly SBOM, known vulnerabilities, and dependency history for {repository}.", feed="feed.xml",
        ))
        self.project_feed(repository, stored)

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

    def advisory_link(self, item: dict[str, Any], depth: int) -> str:
        key = self.aliases.get(item["id"])
        if not key:
            return f"<code>{esc(item['id'])}</code>"
        return f'<a href="{"../" * depth}{exports.advisory_path(key)}index.html"><code>{esc(item["id"])}</code></a>'

    def dispute_cell(self, project: dict[str, Any], item: dict[str, Any], depth: int) -> str:
        page = f"{self.site_url}{project_path(project['repository'])}index.html#{advisory_anchor(item)}"
        recorded = self.disputes.get(exports.dispute_key(project["repository"], item["id"], f"{item['package']}@{item['version']}")) \
            or self.disputes.get(exports.dispute_key(project["repository"], item["id"], ""))
        note = ""
        if recorded:
            note = (f'<div class="small warn"><a href="{"../" * depth}corrections/index.html#disputes">{esc(recorded.get("status", "disputed"))}</a>: '
                    f'{esc(recorded.get("summary", ""))}</div>')
        return (f'<td class="small"><a href="{esc(exports.dispute_url(self.repository, project, item, page))}" '
                f'title="Report that this match is wrong, not applicable, or fixed">Dispute</a>{note}</td>')

    def project_vulnerabilities(self, project: dict[str, Any], depth: int = 3) -> str:
        vulns = project.get("vulnerabilities")
        dependencies = len(project.get("components") or []) if project.get("components") is not None else None
        if vulns is None:
            return '<h2 id="vulnerabilities">Known vulnerabilities</h2><p>The vulnerability scan did not complete this week.</p>'
        if not vulns and dependencies == 0:
            return ('<h2 id="vulnerabilities">Known vulnerabilities</h2><p>No dependencies were found in the scanned manifests, '
                    "so there was nothing to match advisories against. This is not a clean result.</p>")
        if not vulns:
            return '<h2 id="vulnerabilities">Known vulnerabilities</h2><p class="ok">No known advisories matched the declared dependencies.</p>'
        rows = []
        order = {name: index for index, name in enumerate(SEVERITIES)}
        for item in vulns:
            source = f' <a class="small" href="{esc(item["url"])}" title="Upstream advisory">source</a>' if item.get("url") else ""
            aliases = f'<div class="small">{esc(", ".join(item["aliases"]))}</div>' if item.get("aliases") else ""
            fixed = esc(", ".join(item.get("fixed_in") or [])) or '<span class="small">no fix listed</span>'
            osv = '<span class="ok" title="Also reported by OSV-Scanner">✓</span>' if item.get("osv_confirmed") else '<span class="zero">—</span>'
            shipped = item.get("in_binary")
            shipped_cell = (f'<span class="{"bad" if shipped in ("vulnerable code in binary", "package in binary") else "zero"}">{esc(shipped)}</span>'
                            if shipped else '<span class="zero">—</span>')
            rows.append(
                f"<tr id=\"{esc(advisory_anchor(item))}\"{' data-kev' if item.get('kev') else ''}{' data-binary' if shipped == exports.SHIPPED else ''}>"
                f"<td data-sort=\"{order.get(item['severity'], 99)}\">{badge(item['severity'])}</td><td>{self.advisory_link(item, depth)}{source}{aliases}</td>"
                f"<td><code>{esc(item['package'])}</code><div class=\"small\">{esc(item['ecosystem'])}</div></td><td><code>{esc(item['version'])}</code></td>"
                f"<td>{fixed}</td><td class=\"num\">{osv}</td><td class=\"small\">{shipped_cell}</td>"
                f"<td class=\"num\">{kev_cell(item)}</td>{epss_cell(item)}"
                f"<td class=\"small\"><code>{esc(item.get('location') or '')}</code></td>{self.dispute_cell(project, item, depth)}</tr>"
            )
        return (
            f'<h2 id="vulnerabilities">Known vulnerabilities ({len(vulns)})</h2>'
            f'<p class="small">{esc(VULNERABILITY_NOTE)} <strong>OSV</strong>: also reported by OSV-Scanner. '
            "<strong>Released binary</strong>: for Go tools, whether govulncheck found the vulnerable code in the shipped Linux binary. "
            f"{esc(CONTEXT_NOTE)} Select an advisory for every catalog tool it matches. If a match is wrong or does not apply, "
            "use <strong>Dispute</strong>; accepted disputes are annotated here and listed on the corrections page, and the match stays visible.</p>"
            '<div class="controls" data-controls="vulnerabilities-table" hidden><input type="search" placeholder="Filter advisories" aria-label="Filter advisories">'
            '<label><input type="checkbox" data-flag="kev"> in CISA KEV</label><label><input type="checkbox" data-flag="binary"> vulnerable code in binary</label>'
            '<span class="count small"></span></div>'
            '<div class="scroll"><table class="sortable" id="vulnerabilities-table"><thead><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Version</th><th>Fixed in</th>'
            '<th>OSV</th><th>Released binary</th><th>KEV</th><th class="num">EPSS</th><th>Declared in</th><th data-nosort>Dispute</th></tr></thead><tbody>'
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
                f"<tr id=\"{esc(anchor('dep', item['ecosystem'], item['name'], item['version']))}\"><td><code>{esc(item['name'])}</code></td><td><code>{esc(item['version'] or '—')}</code></td>"
                f"<td class=\"small\">{esc(', '.join(item.get('licenses') or []))}</td><td class=\"small\"><code>{esc(item.get('location') or '')}</code></td></tr>"
                for item in items
            )
            parts.append(
                f"<details><summary>{esc(name)} ({len(items)})</summary><div class=\"scroll\"><table><thead><tr><th>Name</th><th>Version</th><th>License</th><th>Declared in</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></div></details>"
            )
        return "\n".join(parts)

    @staticmethod
    def project_history(history: list[dict[str, Any]], pid: str = "") -> str:
        rows = []
        for item in reversed(history):
            vulns = item.get("vulnerabilities")
            counts = count_cells(vulns) if vulns else f'<td colspan="{len(SHOWN_SEVERITIES)}">—</td>'
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
            if item.get("kev_new"):
                changes.append(f"{item['kev_new']} newly in KEV")
            if item.get("errors"):
                changes.append("scan error")
            rows.append(
                f"<tr id=\"{esc(anchor('week', item['date']))}\"><td><a href=\"../../../history/{esc(item['date'])}/index.html#{esc(anchor(pid))}\">{esc(item['date'])}</a></td><td>{esc(item.get('ref') or '—')}</td>"
                f"<td class=\"num\">{item['dependencies'] if item.get('dependencies') is not None else '—'}</td>{counts}<td>{esc(' · '.join(changes) or '—')}</td></tr>"
            )
        return (
            '<h2 id="history">History</h2>'
            '<div class="scroll"><table><thead><tr><th>Week</th><th>Version</th><th class="num">Dependencies</th><th class="num">Critical</th>'
            '<th class="num">High</th><th class="num">Medium</th><th class="num">Low</th><th class="num">Unknown</th><th>Changes</th></tr></thead><tbody>'
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

    # ----- badges and feeds ---------------------------------------------------------------
    def project_badges(self, repository: str, project: dict[str, Any]) -> str:
        snippets = []
        page = f"{self.site_url}{project_path(repository)}index.html"
        for name, label, content in (
            ("release", "release verification", exports.release_badge((project.get("release_integrity") or {}).get("verdict"))),
            ("in-binary", "vulnerable code in binary", exports.in_binary_badge(project.get("go_binary"))),
        ):
            if not content:
                continue
            path = f"badges/{repository}/{name}.json"
            self.write(path, content)
            image = exports.shields_url(self.site_url + path)
            snippets.append(f"[![{label}]({image})]({page})")
        if not snippets:
            return ""
        return ('<h2 id="badges">Badges</h2><p class="small">shields.io endpoints refreshed with each weekly scan. '
                "They report this week's result for the latest release, nothing more.</p>"
                f"<pre><code>{esc(chr(10).join(snippets))}</code></pre>")

    def feed_entry_id(self, *parts: str) -> str:
        host = urllib.parse.urlparse(self.site_url).netloc or "localhost"
        return f"tag:{host},2026:" + "/".join(parts)

    def run_time(self, date: str) -> str:
        run = next((item for item in self.runs if item["date"] == date), {})
        return exports.rfc3339(run.get("generated_at"), date)

    def project_feed(self, repository: str, stored: dict[str, Any]) -> None:
        project = stored["latest"]
        name = project.get("name") or repository
        page = f"{self.site_url}{project_path(repository)}index.html"
        history = stored.get("history") or []
        entries = []
        for position, item in enumerate(reversed(history)):
            text = self.history_change_text(item)
            first = position == len(history) - 1
            if text == "no change" and not first and not item.get("errors"):
                continue
            counts = shown_counts(item.get("vulnerabilities"))
            summary = (("First scan. " if first else f"Changes: {text}. ")
                       + (f"Scan errors: {'; '.join(item['errors'])}. " if item.get("errors") else "")
                       + f"Version {item.get('ref') or '—'}: {item.get('dependencies') if item.get('dependencies') is not None else '—'} dependencies, "
                       + ", ".join(f"{value} {level.lower()}" for level, value in counts.items()) + " advisory matches"
                       + (f", {item['in_binary']['total']} with vulnerable code in the binary" if item.get("in_binary") else "") + ".")
            entries.append({
                "id": self.feed_entry_id("project", repository, item["date"]),
                "title": f"{name}, week of {item['date']}: {'first scan' if first else text}",
                "url": f"{page}#{anchor('week', item['date'])}", "updated": self.run_time(item["date"]), "summary": summary,
            })
        self.write(f"{project_path(repository)}feed.xml", exports.atom_feed(
            self.feed_entry_id("project", repository), f"{name} supply-chain report", f"{self.site_url}{project_path(repository)}feed.xml",
            page, entries))

    def site_feed(self) -> None:
        entries = []
        for run in reversed(self.runs):
            rows = run["projects"]
            facts = [
                f"{len(rows)} projects scanned",
                f"{sum(1 for item in rows if item.get('change_any'))} changed",
                f"{sum(1 for item in rows if item.get('release_changed'))} new releases",
                f"{sum(item.get('new_vulnerabilities') or 0 for item in rows)} new advisory matches",
                f"{sum(item.get('resolved_vulnerabilities') or 0 for item in rows)} resolved",
            ]
            if any("kev_new" in item for item in rows):
                facts.append(f"{sum(item.get('kev_new') or 0 for item in rows)} newly in CISA KEV")
            failed = sum(1 for item in rows if item.get("errors"))
            if failed:
                facts.append(f"{failed} scans with errors")
            entries.append({
                "id": self.feed_entry_id("week", run["date"]), "title": f"Supply-chain report, week of {run['date']}",
                "url": f"{self.site_url}history/{run['date']}/index.html", "updated": exports.rfc3339(run.get("generated_at"), run["date"]),
                "summary": "; ".join(facts) + ".",
            })
        self.write("feed.xml", exports.atom_feed(
            self.feed_entry_id("weekly"), "Weekly supply-chain report for open-source security tools",
            f"{self.site_url}feed.xml", self.site_url + "index.html", entries))

    # ----- advisories ---------------------------------------------------------------------
    def advisory_pages(self) -> None:
        for record in self.advisories.values():
            self.advisory_page(record)
        self.advisory_index()

    def advisory_page(self, record: dict[str, Any]) -> None:
        depth = 2
        root = "../" * depth
        rows = []
        for entry in sorted(record["matches"], key=lambda match: (match["item"].get("in_binary") != exports.SHIPPED,
                                                                   match["project"]["repository"].lower())):
            project, item = entry["project"], entry["item"]
            shipped = item.get("in_binary")
            if shipped:
                status = f'<span class="{"bad" if shipped in (exports.SHIPPED, "package in binary") else "zero"}">{esc(shipped)}</span>'
            elif project.get("go_binary") and item.get("ecosystem") == "golang":
                status = '<span class="zero">—</span>'
            else:
                status = '<span class="zero" title="Only Go release binaries are analyzed for shipped code">not analyzed</span>'
            location = item.get("location") or ""
            kind = " (workflow)" if item.get("ecosystem") == "github" else ""
            rows.append(
                f"<tr{' data-binary' if shipped == exports.SHIPPED else ''}>"
                f"<td data-sort=\"{esc((project.get('name') or project['repository']).lower())}\"><a href=\"{root}{project_path(project['repository'])}index.html#{esc(advisory_anchor(item))}\">{esc(project.get('name') or project['repository'])}</a>"
                f"<div class=\"small\">{esc(project.get('category') or '')}</div></td><td>{esc(project.get('ref') or '—')}</td>"
                f"<td><code>{esc(item['package'])}@{esc(item['version'])}</code><div class=\"small\">{esc(item.get('ecosystem'))}</div></td>"
                f"<td>{esc(', '.join(item.get('fixed_in') or [])) or NO_FIX}</td>"
                f"<td class=\"small\">{status}</td><td class=\"small\"><code>{esc(location)}</code>{esc(kind)}</td>"
                f"{self.dispute_cell(project, item, depth)}</tr>"
            )
        kev = record["kev"]
        cards = [
            f'<div class="card"><div class="big">{len(record["tools"])}</div><div class="small">catalog tools match this advisory</div></div>',
            f'<div class="card"><div class="big">{len(record["shipped"])}</div><div class="small">ship the vulnerable code in their release binary '
            "(Go tools analyzed with govulncheck)</div></div>",
        ]
        if record["kev_checked"]:
            cards.append(f'<div class="card"><div class="big">{"Yes" if kev else "No"}</div><div class="small">in the CISA KEV catalog'
                         + (f" ({esc(kev.get('cve'))}, added {esc(kev.get('date_added'))})" if kev else "") + "</div></div>")
        if record["epss"]:
            cards.append(f'<div class="card"><div class="big">{epss_text(record["epss"])}</div><div class="small">EPSS for {esc(record["epss"].get("cve"))}, '
                         f'percentile {record["epss"]["percentile"] * 100:.0f}</div></div>')
        links = " · ".join(f'<a href="{esc(url)}">{esc(label)}</a>' for label, url in exports.upstream_links(record))
        workflow = ('<p class="note">Every match is a GitHub Action referenced in a workflow file, not a dependency of the shipped tool.</p>'
                    if record["workflow_only"] else "")
        body = (
            f"<h1>{esc(record['id'])}</h1>"
            + (f'<p class="lede">{esc(record["summary"])}</p>' if record["summary"] else "")
            + f'<p class="meta">{badge(record["severity"])} highest severity reported'
            + (f" · also known as {esc(', '.join(record['aliases']))}" if record["aliases"] else "") + "</p>"
            + f'<div class="cards">{"".join(cards)}</div>' + workflow
            + f'<h2 id="tools">Catalog tools matching {esc(record["id"])}</h2>'
            + '<div class="scroll"><table class="sortable" id="matches-table"><thead><tr><th>Tool</th><th>Version scanned</th><th>Package</th>'
            "<th>Fixed in</th><th>Released binary</th><th>Declared in</th><th data-nosort>Dispute</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div>"
            + f'<p class="small">{esc(VULNERABILITY_NOTE)} {esc(CONTEXT_NOTE)} <strong>Released binary</strong> is only analyzed '
            "for Go tools with a Linux release binary; other tools show <em>not analyzed</em>.</p>"
            + f"<h2 id=\"upstream\">Advisory sources</h2><p>{links}</p>"
            + (f"<p class=\"small\">Grype data sources: {' · '.join(f'<a href={chr(34)}{esc(url)}{chr(34)}>{esc(url)}</a>' for url in record['urls'])}</p>" if record["urls"] else "")
        )
        description = (f"{record['id']}: which open-source security tools match it, and which ship the vulnerable code in their release binary.")
        self.write(f"{exports.advisory_path(record['id'])}index.html", self.page(
            f"{record['id']} in open-source security tools", depth, body, description, index=exports.worth_indexing(record)))

    def advisory_index(self) -> None:
        records = sorted(self.advisories.values(), key=exports.sort_key)
        order = {name: index for index, name in enumerate(SEVERITIES)}
        rows = []
        for record in records:
            kev = record["kev"]
            flags = "".join(f" data-{name}" for name, on in (
                ("kev", kev), ("binary", record["shipped"]), ("multi", len(record["tools"]) > 1),
                ("serious", record["severity"] in ("Critical", "High"))) if on)
            kev_text = (f'<span class="pill kev" title="{esc(kev.get("cve"))}, added {esc(kev.get("date_added"))}">KEV</span>' if kev else
                        ('<span class="zero">no</span>' if record["kev_checked"] else '<span class="zero">—</span>'))
            epss = record["epss"]
            rows.append(
                f"<tr{flags}><td data-sort=\"{esc(record['id'].lower())}\"><a href=\"{exports.advisory_path(record['id'])}index.html\"><code>{esc(record['id'])}</code></a>"
                + (f"<div class=\"small\">{esc(', '.join(record['aliases'][:3]))}</div>" if record["aliases"] else "") + "</td>"
                f"<td data-sort=\"{order.get(record['severity'], 99)}\">{badge(record['severity'])}</td>"
                f"<td class=\"small\">{esc(record['summary'][:140])}</td>"
                f"<td class=\"num\">{len(record['tools'])}</td><td class=\"num\">{len(record['shipped']) or ZERO}</td>"
                f"<td class=\"num\">{kev_text}</td>"
                f"<td class=\"num\" data-sort=\"{epss['score'] if epss else -1}\">{epss_text(epss)}</td></tr>"
            )
        in_kev = [record for record in records if record["kev"]]
        kev_list = ""
        if any(record["kev_checked"] for record in records):
            items = "".join(
                f"<li><a href=\"{exports.advisory_path(record['id'])}index.html\"><code>{esc(record['id'])}</code></a> "
                f"({esc(record['kev'].get('cve'))}): {len(record['tools'])} tool(s), "
                f"{len(record['shipped'])} shipping the vulnerable code"
                + (" — workflow references only" if record["workflow_only"] else "") + "</li>"
                for record in in_kev)
            kev_list = (f'<h2 id="kev">In the CISA KEV catalog ({len(in_kev)})</h2>'
                        + (f"<ul>{items}</ul>" if items else "<p>None of the matched advisories is in the catalog this week.</p>")
                        + f'<p class="small">{esc(CONTEXT_NOTE)}</p>')
        shipped = sum(1 for record in records if record["shipped"])
        body = (
            "<h1>Advisories matched in open-source security tools</h1>"
            f'<p class="lede">{len(records)} distinct advisories match the declared dependencies of the catalog\'s tools this week. '
            f"{sum(1 for record in records if len(record['tools']) > 1)} affect more than one tool, and {shipped} have vulnerable code "
            "compiled into at least one tool's release binary. Advisory ids that alias each other (GHSA, Go, CVE) are merged.</p>"
            '<p class="meta"><a href="../data/advisories.csv">CSV</a> · <a href="../data/matches.csv">every match (CSV)</a></p>'
            + kev_list
            + '<h2 id="all">All advisories</h2>'
            '<div class="controls" data-controls="advisories-table" hidden><input type="search" placeholder="Filter by id, package, or text" aria-label="Filter advisories">'
            '<label><input type="checkbox" data-flag="serious"> critical or high</label>'
            '<label><input type="checkbox" data-flag="multi"> more than one tool</label>'
            '<label><input type="checkbox" data-flag="binary"> shipped in a binary</label>'
            '<label><input type="checkbox" data-flag="kev"> in CISA KEV</label><span class="count small"></span></div>'
            '<div class="scroll"><table class="sortable" id="advisories-table"><thead><tr><th>Advisory</th><th>Severity</th><th>Summary</th>'
            '<th class="num">Tools</th><th class="num" title="Tools whose release binary contains the vulnerable code (Go only)">Shipped in binary</th>'
            '<th class="num">KEV</th><th class="num">EPSS</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>"
            + f'<p class="small">{esc(VULNERABILITY_NOTE)}</p>'
        )
        self.write("advisories/index.html", self.page(
            "Advisories matched in open-source security tools", 1, body,
            "Every known advisory matched in the catalog's security tools, with which tools ship the vulnerable code, CISA KEV, and EPSS."))

    # ----- data exports -------------------------------------------------------------------
    def data_exports(self) -> None:
        if not self.latest:
            return
        entries = []
        for entry in self.latest["projects"]:
            packages, kev = self.project_extras(entry, 0)
            entries.append({**entry, "vulnerable_packages": packages, "kev": kev})
        latest = [stored["latest"] for stored in self.projects.values()]
        self.write("data/projects.csv", exports.projects_csv(entries))
        self.write("data/matches.csv", exports.matches_csv(latest, self.aliases))
        self.write("data/advisories.csv", exports.advisories_csv(self.advisories))
        files = (
            ("index.json", "List of weekly runs, newest first, and superseded runs."),
            (f"runs/{self.latest['date']}.json", "This week's summary: one row per project, tool versions, and provenance."),
            ("projects/<owner>__<repo>.json", "Per project: latest inventory, every advisory match, checks, and weekly history."),
            (CHECKSUMS_FILE, "SHA-256 of every data file; attested by the workflow."),
            ("projects.csv", "Derived: this week's project table."),
            ("matches.csv", "Derived: one row per project and advisory match, with KEV and EPSS."),
            ("advisories.csv", "Derived: one row per distinct advisory, with the tools it matches."),
        )
        rows = "".join(
            f"<tr><td>{'<code>' + esc(name) + '</code>' if '<' in name else f'<a href={chr(34)}{esc(name)}{chr(34)}><code>{esc(name)}</code></a>'}</td><td>{esc(text)}</td></tr>"
            for name, text in files)
        body = (
            "<h1>Report data</h1>"
            '<p class="lede">The JSON files are the recorded data from the <code>supply-chain-data</code> branch and are covered by '
            'the attestation described on the <a href="../verify/index.html">verification page</a>. CSV files are derived from that JSON '
            "when the site is built and are not attested themselves.</p>"
            f'<table><thead><tr><th>File</th><th>Contents</th></tr></thead><tbody>{rows}</tbody></table>'
            "<p>Atom feeds: <a href=\"../feed.xml\">weekly summary</a>, and <code>projects/&lt;owner&gt;/&lt;repo&gt;/feed.xml</code> for each project.</p>"
        )
        self.write("data/index.html", self.page("Supply-chain report data", 1, body, "Download the weekly supply-chain report data as JSON or CSV."))

    # ----- history ------------------------------------------------------------------------
    def history(self) -> None:
        rows = []
        for run in reversed(self.runs):
            entries = run["projects"]
            releases = sum(1 for item in entries if item.get("release_changed"))
            new = sum(item.get("new_vulnerabilities") or 0 for item in entries)
            resolved = sum(item.get("resolved_vulnerabilities") or 0 for item in entries)
            changed = sum(1 for item in entries if item.get("change_any"))
            release = self.evidence_release(run)
            rows.append(
                f"<tr id=\"{esc(anchor('week', run['date']))}\"><td><a href=\"{esc(run['date'])}/index.html\">{esc(run['date'])}</a></td><td class=\"num\">{len(entries)}</td>"
                f"<td class=\"num\">{changed}</td><td class=\"num\">{releases}</td><td class=\"num\">{new}</td><td class=\"num\">{resolved}</td>"
                f"<td><a href=\"../data/runs/{esc(run['date'])}.json\">JSON</a>{' · ' + release if release else ''}</td></tr>"
            )
            body = (
                f"<h1>Supply-chain report: week of {esc(run['date'])}</h1>"
                f'<p class="meta">{self.tools_line(run)} · <a href="../../data/runs/{esc(run["date"])}.json">JSON</a>'
                + (f" · raw evidence: {release}" if release else "") + "</p>"
                + self.project_table(entries, depth=2)
            )
            self.write(f"history/{run['date']}/index.html", self.page(
                f"Supply-chain report {run['date']}", 2, body, f"Supply-chain scan of security tools for the week of {run['date']}.", run))
        body = (
            "<h1>Weekly history</h1>"
            '<div class="scroll"><table><thead><tr><th>Week</th><th class="num">Projects</th><th class="num">Changed</th>'
            '<th class="num">New releases</th><th class="num">New advisories</th><th class="num">Resolved</th><th>Data</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>"
        )
        self.write("history/index.html", self.page("Supply-chain report history", 1, body, "Weekly history of the supply-chain report."))

    # ----- verification and corrections ---------------------------------------------------
    def verify_page(self) -> None:
        repo = self.repository
        workflow = f"{repo}/{WORKFLOW_PATH}"
        run = self.latest or {}
        tag = run.get("evidence_release") or "report-YYYY-MM-DD"
        commands = "\n".join((
            f"git clone https://github.com/{repo}.git source",
            f"git clone --branch supply-chain-data https://github.com/{repo}.git report-data",
            "cd report-data",
            f"gh attestation verify {CHECKSUMS_FILE} --repo {repo} --signer-workflow {workflow}",
            f"sha256sum -c {CHECKSUMS_FILE}        # macOS: shasum -a 256 -c {CHECKSUMS_FILE}",
            "# append-only history, recomputation, and release anchors:",
            "python3 ../source/scripts/supply_chain_scan.py verify --data-dir . --history --attestations",
        ))
        single = f"gh attestation verify projects/gitleaks__gitleaks.json --repo {repo} --signer-workflow {workflow}"
        evidence = f"gh release download {tag} --repo {repo}\ngh attestation verify supply-chain-evidence-*.tar.gz --repo {repo} --signer-workflow {workflow}"
        body = (
            "<h1>Verify this data</h1>"
            '<p class="lede">Every file in the report data is published by one GitHub Actions workflow and covered by a '
            "GitHub artifact attestation: a Sigstore-signed statement, recorded in the public Rekor transparency log, that names "
            "the exact file digest, the workflow file, the commit it ran at, and the run.</p>"
            '<h2 id="commands">Check it yourself</h2>'
            "<p>Requires <code>git</code>, <code>sha256sum</code>, and the <a href=\"https://cli.github.com/\">GitHub CLI</a>.</p>"
            f"<pre><code>{esc(commands)}</code></pre>"
            "<p>Any single file can also be checked on its own, for example one project's JSON downloaded from this site:</p>"
            f"<pre><code>{esc(single)}</code></pre>"
            "<p>Raw SBOMs, Grype, OSV-Scanner, and govulncheck output for each week are attached to an immutable GitHub release "
            "with their own attestation:</p>"
            f"<pre><code>{esc(evidence)}</code></pre>"
            '<h2 id="proves">What a successful check proves</h2><ul class="tight">'
            f"<li>The bytes you have were produced by <code>{esc(WORKFLOW_PATH)}</code> in <code>{esc(repo)}</code>, at the commit and run "
            "named in the attestation. The commit is public, so the code that produced the data can be read.</li>"
            "<li>The files were not changed after that run: any edit changes the digest and the check fails.</li>"
            "<li><code>verify --history</code> shows the data branch was only appended to: earlier weeks were never rewritten, "
            "and a replaced run for the same week is kept under <code>runs/superseded/</code>.</li></ul>"
            '<h2 id="limits">What it does not prove</h2><ul class="tight">'
            "<li>That the scanners are right. Results are what Syft, Grype, OSV-Scanner, govulncheck, zizmor, and Scorecard "
            "reported; their databases and the OpenSSF dataset are outside this repository's control.</li>"
            "<li>That the workflow is correct or neutral. It proves which code ran, not that the code is good; review the commit.</li>"
            "<li>Anything about weeks published before 2026-11-08, which predate attestation. Their content is still covered by "
            "the history check and by later attestations of the whole data tree.</li>"
            "<li>That the repository owner cannot publish new data. The owner controls the workflow; every change to it is a "
            "public commit, and manual interventions are listed on the corrections page.</li></ul>"
            + self.provenance_detail(run)
        )
        self.write("verify/index.html", self.page("Verify the supply-chain report data", 1, body,
                                                  "How to verify the weekly supply-chain report data with GitHub artifact attestations."))

    @staticmethod
    def enrichment_detail(run: dict[str, Any]) -> str:
        context = (run.get("provenance") or {}).get("enrichment")
        if not context:
            return ""
        rows = []
        for key, label in (("kev", "CISA Known Exploited Vulnerabilities"), ("epss", "FIRST EPSS")):
            entry = context.get(key) or {}
            detail = (f'<span class="bad">not available: {esc(entry["error"])}</span>' if entry.get("error") else
                      f"{esc(entry.get('version'))}, released {esc(str(entry.get('released') or '?')[:19])}, {esc(entry.get('count'))} entries"
                      f"<div class=\"small\"><code>{esc(str(entry.get('sha256') or '')[:16])}</code></div>")
            rows.append(f"<tr><td><a href=\"{esc(entry.get('url', ''))}\">{label}</a></td><td>{detail}</td></tr>")
        return (f'<h3 id="enrichment">Exploitation data</h3><p class="small">Downloaded {esc(str(context.get("fetched_at") or "")[:16])} UTC by a '
                "read-only job; both files are in the evidence release.</p>"
                f'<table><thead><tr><th>Source</th><th>Snapshot</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')

    def provenance_detail(self, run: dict[str, Any]) -> str:
        shards = (run.get("provenance") or {}).get("shards") or []
        if not shards:
            return self.enrichment_detail(run)
        rows = []
        for shard in shards:
            runner = shard.get("runner") or {}
            grype = shard.get("grype_db") or {}
            go = shard.get("go_vulndb") or {}
            rows.append(
                f"<tr><td class=\"num\">{esc(shard.get('shard'))}</td><td>{esc(runner.get('os', '?'))} {esc(runner.get('image_version', ''))}</td>"
                f"<td>{esc(grype.get('schemaVersion', ''))}, built {esc(str(grype.get('built') or '?')[:16])}"
                f"<div class=\"small\"><code>{esc(str(grype.get('sha256') or '')[:16])}</code></div></td>"
                f"<td>{esc(str(go.get('modified') or go.get('error') or '?')[:19])}</td>"
                f"<td>{esc((shard.get('osv') or {}).get('mode', ''))}</td>"
                f"<td class=\"small\">{esc(str(shard.get('started_at') or '')[11:16])}–{esc(str(shard.get('finished_at') or '')[11:16])}</td></tr>"
            )
        return (
            f'<h2 id="environment">Scan environment for {esc(run.get("date"))}</h2>'
            '<div class="scroll"><table><thead><tr><th class="num">Shard</th><th>Runner image</th><th>Grype database</th>'
            "<th>Go vulnerability database modified</th><th>OSV</th><th>UTC</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div>"
            + self.enrichment_detail(run)
        )

    def corrections_page(self) -> None:
        repo = f"https://github.com/{self.repository}"
        documented = self.corrections

        def source(entry: dict[str, Any]) -> str:
            links = []
            if entry.get("pr"):
                links.append(f'<a href="{repo}/pull/{esc(entry["pr"])}">PR #{esc(entry["pr"])}</a>')
            if entry.get("link"):
                links.append(f'<a href="{esc(entry["link"])}">details</a>')
            return " · ".join(links) or "—"

        pins = (load_json(self.args.tag_patterns).get("projects") or {}) if self.args.tag_patterns.is_file() else {}
        pin_rows = "".join(
            f"<tr><td>{esc(entry.get('added', '—'))}</td><td><code>{esc(name)}</code></td><td><code>{esc(entry['pattern'])}</code></td>"
            f"<td>{esc(entry.get('reason', ''))}</td><td>{source(entry)}</td></tr>"
            for name, entry in sorted(pins.items(), key=lambda kv: kv[0].lower())
        )
        exceptions = documented.get("catalog_exceptions") or {}
        exception_rows = []
        if self.args.tools.is_dir():
            for name, tool in sorted(catalog.load_tools(self.args.tools).items()):
                text = (tool.get("listing") or {}).get("exception")
                if text:
                    meta = exceptions.get(name) or {}
                    exception_rows.append(f"<tr><td>{esc(meta.get('added', '—'))}</td><td><code>{esc(name)}</code></td>"
                                          f"<td>{esc(text)}</td><td>{source(meta)}</td></tr>")
        superseded_rows = []
        for run in self.runs:
            for name in (self.index.get("superseded") or {}).get(run["date"], []):
                old = self.superseded.get(name) or {}
                old_run = (old.get("provenance") or {}).get("run") or {}
                new_run = (run.get("provenance") or {}).get("run") or {}
                replaced = (f'<a href="{esc(old_run["url"])}">run #{esc(old_run["id"])}</a>' if old_run.get("url")
                            else f"unrecorded run, generated {esc(str(old.get('generated_at') or '?')[:16])}")
                superseded_rows.append(
                    f"<tr><td>{esc(run['date'])}</td><td>{replaced} · <a href=\"../data/{esc(name)}\">JSON</a></td>"
                    f"<td>{esc(new_run.get('reason') or 'not recorded')}</td></tr>")
        other_rows = "".join(
            f"<tr><td>{esc(entry.get('date', ''))}</td><td>{esc(entry.get('scope', ''))}</td><td>{esc(entry.get('summary', ''))}</td>"
            f"<td>{source(entry)}</td></tr>"
            for entry in sorted(documented.get("entries") or [], key=lambda item: item.get("date", ""), reverse=True)
        )

        dispute_rows = "".join(
            f"<tr><td>{esc(entry.get('date', ''))}</td><td><a href=\"../{project_path(entry['repository'])}index.html\">{esc(entry['repository'])}</a></td>"
            f"<td><code>{esc(entry['advisory'])}</code>{(' in <code>' + esc(entry['package']) + '</code>') if entry.get('package') else ''}</td>"
            f"<td>{esc(entry.get('status', ''))}</td><td>{esc(entry.get('summary', ''))}</td><td>{source(entry)}</td></tr>"
            for entry in sorted(documented.get("disputes") or [], key=lambda item: item.get("date", ""), reverse=True)
        )

        def table(title: str, ident: str, intro: str, head: list[str], rows: str) -> str:
            header = "".join(f"<th>{esc(item)}</th>" for item in head)
            content = (f'<div class="scroll"><table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table></div>'
                       if rows else "<p>None.</p>")
            return f'<h2 id="{ident}">{esc(title)}</h2><p class="small">{esc(intro)}</p>{content}'

        body = (
            "<h1>Corrections and manual overrides</h1>"
            '<p class="lede">Everything a person changed about what the report scans or publishes, with when and why. '
            "Automated results are never edited by hand; when a week is re-run, the earlier run is kept.</p>"
            + table("Release tag pins", "tag-pins", "Monorepos whose latest GitHub release is not the catalogued tool are scanned at the newest release matching a pattern.",
                    ["Since", "Repository", "Tag pattern", "Reason", "Source"], pin_rows)
            + table("Catalog exceptions", "catalog-exceptions", "Tools kept in an active category although the automated rules would classify them otherwise.",
                    ["Since", "Tool", "Justification", "Source"], "".join(exception_rows))
            + table("Re-run weeks", "superseded-runs", "A week published more than once. The replaced run summary remains available.",
                    ["Week", "Replaced run", "Reason for the new run"], "".join(superseded_rows))
            + table("Disputed findings", "disputes", "Matches reported as wrong, not applicable, or fixed, and how each report was resolved. "
                    "The match stays in the data and is annotated on the project page.",
                    ["Date", "Project", "Advisory", "Resolution", "Summary", "Source"], dispute_rows)
            + table("Other corrections", "other", "Data or methodology corrections not covered above.",
                    ["Date", "Scope", "Correction", "Source"], other_rows)
        )
        self.write("corrections/index.html", self.page("Supply-chain report corrections", 1, body,
                                                       "Manual overrides, re-runs, and corrections to the weekly supply-chain report."))

    # ----- assets -------------------------------------------------------------------------
    def assets(self) -> None:
        self.write("style.css", STYLE.strip() + "\n" + EXTRA_STYLE.strip() + "\n" + exports.TABLE_STYLE.strip() + "\n"
                   + sections.PIPELINE_STYLE.strip() + "\n")
        self.write("report.js", exports.TABLE_SCRIPT.lstrip())
        (self.out / ".nojekyll").write_text("", encoding="utf-8")
        data = self.args.supply_chain_data
        if data and data.is_dir():
            for sub in ("runs", "projects"):
                if (data / sub).is_dir():
                    shutil.copytree(data / sub, self.out / "data" / sub, dirs_exist_ok=True)
            for name in ("index.json", CHECKSUMS_FILE):
                if (data / name).is_file():
                    shutil.copyfile(data / name, self.out / "data" / name)
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
        self.advisory_pages()
        self.data_exports()
        self.site_feed()
        self.history()
        self.verify_page()
        self.corrections_page()


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
