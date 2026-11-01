#!/usr/bin/env python3
"""Build the static SBOM benchmark site from the benchmark data branch.

Pages: an overview of the latest run, one page per generator, a history index, and a frozen
page per run. Everything is plain HTML and CSS generated with the standard library.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import shutil
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import sbom_benchmark  # noqa: E402

DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SECTION = "sbom-benchmark"
GENERATORS = sbom_benchmark.TOOLS
TOOL_NAMES = {
    "syft": "Syft",
    "trivy": "Trivy",
    "cdxgen": "cdxgen",
    "microsoft-sbom-tool": "Microsoft SBOM Tool",
    "cyclonedx-cli": "CycloneDX CLI",
    "sbomlyze": "sbomlyze",
}
TOOL_ROLES = {"cyclonedx-cli": "validator", "sbomlyze": "analyzer"}
STANDARD_NAMES = {"ntia": "NTIA 2021", "cisa": "CISA 2025", "bsi_tr03183": "BSI TR-03183"}
PASS_MARK = '<span class="ok">pass</span>'
FAIL_MARK = '<span class="bad">fail</span>'
NEW_MARK = ' <span class="warn">upgraded</span>'
DISCLOSURE = (
    "sbomlyze is developed by the maintainer of this repository. It is used here only for "
    "week-over-week drift and minimum-element checks, and it is not ranked. Ground-truth scoring "
    "is done by the benchmark's own normalizer against inventories read directly from each fixture."
)

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=pathlib.Path)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--artifacts-dir", type=pathlib.Path, help="sbomlyze stage output for the latest run")
    parser.add_argument("--repository", default="rezmoss/awesome-security-pipeline")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args()


def ordered_standards(standards: dict[str, Any]) -> list[tuple[str, Any]]:
    order = list(STANDARD_NAMES)
    return sorted(standards.items(), key=lambda item: order.index(item[0]) if item[0] in order else len(order))


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def code_markup(text: str) -> str:
    """Escape text and render `backtick` spans as code."""
    parts = esc(text).split("`")
    return "".join(f"<code>{part}</code>" if index % 2 else part for index, part in enumerate(parts))


def tool_name(tool: str) -> str:
    return TOOL_NAMES.get(tool, tool)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


class Site:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.repository = args.repository
        self.config = load_json(args.config)
        runs_dir = args.data_dir / "runs"
        paths = sorted(p for p in runs_dir.glob("*.json") if DATE_PATTERN.fullmatch(p.stem))
        if not paths:
            raise ValueError(f"no benchmark runs found in {runs_dir}")
        self.runs = [load_json(path) for path in paths]
        self.analysis = {}
        for path in paths:
            sidecar = runs_dir / f"{path.stem}.sbomlyze.json"
            if sidecar.is_file():
                self.analysis[path.stem] = load_json(sidecar)
        self.latest = self.runs[-1]
        self.out = args.output / SECTION

    # ----- shared fragments -------------------------------------------------------------
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
<nav aria-label="Benchmark"><a href="{root}index.html">Overview</a>{''.join(f'<a href="{root}tools/{tool}/index.html">{esc(tool_name(tool))}</a>' for tool in GENERATORS)}<a href="{root}history/index.html">History</a><a href="{root}data/latest.json">Data</a><a href="{repo}">Repository</a></nav>
</header>
<main>
{body}
</main>
<footer>
<p>Generated from the <a href="{repo}/blob/main/benchmarks/sbom/README.md">SBOM compatibility benchmark</a> in <a href="{repo}">{esc(self.repository)}</a>. Every number on this page is reproducible from the published commands, fixtures, and data files.</p>
<p>{esc(DISCLOSURE)}</p>
</footer>
</body>
</html>
"""

    def write(self, relative: str, content: str) -> None:
        target = self.out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def fixture_definition(self, fixture_id: str) -> dict[str, Any]:
        return next((item for item in self.config["fixtures"] if item["id"] == fixture_id), {})

    @staticmethod
    def runs_by_tool(result: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
        table: dict[str, dict[str, dict[str, Any]]] = {}
        for fixture in result.get("fixtures") or []:
            for run in fixture.get("runs") or []:
                table.setdefault(run["tool"], {})[fixture["id"]] = run
        return table

    @staticmethod
    def tool_version(result: dict[str, Any], tool: str) -> str:
        return next((item["version"] for item in result.get("tools") or [] if item["id"] == tool), "unknown")

    def score_cell(self, run: dict[str, Any] | None) -> str:
        if not run:
            return "<td>—</td>"
        score = run.get("score") or {}
        status = '<span class="ok">PASS</span>' if run.get("status") == "passed" else '<span class="bad">FAIL</span>'
        lines = [status]
        if score.get("expected"):
            klass = "ok" if score["found"] == score["expected"] else "warn"
            lines.append(f'<span class="{klass}">{score["found"]}/{score["expected"]} found</span>')
        if score.get("extra"):
            lines.append(f'<span class="warn">{len(score["extra"])} not installed</span>')
        if score.get("missing_purl"):
            lines.append(f'{len(score["missing_purl"])} without package URL')
        return "<td>" + "<br>".join(lines) + "</td>"

    # ----- run report (overview and per-date pages) -------------------------------------
    def run_report(self, result: dict[str, Any], depth: int, latest: bool) -> str:
        root = "../" * depth
        date = result["run_date"]
        analysis = self.analysis.get(date) or {}
        by_tool = self.runs_by_tool(result)
        fixtures = result.get("fixtures") or []
        parts = []
        status = result.get("status")
        if status != "passed":
            failures = [
                f"<li><code>{esc(fixture['id'])}</code> / {esc(tool_name(run['tool']))}: {esc('; '.join(run.get('errors') or []))}</li>"
                for fixture in fixtures for run in fixture.get("runs") or [] if run.get("status") != "passed"
            ]
            parts.append(f'<div class="banner"><strong class="bad">This run failed the regression gate.</strong><ul class="tight">{"".join(failures)}</ul></div>')

        # Cards: one per generator
        cards = []
        for tool in GENERATORS:
            runs = by_tool.get(tool, {})
            found = sum((run.get("score") or {}).get("found", 0) for run in runs.values())
            expected = sum((run.get("score") or {}).get("expected", 0) for run in runs.values())
            extra = sum(len((run.get("score") or {}).get("extra") or []) for run in runs.values())
            no_purl = sum(len((run.get("score") or {}).get("missing_purl") or []) for run in runs.values())
            passed = sum(1 for run in runs.values() if run.get("status") == "passed")
            klass = "ok" if found == expected and not extra else "warn"
            cards.append(
                f'<div class="card"><h3><a href="{root}tools/{tool}/index.html">{esc(tool_name(tool))}</a></h3>'
                f'<div class="small">{esc(self.tool_version(result, tool))} · {passed}/{len(runs)} runs passed</div>'
                f'<div class="big {klass}">{found}/{expected}</div><div class="small">ground-truth packages found</div>'
                f'<div class="small">{extra} reported but not installed · {no_purl} without package URL</div></div>'
            )
        parts.append('<h2 id="results">Results at a glance</h2>')
        parts.append(
            '<p>Each generator scans the same three inputs. The expected inventory comes from the input itself '
            '(the declared manifest, the lockfile, or the image’s package database), never from a generator.</p>'
        )
        parts.append(f'<div class="cards">{"".join(cards)}</div>')

        head = "".join(f"<th>{esc(tool_name(tool))}</th>" for tool in GENERATORS)
        rows = "".join(
            f"<tr><th><code>{esc(fixture['id'])}</code><div class=\"small\">{esc(fixture.get('description', ''))}</div></th>"
            + "".join(self.score_cell(by_tool.get(tool, {}).get(fixture["id"])) for tool in GENERATORS)
            + "</tr>"
            for fixture in fixtures
        )
        parts.append(f'<div class="scroll"><table><thead><tr><th>Input</th>{head}</tr></thead><tbody>{rows}</tbody></table></div>')

        notes = sbom_benchmark.notable_differences(result, TOOL_NAMES)
        if notes:
            parts.append('<h2 id="differences">Notable differences</h2><ul>')
            parts.extend(f"<li>{code_markup(note)}</li>" for note in notes)
            parts.append("</ul>")

        parts.append(self.compliance_section(analysis, depth))
        parts.append(self.changes_section(result, analysis, depth, latest))
        parts.append(self.fixtures_section(result))
        parts.append(self.tools_section(result))
        return "\n".join(part for part in parts if part)

    def compliance_section(self, analysis: dict[str, Any], depth: int) -> str:
        runs = analysis.get("runs") or {}
        if not runs:
            return ""
        root = "../" * depth
        rows = []
        for fixture_id, tools in runs.items():
            cells = []
            for tool in GENERATORS:
                compliance = (tools.get(tool) or {}).get("compliance") or {}
                standards = compliance.get("standards") or {}
                if not standards:
                    cells.append("<td>—</td>")
                    continue
                cells.append(
                    "<td>" + "<br>".join(
                        f"{esc(STANDARD_NAMES.get(key, key))}: <strong>{value.get('score')}</strong> "
                        f"<span class=\"small\">({value.get('passed')}/{value.get('total')})</span>"
                        for key, value in ordered_standards(standards)
                    ) + "</td>"
                )
            rows.append(f"<tr><th><code>{esc(fixture_id)}</code></th>{''.join(cells)}</tr>")
        head = "".join(f"<th>{esc(tool_name(tool))}</th>" for tool in GENERATORS)
        return (
            '<h2 id="minimum-elements">Minimum elements</h2>'
            "<p>Scores out of 100 for the NTIA (2021), CISA (2025), and BSI TR-03183 minimum elements, computed by "
            f"{esc(analysis.get('sbomlyze_version', 'sbomlyze'))} on each generated document. Each tool page lists every check "
            "and its evidence. Scores describe document completeness, not inventory accuracy.</p>"
            f'<div class="scroll"><table><thead><tr><th>Input</th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
            f'<p class="note">{esc(DISCLOSURE)} Each tool page lists the individual checks.</p>'
        )

    def changes_section(self, result: dict[str, Any], analysis: dict[str, Any], depth: int, latest: bool) -> str:
        root = "../" * depth
        previous = result.get("previous_run_date")
        if not previous:
            return '<h2 id="changes">Changes</h2><p>This is the first recorded run.</p>'
        parts = [f'<h2 id="changes">What changed since {esc(previous)}</h2>']
        upgrades = result.get("tool_changes") or {}
        if upgrades:
            parts.append(
                "<p>Tool upgrades: " + ", ".join(
                    f"{esc(tool_name(tool))} {esc(change['before'])} → {esc(change['after'])}"
                    for tool, change in upgrades.items()
                ) + ".</p>"
            )
        else:
            parts.append("<p>No tool versions changed.</p>")
        rows = []
        unchanged = 0
        lyze = analysis.get("runs") or {}
        for fixture in result.get("fixtures") or []:
            for run in fixture.get("runs") or []:
                change = run.get("change_from_previous") or {}
                diff = ((lyze.get(fixture["id"]) or {}).get(run["tool"]) or {}).get("diff")
                drift_total = sum((diff or {}).get("drift", {}).values()) if diff else 0
                if not change.get("baseline") and not any(
                    change.get(key) for key in
                    ("added", "removed", "relationships_added", "relationships_removed", "inventory_only_changed")
                ) and not drift_total and not (diff or {}).get("added") and not (diff or {}).get("removed"):
                    unchanged += 1
                    continue
                if change.get("baseline"):
                    text = "first run for this input"
                else:
                    text = f"packages +{len(change.get('added') or [])} / −{len(change.get('removed') or [])}"
                    if change.get("relationships_added") or change.get("relationships_removed"):
                        text += f"; dependency edges +{len(change['relationships_added'])} / −{len(change['relationships_removed'])}"
                    if change.get("inventory_only_changed"):
                        text += f"; files and crypto assets {change['inventory_only_before']} → {change['inventory_only_after']}"
                details = []
                for key, sign in (("added", "+"), ("removed", "−")):
                    for item in (change.get(key) or [])[:10]:
                        details.append(f"{sign} <code>{esc(item)}</code>")
                drift = "—"
                if diff:
                    d = diff.get("drift") or {}
                    drift = (
                        f"version {d.get('version_drift', 0)} · integrity {d.get('integrity_drift', 0)} · "
                        f"metadata {d.get('metadata_drift', 0)}"
                    )
                    if latest and diff.get("html"):
                        drift += f'<br><a href="{root}sbomlyze/{esc(diff["html"])}">full sbomlyze diff</a>'
                rows.append(
                    f"<tr><td><code>{esc(fixture['id'])}</code></td><td>{esc(tool_name(run['tool']))}</td>"
                    f"<td>{esc(text)}{'<br>' + '<br>'.join(details) if details else ''}</td><td>{drift}</td></tr>"
                )
        compared = analysis.get("previous_run_date")
        if rows:
            parts.append(
                '<div class="scroll"><table><thead><tr><th>Input</th><th>Tool</th><th>Package-level change</th>'
                f"<th>sbomlyze drift{' since ' + esc(compared) if compared else ''}</th></tr></thead><tbody>"
                + "".join(rows) + "</tbody></table></div>"
            )
        if unchanged:
            parts.append(f"<p>{'The other ' if rows else 'All '}{unchanged} tool runs reported the same package-level inventory.</p>")
        if latest and compared:
            links = ", ".join(
                f'<a href="{root}sbomlyze/{esc(entry["diff"]["html"])}">{esc(tool_name(tool))} on <code>{esc(fixture_id)}</code></a>'
                for fixture_id, tools in lyze.items() for tool, entry in tools.items()
                if (entry.get("diff") or {}).get("html")
            )
            if links:
                parts.append(f'<details><summary>Full sbomlyze diffs since {esc(compared)}</summary><p>{links}</p></details>')
        parts.append(
            '<p class="small">Package-level changes compare normalized identities (package URL, or type, name, and version). '
            "File and cryptographic-asset entries are compared as a count and a digest. Integrity drift means a hash "
            "changed while the version did not.</p>"
        )
        return "\n".join(parts)

    def fixtures_section(self, result: dict[str, Any]) -> str:
        parts = ['<h2 id="inputs">Inputs and ground truth</h2>']
        for fixture in result.get("fixtures") or []:
            definition = self.fixture_definition(fixture["id"]) or fixture
            expected = definition.get("expected_components") or []
            target = fixture.get("target") or definition.get("path") or definition.get("source_image")
            parts.append(f"<h3><code>{esc(fixture['id'])}</code></h3><p>{esc(definition.get('description', ''))}</p>")
            parts.append(f'<p class="small">Target: <code>{esc(target)}</code></p>')
            if expected:
                items = ", ".join(f"<code>{esc(item['name'])}@{esc(item['version'])}</code>" for item in expected)
                gate = "Missing any of these fails the run." if all(item.get("gate", True) for item in expected) else (
                    "These are scored; a run fails only if a tool loses one it found in the previous run."
                )
                parts.append(f"<details><summary>{len(expected)} expected components</summary><p>{items}</p><p class=\"small\">{gate}</p></details>")
            edges = definition.get("expected_relationships") or []
            if edges:
                parts.append(
                    "<p>Expected dependency edges: " + ", ".join(
                        f"<code>{esc(item['from_name'])}@{esc(item['from_version'])} → {esc(item['to_name'])}@{esc(item['to_version'])}</code>"
                        for item in edges
                    ) + ".</p>"
                )
        return "\n".join(parts)

    def tools_section(self, result: dict[str, Any]) -> str:
        rows = "".join(
            f"<tr><td>{esc(tool_name(tool['id']))}</td><td>{esc(TOOL_ROLES.get(tool['id'], 'generator'))}</td>"
            f"<td><a href=\"https://github.com/{esc(tool['repository'])}/releases/tag/{esc(tool['version'])}\">{esc(tool['version'])}</a></td>"
            f"<td><code>{esc(tool['sha256'])}</code></td><td>{esc(tool['verification'])}</td></tr>"
            for tool in result.get("tools") or []
        )
        env = result.get("environment") or {}
        return (
            '<h2 id="releases">Tool releases</h2>'
            "<p>Each run installs the latest stable GitHub release of every tool and records exactly what executed.</p>"
            '<div class="scroll"><table><thead><tr><th>Tool</th><th>Role</th><th>Version</th><th>Release asset SHA-256</th>'
            f"<th>Verification</th></tr></thead><tbody>{rows}</tbody></table></div>"
            f'<p class="small">Commit <code>{esc(result.get("commit", ""))}</code> · generated {esc(result.get("generated_at", ""))} · '
            f'{esc(env.get("os", ""))}</p>'
        )

    # ----- pages --------------------------------------------------------------------------
    def overview(self) -> None:
        result = self.latest
        status = '<span class="ok">PASS</span>' if result.get("status") == "passed" else '<span class="bad">FAIL</span>'
        body = (
            "<h1>SBOM generator benchmark</h1>"
            '<p class="lede">Syft, Trivy, cdxgen, and Microsoft SBOM Tool run every week against the same Go module, '
            "npm lockfile, and pinned container image. Each SBOM is validated, scored against an inventory read directly "
            "from the input, checked for minimum elements, and compared with the previous week.</p>"
            f'<p class="meta">Latest run {esc(result["run_date"])} · {status} · {len(self.runs)} runs recorded · '
            f'runs every Sunday · <a href="data/runs/{esc(result["run_date"])}.json">JSON for this run</a></p>'
            + self.run_report(result, depth=0, latest=True)
            + self.limits()
        )
        self.write("index.html", self.page(
            "SBOM generator benchmark: Syft vs Trivy vs cdxgen vs Microsoft SBOM Tool", 0, body,
            "Weekly, reproducible comparison of Syft, Trivy, cdxgen, and Microsoft SBOM Tool against independent ground truth.",
        ))

    def limits(self) -> str:
        repo = f"https://github.com/{self.repository}"
        return (
            '<h2 id="method">Method and limits</h2><ul>'
            "<li>Component counts are not rankings: tools model subjects, files, packages, and relationships differently.</li>"
            "<li>Structural validation uses CycloneDX CLI for CycloneDX output and the Microsoft SBOM Tool validator for its SPDX output.</li>"
            "<li>The benchmark does not evaluate vulnerability detection, license accuracy, or performance.</li>"
            "<li>Three small inputs cannot represent every ecosystem; results describe these inputs only.</li>"
            f'<li>Commands, fixtures, and scoring code: <a href="{repo}/blob/main/benchmarks/sbom/README.md">benchmark documentation</a>. '
            f'Background and selection guidance: <a href="{repo}/blob/main/comparisons/sbom-tools.md">SBOM tools comparison</a>.</li>'
            "</ul>"
        )

    def tool_page(self, tool: str) -> None:
        result = self.latest
        runs = self.runs_by_tool(result).get(tool, {})
        analysis = (self.analysis.get(result["run_date"]) or {}).get("runs") or {}
        meta = next((item for item in result.get("tools") or [] if item["id"] == tool), {})
        parts = [
            f"<h1>{esc(tool_name(tool))}</h1>",
            f'<p class="meta">Version {esc(meta.get("version", "unknown"))} in the {esc(result["run_date"])} run · '
            f'<a href="https://github.com/{esc(meta.get("repository", ""))}">upstream repository</a></p>',
        ]
        for fixture_id, run in runs.items():
            score = run.get("score") or {}
            parts.append(f'<h2 id="{esc(fixture_id)}"><code>{esc(fixture_id)}</code></h2>')
            status = '<span class="ok">PASS</span>' if run.get("status") == "passed" else '<span class="bad">FAIL</span>'
            parts.append(
                f"<p>{status} · {esc(run.get('specification', 'no document'))} · "
                f"{score.get('packages', 0)} package-level components · "
                f"{sum((run.get('inventory_only_counts') or {}).values())} file and crypto-asset entries</p>"
            )
            facts = []
            if score.get("expected"):
                facts.append(f"Ground truth found: <strong>{score['found']}/{score['expected']}</strong>")
            if score.get("missed"):
                facts.append("Missed: " + ", ".join(f"<code>{esc(item)}</code>" for item in score["missed"]))
            if score.get("extra"):
                facts.append("Reported but not installed: " + ", ".join(f"<code>{esc(item)}</code>" for item in score["extra"]))
            if score.get("missing_purl"):
                facts.append(f"{len(score['missing_purl'])} component(s) without a package URL: " + ", ".join(
                    f"<code>{esc(item)}</code>" for item in score["missing_purl"][:20]) + ("…" if len(score["missing_purl"]) > 20 else ""))
            if score.get("versionless"):
                facts.append(f"{len(score['versionless'])} component(s) without a version")
            for error in run.get("errors") or []:
                facts.append(f'<span class="bad">{esc(error)}</span>')
            if facts:
                parts.append("<ul>" + "".join(f"<li>{fact}</li>" for fact in facts) + "</ul>")
            parts.append(f"<p class=\"small\">Command: <code>{esc(run.get('command', ''))}</code></p>")
            raw = f"raw/{fixture_id}/{tool}.{'spdx' if tool == 'microsoft-sbom-tool' else 'cdx'}.json"
            if (self.out / raw).is_file():
                parts.append(f'<p><a href="../../{raw}">Download the generated SBOM</a></p>')
            components = [item for item in run.get("components") or [] if not item.get("subject")]
            if components:
                rows = "".join(
                    f"<tr><td>{esc(item['type'])}</td><td><code>{esc(item['name'])}</code></td>"
                    f"<td><code>{esc(item['version'] or '—')}</code></td><td><code>{esc(item['purl'] or '—')}</code></td></tr>"
                    for item in components
                )
                parts.append(
                    f"<details><summary>Package-level inventory ({len(components)})</summary><div class=\"scroll\"><table>"
                    f"<thead><tr><th>Type</th><th>Name</th><th>Version</th><th>Package URL</th></tr></thead><tbody>{rows}</tbody></table></div></details>"
                )
            counts = run.get("inventory_only_counts") or {}
            if counts:
                parts.append('<p class="small">Also reported: ' + ", ".join(f"{count} {esc(kind)}" for kind, count in counts.items()) + ".</p>")
            entry = (analysis.get(fixture_id) or {}).get(tool) or {}
            standards = (entry.get("compliance") or {}).get("standards") or {}
            if standards:
                parts.append(f'<h3 id="{esc(fixture_id)}-minimum-elements">Minimum elements (sbomlyze)</h3>')
                for key, value in ordered_standards(standards):
                    rows = "".join(
                        f"<tr><td>{esc(check['name'])}</td><td>{PASS_MARK if check['passed'] else FAIL_MARK}</td>"
                        f"<td>{esc(check.get('details') or '')}</td></tr>"
                        for check in value.get("checks") or []
                    )
                    parts.append(
                        f"<details><summary>{esc(STANDARD_NAMES.get(key, key))}: {value.get('score')}/100 ({value.get('passed')}/{value.get('total')} checks)</summary>"
                        f"<table><thead><tr><th>Check</th><th>Result</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></details>"
                    )
            diff = entry.get("diff")
            if diff:
                d = diff.get("drift") or {}
                link = f' · <a href="../../sbomlyze/{esc(diff["html"])}">full sbomlyze diff</a>' if diff.get("html") else ""
                churn = f" · {diff['reference_churn']} unchanged components re-identified" if diff.get("reference_churn") else ""
                parts.append(
                    f"<p>Compared with the previous run: +{diff['added']} / −{diff['removed']} / {diff['changed']} changed · "
                    f"version drift {d.get('version_drift', 0)}, integrity drift {d.get('integrity_drift', 0)}, "
                    f"metadata drift {d.get('metadata_drift', 0)}{churn}{link}</p>"
                )
        parts.append(self.tool_history(tool))
        self.write(f"tools/{tool}/index.html", self.page(
            f"{tool_name(tool)} SBOM benchmark results", 2, "\n".join(parts),
            f"Weekly {tool_name(tool)} SBOM accuracy, minimum-element checks, and version history against independent ground truth.",
        ))

    def tool_history(self, tool: str) -> str:
        fixtures = [item["id"] for item in self.config["fixtures"]]
        head = "".join(f"<th><code>{esc(item)}</code></th>" for item in fixtures)
        rows = []
        for result in reversed(self.runs):
            runs = self.runs_by_tool(result).get(tool, {})
            cells = []
            for fixture_id in fixtures:
                run = runs.get(fixture_id)
                if not run:
                    cells.append("<td>—</td>")
                    continue
                score = run.get("score") or {}
                change = run.get("change_from_previous") or {}
                text = "PASS" if run.get("status") == "passed" else "FAIL"
                if score.get("expected"):
                    text += f" · {score['found']}/{score['expected']}"
                if score.get("extra"):
                    text += f" · {len(score['extra'])} extra"
                if not change.get("baseline") and (change.get("added") or change.get("removed")):
                    text += f" · Δ +{len(change['added'])}/−{len(change['removed'])}"
                cells.append(f"<td>{esc(text)}</td>")
            version = self.tool_version(result, tool)
            upgraded = tool in (result.get("tool_changes") or {})
            rows.append(
                f"<tr><td><a href=\"../../history/{esc(result['run_date'])}/index.html\">{esc(result['run_date'])}</a></td>"
                f"<td>{esc(version)}{NEW_MARK if upgraded else ''}</td>{''.join(cells)}</tr>"
            )
        return (
            '<h2 id="history">History</h2>'
            '<p class="small">Per input: status · ground truth found · packages reported but not installed · package-level change from the previous run. '
            "Runs recorded before ground truth was added are scored retroactively from their stored inventory.</p>"
            f'<div class="scroll"><table><thead><tr><th>Run</th><th>Version</th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
        )

    def history(self) -> None:
        rows = []
        for result in reversed(self.runs):
            status = '<span class="ok">PASS</span>' if result.get("status") == "passed" else '<span class="bad">FAIL</span>'
            versions = ", ".join(f"{esc(tool_name(t))} {esc(self.tool_version(result, t))}" for t in GENERATORS)
            by_tool = self.runs_by_tool(result)
            image = []
            for tool in GENERATORS:
                run = by_tool.get(tool, {}).get("pinned-container-image")
                score = (run or {}).get("score") or {}
                if score.get("expected"):
                    image.append(f"{esc(tool_name(tool))} {score['found']}/{score['expected']}")
            rows.append(
                f"<tr><td><a href=\"{esc(result['run_date'])}/index.html\">{esc(result['run_date'])}</a></td><td>{status}</td>"
                f"<td>{versions}</td><td>{', '.join(image) or '—'}</td><td><a href=\"../data/runs/{esc(result['run_date'])}.json\">JSON</a></td></tr>"
            )
        body = (
            "<h1>Benchmark history</h1>"
            '<p class="lede">Every recorded run. Each page is frozen at the state of that run.</p>'
            '<div class="scroll"><table><thead><tr><th>Run</th><th>Status</th><th>Generator versions</th>'
            f"<th>Container ground truth found</th><th>Data</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        )
        self.write("history/index.html", self.page("SBOM benchmark history", 1, body, "History of weekly SBOM generator benchmark runs."))
        for result in self.runs:
            latest = result is self.latest
            status = '<span class="ok">PASS</span>' if result.get("status") == "passed" else '<span class="bad">FAIL</span>'
            body = (
                f"<h1>SBOM benchmark run {esc(result['run_date'])}</h1>"
                f'<p class="meta">{status} · <a href="../../data/runs/{esc(result["run_date"])}.json">JSON for this run</a>'
                f'{" · this is the latest run" if latest else ""}</p>'
                + self.run_report(result, depth=2, latest=latest)
            )
            self.write(f"history/{result['run_date']}/index.html", self.page(
                f"SBOM benchmark run {result['run_date']}", 2, body,
                f"SBOM generator benchmark results for {result['run_date']}.",
            ))

    def assets(self) -> None:
        self.write("style.css", STYLE.strip() + "\n")
        data = self.out / "data"
        (data / "runs").mkdir(parents=True, exist_ok=True)
        for name in ("latest.json", "index.json"):
            source = self.args.data_dir / name
            if source.is_file():
                shutil.copyfile(source, data / name)
        for source in (self.args.data_dir / "runs").glob("*.json"):
            shutil.copyfile(source, data / "runs" / source.name)
        artifacts = self.args.artifacts_dir
        if artifacts:
            for name, target in (("raw", "raw"), ("html", "sbomlyze")):
                if (artifacts / name).is_dir():
                    shutil.copytree(artifacts / name, self.out / target, dirs_exist_ok=True)
        self.args.output.mkdir(parents=True, exist_ok=True)
        (self.args.output / "index.html").write_text(
            '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
            f'<meta http-equiv="refresh" content="0; url={SECTION}/index.html">'
            f'<title>Awesome Security Pipeline</title></head><body><p><a href="{SECTION}/index.html">SBOM generator benchmark</a> · '
            f'<a href="https://github.com/{esc(self.repository)}">Awesome Security Pipeline on GitHub</a></p></body></html>\n',
            encoding="utf-8",
        )
        (self.args.output / ".nojekyll").write_text("", encoding="utf-8")

    def build(self) -> None:
        if self.args.output.exists():
            shutil.rmtree(self.args.output)
        self.assets()
        self.overview()
        for tool in GENERATORS:
            self.tool_page(tool)
        self.history()


def main() -> int:
    args = parse_args()
    Site(args).build()
    print(f"Site written to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"site build failed: {exc}", file=sys.stderr)
        sys.exit(1)
