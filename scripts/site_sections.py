"""HTML sections for the supply-chain report: the pipeline diagram, tool list, and per-check panels."""

from __future__ import annotations

import html
from typing import Any

from scripts import supply_chain_checks as checks

TOOLS = (
    ("Syft", "anchore/syft", "syft", "Generates a CycloneDX SBOM from each release's manifests and lockfiles."),
    ("Grype", "anchore/grype", "grype", "Matches the SBOM against known vulnerabilities."),
    ("OSV-Scanner", "google/osv-scanner", "osv-scanner", "Checks the same files against the OSV database to confirm or add matches."),
    ("govulncheck", "golang/vuln", "govulncheck", "For Go tools, finds which advisories have vulnerable code compiled into the released Linux binary."),
    ("zizmor", "zizmorcore/zizmor", "zizmor", "Audits the project's GitHub Actions workflows for injection, unpinned actions, and excessive permissions."),
    ("OpenSSF Scorecard", "ossf/scorecard", "scorecard", "Scores repository security practices such as code review, branch protection, and pinned dependencies."),
    ("Cosign", "sigstore/cosign", "cosign", "Verifies Sigstore signatures on the release binary or its checksums file."),
    ("slsa-verifier", "slsa-framework/slsa-verifier", "slsa-verifier", "Verifies SLSA build provenance published with the release."),
    ("GitHub CLI attestations", "cli/cli", None, "Verifies GitHub artifact attestations for the release binary."),
    ("sbomlyze", "rezmoss/sbomlyze", "sbomlyze", "Diffs each SBOM against last week and scores NTIA, CISA, and BSI minimum elements. Maintained by this repository's maintainer."),
)

VERDICTS = {
    "verified": ("ok", "verified"),
    "signed": ("warn", "signed, not by a project workflow"),
    "immutable": ("warn", "immutable release only"),
    "unverified": ("bad", "signature did not verify"),
    "checksums-only": ("warn", "checksums only"),
    "none": ("bad", "no checksums or signatures"),
    "no-linux-binary": ("zero", "no Linux binary"),
    "no-assets": ("zero", "no release files"),
}


METHOD_NAMES = {
    "cosign": "Cosign signature",
    "slsa-verifier": "SLSA provenance",
    "github-attestation": "GitHub build attestation",
    "github-immutable-release": "GitHub immutable release",
}
STATUS_NAMES = {"key-signature": "signed with a project key", "signed-other-identity": "signed by another identity"}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def box(x: int, y: int, width: int, title: str, subtitle: str = "", accent: bool = False) -> str:
    height = 46 if subtitle else 34
    klass = "box accent" if accent else "box"
    text = f'<text x="{x + width / 2}" y="{y + (19 if subtitle else 22)}" class="title">{esc(title)}</text>'
    if subtitle:
        text += f'<text x="{x + width / 2}" y="{y + 36}" class="sub">{esc(subtitle)}</text>'
    return f'<g><rect class="{klass}" x="{x}" y="{y}" width="{width}" height="{height}" rx="8"/>{text}</g>'


def arrow(x1: float, y1: float, x2: float, y2: float) -> str:
    middle = (x1 + x2) / 2
    return f'<path class="flow" d="M{x1},{y1} C{middle},{y1} {middle},{y2} {x2},{y2}" marker-end="url(#arrowhead)"/>'


def pipeline_diagram(projects: int | None = None) -> str:
    """A self-contained SVG of the weekly pipeline that follows the page's light or dark theme."""
    inputs = {"manifests": 96, "release": 288, "repository": 380}
    tools = [  # (y, title, subtitle, input)
        (10, "Syft", "SBOM", "manifests"),
        (64, "Grype + OSV-Scanner", "known advisories", "manifests"),
        (118, "sbomlyze", "diff + minimum elements", "manifests"),
        (172, "zizmor", "workflow audit", "manifests"),
        (240, "govulncheck", "vulnerable code in binary", "release"),
        (294, "Cosign · slsa-verifier · gh", "release verification", "release"),
        (358, "OpenSSF Scorecard", "repository practices", "repository"),
    ]
    parts = [
        '<svg class="pipeline" viewBox="0 0 1100 420" role="img" aria-labelledby="pipeline-title pipeline-desc">',
        '<title id="pipeline-title">How the weekly supply-chain report is produced</title>',
        '<desc id="pipeline-desc">Every Sunday the catalog\'s tools are resolved to their latest release. Manifests and '
        "workflows go to Syft, Grype, OSV-Scanner, sbomlyze, and zizmor; the release binary and its signatures go to "
        "govulncheck, Cosign, slsa-verifier, and GitHub attestation verification; the repository goes to OpenSSF "
        "Scorecard. Results are compared with the previous week and published here.</desc>",
        '<defs><marker id="arrowhead" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
        '<path d="M0,0 L8,4 L0,8 z" class="head"/></marker></defs>',
        box(10, 175, 150, "Catalog", f"{projects} tools in README" if projects else "tools in README", accent=True),
        box(195, 175, 165, "Latest release", "GitHub API, every Sunday"),
        box(400, inputs["manifests"] - 23, 190, "Manifests & workflows", "sparse checkout, no tests"),
        box(400, inputs["release"] - 23, 190, "Release binary", "Linux amd64 + signatures"),
        box(400, inputs["repository"] - 23, 190, "Repository", "GitHub & OpenSSF data"),
        arrow(160, 198, 195, 198),
    ]
    for name, y in inputs.items():
        parts.append(arrow(360, 198, 400, y))
    for y, title, subtitle, source in tools:
        parts.append(arrow(590, inputs[source], 630, y + 23))
        parts.append(box(630, y, 230, title, subtitle))
        parts.append(arrow(860, y + 23, 900, 185 if y < 200 else 255))
    parts += [
        box(900, 162, 190, "Compare with last week", "data branch history"),
        box(900, 232, 190, "This report", "overview + project pages", accent=True),
        arrow(995, 208, 995, 232),
        "</svg>",
    ]
    return "".join(parts)


PIPELINE_STYLE = """
.pipeline{width:100%;height:auto;max-width:1100px;margin:8px 0 4px}
.pipeline .box{fill:var(--panel);stroke:var(--line);stroke-width:1.2}.pipeline .accent{stroke:var(--link);stroke-width:1.6}
.pipeline .title{fill:var(--fg);font:600 13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-anchor:middle}
.pipeline .sub{fill:var(--muted);font:11px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-anchor:middle}
.pipeline .flow{fill:none;stroke:var(--muted);stroke-width:1.2}.pipeline .head{fill:var(--muted)}
"""


def tools_table(versions: dict[str, Any]) -> str:
    rows = []
    for name, repository, key, role in TOOLS:
        version = versions.get(key) if key else None
        rows.append(
            f'<tr><td><a href="https://github.com/{esc(repository)}">{esc(name)}</a></td><td>{esc(role)}</td>'
            f'<td class="small">{esc(version) if version else "—"}</td></tr>'
        )
    return (
        '<div class="scroll"><table><thead><tr><th>Tool</th><th>What it does here</th><th>Version this week</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def pipeline_section(versions: dict[str, Any], projects: int | None = None, heading: str = "h2") -> str:
    return (
        f'<{heading} id="how-it-works">How this report is made</{heading}>'
        "<p>Every Sunday a GitHub Actions workflow resolves each catalog tool to its latest release and runs the checks below. "
        "Every tool is installed from its own latest release and verified against its published checksum or digest. "
        "Nothing from the scanned projects is built or executed; release binaries are analyzed as files.</p>"
        + pipeline_diagram(projects) + tools_table(versions)
    )


# ----- per-project panels -------------------------------------------------------------

def plural(count: int, word: str, many: str | None = None) -> str:
    return f"{count} {word if count == 1 else many or word + 's'}"


def method_detail(item: dict[str, Any]) -> str:
    parts = [item.get("identity") or item.get("detail") or ""]
    if item.get("covers") and item["covers"] != "asset":
        parts.append(f"via {item['covers']}")
    if item.get("predicates"):
        parts.append(", ".join(item["predicates"]))
    if item.get("status") == "failed" and item.get("error"):
        parts.append(item["error"])
    return "; ".join(part for part in parts if part)


def verdict_cell(verdict: str | None) -> str:
    if not verdict:
        return "—"
    klass, text = VERDICTS.get(verdict, ("zero", verdict))
    return f'<span class="{klass}">{esc(text)}</span>'


def reachability_section(go: dict[str, Any] | None, vulns: list[dict[str, Any]] | None, note: str | None = None,
                         link: Any = None) -> str:
    """`link(finding)` returns (row id or None, advisory cell HTML); without it ids are shown as plain text."""
    if not go:
        return (f'<h2 id="in-binary">Vulnerable code in the released binary</h2><p class="small">{esc(note)}</p>' if note else "")
    symbols = [item for item in go["findings"] if item["level"] == "symbol"]
    stdlib = [item for item in symbols if item["module"] == "stdlib"]
    dependencies = [item for item in symbols if item["module"] != "stdlib"]
    go_matches = [item for item in vulns or [] if item.get("ecosystem") == "golang"]
    not_shipped = sum(1 for item in go_matches if item.get("in_binary") in ("not in released binary", "vulnerable code not in binary"))
    def cell(item: dict[str, Any]) -> tuple[str | None, str]:
        return link(item) if link else (None, f"<code>{esc(item['id'])}</code>")

    rows = "".join(
        (f'<tr id="{esc(cell(item)[0])}">' if cell(item)[0] else "<tr>")
        + f"<td>{cell(item)[1]}<div class=\"small\">{esc(', '.join(item['aliases'][:3]))}</div></td>"
        f"<td><code>{esc(item['module'])}</code></td><td><code>{esc(item['version'])}</code></td>"
        f"<td>{esc(item.get('fixed_version') or '—')}</td><td class=\"small\">{esc(item.get('summary') or '')}</td></tr>"
        for item in symbols
    )
    return (
        '<h2 id="in-binary">Vulnerable code in the released binary</h2>'
        f"<p>govulncheck analyzed <code>{esc(go['binary'])}</code> from <code>{esc(go['asset'])}</code>, built with "
        f"<strong>{esc(go['go_version'])}</strong>. <strong>{plural(len(symbols), 'advisory', 'advisories')}</strong> {'has' if len(symbols) == 1 else 'have'} vulnerable functions compiled into it: "
        f"{len(stdlib)} in the Go standard library and {len(dependencies)} in dependencies.</p>"
        + (f"<p>Of the {len(go_matches)} Go advisories Grype matched in the source, {not_shipped} are in modules or code paths "
           "that are not in the shipped binary.</p>" if go_matches else "")
        + ('<p class="small">The Go linker removes unreachable functions, so a vulnerable function in the binary is likely reachable. '
           "Standard-library advisories are fixed by rebuilding with a newer Go release.</p>")
        + (f'<div class="scroll"><table><thead><tr><th>Advisory</th><th>Module</th><th>Version</th><th>Fixed in</th><th>Summary</th></tr></thead>'
           f"<tbody>{rows}</tbody></table></div>" if rows else '<p class="ok">No vulnerable functions found in the binary.</p>')
    )


def osv_section(osv: dict[str, Any] | None) -> str:
    if not osv or not osv.get("available"):
        return ""
    only = osv.get("osv_only") or []
    rows = "".join(
        f"<tr><td><code>{esc(', '.join(item['ids'][:3]))}</code></td><td><code>{esc(item['package'])}</code></td>"
        f"<td><code>{esc(item['version'])}</code></td><td>{esc(item['severity'])}</td></tr>"
        for item in only
    )
    return (
        '<h3 id="osv">Second opinion: OSV-Scanner</h3>'
        f"<p>OSV-Scanner found {osv['advisories']} advisories in the same files; {osv['confirmed']} of Grype's matches are confirmed by it "
        f"(marked ✓ above). {len(only)} advisories were reported only by OSV-Scanner.</p>"
        + (f'<p class="small warn">{esc(osv["warning"])}</p>' if osv.get("warning") else "")
        + (f"<details><summary>Reported only by OSV-Scanner ({len(only)})</summary><div class=\"scroll\"><table><thead><tr><th>Advisory</th>"
           f"<th>Package</th><th>Version</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table></div></details>" if rows else "")
    )


def release_section(integrity: dict[str, Any] | None, repository: str) -> str:
    if not integrity:
        return ""
    facts = [
        ("Checksums file", integrity.get("checksums_published")),
        ("Signatures", integrity.get("signatures_published")),
        ("SLSA provenance", integrity.get("provenance_published")),
        ("SBOM published with the release", integrity.get("sbom_published")),
    ]
    yes, no = '<span class="ok">yes</span>', '<span class="zero">no</span>'
    published = "".join(f"<li>{esc(label)}: {yes if value else no}</li>" for label, value in facts)
    methods = "".join(
        f"<tr><td>{esc(METHOD_NAMES.get(item['method'], item['method']))}</td><td>{verdict_cell('verified' if item['status'] == 'verified' else 'unverified') if item['status'] in ('verified', 'failed') else esc(STATUS_NAMES.get(item['status'], item['status']))}</td>"
        f"<td class=\"small\">{esc(method_detail(item))}</td></tr>"
        for item in integrity.get("methods") or []
    )
    dimensions = {**checks.integrity_dimensions(integrity.get("methods") or []),
                  **{key: integrity[key] for key in ("build_provenance", "signature", "signer", "immutable_release") if key in integrity}}
    provenance = {"verified": '<span class="ok">verified</span>', "failed": '<span class="bad">did not verify</span>'}.get(
        dimensions["build_provenance"] or "", '<span class="zero">none published</span>')
    signature = {
        "own-workflow": '<span class="ok">verified, signed by a GitHub Actions workflow in this repository</span>',
        "other-identity": '<span class="warn">valid, but signed by an identity outside this repository\'s workflows</span>',
        "key-unchecked": '<span class="warn">signed with a key; the public key is not checked</span>',
        "failed": '<span class="bad">did not verify</span>',
    }.get(dimensions["signature"] or "", '<span class="zero">none</span>')
    if dimensions.get("signer"):
        signature += f' <span class="small">(signer <code>{esc(dimensions["signer"])}</code>)</span>'
    immutable = {True: '<span class="ok">yes</span>', False: '<span class="bad">did not verify</span>'}.get(
        dimensions["immutable_release"], '<span class="zero">no</span>')
    evidence = (f"<li>Build provenance (how and from which source the file was built): {provenance}</li>"
                f"<li>Signature: {signature}</li>"
                f"<li>Immutable release (the file has not changed since it was published; says nothing about how it was built): {immutable}</li>")
    return (
        '<h2 id="release">Release integrity</h2>'
        f"<p>Verdict: <strong>{verdict_cell(integrity.get('verdict'))}</strong>"
        + (f" for <code>{esc(integrity['asset'])}</code>" if integrity.get("asset") else "")
        + (". The download matches GitHub's recorded digest." if integrity.get("digest_matches_github") else ".")
        + "</p>"
        + f"<ul>{evidence}</ul><p class=\"small\">Published with the release:</p><ul>{published}</ul>"
        + (f"<table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>{methods}</tbody></table>" if methods else "")
        + '<p class="small"><strong>Verified</strong> means build provenance, or a signature from one of '
        f"<code>{esc(repository)}</code>'s own GitHub Actions workflows, was checked. A release that is only immutable is "
        "reported as <em>immutable release only</em>, and a valid signature from any other identity as <em>signed</em>.</p>"
    )


def scorecard_section(card: dict[str, Any] | None, note: str | None, repository: str) -> str:
    if not card:
        return ('<h2 id="scorecard">Repository security (OpenSSF Scorecard)</h2>'
                f"<p>No Scorecard result yet ({esc(note or 'not available')}). Results are added as the weekly budget allows.</p>")
    rows = "".join(
        f"<tr><td>{esc(item['name'])}</td><td class=\"num\">{esc(item['score']) if isinstance(item['score'], (int, float)) and item['score'] >= 0 else '—'}</td>"
        f"<td class=\"small\">{esc(item.get('reason') or '')}</td></tr>"
        for item in card.get("checks") or []
    )
    source = "OpenSSF public dataset" if card.get("source") == "openssf-api" else "Scorecard CLI run by this workflow"
    return (
        '<h2 id="scorecard">Repository security (OpenSSF Scorecard)</h2>'
        f"<p>Score <strong>{esc(card.get('score'))}</strong>/10, assessed {esc(card.get('date'))} ({esc(source)}"
        + (", carried forward from an earlier week" if card.get("carried_forward") else "") + "). "
        f'<a href="https://scorecard.dev/viewer/?uri=github.com/{esc(repository)}">Scorecard viewer</a></p>'
        f'<details><summary>All checks</summary><div class="scroll"><table><thead><tr><th>Check</th><th class="num">Score</th><th>Reason</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div></details>"
    )


def workflow_section(audit: dict[str, Any] | None, repository: str, ref: str) -> str:
    if audit is None:
        return ""
    findings = audit.get("findings") or []
    if not findings:
        return ('<h2 id="workflows">GitHub Actions workflow audit (zizmor)</h2>'
                f"<p class=\"ok\">No medium- or high-confidence issues in {audit.get('files', 0)} workflow files.</p>")
    rows = "".join(
        f"<tr><td>{esc(item['severity'])}</td><td><a href=\"{esc(item['url'])}\">{esc(item['rule'])}</a><div class=\"small\">{esc(item['description'])}</div></td>"
        f"<td><a href=\"https://github.com/{esc(repository)}/blob/{esc(ref)}/{esc(item['file'])}{'#L' + str(item['line']) if item.get('line') else ''}\"><code>{esc(item['file'])}{':' + str(item['line']) if item.get('line') else ''}</code></a></td>"
        f"<td class=\"small\">{esc(item.get('note') or '')}</td></tr>"
        for item in findings
    )
    counts = {level: sum(1 for item in findings if item["severity"] == level) for level in ("High", "Medium", "Low")}
    return (
        '<h2 id="workflows">GitHub Actions workflow audit (zizmor)</h2>'
        f"<p>{len(findings)} potential issues in {audit.get('files', 0)} workflow files at this release: "
        f"{counts['High']} high, {counts['Medium']} medium, {counts['Low']} low severity (medium or high confidence only). "
        "Each is a pattern to review, not a confirmed vulnerability.</p>"
        f'<details><summary>All findings</summary><div class="scroll"><table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Note</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div></details>"
    )
