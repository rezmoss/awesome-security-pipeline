#!/usr/bin/env python3
"""The tool catalog: one JSON file per tool in tools/, rendered into the README.

Each tool file has two parts:
  listing    written by contributors (name, repository, categories, descriptions, notes)
  automated  written only by the weekly refresh (status, stars, last commit, report summary)

Subcommands:
  validate   check every tool file; with --base, reject edits to the automated part
  refresh    fetch repository activity and the latest supply-chain report, set status and section
  render     rewrite the generated catalog and contents in README.md (--check fails if stale)
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import pathlib
import re
import subprocess
import sys
import time
from typing import Any, Callable

SITE = "https://rezmoss.github.io/awesome-security-pipeline/"
CATALOG_START, CATALOG_END = "<!-- catalog:start -->", "<!-- catalog:end -->"
TOC_START, TOC_END = "<!-- catalog-toc:start -->", "<!-- catalog-toc:end -->"
STATS_START, STATS_END = "<!-- catalog-stats:start -->", "<!-- catalog-stats:end -->"
LISTING_KEYS = {"name", "repository", "categories", "disclosure", "use_instead", "exception"}
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
FILE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*\.json$")
STATUS = {
    "active": ("🟢", "Active"),
    "stale": ("🟡", "Stale"),
    "unmaintained": ("🔴", "Unmaintained"),
    "archived": ("⚪", "Archived"),
}
RELEASE = {"verified": "✓&nbsp;Verified", "signed": "Signed", "checksums-only": "Checksums", "unverified": "Not&nbsp;verified"}
STALE_DAYS, UNMAINTAINED_DAYS = 180, 365
CATALOG_INTRO = (
    "Entries are organized by where they operate in a delivery pipeline. Status reflects repository activity, "
    "not security effectiveness; stars indicate adoption, not quality. Multi-purpose tools may appear in more than "
    "one category with a category-specific description."
)
LEGEND = (
    "**Status:** 🟢 Active (commit in the last 6 months) · 🟡 Stale (6–12 months) · 🔴 Unmaintained (over 12 months) · "
    "⚪ Archived. Unmaintained and archived tools move to [Legacy](#legacy-and-reference-tools) automatically and return "
    f"when they are active again. **Scorecard** (OpenSSF, out of 10) and **Release** (whether the Linux release file's "
    f"signature, provenance, or attestation verifies) come from the [weekly supply-chain report]({SITE}); "
    "select a Scorecard value for the tool's full report. Every column is refreshed weekly from each tool's file in "
    "[`tools/`](tools/)."
)
LEGACY_INTRO = (
    "These projects are kept for migration research and historical context, not recommended for new adoption. "
    "They are listed here because their repositories are archived or have had no commit for over 12 months. "
    "Prefer the alternative noted beside an entry or a maintained tool from the matching category above."
)


# ----- loading and validation ------------------------------------------------------------

def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def load_categories(root: pathlib.Path) -> list[dict[str, Any]]:
    return load_json(root / "categories.json")["categories"]


def load_tools(root: pathlib.Path) -> dict[str, dict[str, Any]]:
    return {path.name: load_json(path) for path in sorted(root.glob("*.json")) if path.name != "categories.json"}


def leaf_categories(categories: list[dict[str, Any]]) -> set[str]:
    parents = {item.get("parent") for item in categories}
    return {item["id"] for item in categories if item["id"] not in parents}


def validate(tools: dict[str, dict[str, Any]], categories: list[dict[str, Any]],
             base: dict[str, dict[str, Any]] | None = None) -> list[str]:
    errors = []
    leaves = leaf_categories(categories)
    seen: dict[str, str] = {}
    for file, tool in tools.items():
        where = f"tools/{file}"
        if not FILE_NAME.match(file):
            errors.append(f"{where}: file name must be lower-case letters, digits, '.', '_' or '-'")
        if set(tool) - {"listing", "automated"} or "listing" not in tool:
            errors.append(f"{where}: top level must contain 'listing' and optionally 'automated'")
            continue
        listing = tool["listing"]
        unknown = set(listing) - LISTING_KEYS
        if unknown:
            errors.append(f"{where}: unknown listing fields: {', '.join(sorted(unknown))}")
        if not isinstance(listing.get("name"), str) or not listing["name"].strip() or re.search(r"[|\[\]\n]", listing["name"]):
            errors.append(f"{where}: 'name' is required and cannot contain '|', '[', ']' or line breaks")
        repository = listing.get("repository")
        if not isinstance(repository, str) or not REPOSITORY.match(repository):
            errors.append(f"{where}: 'repository' must look like 'owner/repo'")
        elif repository.lower() in seen:
            errors.append(f"{where}: repository {repository} is already listed in tools/{seen[repository.lower()]}")
        else:
            seen[repository.lower()] = file
        entries = listing.get("categories")
        if not isinstance(entries, list) or not entries:
            errors.append(f"{where}: 'categories' must be a non-empty list")
            entries = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("category") not in leaves:
                errors.append(f"{where}: unknown category {entry.get('category') if isinstance(entry, dict) else entry!r}; "
                              f"use one of: {', '.join(sorted(leaves))}")
                continue
            description = entry.get("description")
            if not isinstance(description, str) or not 10 <= len(description) <= 160:
                errors.append(f"{where}: each category needs a description of 10 to 160 characters")
            elif "|" in description or "\n" in description:
                errors.append(f"{where}: descriptions cannot contain '|' or line breaks")
        for key in ("disclosure", "exception"):
            if listing.get(key) is not None and not isinstance(listing[key], str):
                errors.append(f"{where}: '{key}' must be text or null")
        alternatives = listing.get("use_instead", [])
        tool_ids = {name.removesuffix(".json") for name in tools}
        if not isinstance(alternatives, list) or len(alternatives) > 3 or len(set(alternatives)) != len(alternatives):
            errors.append(f"{where}: 'use_instead' must be a list of up to 3 different tool ids")
        else:
            for alternative in alternatives:
                if alternative == file.removesuffix(".json"):
                    errors.append(f"{where}: 'use_instead' cannot point to the tool itself")
                elif alternative not in tool_ids:
                    errors.append(f"{where}: 'use_instead' entry '{alternative}' is not a tool in tools/ (use its file name without .json)")
        if base is not None:
            before = (base.get(file) or {}).get("automated")
            if tool.get("automated") != before and not (before is None and not tool.get("automated")):
                errors.append(f"{where}: the 'automated' section is maintained by the weekly refresh; please do not edit it")
    return errors


# ----- status ----------------------------------------------------------------------------

def classify(last_commit: str | None, archived: bool, today: dt.date) -> str:
    if archived:
        return "archived"
    if not last_commit:
        return "unknown"
    days = (today - dt.date.fromisoformat(last_commit[:10])).days
    if days > UNMAINTAINED_DAYS:
        return "unmaintained"
    if days > STALE_DAYS:
        return "stale"
    return "active"


def section_for(status: str, listing: dict[str, Any], current: str | None) -> str:
    if status == "archived":
        return "legacy"
    if status == "unmaintained":
        return "active" if listing.get("exception") else "legacy"
    if status in ("active", "stale"):
        return "active"
    return current or "active"


def round_stars(count: int) -> int:
    """Round to what the README shows, so a file only changes when its display changes."""
    if count < 1000:
        return count
    return int(round(count / 100.0)) * 100


def display_stars(count: int | None) -> str:
    if count is None:
        return "—"
    if count < 1000:
        return str(count)
    value = f"{count / 1000:.1f}".rstrip("0").rstrip(".")
    return f"{value}k"


# ----- refresh ---------------------------------------------------------------------------

def gh_api(endpoint: str) -> Any:
    last_error = ""
    for attempt in range(3):
        completed = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, timeout=60, check=False)
        if completed.returncode == 0:
            return json.loads(completed.stdout)
        last_error = completed.stderr.strip()[:200]
        if "404" in last_error or "403" in last_error:
            break
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(last_error or f"gh api {endpoint} failed")


def fetch_activity(repository: str) -> dict[str, Any]:
    data = gh_api(f"repos/{repository}")
    last_commit = data.get("pushed_at")
    try:
        last_commit = gh_api(f"repos/{repository}/commits/{data['default_branch']}")["commit"]["committer"]["date"]
    except (RuntimeError, KeyError, TypeError):
        pass  # some organizations restrict the commits API; fall back to the last push
    return {"stars": int(data.get("stargazers_count") or 0), "archived": bool(data.get("archived")),
            "last_commit": (last_commit or "")[:10] or None}


def report_summary(repository: str, data_dir: pathlib.Path | None) -> dict[str, Any] | None:
    if not data_dir:
        return None
    path = data_dir / "projects" / f"{repository.replace('/', '__')}.json"
    if not path.is_file():
        return None
    stored = load_json(path)
    latest = stored.get("latest") or {}
    counts = {"Critical": 0, "High": 0}
    for finding in latest.get("vulnerabilities") or []:
        if finding.get("severity") in counts:
            counts[finding["severity"]] += 1
    return {
        "url": f"{SITE}projects/{repository}/",
        "week": stored.get("updated"),
        "version": latest.get("ref"),
        "scorecard": (latest.get("scorecard") or {}).get("score"),
        "release": (latest.get("release_integrity") or {}).get("verdict"),
        "critical": counts["Critical"] if latest.get("vulnerabilities") is not None else None,
        "high": counts["High"] if latest.get("vulnerabilities") is not None else None,
    }


def refresh(tools: dict[str, dict[str, Any]], today: dt.date, fetch: Callable[[str], dict[str, Any]],
            report_data: pathlib.Path | None) -> dict[str, list[str]]:
    """Update every tool's automated section in place and return what changed."""
    changes: dict[str, list[str]] = {"moved": [], "status": [], "release": [], "scorecard": [], "added": [], "errors": []}
    for file, tool in sorted(tools.items()):
        listing = tool["listing"]
        name = listing["name"]
        old = dict(tool.get("automated") or {})
        new = dict(old)
        try:
            activity = fetch(listing["repository"])
            status = classify(activity["last_commit"], activity["archived"], today)
            new.update(stars=round_stars(activity["stars"]), last_commit=activity["last_commit"],
                       archived=activity["archived"], status=status)
        except (RuntimeError, KeyError, ValueError, json.JSONDecodeError) as exc:
            changes["errors"].append(f"{name}: {exc}")
            status = old.get("status", "unknown")
        new["section"] = section_for(status, listing, old.get("section"))
        if old.get("status") != new.get("status") or "status_changed" not in new:
            new["status_changed"] = today.isoformat()
        report = report_summary(listing["repository"], report_data)
        if report is not None:
            new["report"] = report
        if not old:
            changes["added"].append(name)
        else:
            if old.get("section") != new["section"]:
                changes["moved"].append(f"{name}: {old.get('section')} → {new['section']} ({new.get('status')})")
            elif old.get("status") != new.get("status"):
                changes["status"].append(f"{name}: {old.get('status')} → {new.get('status')}")
            before, after = (old.get("report") or {}), (new.get("report") or {})
            if before.get("release") != after.get("release") and before:
                changes["release"].append(f"{name}: {before.get('release')} → {after.get('release')}")
            if before.get("scorecard") != after.get("scorecard") and before.get("scorecard") is not None:
                changes["scorecard"].append(f"{name}: {before.get('scorecard')} → {after.get('scorecard')}")
        if new != old:
            tool["automated"] = new
    return changes


# ----- rendering -------------------------------------------------------------------------

def github_anchor(title: str) -> str:
    return re.sub(r"[^a-z0-9 _-]", "", title.lower()).replace(" ", "-")


def esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


# Column widths as percentages. All columns but ★ have a percentage and together they make 100%, which
# makes the browser stretch every table to the full README width with identical columns; ★ (no width)
# keeps only the space its numbers need. Nothing sets a minimum width, so a table can never overflow.
ACTIVE_COLUMNS = [("Tool", 16, "left"), ("What it does", 44, "left"), ("Status", 15, "left"), ("★", 0, "right"),
                  ("Scorecard", 12, "left"), ("Release", 13, "left")]
LEGACY_COLUMNS = [("Tool", 16, "left"), ("What it did", 42, "left"), ("Status", 17, "left"), ("★", 0, "right"),
                  ("Use instead", 25, "left")]
for _columns in (ACTIVE_COLUMNS, LEGACY_COLUMNS):
    assert sum(width for _, width, _ in _columns) == 100


def table(columns: list[tuple[str, int, str]], rows: list[list[str]]) -> str:
    head = "".join(
        f'<th width="{width}%" align="{align}">{esc(title)}</th>' if width else f'<th align="{align}">{esc(title)}</th>'
        for title, width, align in columns
    )
    body = "\n".join(
        "<tr>" + "".join(f'<td align="{columns[index][2]}">{value}</td>' for index, value in enumerate(row)) + "</tr>"
        for row in rows
    )
    return f"<table>\n<thead><tr>{head}</tr></thead>\n<tbody>\n{body}\n</tbody>\n</table>"


def status_cell(automated: dict[str, Any]) -> str:
    status = automated.get("status")
    if status not in STATUS:
        return "—"
    icon, label = STATUS[status]
    updated = automated.get("last_commit")
    when = dt.date.fromisoformat(updated).strftime("%b %Y") if updated else ""
    return f"{icon}&nbsp;{label}<br><sub>{when}</sub>" if when else f"{icon}&nbsp;{label}"


def link(text: str, url: str, bold: bool = False) -> str:
    label = f"<b>{esc(text)}</b>" if bold else esc(text)
    return f'<a href="{esc(url)}">{label}</a>'


def tool_link(listing: dict[str, Any]) -> str:
    return link(listing["name"], f"https://github.com/{listing['repository']}", bold=True)


def describe(listing: dict[str, Any], description: str) -> str:
    text = esc(description.rstrip("."))
    if listing.get("disclosure"):
        text += f" <sub><i>{esc(listing['disclosure'].rstrip('.'))}.</i></sub>"
    return text


def stars_cell(automated: dict[str, Any]) -> str:
    return display_stars(automated.get("stars")) if automated.get("stars") is not None else "—"


def active_row(listing: dict[str, Any], automated: dict[str, Any], description: str) -> list[str]:
    report = automated.get("report") or {}
    score = report.get("scorecard")
    if report.get("url"):
        scorecard = link(f"{score:.1f}" if isinstance(score, (int, float)) else "report", report["url"])
    else:
        scorecard = f"{score:.1f}" if isinstance(score, (int, float)) else "—"
    return [tool_link(listing), describe(listing, description), status_cell(automated), stars_cell(automated),
            scorecard, RELEASE.get(report.get("release"), "—")]


def legacy_row(listing: dict[str, Any], automated: dict[str, Any], description: str,
               tools: dict[str, dict[str, Any]] | None = None) -> list[str]:
    alternatives = [
        link(tools[f"{item}.json"]["listing"]["name"], f"https://github.com/{tools[f'{item}.json']['listing']['repository']}")
        for item in listing.get("use_instead") or [] if tools and f"{item}.json" in tools
    ]
    return [tool_link(listing), describe(listing, description), status_cell(automated), stars_cell(automated),
            ", ".join(alternatives) or "—"]


def category_path(categories: list[dict[str, Any]], category_id: str) -> list[dict[str, Any]]:
    by_id = {item["id"]: item for item in categories}
    path = [by_id[category_id]]
    while path[0].get("parent"):
        path.insert(0, by_id[path[0]["parent"]])
    return path


def entries_by_section(tools: dict[str, dict[str, Any]], section: str) -> dict[str, list[tuple[dict[str, Any], dict[str, Any], str]]]:
    grouped: dict[str, list[tuple[dict[str, Any], dict[str, Any], str]]] = {}
    for tool in tools.values():
        automated = tool.get("automated") or {}
        if automated.get("section", "active") != section:
            continue
        for entry in tool["listing"]["categories"]:
            grouped.setdefault(entry["category"], []).append((tool["listing"], automated, entry["description"]))
    for rows in grouped.values():
        rows.sort(key=lambda row: row[0]["name"].lower())
    return grouped


def render_catalog(tools: dict[str, dict[str, Any]], categories: list[dict[str, Any]]) -> str:
    active = entries_by_section(tools, "active")
    legacy = entries_by_section(tools, "legacy")
    depth = {item["id"]: len(category_path(categories, item["id"])) for item in categories}
    leaves = leaf_categories(categories)
    lines = [CATALOG_START, "## Tool catalog", "", CATALOG_INTRO, "", LEGEND, ""]
    for category in categories:
        has_tools = any(active.get(item["id"]) for item in categories
                        if item["id"] == category["id"] or category["id"] in [p["id"] for p in category_path(categories, item["id"])])
        if not has_tools:
            continue
        lines += [f"{'#' * (depth[category['id']] + 1)} {category['title']}", ""]
        if category.get("description"):
            lines += [category["description"], ""]
        if category["id"] in leaves and active.get(category["id"]):
            lines += [table(ACTIVE_COLUMNS, [active_row(*row) for row in active[category["id"]]]), ""]
    if legacy:
        lines += ["## Legacy and Reference Tools", "", LEGACY_INTRO, ""]
        for category in categories:
            if not legacy.get(category["id"]):
                continue
            title = " › ".join(item["title"] for item in category_path(categories, category["id"]))
            lines += [f"### {title}", "", table(LEGACY_COLUMNS, [legacy_row(*row, tools) for row in legacy[category["id"]]]), ""]
    lines.append(CATALOG_END)
    return "\n".join(lines)


def render_toc(tools: dict[str, dict[str, Any]], categories: list[dict[str, Any]]) -> str:
    active = entries_by_section(tools, "active")
    lines = [TOC_START, "- [Tool catalog](#tool-catalog)"]
    for category in categories:
        level = len(category_path(categories, category["id"]))
        if level > 2:
            continue
        ids = [item["id"] for item in categories if category["id"] in [p["id"] for p in category_path(categories, item["id"])]]
        if any(active.get(item) for item in ids):
            lines.append(f"{'  ' * (level - 1)}- [{category['title']}](#{github_anchor(category['title'])})")
    if entries_by_section(tools, "legacy"):
        lines.append("- [Legacy and Reference Tools](#legacy-and-reference-tools)")
    lines.append(TOC_END)
    return "\n".join(lines)


def replace_between(text: str, start: str, end: str, replacement: str) -> str:
    if start not in text or end not in text:
        raise ValueError(f"README is missing the {start} … {end} markers")
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    return before + replacement + after


def render_stats(tools: dict[str, dict[str, Any]]) -> str:
    active = sum(1 for tool in tools.values() if (tool.get("automated") or {}).get("section", "active") == "active")
    return (f"{STATS_START}**{active} actively maintained tools · {len(tools) - active} legacy references · "
            f"status and supply-chain checks refreshed weekly**{STATS_END}")


def render_readme(readme: str, tools: dict[str, dict[str, Any]], categories: list[dict[str, Any]]) -> str:
    if STATS_START in readme:
        readme = replace_between(readme, STATS_START, STATS_END, render_stats(tools))
    readme = replace_between(readme, TOC_START, TOC_END, render_toc(tools, categories))
    return replace_between(readme, CATALOG_START, CATALOG_END, render_catalog(tools, categories))


def summary_markdown(changes: dict[str, list[str]], tools: dict[str, dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for tool in tools.values():
        status = (tool.get("automated") or {}).get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    lines = ["## Weekly catalog refresh", "",
             "Status: " + ", ".join(f"{STATUS.get(key, ('', key))[0]} {value} {key}" for key, value in sorted(counts.items())), ""]
    titles = {"moved": "Moved between active and Legacy", "status": "Status changes", "release": "Release verification changes",
              "scorecard": "OpenSSF Scorecard changes", "added": "New tools", "errors": "Could not refresh (previous values kept)"}
    for key, title in titles.items():
        if changes.get(key):
            lines += [f"### {title}", "", *(f"- {item}" for item in changes[key]), ""]
    if not any(changes.values()):
        lines.append("No status, section, or report changes this week; star counts and dates may have been refreshed.")
    return "\n".join(lines) + "\n"


# ----- CLI -------------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tools", type=pathlib.Path, default=pathlib.Path("tools"))
    parser.add_argument("--readme", type=pathlib.Path, default=pathlib.Path("README.md"))
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("validate")
    check.add_argument("--base", type=pathlib.Path, help="tools directory of the base branch")
    update = commands.add_parser("refresh")
    update.add_argument("--report-data", type=pathlib.Path, help="checkout of the supply-chain-data branch")
    update.add_argument("--summary", type=pathlib.Path, help="write a Markdown summary of the changes here")
    update.add_argument("--today", default=dt.date.today().isoformat())
    update.add_argument("--only-new", action="store_true", help="refresh only tools without an automated section")
    render = commands.add_parser("render")
    render.add_argument("--check", action="store_true", help="fail if README.md is not up to date")
    args = parser.parse_args()

    categories = load_categories(args.tools)
    tools = load_tools(args.tools)
    if args.command == "validate":
        base = load_tools(args.base) if args.base and args.base.is_dir() else None
        errors = validate(tools, categories, base)
        for error in errors:
            print(f"::error::{error}")
        print(f"{len(tools)} tool files checked, {len(errors)} problems")
        return 1 if errors else 0
    errors = validate(tools, categories)
    if errors:
        for error in errors:
            print(f"::error::{error}")
        return 1
    if args.command == "refresh":
        selected = {file: tool for file, tool in tools.items() if not args.only_new or not tool.get("automated")}
        changes = refresh(selected, dt.date.fromisoformat(args.today), fetch_activity, args.report_data)
        for file, tool in selected.items():
            path = args.tools / file
            text = dump(tool)
            if path.read_text(encoding="utf-8") != text:
                path.write_text(text, encoding="utf-8")
        if args.summary:
            args.summary.write_text(summary_markdown(changes, tools), encoding="utf-8")
        print(summary_markdown(changes, tools))
        tools = load_tools(args.tools)
    readme = args.readme.read_text(encoding="utf-8")
    rendered = render_readme(readme, tools, categories)
    if args.command == "render" and args.check:
        if rendered != readme:
            print("::error::README.md is out of date with tools/. Run: python3 scripts/catalog.py render")
            return 1
        print("README.md matches tools/")
        return 0
    if rendered != readme:
        args.readme.write_text(rendered, encoding="utf-8")
        print("README.md updated")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"catalog: {exc}", file=sys.stderr)
        sys.exit(1)
