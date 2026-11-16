"""Derived views of the report data: advisory pivot, CSV exports, Atom feeds, badges, and table script.

Everything here is computed at site build time from the attested JSON in the data branch; none of
it is recorded data in its own right.
"""

from __future__ import annotations

import csv
import io
import json
import urllib.parse
from typing import Any
from xml.sax.saxutils import escape as xml_escape

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
SHIPPED = "vulnerable code in binary"
ID_PREFERENCE = ("GHSA-", "GO-", "CVE-")


# ----- advisory pivot ------------------------------------------------------------------------

def canonical_id(ids: set[str]) -> str:
    for prefix in ID_PREFERENCE:
        matching = sorted(value for value in ids if value.startswith(prefix))
        if matching:
            return matching[0]
    return sorted(ids)[0]


GOVULNCHECK = "govulncheck"


def go_version(version: str) -> str:
    return version.removeprefix("v").removeprefix("go")


def binary_advisories(go: dict[str, Any] | None, module: str | None = None) -> set[str]:
    """Distinct advisories with vulnerable code in the binary; one advisory can affect several modules."""
    return {item["id"] for item in (go or {}).get("findings") or [] if item.get("level") == "symbol"
            and (module is None or (item.get("module") == "stdlib") == (module == "stdlib"))}


def binary_matches(project: dict[str, Any]) -> list[dict[str, Any]]:
    """govulncheck findings with the vulnerable function compiled into the shipped binary that no Grype match
    covers (mostly the Go standard library, which source manifests do not declare), shaped like Grype matches."""
    binary = project.get("go_binary") or {}
    # A Grype match covers a binary finding only for the same advisory, module, and version.
    covered = {(value, item["package"], go_version(item.get("version") or ""))
               for item in project.get("vulnerabilities") or [] if item.get("ecosystem") == "golang"
               for value in (item["id"], *(item.get("aliases") or []))}
    result, seen = [], set()
    for finding in binary.get("findings") or []:
        version = go_version(finding.get("version") or "")
        key = (finding["id"], finding.get("module"), version)
        if finding.get("level") != "symbol" or key in seen or any(
                (value, finding.get("module"), version) in covered for value in (finding["id"], *(finding.get("aliases") or []))):
            continue
        seen.add(key)
        item = {
            "id": finding["id"], "aliases": sorted(finding.get("aliases") or []),
            # The Go vulnerability database does not rate severity.
            "severity": "Unknown", "package": finding.get("module") or "", "version": finding.get("version") or "",
            "ecosystem": "golang", "fixed_in": [finding["fixed_version"]] if finding.get("fixed_version") else [],
            "fix_state": "fixed" if finding.get("fixed_version") else "unknown",
            "url": f"https://pkg.go.dev/vuln/{finding['id']}", "summary": finding.get("summary") or "",
            "location": binary.get("binary") or binary.get("asset") or "", "in_binary": SHIPPED, "source": GOVULNCHECK,
        }
        item.update({name: finding[name] for name in ("kev", "epss") if name in finding})
        result.append(item)
    return result


def match_locations(item: dict[str, Any]) -> list[str]:
    """Every lockfile or manifest that declares the matched version (records before schema 5 kept one)."""
    return item.get("locations") or ([item["location"]] if item.get("location") else [])


OSV_SCANNER = "osv-scanner"


def osv_only_matches(project: dict[str, Any]) -> list[dict[str, Any]]:
    """Advisories only OSV-Scanner reported, shaped like matches for the CSV export (they are not in the advisory
    pivot: their ids are OSV's, not matched against Grype's)."""
    osv = project.get("osv") or {}
    if not osv.get("available"):
        return []
    return [{"id": canonical_id(set(group["ids"])) if group.get("ids") else "", "aliases": sorted(set(group.get("ids") or []) - {canonical_id(set(group["ids"]))}) if group.get("ids") else [],
             "severity": group.get("severity") or "Unknown", "ecosystem": group.get("ecosystem"), "package": group.get("package"),
             "version": group.get("version"), "fixed_in": [], "location": group.get("path") or "", "source": OSV_SCANNER}
            for group in osv.get("osv_only") or []]


def all_matches(project: dict[str, Any]) -> list[dict[str, Any]]:
    """Grype matches in the declared dependencies plus govulncheck-only findings in the shipped binary."""
    return [*(project.get("vulnerabilities") or []), *binary_matches(project)]


def group_advisories(projects: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Merge every match into one record per advisory; ids that alias each other are one advisory.

    Returns (advisories by canonical id, every known id -> canonical id).
    """
    parent: dict[str, str] = {}

    def find(value: str) -> str:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    matches = [(project, item) for project in projects for item in all_matches(project)]
    for _, item in matches:
        ids = [item["id"], *(item.get("aliases") or [])]
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])
        find(ids[0])
    members: dict[str, set[str]] = {}
    for value in list(parent):
        members.setdefault(find(value), set()).add(value)
    canonical = {root: canonical_id(ids) for root, ids in members.items()}
    aliases = {value: canonical[find(value)] for value in parent}

    advisories: dict[str, dict[str, Any]] = {}
    for project, item in matches:
        key = aliases[item["id"]]
        record = advisories.setdefault(key, {
            "id": key, "aliases": sorted(members[find(item["id"])] - {key}), "severity": "Unknown",
            "summary": "", "urls": set(), "matches": [], "kev": None, "epss": None,
        })
        if SEVERITY_ORDER.index(item["severity"] if item["severity"] in SEVERITY_ORDER else "Unknown") < SEVERITY_ORDER.index(record["severity"]):
            record["severity"] = item["severity"]
        record["summary"] = record["summary"] or item.get("summary") or ""
        if item.get("url"):
            record["urls"].add(item["url"])
        if item.get("kev") and not record["kev"]:
            record["kev"] = item["kev"]
        if item.get("epss") and (not record["epss"] or item["epss"]["score"] > record["epss"]["score"]):
            record["epss"] = item["epss"]
        record.setdefault("kev_checked", False)
        record["kev_checked"] = record["kev_checked"] or "kev" in item
        record["matches"].append({"project": project, "item": item})
    for project in projects:
        # govulncheck summaries describe Go advisories that Grype matched under a GHSA or CVE id.
        for finding in (project.get("go_binary") or {}).get("findings") or []:
            key = aliases.get(finding["id"]) or next((aliases[a] for a in finding.get("aliases") or [] if a in aliases), None)
            if key and not advisories[key]["summary"]:
                advisories[key]["summary"] = finding.get("summary") or ""
    for record in advisories.values():
        record["urls"] = sorted(record["urls"])
        record["tools"] = sorted({entry["project"]["repository"] for entry in record["matches"]}, key=str.lower)
        record["shipped"] = sorted({entry["project"]["repository"] for entry in record["matches"]
                                    if entry["item"].get("in_binary") == SHIPPED}, key=str.lower)
        record["workflow_only"] = all(entry["item"].get("ecosystem") == "github" for entry in record["matches"])
    return advisories, aliases


def worth_indexing(record: dict[str, Any]) -> bool:
    """Single-tool advisories without a binary or KEV signal add little beyond the upstream advisory."""
    return len(record["tools"]) > 1 or bool(record["shipped"]) or bool(record["kev"])


def advisory_path(identifier: str) -> str:
    return f"advisories/{identifier}/"


def upstream_links(record: dict[str, Any]) -> list[tuple[str, str]]:
    ids = [record["id"], *record["aliases"]]
    links = []
    for value in ids:
        if value.startswith("GHSA-"):
            links.append((f"GitHub advisory {value}", f"https://github.com/advisories/{value}"))
        elif value.startswith("GO-"):
            links.append((f"Go vulnerability {value}", f"https://pkg.go.dev/vuln/{value}"))
        elif value.startswith("CVE-"):
            links.append((f"NVD {value}", f"https://nvd.nist.gov/vuln/detail/{value}"))
    links.append((f"OSV {record['id']}", f"https://osv.dev/vulnerability/{record['id']}"))
    return links


# ----- CSV ----------------------------------------------------------------------------------

def csv_cell(value: Any) -> str:
    """Plain text that spreadsheet programs will not evaluate as a formula."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if text[:1] in ("=", "+", "@", "\t", "\r") or (text[:1] == "-" and not _is_number(text)):
        return "'" + text
    return text


def _is_number(text: str) -> bool:
    try:
        float(text)
        return True
    except ValueError:
        return False


def to_csv(header: list[str], rows: list[list[Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    writer.writerows([csv_cell(value) for value in row] for row in rows)
    return buffer.getvalue()


def projects_csv(entries: list[dict[str, Any]]) -> str:
    header = ["repository", "name", "category", "ref", "ref_kind", "dependencies", "critical", "high", "medium", "low",
              "unknown", "vulnerable_packages", "fixable", "kev", "in_binary", "scorecard", "scorecard_source",
              "release_integrity", "workflow_high", "changed", "go_binary_state", "scorecard_previous", "scorecard_delta",
              "release_previous"]
    rows = []
    for entry in entries:
        vulns = entry.get("vulnerabilities") or {}
        rows.append([
            entry["repository"], entry.get("name"), entry.get("category"), entry.get("ref"), entry.get("ref_kind"),
            entry.get("dependencies"), *(vulns.get(level) if vulns else None for level in ("Critical", "High", "Medium", "Low")),
            (vulns.get("Unknown", 0) + vulns.get("Negligible", 0)) if vulns else None,
            entry.get("vulnerable_packages"), entry.get("fixable"), entry.get("kev"),
            (entry.get("in_binary") or {}).get("total"), entry.get("scorecard"), entry.get("scorecard_source"),
            entry.get("release_integrity"), (entry.get("workflow") or {}).get("High"), entry.get("change_any"),
            entry.get("go_binary_state"), entry.get("scorecard_previous"), entry.get("scorecard_delta"),
            entry.get("release_previous"),
        ])
    return to_csv(header, rows)


def binary_analysis(project: dict[str, Any], item: dict[str, Any]) -> str | None:
    """For a Go match: the project's binary-analysis state (analyzed, or why not); empty for other ecosystems and
    for weeks recorded before states existed."""
    status = project.get("go_binary_status")
    if item.get("ecosystem") != "golang" or not status:
        return None
    return status["state"]


def matches_csv(projects: list[dict[str, Any]], aliases: dict[str, str]) -> str:
    header = ["repository", "ref", "source", "advisory", "canonical_advisory", "aliases", "severity", "ecosystem", "package", "version",
              "fixed_in", "location", "osv_confirmed", "in_binary", "kev", "kev_date_added", "epss", "epss_percentile", "locations",
              "binary_analysis"]
    rows = []
    for project in projects:
        for item in [*all_matches(project), *osv_only_matches(project)]:
            kev, epss = item.get("kev"), item.get("epss")
            rows.append([
                project["repository"], project.get("ref"), item.get("source", "grype"), item["id"], aliases.get(item["id"], item["id"]),
                " ".join(item.get("aliases") or []), item["severity"], item.get("ecosystem"), item["package"], item["version"],
                " ".join(item.get("fixed_in") or []), item.get("location"), item.get("osv_confirmed"), item.get("in_binary"),
                (bool(kev) if "kev" in item else None), (kev or {}).get("date_added"),
                (epss or {}).get("score"), (epss or {}).get("percentile"), " ".join(match_locations(item)),
                binary_analysis(project, item),
            ])
    return to_csv(header, rows)


def advisories_csv(advisories: dict[str, dict[str, Any]]) -> str:
    header = ["advisory", "aliases", "severity", "tools", "tools_shipping_vulnerable_code", "kev", "epss", "repositories"]
    rows = [[
        record["id"], " ".join(record["aliases"]), record["severity"], len(record["tools"]), len(record["shipped"]),
        (bool(record["kev"]) if record["kev_checked"] else None), (record["epss"] or {}).get("score"), " ".join(record["tools"]),
    ] for record in sorted(advisories.values(), key=sort_key)]
    return to_csv(header, rows)


def sort_key(record: dict[str, Any]) -> tuple:
    return (-len(record["shipped"]), not record["kev"], SEVERITY_ORDER.index(record["severity"]), -len(record["tools"]), record["id"])


# ----- Atom ---------------------------------------------------------------------------------

def atom_feed(feed_id: str, title: str, self_url: str, page_url: str, entries: list[dict[str, str]]) -> str:
    """entries: id, title, url, updated (RFC 3339), summary (plain text). Newest first."""
    updated = max((entry["updated"] for entry in entries), default="1970-01-01T00:00:00Z")
    items = "".join(
        "<entry>"
        f"<id>{xml_escape(entry['id'])}</id><title>{xml_escape(entry['title'])}</title>"
        f'<link rel="alternate" type="text/html" href="{xml_escape(entry["url"])}"/>'
        f"<updated>{xml_escape(entry['updated'])}</updated>"
        f'<summary type="text">{xml_escape(entry["summary"])}</summary>'
        "</entry>\n"
        for entry in entries
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">\n'
        f"<id>{xml_escape(feed_id)}</id><title>{xml_escape(title)}</title><updated>{xml_escape(updated)}</updated>\n"
        f'<link rel="self" type="application/atom+xml" href="{xml_escape(self_url)}"/>'
        f'<link rel="alternate" type="text/html" href="{xml_escape(page_url)}"/>\n'
        "<author><name>Awesome Security Pipeline supply-chain report</name></author>\n"
        + items + "</feed>\n"
    )


def rfc3339(value: str | None, date: str) -> str:
    """A run's generation time, or midnight UTC of its week when the run predates that field."""
    text = str(value or "")
    if len(text) > 19:
        return text
    return text + "Z" if len(text) == 19 else f"{date}T00:00:00Z"


# ----- badges -------------------------------------------------------------------------------

RELEASE_BADGES = {
    "verified": ("verified", "brightgreen"), "signed": ("signed, not by a project workflow", "yellow"),
    "immutable": ("immutable release only", "yellow"),
    "unverified": ("signature did not verify", "red"), "checksums-only": ("checksums only", "yellow"),
    "none": ("no checksums or signatures", "red"), "no-linux-binary": ("no Linux binary", "lightgrey"),
    "no-assets": ("no release files", "lightgrey"),
}


def badge_json(label: str, message: str, color: str) -> str:
    return json.dumps({"schemaVersion": 1, "label": label, "message": message, "color": color}, sort_keys=True) + "\n"


def release_badge(verdict: str | None, signature: str | None = None) -> str | None:
    if not verdict or verdict not in RELEASE_BADGES:
        return None
    message, color = RELEASE_BADGES[verdict]
    if verdict == "signed" and signature == "key-unchecked":
        message = "signed, key not checked"
    return badge_json("release verification", message, color)


def in_binary_badge(go: dict[str, Any] | None, state: str | None = None) -> str | None:
    if state and state != "analyzed":
        return badge_json("vulnerable code in binary", "not analyzed", "lightgrey")
    if not go:
        return None
    count = len(binary_advisories(go))
    return badge_json("vulnerable code in binary", str(count), "red" if count else "brightgreen")


def shields_url(endpoint: str) -> str:
    return "https://img.shields.io/endpoint?url=" + urllib.parse.quote(endpoint, safe="")


# ----- disputes -----------------------------------------------------------------------------

DISPUTE_TEMPLATE = "report-finding-dispute.yml"


def dispute_url(repository: str, project: dict[str, Any], item: dict[str, Any], page_url: str) -> str:
    fields = {
        "template": DISPUTE_TEMPLATE,
        "title": f"[Finding]: {item['id']} in {project['repository']}",
        "project": project["repository"],
        "advisory": item["id"],
        "package": f"{item['package']}@{item['version']}",
        "version_scanned": str(project.get("ref") or ""),
        "location": page_url,
    }
    return f"https://github.com/{repository}/issues/new?" + urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)


def dispute_key(repository: str, advisory: str, package: str) -> str:
    return f"{repository}|{advisory}|{package}".lower()


# ----- table script -------------------------------------------------------------------------

TABLE_SCRIPT = r"""
// Sorting and filtering for report tables. Tables work without it; nothing is loaded from elsewhere.
(function () {
  function value(cell) {
    var raw = cell.getAttribute('data-sort');
    if (raw === null) raw = cell.textContent.trim();
    var number = parseFloat(raw.replace(/[,†*]/g, ''));
    return { raw: raw.toLowerCase(), number: isNaN(number) || !/^-?[\d.,]+/.test(raw) ? null : number };
  }
  function sortBy(table, index, header) {
    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    var descending = header.getAttribute('aria-sort') !== 'descending';
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function (cell) { cell.removeAttribute('aria-sort'); });
    header.setAttribute('aria-sort', descending ? 'descending' : 'ascending');
    rows.sort(function (a, b) {
      var x = value(a.cells[index]), y = value(b.cells[index]);
      var order;
      if (x.number !== null && y.number !== null) order = x.number - y.number;
      else if (x.number !== null) order = 1;
      else if (y.number !== null) order = -1;
      else order = x.raw < y.raw ? -1 : x.raw > y.raw ? 1 : 0;
      return descending ? -order : order;
    });
    rows.forEach(function (row) { body.appendChild(row); });
  }
  function filter(table, controls) {
    var text = (controls.querySelector('input[type=search]') || { value: '' }).value.toLowerCase();
    var flags = Array.prototype.filter.call(controls.querySelectorAll('input[type=checkbox]'), function (box) { return box.checked; })
      .map(function (box) { return box.getAttribute('data-flag'); });
    var shown = 0;
    Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
      var visible = (!text || row.textContent.toLowerCase().indexOf(text) !== -1)
        && flags.every(function (flag) { return row.hasAttribute('data-' + flag); });
      row.hidden = !visible;
      if (visible) shown++;
    });
    var count = controls.querySelector('.count');
    if (count) count.textContent = shown + ' of ' + table.tBodies[0].rows.length + ' rows';
  }
  Array.prototype.forEach.call(document.querySelectorAll('table.sortable'), function (table) {
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function (header, index) {
      if (header.hasAttribute('data-nosort')) return;
      var button = document.createElement('button');
      button.type = 'button';
      button.className = 'sort';
      while (header.firstChild) button.appendChild(header.firstChild);
      header.appendChild(button);
      button.addEventListener('click', function () { sortBy(table, index, header); });
    });
    var controls = table.id && document.querySelector('[data-controls="' + table.id + '"]');
    if (controls) {
      controls.hidden = false;
      controls.addEventListener('input', function () { filter(table, controls); });
      filter(table, controls);
    }
  });

  var projects = document.getElementById('projects-table');
  var projectControls = projects && document.querySelector('[data-controls="projects-table"]');
  if (!projectControls) return;
  function only(flag) {
    Array.prototype.forEach.call(projectControls.querySelectorAll('input[type=checkbox]'), function (box) {
      box.checked = box.getAttribute('data-flag') === flag;
    });
    var search = projectControls.querySelector('input[type=search]');
    if (search) search.value = '';
    filter(projects, projectControls);
    projectControls.scrollIntoView({ block: 'start' });
  }
  // Each "what got worse" count links to its list; the button next to it shows the matching table rows.
  Array.prototype.forEach.call(document.querySelectorAll('[data-strip]'), function (item) {
    var flag = item.getAttribute('data-strip');
    if (!projects.querySelector('tr[data-' + flag + ']')) return;
    var button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'show in table';
    button.setAttribute('aria-label', 'Show only these tools in the table: ' + item.textContent.trim());
    button.addEventListener('click', function () { only(flag); });
    item.appendChild(button);
  });

  // "Since your last visit": the date of the newest report seen is kept in this browser only.
  var payload = document.getElementById('week-events');
  if (!payload) return;
  var data;
  try { data = JSON.parse(payload.textContent); } catch (error) { return; }
  var latest = data.latest;
  if (!latest || !data.weeks) return;
  function validDate(text) {
    if (typeof text !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return false;
    var date = new Date(text + 'T00:00:00Z');
    return !isNaN(date.getTime()) && date.toISOString().slice(0, 10) === text;
  }
  function storage(kind) {
    try { var store = window[kind]; store.setItem('asp-test', '1'); store.removeItem('asp-test'); return store; }
    catch (error) { return null; }
  }
  function read(store, key) {
    try { return JSON.parse(store.getItem(key)); } catch (error) { return null; }
  }
  function write(store, key, value) {
    try { store.setItem(key, JSON.stringify(value)); } catch (error) { /* storage full or blocked */ }
  }
  var local = storage('localStorage'), session = storage('sessionStorage');
  var since = null, revised = false, fromLink = false;
  var match = /[?&]since=([^&#]*)/.exec(window.location.search);
  if (match) {
    var asked = null;
    try { asked = decodeURIComponent(match[1]); } catch (error) { asked = null; }
    if (validDate(asked) && asked < latest.date) { since = asked; fromLink = true; }
  } else {
    var kept = session && read(session, 'asp-since');
    if (kept && kept.revision === latest.revision) {
      since = validDate(kept.since) ? kept.since : null;
      revised = kept.revised === true;
    } else {
      var seen = local && read(local, 'asp-last-seen');
      if (seen && validDate(seen.date)) {
        if (seen.date < latest.date) since = seen.date;
        else if (seen.date === latest.date && seen.revision !== latest.revision) revised = true;
      }
      if (session) write(session, 'asp-since', { since: since, revised: revised, revision: latest.revision });
    }
    if (local) write(local, 'asp-last-seen', latest);
  }
  if (!since && !revised) return;
  var weeks = data.weeks.filter(function (week) { return revised && !since ? week.date === latest.date : week.date > since; });
  if (!weeks.length) return;
  var changed = {};
  weeks.forEach(function (week) {
    Object.keys(week.events).forEach(function (id) {
      (changed[id] = changed[id] || []).push(week.date + (week.method_change ? ' (scan method changed)' : '') + ': ' + week.events[id]);
    });
  });
  var tools = 0;
  Object.keys(changed).forEach(function (id) {
    var row = document.getElementById(id);
    if (!row || row.parentNode !== projects.tBodies[0]) return;
    tools++;
    row.setAttribute('data-since', '');
    row.classList.add('since');
    var cell = row.querySelector('td.change');
    if (!cell) return;
    var box = document.createElement('div');
    box.className = 'since-events';
    var title = document.createElement('strong');
    title.textContent = revised && !since ? 'In this report (not a comparison with the earlier run):' : 'Since ' + since + ':';
    box.appendChild(title);
    changed[id].forEach(function (text) {
      var line = document.createElement('div');
      line.textContent = text;
      box.appendChild(line);
    });
    cell.appendChild(box);
  });
  var label = document.createElement('label');
  var check = document.createElement('input');
  check.type = 'checkbox';
  check.setAttribute('data-flag', 'since');
  label.appendChild(check);
  label.appendChild(document.createTextNode(fromLink ? ' changed since ' + since : ' changed since your last visit'));
  projectControls.insertBefore(label, projectControls.querySelector('label'));
  var added = [], removed = 0, method = [];
  weeks.forEach(function (week) {
    added = added.concat(week.added || []);
    removed += week.removed || 0;
    if (week.method_change) method.push(week.date);
  });
  var text;
  if (revised && !since) {
    text = "This week's report (" + latest.date + ') was re-run since your last visit. Marked rows show this report\'s changes from the week before; '
      + 'they are not a comparison with the earlier run, which is kept in the data under runs/superseded.';
  } else {
    text = (fromLink ? 'Changes recorded since ' : 'Changes recorded since your last visit on ') + since + ': '
      + weeks.length + ' report' + (weeks.length === 1 ? '' : 's') + ' (' + weeks.map(function (week) { return week.date; }).join(', ')
      + '), ' + tools + ' tool' + (tools === 1 ? '' : 's') + ' with changes, marked in blue. Each week is listed separately, not as a net difference.';
    if (data.first && since < data.first) text += ' The report history starts on ' + data.first + '.';
    if (revised) text += " This week's report was also re-run since then.";
  }
  if (method.length) text += ' The scan method changed in ' + method.join(', ') + '; most differences in those weeks come from that.';
  if (added.length) text += ' Added to the report: ' + added.join(', ') + '.';
  if (removed) text += ' ' + removed + ' tool' + (removed === 1 ? '' : 's') + ' left the catalog; see History.';
  text += fromLink ? ' The date comes from this page address.' : ' Your last visit is stored only in this browser.';
  var banner = document.getElementById('since-visit');
  if (!banner) return;
  var message = document.createElement('span');
  message.textContent = text + ' ';
  banner.appendChild(message);
  var show = document.createElement('button');
  show.type = 'button';
  show.textContent = 'show only these tools';
  show.addEventListener('click', function () { only('since'); });
  banner.appendChild(show);
  banner.hidden = false;
  filter(projects, projectControls);
})();
"""

TABLE_STYLE = """
button.sort{all:unset;cursor:pointer}button.sort:focus-visible{outline:2px solid var(--link)}
th[aria-sort=ascending] button.sort::after{content:" \\25B2";font-size:10px}th[aria-sort=descending] button.sort::after{content:" \\25BC";font-size:10px}
[hidden]{display:none!important}
.controls{display:flex;flex-wrap:wrap;gap:14px;align-items:center;margin:10px 0;font-size:14px}
.controls input[type=search]{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);min-width:220px}
.sev-Unknown{color:#1f2328;background:#eaeef2}.kev{color:#fff;background:#6639ba}
"""
