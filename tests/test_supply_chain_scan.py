import csv
import gzip
import io
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
import unittest.mock
import urllib.error
import urllib.parse
from xml.etree import ElementTree

from scripts import build_site
from scripts import enrichment
from scripts import site_exports
from scripts import supply_chain_checks as checks
from scripts import supply_chain_scan as scan

ROOT = pathlib.Path(__file__).resolve().parent.parent


UNUSED_README = """# List

## Secrets Detection

- [gitleaks](https://github.com/gitleaks/gitleaks) - Detect secrets. ![Active](x) ![Stars](y)

### Container Security › Image Scanning

- [trivy](https://github.com/aquasecurity/trivy) - Scan images. ![Active](x)
- [gitleaks again](https://github.com/gitleaks/gitleaks) - Duplicate entry. ![Active](x)

## Legacy and Reference Tools

- [old](https://github.com/example/old) - Archived. ![Archived](x)
"""


def component(name, version, ecosystem="golang", licenses=None):
    return {"name": name, "version": version, "purl": f"pkg:{ecosystem}/{name}@{version}",
            "ecosystem": ecosystem, "licenses": licenses or [], "location": "go.mod"}


def finding(identifier, package, severity="High"):
    return {"id": identifier, "aliases": [], "severity": severity, "package": package, "version": "1",
            "ecosystem": "golang", "fixed_in": ["2"], "fix_state": "fixed", "url": "", "location": "go.mod"}


class SupplyChainScanTest(unittest.TestCase):
    def test_targets_come_from_active_tool_files(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        entries = scan.active_catalog(root / "tools")
        repositories = {item["repository"] for item in entries}

        self.assertIn("gitleaks/gitleaks", repositories)
        self.assertTrue(all(item["category"] and item["description"] for item in entries))
        self.assertEqual(len(repositories), len(entries))

    def test_only_manifests_outside_test_and_fixture_directories_are_fetched(self):
        self.assertTrue(scan.wanted_path("go.mod"))
        self.assertTrue(scan.wanted_path("web/package-lock.json"))
        self.assertTrue(scan.wanted_path("requirements-dev.txt"))
        self.assertTrue(scan.wanted_path(".github/workflows/ci.yml"))
        self.assertFalse(scan.wanted_path("pkg/testdata/go.mod"))
        self.assertFalse(scan.wanted_path("integration/fixtures/package-lock.json"))
        self.assertFalse(scan.wanted_path("examples/app/requirements.txt"))
        self.assertFalse(scan.wanted_path("main.go"))
        for path in ("java/ql/integration-tests/app/pom.xml", "syft/test-fixtures/go.mod", "functional-tests/Cargo.toml",
                     "pkg/gotestdata/go.mod", "server-mock/package.json", "ql/test/query-tests/.github/actions/a/action.yml"):
            self.assertFalse(scan.wanted_path(path), path)
        for path in ("latest/package.json", "attestation/go.mod", ".github/actions/build/action.yml", "contest/pyproject.toml"):
            self.assertTrue(scan.wanted_path(path), path)

    def test_duplicate_declarations_merge_independent_of_order(self):
        def entry(location, licenses):
            return {"type": "library", "name": "ms", "version": "2.1.3", "purl": "pkg:npm/ms@2.1.3",
                    "licenses": [{"license": {"id": item}} for item in licenses],
                    "properties": [{"name": "syft:location:0:path", "value": location}]}

        first = scan.normalize_sbom({"components": [entry("/b/package-lock.json", ["MIT"]), entry("/a/package-lock.json", [])]})
        second = scan.normalize_sbom({"components": [entry("/a/package-lock.json", []), entry("/b/package-lock.json", ["MIT"])]})

        self.assertEqual(first, second)
        self.assertEqual((first[0]["licenses"], first[0]["location"]), (["MIT"], "a/package-lock.json"))

    def test_grype_matches_are_normalized_and_deduplicated(self):
        match = {
            "vulnerability": {"id": "GHSA-1", "severity": "High", "fix": {"versions": ["1.2"], "state": "fixed"},
                              "dataSource": "https://example.invalid"},
            "relatedVulnerabilities": [{"id": "CVE-1"}, {"id": "GHSA-1"}],
            "artifact": {"name": "x/crypto", "version": "1.0", "purl": "pkg:golang/x/crypto@1.0",
                         "locations": [{"path": "/go.mod"}]},
        }

        findings = scan.normalize_grype({"matches": [match, match]})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["aliases"], ["CVE-1"])
        self.assertEqual((findings[0]["fixed_in"], findings[0]["location"]), (["1.2"], "go.mod"))

    def test_matches_without_an_installed_registry_version_are_excluded_and_counted(self):
        def match(identifier, name, version, purl_type):
            return {"vulnerability": {"id": identifier, "severity": "Critical"},
                    "artifact": {"name": name, "version": version, "purl": f"pkg:{purl_type}/{name}@{version}",
                                 "locations": [{"path": "/x"}]}}

        excluded = {}
        findings = scan.normalize_grype({"matches": [
            match("GHSA-a", "actions/download-artifact", "v4", "github"),
            match("GHSA-a", "actions/download-artifact", "v4", "github"),
            match("GHSA-b", "pypa/gh-action-pypi-publish", "release/v1", "github"),
            match("GHSA-c", "tj-actions/changed-files", "v44.5.2", "github"),
            match("GHSA-d", "tree-sitter-r", "file:src/tree-sitter-r", "npm"),
            match("GHSA-e", "cloudsplaining", "0.4.8", "npm"),
            match("GHSA-f", "lodash", "4.17.20", "npm"),
        ]}, {"cloudsplaining"}, excluded)

        self.assertEqual(sorted(item["id"] for item in findings), ["GHSA-c", "GHSA-f"])
        self.assertEqual(excluded, {"action reference to a moving tag or branch": 2, "package defined in the repository itself": 2})

    def test_shrinkwrap_is_read_as_a_lockfile_and_local_package_names_are_collected(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = pathlib.Path(temporary.name)
        (source / "a").mkdir()
        (source / "npm-shrinkwrap.json").write_text("{}")
        (source / "a" / "npm-shrinkwrap.json").write_text("{}")
        (source / "a" / "package-lock.json").write_text("{}")
        (source / "package.json").write_text(json.dumps({"name": "snyk", "version": "1.0.0-monorepo"}))
        (source / "a" / "package.json").write_text("not json")

        self.assertEqual(scan.lockfile_aliases(source), {"package-lock.json": "npm-shrinkwrap.json"})
        self.assertTrue((source / "package-lock.json").is_file())
        self.assertEqual(scan.local_npm_packages(source), {"snyk"})

    def test_changes_classify_upgrades_additions_removals_and_advisories(self):
        previous = {"ref": "v1", "components": [component("a", "1"), component("b", "1"), component("c", "1"),
                                                  component("d", "1"), component("d", "2")],
                    "vulnerabilities": [finding("OLD", "a")]}
        current = {"ref": "v2", "components": [component("a", "2"), component("c", "1"), component("e", "1"),
                                                 component("d", "1")],
                   "vulnerabilities": [finding("NEW", "e", "Critical")]}

        change = scan.changes(previous, current)

        self.assertTrue(change["release_changed"])
        self.assertEqual(change["upgraded"], [{"package": "a", "ecosystem": "golang", "from": "1", "to": "2"}])
        self.assertEqual(change["added"], ["e@1"])
        self.assertEqual(change["removed"], ["b@1", "d@2"])
        self.assertEqual([item["id"] for item in change["new_vulnerabilities"]], ["NEW"])
        self.assertEqual([item["id"] for item in change["resolved_vulnerabilities"]], ["OLD"])
        self.assertTrue(change["any"])
        self.assertTrue(scan.changes(None, current)["baseline"])

    def test_cvss_scores_map_to_severity_buckets(self):
        self.assertEqual([checks.cvss_bucket(value) for value in ("9.8", "7.5", "5.3", "2.0", "", None)],
                         ["Critical", "High", "Medium", "Low", "Unknown", "Unknown"])

    def test_osv_cross_reference_uses_aliases_and_package(self):
        grype = [finding("GHSA-1", "a"), finding("GHSA-2", "b")]
        grype[0]["aliases"] = ["CVE-1"]
        osv = {"groups": [
            {"ids": ["GO-1", "CVE-1"], "package": "a", "version": "1", "ecosystem": "Go", "severity": "High", "score": "7.5"},
            {"ids": ["GHSA-2"], "package": "other", "version": "1", "ecosystem": "Go", "severity": "Low", "score": "2"},
        ]}

        result = checks.cross_reference(grype, osv)

        self.assertEqual([item["osv_confirmed"] for item in grype], [True, False])
        self.assertEqual((result["advisories"], result["confirmed"], len(result["osv_only"])), (2, 1, 1))
        self.assertFalse(checks.cross_reference(None, osv)["available"])

    def test_linux_amd64_release_asset_selection(self):
        assets = [{"name": name, "size": 1000} for name in (
            "tool_1.0_linux_arm64.tar.gz", "tool_1.0_linux_amd64.tar.gz", "tool_1.0_linux_amd64.tar.gz.sig",
            "tool_1.0_linux_amd64.sbom.json", "tool_1.0_checksums.txt", "tool_1.0_darwin_amd64.tar.gz",
            "tool-1.0-x86_64.rpm", "helper_1.0_linux_amd64.tar.gz")]

        selected = checks.select_linux_asset(assets, "owner/tool")

        self.assertEqual(selected["name"], "tool_1.0_linux_amd64.tar.gz")
        self.assertIsNone(checks.select_linux_asset([{"name": "tool.whl", "size": 10}], "owner/tool"))
        raw = checks.select_linux_asset([{"name": "slsa-verifier-linux-amd64", "size": 10}], "owner/slsa-verifier")
        self.assertEqual(raw["name"], "slsa-verifier-linux-amd64")
        for names, expected in (
            (["sops-v3.13.3.darwin.amd64", "sops-v3.13.3.linux.amd64", "sops-v3.13.3.amd64.exe"], "sops-v3.13.3.linux.amd64"),
            (["kube-linter-darwin", "kube-linter-linux", "kube-linter-linux_arm64"], "kube-linter-linux"),
            (["tracee-x86_64.v0.24.1.tar.gz", "checksum-x86_64.v0.24.1.txt"], "tracee-x86_64.v0.24.1.tar.gz"),
        ):
            chosen = checks.select_linux_asset([{"name": name, "size": 10} for name in names], "owner/" + names[0].split("-")[0])
            self.assertEqual(chosen["name"], expected)

    def test_govulncheck_stream_parsing_and_reachability(self):
        stream = '{"config": {}}\n{"SBOM": {"go_version": "go1.24.1", "modules": [{"path": "x/net"}]}}\n' \
                 '{"osv": {"id": "GO-1", "aliases": ["CVE-1"], "summary": "bad"}}\n' \
                 '{"finding": {"osv": "GO-1", "fixed_version": "v2", "trace": [{"module": "x/net", "version": "v1", "package": "x/net/http", "function": "Get"}]}}\n'
        objects = checks.json_stream(stream)
        self.assertEqual(len(objects), 4)
        go = {"modules": ["x/net"], "findings": [{"id": "GO-1", "aliases": ["CVE-1"], "level": "symbol", "module": "x/net"}]}
        grype = [finding("CVE-1", "x/net"), finding("CVE-9", "x/net"), finding("CVE-8", "x/dev-only")]

        checks.annotate_reachability(grype, go)

        self.assertEqual([item["in_binary"] for item in grype],
                         ["vulnerable code in binary", "vulnerable code not in binary", "not in released binary"])

    def write_shard(self, directory, ref, components, vulnerabilities, errors=None):
        project = {
            "id": "gitleaks__gitleaks", "repository": "gitleaks/gitleaks", "name": "gitleaks",
            "description": "Detect <secrets>.", "category": "Secrets", "ref": ref, "ref_kind": "release",
            "released_at": "2026-10-01T00:00:00Z", "commit": "abc", "scanned_at": "2026-11-01T00:00:00Z",
            "manifests": ["go.mod"], "errors": errors or [],
        }
        if components is not None:
            project.update(components=components, vulnerabilities=vulnerabilities,
                           compliance={"standards": {"ntia": {"score": 71, "passed": 5, "total": 7, "failed_checks": []}}})
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "shard-0.json").write_text(json.dumps({"tools": {"syft": "1", "grype": "2"}, "projects": [project]}))

    def test_weekly_publication_history_and_site(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        data = root / "data"
        self.write_shard(root / "week1", "v1", [component("a", "1")], [])
        self.write_shard(root / "week2", "v2", [component("a", "2")], [finding("GHSA-9", "a", "Critical")])
        self.write_shard(root / "week3", "v2", None, None, errors=["clone failed"])
        for week, date in (("week1", "2026-11-01"), ("week2", "2026-11-08"), ("week3", "2026-11-15")):
            self.publish(root / week, data, date)

        stored = json.loads((data / "projects" / "gitleaks__gitleaks.json").read_text())
        self.assertEqual([item["date"] for item in stored["history"]], ["2026-11-01", "2026-11-08", "2026-11-15"])
        self.assertEqual(stored["history"][1]["upgraded"], 1)
        self.assertEqual(stored["history"][1]["new_vulnerabilities"], 1)
        self.assertTrue(stored["latest"]["stale"])
        self.assertEqual(stored["latest"]["components"], [component("a", "2")])

        site = root / "site"
        argv = ["build", "--output", str(site), "--supply-chain-data", str(data)]
        with unittest.mock.patch("sys.argv", argv):
            self.assertEqual(build_site.main(), 0)
        overview = (site / "index.html").read_text()
        page = (site / "projects" / "gitleaks" / "gitleaks" / "index.html").read_text()
        self.assertIn("Weekly supply-chain report", overview)
        self.assertIn("projects/gitleaks/gitleaks/index.html", overview)
        self.assertIn("The latest scan failed", page)
        self.assertIn("GHSA-9", page)
        self.assertIn("Detect &lt;secrets&gt;.", page)
        self.assertNotIn("Detect <secrets>", page)
        self.assertIn('id="gitleaks-gitleaks"', overview)
        self.assertIn('id="adv-ghsa-9-a-1"', page)
        self.assertIn("history/2026-11-15/index.html#gitleaks-gitleaks", page)
        self.assertIn("predates run-level provenance", page)
        corrections = (site / "corrections" / "index.html").read_text()
        self.assertIn("cargo-audit", corrections)
        self.assertIn("gh attestation verify", (site / "verify" / "index.html").read_text())
        for path in ("history/index.html", "history/2026-11-08/index.html", "data/index.json", "style.css"):
            self.assertTrue((site / path).is_file(), path)

    def publish(self, shards, data, date, enrichment=None, **environment):
        """Publish with only the given GitHub Actions variables, so tests behave the same in CI."""
        argv = ["scan", "publish", "--shards-dir", str(shards), "--data-dir", str(data), "--date", date]
        if enrichment:
            argv += ["--enrichment-dir", str(enrichment)]
        clean = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
        with unittest.mock.patch("sys.argv", argv), unittest.mock.patch.dict(os.environ, {**clean, **environment}, clear=True):
            self.assertEqual(scan.main(), 0)

    def test_scorecard_errors_name_the_actual_cause(self):
        def fail(error):
            return unittest.mock.patch("urllib.request.urlopen", side_effect=error)

        with fail(urllib.error.HTTPError("u", 404, "missing", {}, io.BytesIO())):
            self.assertIn("not in the OpenSSF public dataset", checks.scorecard("a/b", False)["error"])
        with fail(urllib.error.URLError("timed out")):
            self.assertIn("could not be reached (timed out)", checks.scorecard("a/b", False)["error"])
        old = io.BytesIO(json.dumps({"date": "2020-01-01", "score": 5}).encode())
        with unittest.mock.patch("urllib.request.urlopen", return_value=unittest.mock.MagicMock(__enter__=lambda self: old)):
            error = checks.scorecard("a/b", False)["error"]
        self.assertIn("days old (limit 30)", error)
        self.assertIn("budget was used", error)

    def test_publication_records_provenance_checksums_and_scorecard_source(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        data = root / "data"
        self.write_shard(root / "week1", "v1", [component("a", "1")], [])
        shard = json.loads((root / "week1" / "shard-0.json").read_text())
        shard["projects"][0]["scorecard"] = {"score": 6.2, "date": "2026-10-30", "source": "openssf-api", "checks": []}
        shard["environment"] = {"shard": 0, "runner": {"os": "ubuntu24"}, "grype_db": {"built": "2026-11-01"}}
        (root / "week1" / "shard-0.json").write_text(json.dumps(shard))
        self.write_shard(root / "week2", "v1", [component("a", "1")], [])
        self.publish(root / "week1", data, "2026-11-01", GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="2",
                     GITHUB_REPOSITORY="o/r", GITHUB_EVENT_NAME="schedule")
        run = json.loads((data / "runs" / "2026-11-01.json").read_text())
        self.assertEqual(run["provenance"]["run"]["id"], 7)
        self.assertEqual(run["provenance"]["run"]["reason"], "scheduled weekly scan (re-run attempt 2)")
        self.assertEqual(run["provenance"]["run"]["url"], "https://github.com/o/r/actions/runs/7/attempts/2")
        self.assertEqual(run["provenance"]["shards"][0]["runner"], {"os": "ubuntu24"})
        self.assertEqual(run["projects"][0]["scorecard_source"], "openssf-api")
        self.publish(root / "week2", data, "2026-11-08")
        row = json.loads((data / "runs" / "2026-11-08.json").read_text())["projects"][0]
        self.assertEqual((row["scorecard"], row["scorecard_source"], row["scorecard_date"]), (6.2, "carried-forward", "2026-10-30"))
        listed = (data / "SHA256SUMS").read_text()
        self.assertIn("  projects/gitleaks__gitleaks.json\n", listed)
        self.assertNotIn("SHA256SUMS", listed)
        self.assertEqual(scan.verify_tree(data), [])

        # A hand edit anywhere is caught by recomputation or by the checksum list.
        path = data / "projects" / "gitleaks__gitleaks.json"
        stored = json.loads(path.read_text())
        stored["history"][0]["dependencies"] = 99
        path.write_text(json.dumps(stored))
        problems = scan.verify_tree(data)
        self.assertTrue(any("differs from its history entry: dependencies" in item for item in problems), problems)
        self.assertTrue(any("does not match its SHA256SUMS digest" in item for item in problems), problems)

    def test_rerun_of_a_week_keeps_the_replaced_run_and_compares_with_the_previous_week(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        data = root / "data"
        data.mkdir()

        def git(*arguments):
            subprocess.run(["git", "-C", str(data), *arguments], check=True, capture_output=True)

        def commit(message):
            git("add", "--all")
            git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "--quiet", "-m", message)

        git("init", "--quiet")
        self.write_shard(root / "week1", "v1", [component("a", "1")], [])
        self.write_shard(root / "week2", "v2", [component("a", "2")], [])
        self.publish(root / "week1", data, "2026-11-01", GITHUB_RUN_ID="1")
        commit("week 1")
        self.publish(root / "week2", data, "2026-11-08", GITHUB_RUN_ID="2")
        commit("week 2")
        git("tag", "report-2026-11-08")
        self.publish(root / "week2", data, "2026-11-08", GITHUB_RUN_ID="3")
        commit("week 2 again")

        stored = json.loads((data / "projects" / "gitleaks__gitleaks.json").read_text())
        self.assertEqual(len(stored["latest"]["changes"]["upgraded"]), 1, "re-run must compare with 2026-11-01")
        run = json.loads((data / "runs" / "2026-11-08.json").read_text())
        self.assertEqual(run["supersedes"], "runs/superseded/2026-11-08/2-1.json")
        self.assertEqual(json.loads((data / run["supersedes"]).read_text())["provenance"]["run"]["id"], 2)
        problems, count = scan.verify_history(data, ["report-2026-11-08"])
        self.assertEqual((problems, count), ([], 3))

        # Rewriting an earlier week is reported.
        path = data / "runs" / "2026-11-01.json"
        path.write_text(path.read_text().replace('"v1"', '"v0"'))
        commit("rewrite")
        problems, _ = scan.verify_history(data, [])
        self.assertTrue(any("rewrites runs/2026-11-01.json" in item for item in problems), problems)

    @staticmethod
    def write_enrichment(directory, kev_ids, epss):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "kev.json").write_text(json.dumps({"catalogVersion": "1", "vulnerabilities": [
            {"cveID": cve, "dateAdded": "2026-11-02"} for cve in kev_ids]}))
        rows = "".join(f"{cve},{score},0.9\n" for cve, score in epss.items())
        (directory / "epss_scores.csv.gz").write_bytes(gzip.compress(
            f"#model_version:v1,score_date:2026-11-01T00:00:00Z\ncve,epss,percentile\n{rows}".encode()))
        (directory / "enrichment.json").write_text(json.dumps({
            "fetched_at": "2026-11-01T00:00:00+00:00", "kev": {"version": "1", "count": len(kev_ids)}, "epss": {"version": "v1"}}))

    def test_kev_and_epss_are_applied_at_publish_and_new_kev_listings_are_changes(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        data = root / "data"
        vulnerable = finding("GHSA-k", "a")
        vulnerable["aliases"] = ["CVE-2026-1"]
        for week in ("week1", "week2"):
            self.write_shard(root / week, "v1", [component("a", "1")], [dict(vulnerable)])
        self.write_enrichment(root / "e1", [], {"CVE-2026-1": 0.02})
        self.write_enrichment(root / "e2", ["CVE-2026-1"], {"CVE-2026-1": 0.5})
        self.publish(root / "week1", data, "2026-11-01", enrichment=root / "e1")
        self.publish(root / "week2", data, "2026-11-08", enrichment=root / "e2")

        stored = json.loads((data / "projects" / "gitleaks__gitleaks.json").read_text())
        match = stored["latest"]["vulnerabilities"][0]
        self.assertEqual(match["kev"], {"date_added": "2026-11-02", "cve": "CVE-2026-1"})
        self.assertEqual(match["epss"], {"score": 0.5, "percentile": 0.9, "cve": "CVE-2026-1"})
        self.assertEqual([item["id"] for item in stored["latest"]["changes"]["kev_new"]], ["GHSA-k"])
        self.assertTrue(stored["latest"]["changes"]["any"])
        self.assertEqual((stored["history"][0]["kev"], stored["history"][1]["kev"], stored["history"][1]["kev_new"]), (0, 1, 1))
        run = json.loads((data / "runs" / "2026-11-08.json").read_text())
        self.assertEqual(run["provenance"]["enrichment"]["kev"]["version"], "1")
        self.assertEqual(scan.verify_tree(data), [])

        # Without enrichment, matches carry no kev key: "not checked" rather than "not listed".
        unchecked = [dict(vulnerable)]
        enrichment.annotate(unchecked, None)
        self.assertNotIn("kev", unchecked[0])

    def test_site_counts_every_severity_and_writes_advisories_exports_feeds_and_badges(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        data, site = root / "data", root / "site"
        shared_ghsa = finding("GHSA-s", "x/net")
        shared_ghsa["aliases"] = ["CVE-2026-7"]
        shared_ghsa["in_binary"] = "vulnerable code in binary"
        shared_cve = finding("CVE-2026-7", "x/net")
        shared_cve["aliases"] = ["GHSA-s"]
        projects = [
            {"id": "gitleaks__gitleaks", "repository": "gitleaks/gitleaks", "name": "gitleaks", "ref": "v1", "ref_kind": "release",
             "components": [component("x/net", "1")], "errors": [],
             "vulnerabilities": [shared_ghsa, finding("GHSA-u", "x/net", "Unknown"), finding("GHSA-n", "x/net", "Negligible")],
             "go_binary": {"go_version": "go1.24", "binary": "gitleaks", "asset": "a.tar.gz", "main_module": "",
                           "findings": [{"id": "GO-1", "aliases": ["GHSA-s"], "level": "symbol", "module": "x/net",
                                         "version": "1", "summary": "Bad =parsing"}]},
             "release_integrity": {"verdict": "verified"}},
            {"id": "aquasecurity__trivy", "repository": "aquasecurity/trivy", "name": "trivy", "ref": "v2", "ref_kind": "release",
             "components": [component("x/net", "1")], "errors": [], "vulnerabilities": [shared_cve]},
        ]
        (root / "shards").mkdir()
        (root / "shards" / "shard-0.json").write_text(json.dumps({"tools": {}, "projects": projects}))
        self.write_enrichment(root / "e", ["CVE-2026-7"], {"CVE-2026-7": 0.3})
        self.publish(root / "shards", data, "2026-11-01", enrichment=root / "e")
        # Data published before 2026-11-08 compared same-day re-runs; the first week must still read as a first scan.
        stored_path = data / "projects" / "gitleaks__gitleaks.json"
        stored = json.loads(stored_path.read_text())
        stored["latest"]["changes"] = {"any": True, "baseline": False, "scorecard": {"from": 8, "to": 8.2}}
        stored_path.write_text(json.dumps(stored))
        run_path = data / "runs" / "2026-11-01.json"
        run = json.loads(run_path.read_text())
        run["projects"][0]["change_any"] = True
        run_path.write_text(json.dumps(run))
        (data / scan.CHECKSUMS_FILE).unlink()
        argv = ["build", "--output", str(site), "--supply-chain-data", str(data)]
        with unittest.mock.patch("sys.argv", argv):
            self.assertEqual(build_site.main(), 0)

        overview = (site / "index.html").read_text()
        self.assertIn("4 matches of any severity", overview)
        self.assertIn('title="Unknown or negligible severity">Unknown</th>', overview)
        self.assertIn('table class="sortable" id="projects-table"', overview)
        self.assertTrue((site / "report.js").is_file())
        self.assertNotIn("8.2", overview)
        self.assertNotIn('class="changed"', overview)
        self.assertIn("First scan", (site / "projects" / "gitleaks" / "gitleaks" / "index.html").read_text())
        self.assertIn("No attested week has been published yet", (site / "verify" / "index.html").read_text())

        # GHSA-s and CVE-2026-7 alias each other: one advisory page listing both tools.
        page = (site / "advisories" / "GHSA-s" / "index.html").read_text()
        self.assertFalse((site / "advisories" / "CVE-2026-7").exists())
        self.assertIn("trivy", page)
        self.assertIn("gitleaks", page)
        self.assertIn("Bad =parsing", page)
        self.assertIn("not analyzed", page)
        self.assertNotIn("noindex", page)
        self.assertIn("noindex", (site / "advisories" / "GHSA-u" / "index.html").read_text())
        self.assertIn('href="../../../advisories/GHSA-s/index.html"',
                      (site / "projects" / "gitleaks" / "gitleaks" / "index.html").read_text())

        project = (site / "projects" / "gitleaks" / "gitleaks" / "index.html").read_text()
        self.assertIn("template=report-finding-dispute.yml", project)
        self.assertIn("advisory=GHSA-s", project)
        self.assertIn("badges%2Fgitleaks%2Fgitleaks%2Frelease.json", project)
        self.assertEqual(json.loads((site / "badges/gitleaks/gitleaks/in-binary.json").read_text())["message"], "1")
        self.assertFalse((site / "badges/aquasecurity/trivy/in-binary.json").exists())

        matches = list(csv.DictReader(io.StringIO((site / "data" / "matches.csv").read_text())))
        self.assertEqual(len(matches), 4)
        self.assertEqual({row["canonical_advisory"] for row in matches if row["package"] == "x/net" and row["kev"] == "true"}, {"GHSA-s"})
        self.assertEqual(len(list(csv.DictReader(io.StringIO((site / "data" / "advisories.csv").read_text())))), 3)
        self.assertEqual(len(list(csv.DictReader(io.StringIO((site / "data" / "projects.csv").read_text())))), 2)

        feed = ElementTree.parse(site / "feed.xml").getroot()
        atom = "{http://www.w3.org/2005/Atom}"
        self.assertEqual([entry.find(atom + "id").text for entry in feed.findall(atom + "entry")],
                         ["tag:rezmoss.github.io,2026:week/2026-11-01"])
        project_feed = ElementTree.parse(site / "projects" / "gitleaks" / "gitleaks" / "feed.xml").getroot()
        self.assertEqual(len(project_feed.findall(atom + "entry")), 1)

        # Every relative link and asset in the built site must resolve to a file.
        broken = []
        for html in site.rglob("*.html"):
            for target in re.findall(r'(?:href|src)="([^"#?]*)', html.read_text()):
                if not target or re.match(r"[a-z]+:", target):
                    continue
                resolved = (html.parent / urllib.parse.unquote(target)).resolve()
                if not (resolved.is_file() or (resolved / "index.html").is_file()):
                    broken.append(f"{html.relative_to(site)} -> {target}")
        self.assertEqual(broken, [])

    def test_csv_cells_are_never_spreadsheet_formulas(self):
        self.assertEqual([site_exports.csv_cell(value) for value in ("=cmd", "+1+1", "@x", "-2", "-x", None, True)],
                         ["'=cmd", "'+1+1", "'@x", "-2", "'-x", "", "true"])

    def test_every_manual_override_is_documented(self):
        pins = json.loads((ROOT / "benchmarks/supply-chain/release-tags.json").read_text())["projects"]
        for name, entry in pins.items():
            self.assertTrue(entry.get("reason") and entry.get("added") and entry.get("pr"), name)
        corrections = json.loads((ROOT / "benchmarks/supply-chain/corrections.json").read_text())
        for entry in corrections["entries"]:
            self.assertTrue(entry.get("date") and entry.get("summary") and (entry.get("pr") or entry.get("link")), entry)
        for entry in corrections.get("disputes") or []:
            self.assertTrue(entry.get("date") and entry.get("repository") and entry.get("advisory") and entry.get("status")
                            and entry.get("summary") and (entry.get("pr") or entry.get("link")), entry)
        documented = corrections["catalog_exceptions"]
        for path in sorted((ROOT / "tools").glob("*.json")):
            tool = json.loads(path.read_text())
            if (tool.get("listing") or {}).get("exception"):
                meta = documented.get(path.stem) or {}
                self.assertTrue(meta.get("added") and meta.get("pr"), f"{path.name} has an undocumented catalog exception")


if __name__ == "__main__":
    unittest.main()
