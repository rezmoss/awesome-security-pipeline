import json
import pathlib
import tempfile
import unittest
import unittest.mock

from scripts import build_site
from scripts import supply_chain_checks as checks
from scripts import supply_chain_scan as scan


README = """# List

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
    def test_catalog_parsing_stops_at_legacy_section_and_deduplicates(self):
        entries = scan.parse_catalog(README)

        self.assertEqual([item["repository"] for item in entries], ["aquasecurity/trivy", "gitleaks/gitleaks"])
        self.assertEqual(entries[1]["category"], "Secrets Detection")
        self.assertEqual(entries[0]["category"], "Secrets Detection › Container Security › Image Scanning")

    def test_only_manifests_outside_test_and_fixture_directories_are_fetched(self):
        self.assertTrue(scan.wanted_path("go.mod"))
        self.assertTrue(scan.wanted_path("web/package-lock.json"))
        self.assertTrue(scan.wanted_path("requirements-dev.txt"))
        self.assertTrue(scan.wanted_path(".github/workflows/ci.yml"))
        self.assertFalse(scan.wanted_path("pkg/testdata/go.mod"))
        self.assertFalse(scan.wanted_path("integration/fixtures/package-lock.json"))
        self.assertFalse(scan.wanted_path("examples/app/requirements.txt"))
        self.assertFalse(scan.wanted_path("main.go"))

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
            argv = ["scan", "publish", "--shards-dir", str(root / week), "--data-dir", str(data), "--date", date]
            with unittest.mock.patch("sys.argv", argv):
                self.assertEqual(scan.main(), 0)

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
        for path in ("history/index.html", "history/2026-11-08/index.html", "data/index.json", "style.css"):
            self.assertTrue((site / path).is_file(), path)


if __name__ == "__main__":
    unittest.main()
