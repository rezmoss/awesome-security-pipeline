import unittest

from scripts import site_exports
from scripts import site_triage as triage
from scripts import supply_chain_scan as scan


def row(repository="o/a", **fields):
    return {"id": repository.replace("/", "__"), "repository": repository, "name": repository.split("/")[1], **fields}


def vuln(identifier, package, version, severity="High", **fields):
    return {"id": identifier, "package": package, "version": version, "severity": severity, **fields}


class ScorecardTest(unittest.TestCase):
    def test_only_scores_from_the_same_live_source_are_compared(self):
        before = row(scorecard=3.8, scorecard_source="openssf-api")
        self.assertEqual(triage.score_delta(before, row(scorecard=3.0, scorecard_source="openssf-api")), -0.8)
        self.assertIsNone(triage.score_delta(before, row(scorecard=3.0, scorecard_source="scorecard-cli")))
        self.assertIsNone(triage.score_delta(before, row(scorecard=3.0, scorecard_source="carried-forward")))
        self.assertIsNone(triage.score_delta(before, row(scorecard=3.0, scorecard_source="openssf-api", stale=True)))
        self.assertIsNone(triage.score_delta(before, row(scorecard=3.0, scorecard_source="openssf-api", errors=["x"])))
        self.assertIsNone(triage.score_delta(before, row(scorecard=None, scorecard_source=None)))
        self.assertIsNone(triage.score_delta(None, row(scorecard=3.0, scorecard_source="openssf-api")))

    def test_a_score_that_is_not_compared_says_why(self):
        before = row(scorecard=5.7, scorecard_source="openssf-api")
        self.assertEqual(triage.score_change_reason(before, row(scorecard=5.5, scorecard_source="scorecard-cli")), "source changed")
        self.assertEqual(triage.score_change_reason(before, row(scorecard=5.5, scorecard_source="carried-forward")), "carried forward")
        self.assertIsNone(triage.score_change_reason(before, row(scorecard=5.5, scorecard_source="openssf-api")))
        self.assertIsNone(triage.score_change_reason(before, row(scorecard=5.7, scorecard_source="scorecard-cli")))


class AdvisoryTest(unittest.TestCase):
    def test_severe_pairs_count_each_advisory_and_package_once(self):
        change = {"new_vulnerabilities": [vuln("GHSA-1", "dnspython", "2.8.0"), vuln("GHSA-1", "dnspython", "2.9.0"),
                                          vuln("GHSA-2", "x", "1", "Medium"), vuln("CVE-9", "y", "1", "Critical")]}
        self.assertEqual(triage.severe_pairs(change, {"CVE-9": "GHSA-9"}), {("GHSA-1", "dnspython"), ("GHSA-9", "y")})
        self.assertEqual(triage.severe_pairs({"baseline": True, "new_vulnerabilities": change["new_vulnerabilities"]}, {}), set())

    def test_new_advisories_are_grouped_across_tools_most_severe_first(self):
        projects = [
            {"repository": "o/a", "changes": {"new_vulnerabilities": [vuln("GHSA-m", "otel", "1", "Medium"), vuln("GHSA-h", "forge", "1")]}},
            {"repository": "o/b", "changes": {"new_vulnerabilities": [vuln("GHSA-m", "otel", "2", "Medium")]}},
            {"repository": "o/c", "changes": {"baseline": True, "new_vulnerabilities": [vuln("GHSA-h", "forge", "1")]}},
        ]
        grouped = triage.new_by_advisory(projects, {})
        self.assertEqual([record["id"] for record in grouped], ["GHSA-h", "GHSA-m"])
        self.assertEqual(sorted(grouped[1]["tools"]), ["o/a", "o/b"])
        self.assertEqual(sorted(grouped[0]["tools"]), ["o/a"])

    def test_binary_findings_are_grouped_by_advisory(self):
        projects = [{"repository": f"o/{name}", "changes": {"in_binary_new": ["GO-1"]}} for name in "abc"]
        projects.append({"repository": "o/d", "changes": {"in_binary_new": ["GO-2"]}})
        grouped = triage.binary_new_by_advisory(projects, {})
        self.assertEqual([(record["id"], len(record["tools"])) for record in grouped], [("GO-1", 3), ("GO-2", 1)])


class ReleaseTest(unittest.TestCase):
    def test_a_failed_check_is_reported_even_when_another_verifies(self):
        integrity = {"verdict": "verified", "methods": [{"method": "github-attestation", "status": "verified"},
                                                        {"method": "cosign", "status": "failed"}]}
        self.assertEqual(triage.failed_methods(integrity), ["cosign"])
        self.assertEqual(scan.release_evidence(integrity)["failed"], ["cosign"])

    def test_lost_evidence_needs_both_weeks(self):
        before = {"build_provenance": "verified", "signature": "own-workflow", "immutable_release": True}
        after = {"build_provenance": None, "signature": "own-workflow", "immutable_release": None}
        self.assertEqual(triage.evidence_lost(before, after), ["build provenance", "immutable release"])
        self.assertEqual(triage.evidence_lost(None, after), [])
        self.assertEqual(triage.evidence_lost(before, before), [])

    def test_releases_without_files_have_no_evidence(self):
        self.assertIsNone(scan.release_evidence({"verdict": "no-assets"}))
        self.assertIsNone(triage.evidence_of(None))


class EventsTest(unittest.TestCase):
    def test_counts_that_were_not_compared_are_left_out(self):
        before = row(scorecard=8.6, scorecard_source="openssf-api", release_integrity="signed")
        after = row(scorecard=9.2, scorecard_source="openssf-api", release_integrity="verified", release_changed=True,
                    ref="v2", new_advisories=3, new_vulnerabilities=4, new_severe=None, added=None, upgraded=2)
        events = triage.row_events(before, after)
        self.assertIn("new release v2", events)
        self.assertIn("3 new advisories (severity not recorded)", events)
        self.assertIn("Scorecard 8.6 → 9.2", events)
        self.assertIn("release signed → verified", events)
        self.assertIn("2 dependency changes", events)
        self.assertEqual(triage.row_events(row(), row(new_advisories=1, new_severe=1)), ["1 new advisory (1 Critical/High)"])

    def test_weeks_record_revisions_method_changes_and_catalog_changes(self):
        runs = [
            {"date": "2026-11-01", "generated_at": "2026-11-01T05:00:00Z", "projects": [row("o/a"), row("o/gone")]},
            {"date": "2026-11-08", "provenance": {"run": {"id": 7, "attempt": 2}},
             "projects": [row("o/a", release_integrity="verified", scorecard=1.0, scorecard_source="openssf-api"), row("o/new")]},
        ]
        runs[0]["projects"][0].update(release_integrity="signed", scorecard=2.0, scorecard_source="openssf-api")
        payload = triage.week_events(runs, lambda date: date == "2026-11-08", {"o/a": ("immutable", "verified")})
        week = payload["weeks"][0]
        self.assertEqual(payload["first"], "2026-11-01")
        self.assertEqual(payload["latest"], {"date": "2026-11-08", "revision": "7-2"})
        self.assertTrue(week["method_change"])
        self.assertEqual(week["added"], ["new"])
        self.assertEqual(week["events"]["o-new"], "added to the report")
        self.assertEqual(week["removed"], 1)
        # The newest week's verdict change comes from the scan, not from comparing relabelled rows.
        self.assertEqual(week["events"]["o-a"], "Scorecard 2.0 → 1.0; release immutable release only → verified")

    def test_every_recorded_change_is_an_event(self):
        events = triage.row_events(row(), row(in_binary_resolved=2, workflow_resolved=1, file_changes=3, integrity_drift=1,
                                               binary_analysis={"from": "analyzed", "to": "no-binary"}, dependency_state="unavailable"))
        self.assertEqual(events, ["2 removed from binary", "binary not analyzed", "1 workflow finding resolved",
                                  "3 manifest or workflow files changed", "1 package hash change", "dependency changes unavailable"])
        # A comparison that could not be made does not mark a tool as changed on its own.
        self.assertEqual(triage.row_events(row(), row(dependency_state="unavailable", advisory_state="unavailable")), [])

    def test_card_delta(self):
        self.assertEqual(triage.card_delta(10, 7), "−3")
        self.assertEqual(triage.card_delta(6.5, 6.5, 1), "±0")
        self.assertEqual(triage.card_delta(None, 3), "")


class ScanFieldsTest(unittest.TestCase):
    def test_history_entry_records_new_severe_and_release_evidence(self):
        project = {"changes": {"advisory_state": "ok", "new_vulnerabilities": [vuln("A", "p", "1"), vuln("A", "p", "2"),
                                                                                vuln("B", "q", "1", "Low")]},
                   "release_integrity": {"verdict": "immutable", "methods": [{"method": "github-immutable-release", "status": "verified"}]}}
        entry = scan.history_entry("2026-11-15", project)
        self.assertEqual(entry["new_severe"], 1)
        self.assertEqual(entry["release_evidence"], {"build_provenance": None, "signature": None, "immutable_release": True, "failed": []})
        self.assertIsNone(scan.severe_new_count({"advisory_state": "unavailable"}))

    def test_scanner_compares_scorecard_only_from_the_same_live_source(self):
        def project(score, source, **card):
            return {"ref": "v1", "components": [], "vulnerabilities": [], "scorecard": {"score": score, "source": source, **card}}
        change = scan.changes(project(8.0, "openssf-api"), project(5.0, "scorecard-cli"))
        self.assertNotIn("scorecard", change)
        self.assertEqual(change["scorecard_not_compared"], {"from": 8.0, "to": 5.0, "reason": "source changed"})
        self.assertFalse(change["any"])
        change = scan.changes(project(8.0, "scorecard-cli"), project(7.0, "scorecard-cli", carried_forward=True))
        self.assertEqual(change["scorecard_not_compared"]["reason"], "carried forward")
        self.assertEqual(scan.changes(project(8.0, "openssf-api"), project(7.2, "openssf-api"))["scorecard"], {"from": 8.0, "to": 7.2})
        failed = {**project(7.0, "openssf-api"), "errors": ["osv-scanner failed"]}
        self.assertEqual(scan.changes(project(8.0, "openssf-api"), failed)["scorecard_not_compared"]["reason"],
                         "a scan error in one of the two weeks")

    def test_new_severe_merges_aliases_like_new_advisories(self):
        previous = {"ref": "v1", "components": [], "vulnerabilities": []}
        current = {"ref": "v1", "components": [], "vulnerabilities": [
            vuln("GHSA-a", "p", "1", aliases=["CVE-1"], ecosystem="go"), vuln("CVE-1", "p", "1", aliases=["GHSA-a"], ecosystem="go")]}
        change = scan.changes(previous, current)
        self.assertEqual((change["new_advisories"], change["new_severe"]), (1, 1))
        self.assertEqual(scan.history_entry("2026-11-22", {"changes": change})["new_severe"], 1)

    def test_projects_csv_has_previous_week_columns(self):
        text = site_exports.projects_csv([{"repository": "o/a", "scorecard_previous": 3.8, "scorecard_delta": -0.8,
                                           "release_previous": "signed"}])
        header, values = text.splitlines()[:2]
        self.assertTrue(header.endswith("scorecard_previous,scorecard_delta,release_previous"))
        self.assertTrue(values.endswith("3.8,-0.8,signed"))


if __name__ == "__main__":
    unittest.main()
