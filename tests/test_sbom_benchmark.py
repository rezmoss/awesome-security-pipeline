import json
import pathlib
import tempfile
import unittest
import unittest.mock

from scripts import build_sbom_site
from scripts import derive_image_ground_truth
from scripts import publish_sbom_benchmark
from scripts import sbom_benchmark
from scripts import sbomlyze_compare


IMAGE_FIXTURE = {
    "id": "image",
    "kind": "image",
    "description": "test image",
    "source_image": "example@sha256:abc",
    "complete_purl_types": ["apk"],
    "expected_components": [
        {"name": "musl", "version": "1.2.6-r2", "relationship": "installed-os-package", "gate": False},
        {"name": "stdlib", "version": "1.26.5", "relationship": "go-toolchain", "gate": False},
    ],
}


def component(name, version, purl="", kind="library", subject=False):
    return {"type": kind, "name": name, "version": version, "purl": purl, "subject": subject}


class SbomBenchmarkTest(unittest.TestCase):
    def write_document(self, document):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = pathlib.Path(temporary.name) / "sbom.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_cyclonedx_components_and_dependency_edges_are_normalized(self):
        path = self.write_document(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "fixture",
                        "version": "1.0.0",
                        "bom-ref": "pkg:npm/fixture@1.0.0",
                        "purl": "pkg:npm/fixture@1.0.0",
                    }
                },
                "components": [
                    {
                        "type": "library",
                        "name": "is-odd",
                        "version": "3.0.1",
                        "bom-ref": "odd-ref",
                        "purl": "pkg:npm/is-odd@3.0.1",
                    },
                    {
                        "type": "library",
                        "name": "is-number",
                        "version": "6.0.0",
                        "bom-ref": "number-ref",
                        "purl": "pkg:npm/is-number@6.0.0",
                    },
                ],
                "dependencies": [
                    {"ref": "pkg:npm/fixture@1.0.0", "dependsOn": ["odd-ref"]},
                    {"ref": "odd-ref", "dependsOn": ["number-ref"]},
                ],
            }
        )

        parsed = sbom_benchmark.parse_document(path)

        self.assertEqual(parsed["specification"], "CycloneDX 1.6")
        self.assertEqual(parsed["component_count"], 3)
        self.assertEqual(parsed["dependency_edge_count"], 2)
        edge = parsed["relationships"][1]
        self.assertEqual((edge["from_name"], edge["to_name"]), ("is-odd", "is-number"))

    def test_spdx_subject_purl_drops_volatile_tag_identifier(self):
        path = self.write_document(
            {
                "spdxVersion": "SPDX-2.2",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-RootPackage",
                        "name": "fixture",
                        "versionInfo": "1.0.0",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:swid/example/fixture@1.0.0?tag_id=random-value",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-Dependency",
                        "name": "dependency",
                        "versionInfo": "2.0.0",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/dependency@2.0.0",
                            }
                        ],
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-RootPackage",
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": "SPDXRef-Dependency",
                    }
                ],
                "files": [],
            }
        )

        parsed = sbom_benchmark.parse_document(path)

        subject = next(item for item in parsed["components"] if item["subject"])
        self.assertEqual(subject["purl"], "pkg:swid/example/fixture@1.0.0")
        self.assertEqual(parsed["dependency_edge_count"], 1)

    def test_expected_relationship_requires_names_versions_and_type(self):
        expected = [
            {
                "from_name": "is-odd",
                "from_version": "3.0.1",
                "to_name": "is-number",
                "to_version": "6.0.0",
                "type": "DEPENDS_ON",
            }
        ]
        relationships = [
            {
                **expected[0],
                "from_purl": "pkg:npm/is-odd@3.0.1",
                "to_purl": "pkg:npm/is-number@6.0.0",
            }
        ]

        result = sbom_benchmark.expected_relationship_results(expected, relationships)

        self.assertTrue(result[0]["found"])
        relationships[0]["to_version"] = "7.0.0"
        result = sbom_benchmark.expected_relationship_results(expected, relationships)
        self.assertFalse(result[0]["found"])

    def test_display_command_removes_workspace_and_output_paths(self):
        repository = pathlib.Path("/workspace/repository")
        output = repository / "benchmark-output"
        command = ["tool", str(repository / "fixture"), str(output / "result.json")]

        rendered = sbom_benchmark.display_command(command, repository, output)

        self.assertNotIn("/workspace/repository", rendered)
        self.assertIn("$REPOSITORY", rendered)
        self.assertIn("$OUTPUT_DIR", rendered)

    def test_versions_match_without_cosmetic_prefixes(self):
        self.assertEqual(sbom_benchmark.normalize_version("go1.26.5"), "1.26.5")
        self.assertEqual(sbom_benchmark.normalize_version("v3.2.0+incompatible"), "3.2.0+incompatible")
        self.assertEqual(sbom_benchmark.normalize_version("vendor-1"), "vendor-1")
        found = sbom_benchmark.identity_found(
            {"name": "stdlib", "version": "1.26.5"}, [component("stdlib", "go1.26.5")]
        )
        self.assertTrue(found)

    def test_score_reports_missed_extra_and_missing_identifiers(self):
        components = [
            component("image", "", kind="container", subject=True),
            component("musl", "1.2.6-r2", "pkg:apk/alpine/musl@1.2.6-r2"),
            component("openssl", "3.5.7-r0", "pkg:apk/alpine/openssl@3.5.7-r0"),
            component("usr/local/go/bin/go", "", kind="application"),
            component("alpine", "3.24.1", kind="operating-system"),
            component("cert", "abc", kind="cryptographic-asset"),
        ]

        score = sbom_benchmark.score_run(IMAGE_FIXTURE, components)

        self.assertEqual((score["found"], score["expected"]), (1, 2))
        self.assertEqual(score["missed"], ["stdlib@1.26.5"])
        self.assertEqual(score["extra"], ["openssl@3.5.7-r0"])
        self.assertEqual(score["missing_purl"], ["usr/local/go/bin/go"])
        self.assertEqual(score["versionless"], ["usr/local/go/bin/go"])
        self.assertEqual(score["packages"], 4)

    def test_inventory_only_entries_become_counts_and_do_not_drive_package_changes(self):
        legacy = {
            "components": [
                component("musl", "1.2.6-r2", "pkg:apk/alpine/musl@1.2.6-r2"),
                component("a.crt", "", kind="file"),
            ]
        }
        packages, counts, digest = sbom_benchmark.split_inventory(
            legacy["components"] + [component("b.crt", "", kind="file")]
        )
        current = {
            "components": packages,
            "relationships": [],
            "inventory_only_counts": counts,
            "inventory_only_digest": digest,
        }

        change = sbom_benchmark.change_from_previous(current, legacy, True)

        self.assertEqual(counts, {"file": 2})
        self.assertEqual((change["added"], change["removed"]), ([], []))
        self.assertTrue(change["inventory_only_changed"])
        self.assertEqual((change["inventory_only_before"], change["inventory_only_after"]), (1, 2))

    def test_relationships_are_limited_to_package_endpoints(self):
        musl = component("musl", "1", "pkg:apk/alpine/musl@1")
        crt = component("a.crt", "", kind="file")
        edges = [
            sbom_benchmark.normalized_relationship(musl, crt, "DEPENDS_ON"),
            sbom_benchmark.normalized_relationship(musl, musl, "DEPENDS_ON"),
        ]

        kept = sbom_benchmark.package_relationships(edges, [musl])

        self.assertEqual(len(kept), 1)

    def test_apk_database_parsing_builds_non_gating_ground_truth(self):
        database = "P:musl\nV:1.2.6-r2\nA:x86_64\n\nP:zlib\nV:1.3.2-r0\n"

        expected = derive_image_ground_truth.ground_truth(database, "go1.26.5\ntime 2026\n")

        self.assertEqual(
            [(item["name"], item["version"]) for item in expected],
            [("musl", "1.2.6-r2"), ("zlib", "1.3.2-r0"), ("stdlib", "1.26.5")],
        )
        self.assertTrue(all(item["gate"] is False for item in expected))

    def test_sbomlyze_summary_nets_out_reidentified_components(self):
        report = {
            "diff": {
                "added": [{"name": "go", "version": ""}, {"name": "new", "version": "2"}],
                "removed": [{"name": "go", "version": ""}],
                "changed": [{"name": "musl", "before": {"version": "1"}, "after": {"version": "1"},
                             "drift": {"type": "integrity"}}],
                "drift_summary": {"version_drift": 0, "integrity_drift": 1, "metadata_drift": 0},
            },
            "findings": {"findings": [{"message": "example"}]},
        }

        summary = sbomlyze_compare.diff_summary(report)

        self.assertEqual((summary["added"], summary["removed"], summary["reference_churn"]), (1, 0, 1))
        self.assertEqual(summary["changed_sample"][0]["drift"], "integrity")

    def write_run(self, directory, date, components, tools=None):
        result = {
            "schema_version": 1,
            "run_date": date,
            "status": "passed",
            "commit": "abc",
            "tools": tools or [{"id": "syft", "version": "v1", "repository": "anchore/syft",
                                "sha256": "0" * 64, "verification": "upstream-checksum"}],
            "fixtures": [{
                "id": "image", "kind": "image", "description": "test image",
                "target": "example@sha256:abc",
                "runs": [{"tool": "syft", "status": "passed", "errors": [], "components": components,
                          "relationships": [], "component_count": len(components)}],
            }],
        }
        path = pathlib.Path(directory) / f"{date}.json"
        path.write_text(json.dumps(result), encoding="utf-8")
        return path

    def test_publication_imports_legacy_runs_scores_them_and_builds_the_site(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        config = root / "fixtures.json"
        config.write_text(json.dumps({"fixtures": [IMAGE_FIXTURE]}), encoding="utf-8")
        musl = component("musl", "1.2.6-r2", "pkg:apk/alpine/musl@1.2.6-r2")
        first = self.write_run(root, "2026-07-01", [musl, component("a.crt", "", kind="file")])
        second = self.write_run(
            root, "2026-07-08",
            [musl, component("<script>", "1", "pkg:apk/alpine/x@1")],
            tools=[{"id": "syft", "version": "v2", "repository": "anchore/syft",
                    "sha256": "1" * 64, "verification": "upstream-checksum"}],
        )
        data = root / "data"
        argv = ["--data-dir", str(data), "--config", str(config), "--seed", str(first), "--seed", str(second)]
        with unittest.mock.patch("sys.argv", ["publish", *argv]):
            self.assertEqual(publish_sbom_benchmark.main(), 0)

        latest = json.loads((data / "latest.json").read_text(encoding="utf-8"))
        run = latest["fixtures"][0]["runs"][0]
        self.assertEqual(run["score"]["found"], 1)
        self.assertTrue(run["score"]["retroactive"])
        self.assertEqual(run["change_from_previous"]["added"], ["pkg:apk/alpine/x@1"])
        self.assertEqual(latest["tool_changes"], {"syft": {"before": "v1", "after": "v2"}})
        index = json.loads((data / "index.json").read_text(encoding="utf-8"))
        self.assertEqual([item["run_date"] for item in index["runs"]], ["2026-07-08", "2026-07-01"])

        site = root / "site"
        argv = ["--data-dir", str(data), "--config", str(config), "--output", str(site)]
        with unittest.mock.patch("sys.argv", ["build", *argv]):
            self.assertEqual(build_sbom_site.main(), 0)
        overview = (site / "sbom-benchmark" / "index.html").read_text(encoding="utf-8")
        self.assertIn("SBOM generator benchmark", overview)
        self.assertIn("1/2", overview)
        self.assertNotIn("<script>", overview)
        for page in ("tools/syft/index.html", "history/index.html", "history/2026-07-01/index.html",
                     "data/runs/2026-07-08.json", "style.css"):
            self.assertTrue((site / "sbom-benchmark" / page).is_file(), page)
        tool_page = (site / "sbom-benchmark" / "tools" / "syft" / "index.html").read_text(encoding="utf-8")
        self.assertIn("&lt;script&gt;", tool_page)


if __name__ == "__main__":
    unittest.main()
