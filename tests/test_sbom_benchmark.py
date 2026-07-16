import json
import pathlib
import tempfile
import unittest

from scripts import sbom_benchmark


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


if __name__ == "__main__":
    unittest.main()
