import datetime as dt
import json
import pathlib
import tempfile
import unittest

from scripts import catalog

CATEGORIES = [
    {"id": "secrets", "title": "Pre-commit & Secrets Detection", "description": "Catch secrets."},
    {"id": "sast", "title": "Static Application Security Testing (SAST)", "description": "Analyze code."},
    {"id": "sast-python", "parent": "sast", "title": "Python"},
]
TODAY = dt.date(2026, 11, 1)


def tool(name, repository, category="secrets", automated=None, **listing):
    entry = {"listing": {"name": name, "repository": repository,
                         "categories": [{"category": category, "description": f"Detect things with {name}."}],
                         "disclosure": None, "use_instead": [], "exception": None, **listing}}
    if automated is not None:
        entry["automated"] = automated
    return entry


class CatalogTest(unittest.TestCase):
    def test_status_rules_follow_the_methodology(self):
        self.assertEqual(catalog.classify("2026-10-01", False, TODAY), "active")
        self.assertEqual(catalog.classify("2026-05-05", False, TODAY), "active")  # 180 days
        self.assertEqual(catalog.classify("2026-05-04", False, TODAY), "stale")  # 181 days
        self.assertEqual(catalog.classify("2025-11-01", False, TODAY), "stale")  # 365 days
        self.assertEqual(catalog.classify("2025-10-30", False, TODAY), "unmaintained")
        self.assertEqual(catalog.classify("2026-10-01", True, TODAY), "archived")
        self.assertEqual(catalog.classify(None, False, TODAY), "unknown")

    def test_sections_move_both_ways_and_respect_exceptions(self):
        self.assertEqual(catalog.section_for("unmaintained", {}, "active"), "legacy")
        self.assertEqual(catalog.section_for("archived", {"exception": "done"}, "active"), "legacy")
        self.assertEqual(catalog.section_for("unmaintained", {"exception": "feature-complete"}, "active"), "active")
        self.assertEqual(catalog.section_for("stale", {}, "legacy"), "active")
        self.assertEqual(catalog.section_for("unknown", {}, "legacy"), "legacy")

    def test_stars_round_to_their_display_value(self):
        self.assertEqual([catalog.round_stars(n) for n in (552, 4749, 30561)], [552, 4700, 30600])
        self.assertEqual([catalog.display_stars(n) for n in (552, 4700, 30600, 4000)], ["552", "4.7k", "30.6k", "4k"])

    def test_refresh_moves_tools_and_reports_changes(self):
        tools = {
            "old.json": tool("old", "o/old", automated={"section": "active", "status": "active", "stars": 10}),
            "back.json": tool("back", "o/back", automated={"section": "legacy", "status": "unmaintained", "stars": 10}),
            "new.json": tool("new", "o/new"),
            "broken.json": tool("broken", "o/broken", automated={"section": "active", "status": "stale", "stars": 7}),
        }
        activity = {"o/old": ("2024-01-01", False), "o/back": ("2026-10-20", False), "o/new": ("2026-10-30", False)}

        def fetch(repository):
            if repository not in activity:
                raise RuntimeError("API unavailable")
            last, archived = activity[repository]
            return {"stars": 1234, "archived": archived, "last_commit": last}

        changes = catalog.refresh(tools, TODAY, fetch, None)

        self.assertEqual(tools["old.json"]["automated"]["section"], "legacy")
        self.assertEqual(tools["back.json"]["automated"]["section"], "active")
        self.assertEqual(tools["new.json"]["automated"]["stars"], 1200)
        self.assertEqual(tools["broken.json"]["automated"], {"section": "active", "status": "stale", "stars": 7, "status_changed": "2026-11-01"})
        self.assertEqual(changes["added"], ["new"])
        self.assertEqual(sorted(changes["moved"]), ["back: legacy → active (active)", "old: active → legacy (unmaintained)"])
        self.assertTrue(changes["errors"][0].startswith("broken:"))

    def test_report_summary_is_read_from_supply_chain_data(self):
        with tempfile.TemporaryDirectory() as directory:
            data = pathlib.Path(directory)
            (data / "projects").mkdir()
            (data / "projects" / "o__tool.json").write_text(json.dumps({"updated": "2026-11-01", "latest": {
                "ref": "v1", "scorecard": {"score": 7.9}, "release_integrity": {"verdict": "verified"},
                "vulnerabilities": [{"severity": "Critical"}, {"severity": "High"}, {"severity": "Low"}]}}))
            summary = catalog.report_summary("o/tool", data)
        self.assertEqual((summary["scorecard"], summary["release"], summary["critical"], summary["high"]), (7.9, "verified", 1, 1))
        self.assertTrue(summary["url"].endswith("/projects/o/tool/"))

    def test_validation_rejects_bad_files_and_automated_edits(self):
        good = {"a.json": tool("a", "o/a"), "b.json": tool("b", "o/b", category="sast-python", use_instead=["a"])}
        self.assertEqual(catalog.validate(good, CATEGORIES), [])
        bad = {
            "Bad.json": tool("x|y", "o/x"),
            "dup.json": tool("dup", "O/A"),
            "parent.json": tool("p", "o/p", category="sast"),
            "alt.json": tool("alt", "o/alt", use_instead=["alt", "missing", "a", "b"]),
            "a.json": tool("a", "o/a"),
        }
        errors = "\n".join(catalog.validate(bad, CATEGORIES))
        for expected in ("file name", "already listed", "unknown category", "up to 3", "'name' is required"):
            self.assertIn(expected, errors)
        base = {"a.json": tool("a", "o/a", automated={"status": "stale"})}
        edited = {"a.json": tool("a", "o/a", automated={"status": "active"})}
        self.assertIn("maintained by the weekly refresh", "\n".join(catalog.validate(edited, CATEGORIES, base)))
        self.assertEqual(catalog.validate({"a.json": tool("a", "o/a"), "n.json": tool("n", "o/n")}, CATEGORIES,
                                          {"a.json": tool("a", "o/a")}), [])
        self.assertIn("cannot point to the tool itself",
                      "\n".join(catalog.validate({"a.json": tool("a", "o/a", use_instead=["a"])}, CATEGORIES)))

    def test_rendering_builds_tables_contents_and_legacy(self):
        tools = {
            "gitleaks.json": tool("gitleaks", "gitleaks/gitleaks", automated={
                "section": "active", "status": "active", "stars": 30600, "last_commit": "2026-10-23",
                "report": {"url": "https://example.invalid/r/", "scorecard": 5.1, "release": "checksums-only"}}),
            "bandit.json": tool("bandit", "PyCQA/bandit", category="sast-python", disclosure="Maintained by us",
                                automated={"section": "active", "status": "stale", "stars": 7000}),
            "old.json": tool("old", "o/old", use_instead=["gitleaks"],
                             automated={"section": "legacy", "status": "archived", "stars": 1200, "last_commit": "2023-01-02"}),
        }
        readme = ("intro <!-- catalog-stats:start --><!-- catalog-stats:end -->\n<!-- catalog-toc:start -->\n<!-- catalog-toc:end -->\n"
                  "<!-- catalog:start -->\n<!-- catalog:end -->\nend")
        rendered = catalog.render_readme(readme, tools, CATEGORIES)
        self.assertIn("**2 actively maintained tools · 1 legacy references", rendered)
        self.assertIn("- [Pre-commit & Secrets Detection](#pre-commit--secrets-detection)", rendered)
        self.assertIn("### Python", rendered)
        self.assertIn('<tr><td align="left"><a href="https://github.com/gitleaks/gitleaks"><b>gitleaks</b></a></td>'
                      '<td align="left">Detect things with gitleaks</td><td align="left">🟢&nbsp;Active<br><sub>Oct 2026</sub></td>'
                      '<td align="right">30.6k</td><td align="left"><a href="https://example.invalid/r/">5.1</a></td>'
                      '<td align="left">Checksums</td></tr>', rendered)
        self.assertIn("<sub><i>Maintained by us.</i></sub>", rendered)
        self.assertIn("### Pre-commit & Secrets Detection", rendered.split("## Legacy and Reference Tools")[1])
        self.assertIn('<a href="https://github.com/gitleaks/gitleaks">gitleaks</a></td></tr>', rendered.split("## Legacy")[1])
        self.assertTrue(rendered.endswith("end"))
        self.assertEqual(catalog.render_readme(rendered, tools, CATEGORIES), rendered)

    def test_tables_use_percentage_columns_with_one_auto_column(self):
        rendered = catalog.table(catalog.ACTIVE_COLUMNS, [["<b>x</b>", "a &amp; b", "s", "1", "2", "3"]])
        widths = [int(value) for value in __import__("re").findall(r'width="(\d+)%"', rendered)]
        self.assertEqual(sum(widths), 100)
        self.assertEqual(rendered.count("<th "), 6)
        self.assertEqual(len(widths), 5)
        self.assertEqual(catalog.describe({"disclosure": None}, "Use <b> & co."), "Use &lt;b&gt; &amp; co")

    def test_repository_files_are_valid_and_readme_is_current(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        tools = catalog.load_tools(root / "tools")
        categories = catalog.load_categories(root / "tools")
        self.assertEqual(catalog.validate(tools, categories), [])
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertEqual(catalog.render_readme(readme, tools, categories), readme)


if __name__ == "__main__":
    unittest.main()
