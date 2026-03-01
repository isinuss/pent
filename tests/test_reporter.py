"""Tests for modules/reporter.py — report generation in MD/HTML/JSON formats."""

import json
import os
from io import StringIO

import pytest

from rich.console import Console
from modules.reporter import ReporterModule


def _make_module():
    console = Console(file=StringIO(), force_terminal=False)
    return ReporterModule(console)


# ======================================================================
# _count_severities
# ======================================================================

class TestCountSeverities:

    def test_correct_counts(self, sample_findings):
        mod = _make_module()
        mod.add_findings(sample_findings)
        counts = mod._count_severities()
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 2
        assert counts["low"] == 2
        assert counts["info"] == 1

    def test_empty_findings(self):
        mod = _make_module()
        counts = mod._count_severities()
        assert all(v == 0 for v in counts.values())

    def test_unknown_severity_counted_as_info(self):
        mod = _make_module()
        mod.add_findings([{"severity": "unknown", "title": "test"}])
        counts = mod._count_severities()
        assert counts["info"] == 1


# ======================================================================
# _generate_recommendations
# ======================================================================

class TestGenerateRecommendations:

    def test_xss_recommendation(self):
        mod = _make_module()
        mod.add_findings([{"severity": "high", "category": "XSS", "title": "XSS Found"}])
        recs = mod._generate_recommendations()
        assert any("XSS" in r["title"] or "Cross-Site" in r["title"] for r in recs)

    def test_sqli_recommendation(self):
        mod = _make_module()
        mod.add_findings([{"severity": "high", "category": "SQLi", "title": "SQLi Found"}])
        recs = mod._generate_recommendations()
        assert any("SQL" in r["title"] for r in recs)

    def test_csrf_recommendation(self):
        mod = _make_module()
        mod.add_findings([{"severity": "medium", "category": "CSRF", "title": "No CSRF"}])
        recs = mod._generate_recommendations()
        assert any("CSRF" in r["title"] for r in recs)

    def test_missing_header_recommendation(self):
        mod = _make_module()
        mod.add_findings([{"severity": "medium", "category": "missing_header", "title": "Missing HSTS"}])
        recs = mod._generate_recommendations()
        assert any("Header" in r["title"] for r in recs)

    def test_no_matching_gives_generic(self):
        mod = _make_module()
        mod.add_findings([{"severity": "info", "category": "dns", "title": "DNS record"}])
        recs = mod._generate_recommendations()
        assert len(recs) >= 1  # Generic recommendation

    def test_empty_findings_generic(self):
        mod = _make_module()
        recs = mod._generate_recommendations()
        assert len(recs) == 1
        assert "Continue" in recs[0]["title"]


# ======================================================================
# add_findings
# ======================================================================

class TestAddFindings:

    def test_aggregates_findings(self):
        mod = _make_module()
        mod.add_findings([{"severity": "high", "title": "A"}])
        mod.add_findings([{"severity": "low", "title": "B"}])
        assert len(mod.findings) == 2


# ======================================================================
# generate_markdown
# ======================================================================

class TestGenerateMarkdown:

    def test_file_created(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.tester = "Test Runner"
        mod.add_findings(sample_findings)
        filepath = mod.generate_markdown(str(tmp_path))
        assert os.path.exists(filepath)
        assert filepath.endswith(".md")

    def test_contains_target(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        filepath = mod.generate_markdown(str(tmp_path))
        content = open(filepath).read()
        assert "example.com" in content

    def test_contains_findings(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        filepath = mod.generate_markdown(str(tmp_path))
        content = open(filepath).read()
        assert "CRITICAL" in content
        assert "HIGH" in content


# ======================================================================
# generate_html
# ======================================================================

class TestGenerateHTML:

    def test_file_created(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        filepath = mod.generate_html(str(tmp_path))
        assert os.path.exists(filepath)

    def test_valid_html(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        filepath = mod.generate_html(str(tmp_path))
        content = open(filepath).read()
        assert "<!DOCTYPE html>" in content or "PENT" in content


# ======================================================================
# generate_json
# ======================================================================

class TestGenerateJSON:

    def test_file_created(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        filepath = mod.generate_json(str(tmp_path))
        assert os.path.exists(filepath)
        assert filepath.endswith(".json")

    def test_valid_json(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        filepath = mod.generate_json(str(tmp_path))
        with open(filepath) as f:
            data = json.load(f)
        assert "meta" in data
        assert "summary" in data
        assert "findings" in data
        assert "recommendations" in data

    def test_correct_schema(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.tester = "Bot"
        mod.add_findings(sample_findings)
        filepath = mod.generate_json(str(tmp_path))
        with open(filepath) as f:
            data = json.load(f)
        assert data["meta"]["tool"] == "PENT"
        assert data["meta"]["target"] == "example.com"
        assert data["meta"]["tester"] == "Bot"
        assert data["meta"]["total_findings"] == len(sample_findings)

    def test_all_findings_included(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        filepath = mod.generate_json(str(tmp_path))
        with open(filepath) as f:
            data = json.load(f)
        assert len(data["findings"]) == len(sample_findings)


# ======================================================================
# run
# ======================================================================

class TestRun:

    def test_run_md(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        path = mod.run(output_dir=str(tmp_path), fmt="md")
        assert path.endswith(".md")

    def test_run_json(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        path = mod.run(output_dir=str(tmp_path), fmt="json")
        assert path.endswith(".json")

    def test_run_html(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        path = mod.run(output_dir=str(tmp_path), fmt="html")
        assert os.path.exists(path)

    def test_run_unknown_format_defaults_md(self, sample_findings, tmp_path):
        mod = _make_module()
        mod.target = "example.com"
        mod.add_findings(sample_findings)
        path = mod.run(output_dir=str(tmp_path), fmt="pdf")
        assert path.endswith(".md")
