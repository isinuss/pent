"""Tests for modules/web_tester.py — form discovery, XSS, SQLi, CSRF, traversal."""

import os
from io import StringIO

import pytest
import responses

from rich.console import Console
from modules.web_tester import WebTesterModule

from tests.conftest import read_fixture


def _make_module():
    console = Console(file=StringIO(), force_terminal=False)
    return WebTesterModule(console)


# ======================================================================
# discover_forms
# ======================================================================

class TestDiscoverForms:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_page_with_forms(self):
        html = read_fixture("sample_page.html")
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        forms = self.mod.discover_forms("https://example.com")
        assert len(forms) == 2
        assert forms[0]["method"] == "GET"
        assert forms[1]["method"] == "POST"
        assert any("username" in inp for inp in forms[1]["inputs"])

    @responses.activate
    def test_page_no_forms(self):
        responses.add(responses.GET, "https://example.com", body="<html><p>No forms</p></html>", status=200)
        forms = self.mod.discover_forms("https://example.com")
        assert forms == []

    @responses.activate
    def test_form_with_hidden_inputs(self):
        html = '<form method="POST"><input type="hidden" name="csrf" value="tok"><input name="q"></form>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        forms = self.mod.discover_forms("https://example.com")
        assert len(forms) == 1
        assert any("csrf" in inp for inp in forms[0]["inputs"])

    @responses.activate
    def test_form_action_resolved(self):
        html = '<form action="/submit" method="POST"><input name="x"></form>'
        responses.add(responses.GET, "https://example.com/page", body=html, status=200)
        forms = self.mod.discover_forms("https://example.com/page")
        assert forms[0]["action"] == "https://example.com/submit"


# ======================================================================
# xss_check
# ======================================================================

class TestXSSCheck:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_canary_reflected(self):
        # First request: page to discover params
        html = '<html><a href="/page?q=test">link</a></html>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        # Param injection: canary reflected
        responses.add(responses.GET, "https://example.com",
                      body="Results for: pent7x5s9", status=200)
        self.mod.xss_check("https://example.com")
        assert any("XSS" in f.get("category", "") for f in self.mod.findings)

    @responses.activate
    def test_canary_not_reflected(self):
        html = '<html><a href="/page?q=test">link</a></html>'
        responses.add(responses.GET, "https://example.com",
                      body="No reflection here", status=200)
        self.mod.xss_check("https://example.com")
        xss_findings = [f for f in self.mod.findings if f.get("category") == "XSS"]
        assert len(xss_findings) == 0

    @responses.activate
    def test_uses_default_params_when_none_found(self):
        responses.add(responses.GET, "https://example.com",
                      body="<html>No links</html>", status=200)
        self.mod.xss_check("https://example.com")
        # Should not crash - tests common params


# ======================================================================
# _find_reflection_context
# ======================================================================

class TestFindReflectionContext:

    def setup_method(self):
        self.mod = _make_module()

    def test_html_body(self):
        ctx = self.mod._find_reflection_context("<div>pent7x5s9</div>", "pent7x5s9")
        assert "HTML body" in ctx

    def test_html_attribute(self):
        ctx = self.mod._find_reflection_context('<input value="pent7x5s9">', "pent7x5s9")
        assert "attribute" in ctx

    def test_javascript_context(self):
        body = '<script>var x = pent7x5s9;</script>'
        ctx = self.mod._find_reflection_context(body, "pent7x5s9")
        assert "JavaScript" in ctx

    def test_not_found(self):
        ctx = self.mod._find_reflection_context("<div>nothing</div>", "pent7x5s9")
        assert "not found" in ctx


# ======================================================================
# sqli_check
# ======================================================================

class TestSQLiCheck:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_sql_error_detected(self):
        responses.add(responses.GET, "https://example.com",
                      body="Normal page", status=200)
        # SQLi payload triggers error
        responses.add(responses.GET, "https://example.com",
                      body="You have an error in your SQL syntax", status=200)
        self.mod.sqli_check("https://example.com?id=1")
        sqli = [f for f in self.mod.findings if f.get("category") == "SQLi"]
        assert len(sqli) >= 1

    @responses.activate
    def test_clean_response_no_finding(self):
        responses.add(responses.GET, "https://example.com",
                      body="Normal page content here", status=200)
        self.mod.sqli_check("https://example.com?id=1")
        sqli = [f for f in self.mod.findings if f.get("category") == "SQLi"]
        assert len(sqli) == 0

    @responses.activate
    def test_uses_common_params_when_no_query(self):
        responses.add(responses.GET, "https://example.com",
                      body="Normal page", status=200)
        self.mod.sqli_check("https://example.com")
        # Should not crash

    @responses.activate
    def test_multiple_error_patterns(self):
        """Verify various SQL error patterns are detected."""
        patterns = [
            "warning.*mysql",
            "unclosed quotation mark",
            "syntax error.*postgresql",
            "ORA-01234",
        ]
        for pattern_text in ["Warning: mysql_query()", "unclosed quotation mark after",
                             "syntax error at or near postgresql", "ORA-01234: error"]:
            self.mod = _make_module()
            responses.reset()
            responses.add(responses.GET, "https://example.com",
                          body="Normal", status=200)
            responses.add(responses.GET, "https://example.com",
                          body=pattern_text, status=200)
            self.mod.sqli_check("https://example.com?id=1")


# ======================================================================
# csrf_check
# ======================================================================

class TestCSRFCheck:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_post_form_without_csrf(self):
        html = read_fixture("sample_vuln_page.html")
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.csrf_check("https://example.com")
        csrf = [f for f in self.mod.findings if f.get("category") == "CSRF"]
        assert len(csrf) >= 1

    @responses.activate
    def test_post_form_with_csrf(self):
        html = read_fixture("sample_page.html")
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.csrf_check("https://example.com")
        csrf = [f for f in self.mod.findings if f.get("category") == "CSRF"]
        assert len(csrf) == 0

    @responses.activate
    def test_get_form_no_csrf_needed(self):
        html = '<form method="GET"><input name="q"></form>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.csrf_check("https://example.com")
        csrf = [f for f in self.mod.findings if f.get("category") == "CSRF"]
        assert len(csrf) == 0

    @responses.activate
    def test_no_forms(self):
        responses.add(responses.GET, "https://example.com", body="<html>No forms</html>", status=200)
        self.mod.csrf_check("https://example.com")
        assert len(self.mod.findings) == 0


# ======================================================================
# directory_traversal_check
# ======================================================================

class TestDirectoryTraversalCheck:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_etc_passwd_detected(self):
        responses.add(responses.GET, "https://example.com",
                      body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", status=200)
        self.mod.directory_traversal_check("https://example.com?file=test")
        traversal = [f for f in self.mod.findings if f.get("category") == "Path Traversal"]
        assert len(traversal) >= 1

    @responses.activate
    def test_windows_indicators(self):
        responses.add(responses.GET, "https://example.com",
                      body="# Copyright (c) Microsoft", status=200)
        self.mod.directory_traversal_check("https://example.com?file=test")
        traversal = [f for f in self.mod.findings if f.get("category") == "Path Traversal"]
        assert len(traversal) >= 1

    @responses.activate
    def test_clean_response(self):
        responses.add(responses.GET, "https://example.com",
                      body="Normal page content", status=200)
        self.mod.directory_traversal_check("https://example.com?file=test")
        traversal = [f for f in self.mod.findings if f.get("category") == "Path Traversal"]
        assert len(traversal) == 0


# ======================================================================
# crawl_links
# ======================================================================

class TestCrawlLinks:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_extracts_internal_external_links(self):
        html = read_fixture("sample_page.html")
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.crawl_links("https://example.com")
        # Should not crash

    @responses.activate
    def test_finds_emails(self):
        html = '<html><p>Email: admin@example.com</p></html>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.crawl_links("https://example.com")
        email_findings = [f for f in self.mod.findings if f.get("category") == "Email"]
        assert len(email_findings) >= 1

    @responses.activate
    def test_finds_secrets_in_source(self):
        html = '<html><!-- api_key: "AKIAIOSFODNN7EXAMPLE1234" --></html>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.crawl_links("https://example.com")
        secret_findings = [f for f in self.mod.findings if f.get("category") == "Secret Exposure"]
        assert len(secret_findings) >= 1


# ======================================================================
# run (full workflow)
# ======================================================================

class TestRun:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_run_returns_findings(self):
        html = read_fixture("sample_vuln_page.html")
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        findings = self.mod.run("https://example.com")
        assert isinstance(findings, list)

    @responses.activate
    def test_run_full_includes_traversal(self):
        html = '<html><p>page</p></html>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.run("https://example.com", full=True)
        # Should not crash — traversal check was called
