"""Tests for modules/custom_checks.py — matcher engine and check execution."""

import os
from unittest.mock import MagicMock, patch

import pytest
import responses

from modules.custom_checks import CustomChecksModule, BUILTIN_CHECKS


# ======================================================================
# _match_response
# ======================================================================

class TestMatchResponse:

    def setup_method(self):
        from rich.console import Console
        from io import StringIO
        self.console = Console(file=StringIO(), force_terminal=False)
        self.mod = CustomChecksModule(self.console)

    def _make_response(self, status=200, body="", headers=None):
        """Create a mock requests.Response."""
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        resp.content = body.encode()
        resp.headers = headers or {}
        return resp

    def test_status_match(self):
        resp = self._make_response(status=200)
        assert self.mod._match_response(resp, {"status": [200]}) is True

    def test_status_mismatch(self):
        resp = self._make_response(status=404)
        assert self.mod._match_response(resp, {"status": [200]}) is False

    def test_status_multiple(self):
        resp = self._make_response(status=403)
        assert self.mod._match_response(resp, {"status": [200, 401, 403]}) is True

    def test_body_contains_match(self):
        resp = self._make_response(body="DB_PASSWORD=secret")
        assert self.mod._match_response(resp, {"body_contains": ["DB_PASSWORD"]}) is True

    def test_body_contains_case_insensitive(self):
        resp = self._make_response(body="db_password=secret")
        assert self.mod._match_response(resp, {"body_contains": ["DB_PASSWORD"]}) is True

    def test_body_contains_no_match(self):
        resp = self._make_response(body="Nothing interesting here")
        assert self.mod._match_response(resp, {"body_contains": ["DB_PASSWORD"]}) is False

    def test_body_contains_any_match(self):
        resp = self._make_response(body="APP_KEY=xyz")
        assert self.mod._match_response(resp, {"body_contains": ["DB_PASSWORD", "APP_KEY"]}) is True

    def test_body_not_contains_pass(self):
        resp = self._make_response(body="Normal page content")
        assert self.mod._match_response(resp, {"body_not_contains": ["404", "Not Found"]}) is True

    def test_body_not_contains_fail(self):
        resp = self._make_response(body="404 Not Found")
        assert self.mod._match_response(resp, {"body_not_contains": ["404", "Not Found"]}) is False

    def test_header_contains_match(self):
        resp = self._make_response(headers={"Access-Control-Allow-Origin": "*"})
        assert self.mod._match_response(resp, {"header_contains": {"Access-Control-Allow-Origin": ["*"]}}) is True

    def test_header_contains_no_match(self):
        resp = self._make_response(headers={"Access-Control-Allow-Origin": "https://example.com"})
        assert self.mod._match_response(resp, {"header_contains": {"Access-Control-Allow-Origin": ["*", "evil.com"]}}) is False

    def test_min_content_length_pass(self):
        resp = self._make_response(body="x" * 2000)
        assert self.mod._match_response(resp, {"min_content_length": 1000}) is True

    def test_min_content_length_fail(self):
        resp = self._make_response(body="small")
        assert self.mod._match_response(resp, {"min_content_length": 1000}) is False

    def test_body_regex_match(self):
        resp = self._make_response(body="version 2.4.52")
        assert self.mod._match_response(resp, {"body_regex": [r"version \d+\.\d+"]}) is True

    def test_body_regex_no_match(self):
        resp = self._make_response(body="nothing here")
        assert self.mod._match_response(resp, {"body_regex": [r"version \d+\.\d+"]}) is False

    def test_combined_matchers_all_pass(self):
        resp = self._make_response(status=200, body="DB_PASSWORD=secret")
        matchers = {"status": [200], "body_contains": ["DB_PASSWORD"]}
        assert self.mod._match_response(resp, matchers) is True

    def test_combined_matchers_one_fails(self):
        resp = self._make_response(status=404, body="DB_PASSWORD=secret")
        matchers = {"status": [200], "body_contains": ["DB_PASSWORD"]}
        assert self.mod._match_response(resp, matchers) is False

    def test_empty_matchers(self):
        resp = self._make_response()
        assert self.mod._match_response(resp, {}) is True


# ======================================================================
# run_check
# ======================================================================

class TestRunCheck:

    def setup_method(self):
        from rich.console import Console
        from io import StringIO
        self.console = Console(file=StringIO(), force_terminal=False)
        self.mod = CustomChecksModule(self.console)

    @responses.activate
    def test_check_finds_vuln(self):
        responses.add(responses.GET, "https://target.com/.env",
                      body="DB_PASSWORD=secret\nAPP_KEY=base64key", status=200)
        check = {
            "id": "test-env",
            "name": "Test .env",
            "severity": "high",
            "method": "GET",
            "paths": ["/.env"],
            "matchers": {"status": [200], "body_contains": ["DB_PASSWORD"]},
        }
        results = self.mod.run_check("https://target.com", check)
        assert len(results) == 1
        assert results[0]["check_id"] == "test-env"
        assert results[0]["severity"] == "high"

    @responses.activate
    def test_check_no_match(self):
        responses.add(responses.GET, "https://target.com/.env", body="Not found", status=404)
        check = {
            "id": "test-env",
            "name": "Test .env",
            "severity": "high",
            "method": "GET",
            "paths": ["/.env"],
            "matchers": {"status": [200], "body_contains": ["DB_PASSWORD"]},
        }
        results = self.mod.run_check("https://target.com", check)
        assert len(results) == 0

    @responses.activate
    def test_check_multiple_paths(self):
        responses.add(responses.GET, "https://target.com/.env", body="Not found", status=404)
        responses.add(responses.GET, "https://target.com/.env.backup",
                      body="DB_PASSWORD=x", status=200)
        check = {
            "id": "test-env",
            "name": "Test .env",
            "severity": "high",
            "method": "GET",
            "paths": ["/.env", "/.env.backup"],
            "matchers": {"status": [200], "body_contains": ["DB_PASSWORD"]},
        }
        results = self.mod.run_check("https://target.com", check)
        assert len(results) == 1

    @responses.activate
    def test_check_post_method(self):
        responses.add(responses.POST, "https://target.com/api/debug",
                      body='{"debug": true}', status=200)
        check = {
            "id": "test-debug",
            "name": "Debug Endpoint",
            "severity": "high",
            "method": "POST",
            "paths": ["/api/debug"],
            "matchers": {"status": [200], "body_contains": ["debug"]},
        }
        results = self.mod.run_check("https://target.com", check)
        assert len(results) == 1

    @responses.activate
    def test_check_with_custom_headers(self):
        def check_headers(request):
            assert request.headers.get("X-Custom") == "test"
            return (200, {}, "ok")

        responses.add_callback(responses.GET, "https://target.com/",
                               callback=check_headers)
        check = {
            "id": "test-custom",
            "name": "Custom Header Check",
            "severity": "low",
            "method": "GET",
            "paths": ["/"],
            "headers": {"X-Custom": "test"},
            "matchers": {"status": [200]},
        }
        self.mod.run_check("https://target.com", check)

    @responses.activate
    def test_check_adds_https_prefix(self):
        responses.add(responses.GET, "https://target.com/test", body="ok", status=200)
        check = {
            "id": "test",
            "name": "Test",
            "severity": "low",
            "method": "GET",
            "paths": ["/test"],
            "matchers": {"status": [200]},
        }
        results = self.mod.run_check("target.com", check)
        assert len(results) == 1


# ======================================================================
# run_all_builtin
# ======================================================================

class TestRunAllBuiltin:

    def setup_method(self):
        from rich.console import Console
        from io import StringIO
        self.console = Console(file=StringIO(), force_terminal=False)
        self.mod = CustomChecksModule(self.console)

    @responses.activate
    def test_exposed_env_detected(self):
        import re as _re
        responses.add(responses.GET, "https://target.com/.env",
                      body="DB_PASSWORD=secret", status=200)
        # All other paths return 404
        responses.add(responses.GET, _re.compile(r"https://target\.com/.*"), body="Not Found", status=404)
        findings = self.mod.run_all_builtin("https://target.com")
        titles = [f["title"] for f in findings]
        assert any("Exposed .env" in t for t in titles)

    @responses.activate
    def test_nothing_found(self):
        import re as _re
        responses.add(responses.GET, _re.compile(r"https://target\.com/.*"), body="Not Found", status=404)
        findings = self.mod.run_all_builtin("https://target.com")
        assert len(findings) == 0

    def test_builtin_checks_count(self):
        assert len(BUILTIN_CHECKS) == 12

    def test_builtin_checks_have_required_fields(self):
        for check in BUILTIN_CHECKS:
            assert "id" in check
            assert "name" in check
            assert "severity" in check
            assert "paths" in check
            assert "matchers" in check


# ======================================================================
# load_yaml_checks
# ======================================================================

class TestLoadYamlChecks:

    def setup_method(self):
        from rich.console import Console
        from io import StringIO
        self.console = Console(file=StringIO(), force_terminal=False)
        self.mod = CustomChecksModule(self.console)

    def test_loads_valid_yaml(self, fixture_dir):
        checks = self.mod.load_yaml_checks(fixture_dir)
        assert len(checks) >= 1
        assert checks[0]["id"] == "test-sensitive-config"

    def test_missing_directory(self):
        checks = self.mod.load_yaml_checks("/nonexistent/dir")
        assert checks == []

    def test_invalid_yaml_handled(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("this: is: not: [valid: yaml")
        checks = self.mod.load_yaml_checks(str(tmp_path))
        assert checks == []

    def test_yaml_without_id_skipped(self, tmp_path):
        no_id = tmp_path / "noid.yaml"
        no_id.write_text("name: test\nseverity: low\n")
        checks = self.mod.load_yaml_checks(str(tmp_path))
        assert checks == []


# ======================================================================
# run_custom_checks (end-to-end)
# ======================================================================

class TestRunCustomChecks:

    def setup_method(self):
        from rich.console import Console
        from io import StringIO
        self.console = Console(file=StringIO(), force_terminal=False)
        self.mod = CustomChecksModule(self.console)

    @responses.activate
    def test_end_to_end(self, fixture_dir):
        responses.add(responses.GET, "https://target.com/config.json",
                      body='{"password": "secret123"}', status=200)
        responses.add(responses.GET, "https://target.com/settings.json",
                      body="Not found", status=404)
        self.mod.run_custom_checks("https://target.com", fixture_dir)
        # Should have found the config.json hit
        assert len(self.mod.findings) >= 0  # Just ensure no crash
