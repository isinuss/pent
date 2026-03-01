"""Tests for modules/takeover.py — subdomain takeover detection."""

import socket
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
import responses

from rich.console import Console
from modules.takeover import TakeoverModule, TAKEOVER_FINGERPRINTS


def _make_module():
    console = Console(file=StringIO(), force_terminal=False)
    return TakeoverModule(console)


# ======================================================================
# _get_cname
# ======================================================================

class TestGetCNAME:

    def setup_method(self):
        self.mod = _make_module()

    @patch("modules.takeover.HAS_DNS", True)
    @patch("modules.takeover.dns.resolver.resolve")
    def test_cname_found(self, mock_resolve):
        mock_rdata = MagicMock()
        mock_rdata.target = MagicMock()
        mock_rdata.target.__str__ = lambda self: "example.github.io."
        mock_resolve.return_value = [mock_rdata]
        result = self.mod._get_cname("blog.example.com")
        assert result == "example.github.io"

    @patch("modules.takeover.HAS_DNS", True)
    @patch("modules.takeover.dns.resolver.resolve", side_effect=Exception("No CNAME"))
    def test_no_cname(self, mock_resolve):
        result = self.mod._get_cname("example.com")
        assert result == ""

    @patch("modules.takeover.HAS_DNS", False)
    @patch("modules.takeover.socket.getaddrinfo", side_effect=Exception("fail"))
    def test_fallback_failure(self, mock_addr):
        result = self.mod._get_cname("bad.invalid")
        assert result == ""


# ======================================================================
# _check_nxdomain
# ======================================================================

class TestCheckNXDOMAIN:

    def setup_method(self):
        self.mod = _make_module()

    @patch("modules.takeover.HAS_DNS", True)
    @patch("modules.takeover.dns.resolver.resolve")
    def test_nxdomain_true(self, mock_resolve):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        assert self.mod._check_nxdomain("dead.example.com") is True

    @patch("modules.takeover.HAS_DNS", True)
    @patch("modules.takeover.dns.resolver.resolve")
    def test_valid_domain(self, mock_resolve):
        mock_resolve.return_value = [MagicMock()]
        assert self.mod._check_nxdomain("live.example.com") is False

    @patch("modules.takeover.HAS_DNS", False)
    @patch("modules.takeover.socket.gethostbyname", side_effect=socket.gaierror)
    def test_fallback_nxdomain(self, mock_resolve):
        assert self.mod._check_nxdomain("dead.example.com") is True

    @patch("modules.takeover.HAS_DNS", False)
    @patch("modules.takeover.socket.gethostbyname", return_value="1.2.3.4")
    def test_fallback_valid(self, mock_resolve):
        assert self.mod._check_nxdomain("live.example.com") is False


# ======================================================================
# _check_http_fingerprint
# ======================================================================

class TestCheckHTTPFingerprint:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_github_pages_match(self):
        fingerprint = TAKEOVER_FINGERPRINTS[0]  # GitHub Pages
        responses.add(responses.GET, "https://blog.example.com",
                      body="There isn't a GitHub Pages site here.", status=404)
        result = self.mod._check_http_fingerprint("blog.example.com", fingerprint)
        assert result is True

    @responses.activate
    def test_heroku_match(self):
        fingerprint = TAKEOVER_FINGERPRINTS[1]  # Heroku
        responses.add(responses.GET, "https://app.example.com",
                      body="No such app", status=404)
        result = self.mod._check_http_fingerprint("app.example.com", fingerprint)
        assert result is True

    @responses.activate
    def test_no_match(self):
        fingerprint = TAKEOVER_FINGERPRINTS[0]  # GitHub Pages
        responses.add(responses.GET, "https://blog.example.com",
                      body="Welcome to my blog!", status=200)
        responses.add(responses.GET, "http://blog.example.com",
                      body="Welcome to my blog!", status=200)
        result = self.mod._check_http_fingerprint("blog.example.com", fingerprint)
        assert result is False

    @responses.activate
    def test_connection_error_handled(self):
        fingerprint = TAKEOVER_FINGERPRINTS[0]
        responses.add(responses.GET, "https://dead.example.com",
                      body=responses.ConnectionError())
        responses.add(responses.GET, "http://dead.example.com",
                      body=responses.ConnectionError())
        result = self.mod._check_http_fingerprint("dead.example.com", fingerprint)
        assert result is False


# ======================================================================
# check_subdomain
# ======================================================================

class TestCheckSubdomain:

    def setup_method(self):
        self.mod = _make_module()

    @patch.object(TakeoverModule, "_get_cname", return_value="example.github.io")
    @patch.object(TakeoverModule, "_check_http_fingerprint", return_value=True)
    def test_vulnerable(self, mock_http, mock_cname):
        result = self.mod.check_subdomain("blog.example.com")
        assert result["vulnerable"] is True
        assert result["service"] == "GitHub Pages"

    @patch.object(TakeoverModule, "_get_cname", return_value="example.github.io")
    @patch.object(TakeoverModule, "_check_http_fingerprint", return_value=False)
    def test_cname_matches_but_no_fingerprint(self, mock_http, mock_cname):
        result = self.mod.check_subdomain("blog.example.com")
        assert result["vulnerable"] is False
        assert result["service"] == "GitHub Pages"
        assert "verify manually" in result["evidence"]

    @patch.object(TakeoverModule, "_get_cname", return_value="")
    @patch.object(TakeoverModule, "_check_nxdomain", return_value=True)
    def test_nxdomain_no_cname(self, mock_nx, mock_cname):
        result = self.mod.check_subdomain("dead.example.com")
        assert result["vulnerable"] is False
        assert "NXDOMAIN" in result["evidence"]

    @patch.object(TakeoverModule, "_get_cname", return_value="")
    @patch.object(TakeoverModule, "_check_nxdomain", return_value=False)
    def test_no_cname_no_nxdomain(self, mock_nx, mock_cname):
        result = self.mod.check_subdomain("normal.example.com")
        assert result["vulnerable"] is False
        assert result["service"] == ""


# ======================================================================
# check_subdomains (batch)
# ======================================================================

class TestCheckSubdomains:

    def setup_method(self):
        self.mod = _make_module()

    @patch.object(TakeoverModule, "check_subdomain")
    def test_processes_all(self, mock_check):
        mock_check.return_value = {
            "subdomain": "sub.example.com",
            "cname": "",
            "vulnerable": False,
            "service": "",
            "evidence": "",
        }
        self.mod.check_subdomains(["a.example.com", "b.example.com", "c.example.com"])
        assert mock_check.call_count == 3

    @patch.object(TakeoverModule, "check_subdomain")
    def test_vulnerable_creates_high_finding(self, mock_check):
        mock_check.return_value = {
            "subdomain": "vuln.example.com",
            "cname": "vuln.github.io",
            "vulnerable": True,
            "service": "GitHub Pages",
            "evidence": "CNAME + fingerprint match",
        }
        self.mod.check_subdomains(["vuln.example.com"])
        assert len(self.mod.findings) == 1
        assert self.mod.findings[0]["severity"] == "high"


# ======================================================================
# TAKEOVER_FINGERPRINTS data validation
# ======================================================================

class TestFingerprints:

    def test_all_have_required_fields(self):
        for fp in TAKEOVER_FINGERPRINTS:
            assert "service" in fp
            assert "cnames" in fp
            assert "fingerprints" in fp
            assert "status" in fp

    def test_known_services_present(self):
        services = {fp["service"] for fp in TAKEOVER_FINGERPRINTS}
        for expected in ["GitHub Pages", "Heroku", "AWS S3", "Azure", "Netlify"]:
            assert expected in services

    def test_fingerprint_count(self):
        assert len(TAKEOVER_FINGERPRINTS) == 19
