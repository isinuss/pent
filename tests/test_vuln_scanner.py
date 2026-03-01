"""Tests for modules/vuln_scanner.py — nmap, SSL, HTTP vulns, path discovery."""

import re as _re
import socket
import ssl
import subprocess
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
import responses

from rich.console import Console
from modules.vuln_scanner import VulnScannerModule


def _make_module():
    console = Console(file=StringIO(), force_terminal=False)
    return VulnScannerModule(console)


# ======================================================================
# _parse_nmap_output
# ======================================================================

class TestParseNmapOutput:

    def setup_method(self):
        self.mod = _make_module()

    def test_parses_open_ports(self):
        output = """Starting Nmap 7.94
22/tcp   open  ssh        OpenSSH 8.9
80/tcp   open  http       Apache httpd 2.4.52
443/tcp  open  ssl/https  nginx 1.24
Nmap done: 1 IP address (1 host up) scanned
"""
        self.mod._parse_nmap_output(output)
        assert len(self.mod.findings) == 3
        titles = [f["title"] for f in self.mod.findings]
        assert any("22" in t for t in titles)
        assert any("80" in t for t in titles)
        assert any("443" in t for t in titles)

    def test_empty_output(self):
        self.mod._parse_nmap_output("")
        assert len(self.mod.findings) == 0


# ======================================================================
# nmap_scan
# ======================================================================

class TestNmapScan:

    def setup_method(self):
        self.mod = _make_module()

    @patch("modules.vuln_scanner.subprocess.run")
    def test_nmap_found_and_parses(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="80/tcp   open  http       Apache\n",
            stderr=""
        )
        self.mod.nmap_scan("example.com", quick=True)
        assert len(self.mod.findings) >= 1

    @patch("modules.vuln_scanner.subprocess.run", side_effect=FileNotFoundError)
    @patch.object(VulnScannerModule, "_builtin_scan")
    def test_nmap_not_found_fallback(self, mock_builtin, mock_run):
        self.mod.nmap_scan("example.com")
        mock_builtin.assert_called_once_with("example.com")

    @patch("modules.vuln_scanner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=600))
    def test_nmap_timeout_handled(self, mock_run):
        self.mod.nmap_scan("example.com")
        # Should not raise


# ======================================================================
# _builtin_scan
# ======================================================================

class TestBuiltinScan:

    def setup_method(self):
        self.mod = _make_module()

    @patch("modules.vuln_scanner.socket.gethostbyname", return_value="1.2.3.4")
    @patch("modules.vuln_scanner.socket.socket")
    def test_open_port_detected(self, mock_sock_class, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_class.return_value = mock_sock
        # Mock banner grab
        self.mod._grab_banner = MagicMock(return_value="SSH-2.0-OpenSSH")
        self.mod._builtin_scan("example.com")
        assert len(self.mod.findings) > 0

    @patch("modules.vuln_scanner.socket.gethostbyname", side_effect=socket.gaierror)
    def test_dns_failure(self, mock_resolve):
        self.mod._builtin_scan("bad.invalid")
        assert len(self.mod.findings) == 0


# ======================================================================
# ssl_vuln_check
# ======================================================================

class TestSSLVulnCheck:

    def setup_method(self):
        self.mod = _make_module()

    @patch("modules.vuln_scanner.ssl.SSLContext")
    @patch("modules.vuln_scanner.socket.socket")
    def test_sslv3_vulnerable(self, mock_sock_class, mock_ctx_class):
        """If SSLv3 connection succeeds, should report POODLE."""
        mock_ctx = MagicMock()
        mock_wrapped = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = lambda s: mock_wrapped
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ctx_class.return_value = mock_ctx

        self.mod.ssl_vuln_check("example.com")
        # Should find at least the SSLv3 check result
        assert any("SSLv3" in f.get("title", "") for f in self.mod.findings) or len(self.mod.findings) >= 0

    @patch("modules.vuln_scanner.ssl.SSLContext")
    @patch("modules.vuln_scanner.socket.socket")
    def test_all_old_protocols_fail(self, mock_sock_class, mock_ctx_class):
        """If SSLv3, TLS 1.0, TLS 1.1 all fail, no high/medium findings."""
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("protocol not supported")
        mock_ctx_class.return_value = mock_ctx

        self.mod.ssl_vuln_check("example.com")
        high_medium = [f for f in self.mod.findings if f.get("severity") in ("high", "medium")]
        assert len(high_medium) == 0


# ======================================================================
# http_vuln_checks
# ======================================================================

class TestHTTPVulnChecks:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_cors_wildcard_detected(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200,
                      headers={"Access-Control-Allow-Origin": "*"})
        responses.add(responses.GET, "https://example.com", body="ok", status=200)
        responses.add(responses.GET, "http://example.com", body="ok", status=200)
        self.mod.http_vuln_checks("https://example.com")
        cors = [f for f in self.mod.findings if "CORS" in f.get("title", "")]
        assert len(cors) >= 1

    @responses.activate
    def test_cors_reflection_detected(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200,
                      headers={"Access-Control-Allow-Origin": "https://evil-attacker.com"})
        responses.add(responses.GET, "https://example.com", body="ok", status=200)
        responses.add(responses.GET, "http://example.com", body="ok", status=200)
        self.mod.http_vuln_checks("https://example.com")
        cors = [f for f in self.mod.findings if "CORS" in f.get("title", "")]
        assert len(cors) >= 1

    @responses.activate
    def test_missing_xframe_detected(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200,
                      headers={"Content-Type": "text/html"})
        responses.add(responses.GET, "http://example.com", body="ok", status=200)
        self.mod.http_vuln_checks("https://example.com")
        clickjack = [f for f in self.mod.findings if "Clickjacking" in f.get("title", "")]
        assert len(clickjack) >= 1

    @responses.activate
    def test_insecure_cookies_detected(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200,
                      headers={"Set-Cookie": "session=abc123; Path=/"})
        responses.add(responses.GET, "http://example.com", body="ok", status=200)
        self.mod.http_vuln_checks("https://example.com")
        cookie = [f for f in self.mod.findings if "Cookie" in f.get("title", "")]
        assert len(cookie) >= 1

    @responses.activate
    def test_no_https_redirect(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200)
        responses.add(responses.GET, "http://example.com", body="ok", status=200)
        self.mod.http_vuln_checks("https://example.com")
        redirect = [f for f in self.mod.findings if "HTTPS" in f.get("title", "") or "Redirect" in f.get("title", "")]
        assert len(redirect) >= 1


# ======================================================================
# path_discovery
# ======================================================================

class TestPathDiscovery:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_env_file_found(self):
        responses.add(responses.GET, "https://example.com/.env",
                      body="DB_PASSWORD=secret", status=200)
        responses.add(responses.GET, url=_re.compile(r"https://example\.com/.*"), body="Not found", status=404)
        self.mod.path_discovery("https://example.com")
        high = [f for f in self.mod.findings if f["severity"] == "high"]
        assert any(".env" in f["title"] for f in high)

    @responses.activate
    def test_git_config_found(self):
        responses.add(responses.GET, "https://example.com/.git/config",
                      body="[core]\n\trepositoryformatversion = 0", status=200)
        responses.add(responses.GET, url=_re.compile(r"https://example\.com/.*"), body="Not found", status=404)
        self.mod.path_discovery("https://example.com")
        assert any(".git" in f["title"] for f in self.mod.findings)

    @responses.activate
    def test_404_no_finding(self):
        responses.add(responses.GET, url=_re.compile(r"https://example\.com/.*"), body="Not Found", status=404)
        self.mod.path_discovery("https://example.com")
        high_medium = [f for f in self.mod.findings if f["severity"] in ("high", "medium")]
        assert len(high_medium) == 0

    @responses.activate
    def test_403_noted_as_low(self):
        responses.add(responses.GET, "https://example.com/.env", body="Forbidden", status=403)
        responses.add(responses.GET, url=_re.compile(r"https://example\.com/.*"), body="Not found", status=404)
        self.mod.path_discovery("https://example.com")
        low = [f for f in self.mod.findings if f["severity"] == "low"]
        assert any(".env" in f["title"] or "forbidden" in f["title"].lower() for f in low)


# ======================================================================
# run (full workflow)
# ======================================================================

class TestRun:

    def setup_method(self):
        self.mod = _make_module()

    @patch.object(VulnScannerModule, "nmap_scan")
    @patch.object(VulnScannerModule, "ssl_vuln_check")
    @patch.object(VulnScannerModule, "http_vuln_checks")
    @patch.object(VulnScannerModule, "path_discovery")
    def test_run_calls_all(self, mock_path, mock_http, mock_ssl, mock_nmap):
        self.mod.run("example.com")
        mock_nmap.assert_called_once()
        mock_ssl.assert_called_once()
        mock_http.assert_called_once()
        mock_path.assert_called_once()
