"""Tests for modules/recon.py — DNS, subdomains, headers, SSL, tech detection, port scan."""

import socket
import ssl
from io import StringIO
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import responses

from rich.console import Console
from modules.recon import ReconModule


def _make_module():
    console = Console(file=StringIO(), force_terminal=False)
    return ReconModule(console)


# ======================================================================
# dns_lookup
# ======================================================================

class TestDNSLookup:

    def setup_method(self):
        self.mod = _make_module()

    @patch("modules.recon.HAS_DNS", True)
    @patch("modules.recon.dns.resolver.resolve")
    def test_records_found(self, mock_resolve):
        mock_record = MagicMock()
        mock_record.__str__ = lambda self: "93.184.216.34"
        mock_resolve.return_value = [mock_record]
        self.mod.dns_lookup("example.com")
        assert len(self.mod.findings) > 0
        assert any(f["category"] == "dns" for f in self.mod.findings)

    @patch("modules.recon.HAS_DNS", True)
    @patch("modules.recon.dns.resolver.resolve")
    def test_nxdomain_handled(self, mock_resolve):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        self.mod.dns_lookup("nonexistent.invalid")
        # Should not raise

    @patch("modules.recon.HAS_DNS", False)
    @patch("modules.recon.socket.getaddrinfo")
    def test_fallback_socket(self, mock_addr):
        mock_addr.return_value = [(None, None, None, None, ("1.2.3.4", 0))]
        self.mod.dns_lookup("example.com")
        assert any(f["value"] == "1.2.3.4" for f in self.mod.findings)

    @patch("modules.recon.HAS_DNS", False)
    @patch("modules.recon.socket.getaddrinfo", side_effect=socket.gaierror("fail"))
    def test_fallback_socket_failure(self, mock_addr):
        self.mod.dns_lookup("bad.invalid")
        # Should not raise


# ======================================================================
# subdomain_enum
# ======================================================================

class TestSubdomainEnum:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_subdomains_extracted(self):
        crtsh_data = [
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com\nmail.example.com"},
            {"name_value": "*.example.com"},  # wildcard should be filtered
        ]
        import json
        responses.add(responses.GET, "https://crt.sh/",
                      json=crtsh_data, status=200)
        subs = self.mod.subdomain_enum("example.com")
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        # Wildcard should NOT be included
        assert not any("*" in s for s in subs)

    @responses.activate
    def test_empty_response(self):
        responses.add(responses.GET, "https://crt.sh/", json=[], status=200)
        subs = self.mod.subdomain_enum("example.com")
        assert subs == []

    @responses.activate
    def test_http_error(self):
        responses.add(responses.GET, "https://crt.sh/", body="Server Error", status=500)
        subs = self.mod.subdomain_enum("example.com")
        assert subs == []

    @responses.activate
    def test_deduplication(self):
        crtsh_data = [
            {"name_value": "www.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "WWW.EXAMPLE.COM"},
        ]
        responses.add(responses.GET, "https://crt.sh/", json=crtsh_data, status=200)
        subs = self.mod.subdomain_enum("example.com")
        assert subs.count("www.example.com") == 1


# ======================================================================
# http_headers
# ======================================================================

class TestHTTPHeaders:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_missing_headers_detected(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200,
                      headers={"Content-Type": "text/html"})
        self.mod.http_headers("https://example.com")
        missing = [f for f in self.mod.findings if f["category"] == "missing_header"]
        header_names = [f["key"] for f in missing]
        assert "Strict-Transport-Security" in header_names
        assert "Content-Security-Policy" in header_names

    @responses.activate
    def test_all_security_headers_present(self):
        hdrs = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        }
        responses.add(responses.GET, "https://example.com", body="ok", status=200, headers=hdrs)
        self.mod.http_headers("https://example.com")
        missing = [f for f in self.mod.findings if f["category"] == "missing_header"]
        assert len(missing) == 0

    @responses.activate
    def test_info_disclosure_detected(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200,
                      headers={"Server": "Apache/2.4.52", "X-Powered-By": "PHP/8.1"})
        self.mod.http_headers("https://example.com")
        disclosed = [f for f in self.mod.findings if f["category"] == "info_disclosure"]
        assert len(disclosed) >= 2

    @responses.activate
    def test_adds_https_prefix(self):
        responses.add(responses.GET, "https://example.com", body="ok", status=200)
        self.mod.http_headers("example.com")
        # Should not crash

    @responses.activate
    def test_request_failure_handled(self):
        responses.add(responses.GET, "https://bad.invalid",
                      body=responses.ConnectionError("Connection refused"))
        self.mod.http_headers("https://bad.invalid")
        # Should not raise


# ======================================================================
# tech_detect
# ======================================================================

class TestTechDetect:

    def setup_method(self):
        self.mod = _make_module()

    @responses.activate
    def test_wordpress_detected(self):
        html = '<html><link href="/wp-content/themes/style.css"></html>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.tech_detect("https://example.com")
        techs = [f for f in self.mod.findings if f["category"] == "tech"]
        assert any("WordPress" in f["value"] for f in techs)

    @responses.activate
    def test_react_detected(self):
        html = '<html><div id="root" data-reactroot></div><script>window.__react</script></html>'
        responses.add(responses.GET, "https://example.com", body=html, status=200)
        self.mod.tech_detect("https://example.com")
        techs = [f for f in self.mod.findings if f["category"] == "tech"]
        assert any("React" in f["value"] for f in techs)

    @responses.activate
    def test_no_tech_detected(self):
        responses.add(responses.GET, "https://example.com", body="<html>Plain page</html>", status=200)
        self.mod.tech_detect("https://example.com")
        techs = [f for f in self.mod.findings if f["category"] == "tech"]
        # May detect via server header, but no framework techs
        framework_techs = [t for t in techs if t["key"] in ("Frontend", "CMS", "Backend")]
        assert len(framework_techs) == 0

    @responses.activate
    def test_server_header_detected(self):
        responses.add(responses.GET, "https://example.com", body="<html></html>", status=200,
                      headers={"Server": "nginx/1.24"})
        self.mod.tech_detect("https://example.com")
        techs = [f for f in self.mod.findings if f["category"] == "tech"]
        assert any("nginx" in f["value"] for f in techs)


# ======================================================================
# port_scan
# ======================================================================

class TestPortScan:

    def setup_method(self):
        self.mod = _make_module()

    @patch("modules.recon.socket.gethostbyname", return_value="93.184.216.34")
    @patch("modules.recon.socket.socket")
    def test_open_port_detected(self, mock_sock_class, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # Port open
        mock_sock_class.return_value = mock_sock
        self.mod.port_scan("example.com", top_ports=5)
        assert len(self.mod.findings) > 0
        assert any(f["category"] == "port" for f in self.mod.findings)

    @patch("modules.recon.socket.gethostbyname", return_value="93.184.216.34")
    @patch("modules.recon.socket.socket")
    def test_all_ports_closed(self, mock_sock_class, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Port closed
        mock_sock_class.return_value = mock_sock
        self.mod.port_scan("example.com", top_ports=5)
        port_findings = [f for f in self.mod.findings if f["category"] == "port"]
        assert len(port_findings) == 0

    @patch("modules.recon.socket.gethostbyname", side_effect=socket.gaierror("fail"))
    def test_dns_failure_handled(self, mock_resolve):
        self.mod.port_scan("bad.invalid")
        # Should not raise


# ======================================================================
# run (full recon workflow)
# ======================================================================

class TestRun:

    def setup_method(self):
        self.mod = _make_module()

    @patch.object(ReconModule, "dns_lookup")
    @patch.object(ReconModule, "subdomain_enum")
    @patch.object(ReconModule, "http_headers")
    @patch.object(ReconModule, "ssl_info")
    @patch.object(ReconModule, "whois_lookup")
    @patch.object(ReconModule, "tech_detect")
    @patch.object(ReconModule, "port_scan")
    def test_run_calls_all(self, mock_port, mock_tech, mock_whois,
                           mock_ssl, mock_headers, mock_sub, mock_dns):
        self.mod.run("example.com")
        mock_dns.assert_called_once()
        mock_sub.assert_called_once()
        mock_headers.assert_called_once()
        mock_ssl.assert_called_once()
        mock_whois.assert_called_once()
        mock_tech.assert_called_once()
        mock_port.assert_called_once()

    @patch.object(ReconModule, "dns_lookup")
    @patch.object(ReconModule, "subdomain_enum")
    @patch.object(ReconModule, "http_headers")
    @patch.object(ReconModule, "ssl_info")
    @patch.object(ReconModule, "whois_lookup")
    @patch.object(ReconModule, "tech_detect")
    @patch.object(ReconModule, "port_scan")
    def test_passive_only_skips_port_scan(self, mock_port, mock_tech, mock_whois,
                                          mock_ssl, mock_headers, mock_sub, mock_dns):
        self.mod.run("example.com", passive_only=True)
        mock_port.assert_not_called()
