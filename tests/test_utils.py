"""Tests for modules/utils.py — target validation, scope enforcement, helpers."""

import socket
import time
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from modules.utils import (
    validate_target,
    rate_limit,
    resolve_domain,
    is_internal_ip,
    severity_color,
    print_finding,
    sanitize_filename,
    ScopedSession,
)


# ======================================================================
# validate_target
# ======================================================================

class TestValidateTarget:

    def test_https_url(self):
        r = validate_target("https://example.com/path")
        assert r["valid"] is True
        assert r["type"] == "url"
        assert r["domain"] == "example.com"
        assert r["scheme"] == "https"

    def test_http_url(self):
        r = validate_target("http://example.com")
        assert r["valid"] is True
        assert r["type"] == "url"
        assert r["scheme"] == "http"

    def test_url_with_port(self):
        r = validate_target("https://example.com:8443/api")
        assert r["valid"] is True
        assert r["port"] == 8443

    def test_ip_address(self):
        r = validate_target("93.184.216.34")
        assert r["valid"] is True
        assert r["type"] == "ip"
        assert r["ip"] == "93.184.216.34"
        assert r["url"] == "https://93.184.216.34"

    def test_domain(self):
        r = validate_target("example.com")
        assert r["valid"] is True
        assert r["type"] == "domain"
        assert r["domain"] == "example.com"

    def test_domain_with_port(self):
        r = validate_target("example.com:8080")
        assert r["valid"] is True
        assert r["port"] == 8080
        assert r["domain"] == "example.com"

    def test_subdomain(self):
        r = validate_target("sub.example.com")
        assert r["valid"] is True
        assert r["domain"] == "sub.example.com"

    @patch("modules.utils.socket.getaddrinfo", side_effect=socket.gaierror("fail"))
    def test_invalid_string(self, mock_dns):
        r = validate_target("not-a-valid-target!!!")
        assert r["valid"] is False

    def test_empty_string(self):
        r = validate_target("")
        assert r["valid"] is False

    def test_whitespace_only(self):
        r = validate_target("   ")
        assert r["valid"] is False

    @patch("modules.utils.socket.getaddrinfo", return_value=[(None, None, None, None, ("1.2.3.4", 0))])
    def test_hostname_resolves(self, mock_dns):
        r = validate_target("myhost")
        assert r["valid"] is True
        assert r["type"] == "hostname"

    def test_ip_edge_255(self):
        r = validate_target("255.255.255.255")
        assert r["valid"] is True
        assert r["type"] == "ip"

    def test_ip_edge_zeros(self):
        r = validate_target("0.0.0.0")
        assert r["valid"] is True
        assert r["type"] == "ip"


# ======================================================================
# is_internal_ip
# ======================================================================

class TestIsInternalIP:

    def test_private_10(self):
        assert is_internal_ip("10.0.0.1") is True

    def test_private_172(self):
        assert is_internal_ip("172.16.0.1") is True

    def test_private_192(self):
        assert is_internal_ip("192.168.1.1") is True

    def test_loopback(self):
        assert is_internal_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert is_internal_ip("8.8.8.8") is False

    def test_invalid_string(self):
        assert is_internal_ip("not-an-ip") is False

    def test_reserved_0(self):
        assert is_internal_ip("0.0.0.0") is True


# ======================================================================
# resolve_domain
# ======================================================================

class TestResolveDomain:

    @patch("modules.utils.socket.gethostbyname", return_value="93.184.216.34")
    def test_success(self, mock_dns):
        assert resolve_domain("example.com") == "93.184.216.34"

    @patch("modules.utils.socket.gethostbyname", side_effect=socket.gaierror)
    def test_failure_returns_empty(self, mock_dns):
        assert resolve_domain("nonexistent.invalid") == ""


# ======================================================================
# severity_color
# ======================================================================

class TestSeverityColor:

    @pytest.mark.parametrize("severity,expected", [
        ("critical", "bold red"),
        ("high", "red"),
        ("medium", "yellow"),
        ("low", "green"),
        ("info", "dim"),
    ])
    def test_known_severity(self, severity, expected):
        assert severity_color(severity) == expected

    def test_unknown_severity(self):
        assert severity_color("unknown") == "white"

    def test_case_insensitive(self):
        assert severity_color("HIGH") == "red"


# ======================================================================
# sanitize_filename
# ======================================================================

class TestSanitizeFilename:

    def test_special_chars_stripped(self):
        assert sanitize_filename("test/file:name?") == "test_file_name_"

    def test_length_capped(self):
        long_name = "a" * 200
        assert len(sanitize_filename(long_name)) == 100

    def test_dots_and_hyphens_preserved(self):
        assert sanitize_filename("report-2024.01.md") == "report-2024.01.md"

    def test_normal_name_unchanged(self):
        assert sanitize_filename("my_report") == "my_report"


# ======================================================================
# print_finding
# ======================================================================

class TestPrintFinding:

    def test_all_severities_print(self, mock_console):
        for sev in ["critical", "high", "medium", "low", "info"]:
            print_finding(mock_console, sev, f"Test {sev}", "detail")
        # Should not raise

    def test_with_detail(self, mock_console):
        print_finding(mock_console, "high", "XSS Found", "In param q")
        # Should not raise

    def test_without_detail(self, mock_console):
        print_finding(mock_console, "info", "Note")
        # Should not raise


# ======================================================================
# rate_limit
# ======================================================================

class TestRateLimit:

    @patch("modules.utils.time.sleep")
    @patch("modules.utils.time.time")
    def test_rate_limit_sleeps(self, mock_time, mock_sleep):
        # First call: time() returns 100.0 for elapsed calc, then 100.0 for last_call update
        # Second call: time() returns 100.2 for elapsed calc (< 1.0 interval), then 101.0 for update
        mock_time.side_effect = [100.0, 100.0, 100.2, 101.0]

        @rate_limit(min_interval=1.0)
        def my_func():
            return True

        my_func()   # First call: elapsed = 100.0 - 0.0 = 100 > 1.0, no sleep
        my_func()   # Second call: elapsed = 100.2 - 100.0 = 0.2 < 1.0, SHOULD sleep

        mock_sleep.assert_called_once_with(pytest.approx(0.8, abs=0.01))


# ======================================================================
# ScopedSession
# ======================================================================

class TestScopedSession:

    def test_in_scope_allowed(self):
        session = ScopedSession(["example.com"])
        assert session._check_scope("https://example.com/path") is True

    def test_subdomain_allowed(self):
        session = ScopedSession(["example.com"])
        assert session._check_scope("https://sub.example.com/path") is True

    def test_out_of_scope_blocked(self, mock_console):
        session = ScopedSession(["example.com"], console=mock_console)
        assert session._check_scope("https://evil.com") is False

    def test_get_out_of_scope_raises(self):
        session = ScopedSession(["example.com"])
        with pytest.raises(ValueError, match="out of scope"):
            session.get("https://evil.com")

    def test_post_out_of_scope_raises(self):
        session = ScopedSession(["example.com"])
        with pytest.raises(ValueError, match="out of scope"):
            session.post("https://evil.com")

    def test_user_agent_set(self):
        session = ScopedSession(["example.com"])
        assert "Mozilla" in session.session.headers.get("User-Agent", "")

    def test_case_insensitive_scope(self):
        session = ScopedSession(["Example.COM"])
        assert session._check_scope("https://example.com/path") is True
