"""Shared fixtures for the PENT test suite."""

import os
import sys
from io import StringIO
from datetime import datetime

import pytest
import responses

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def mock_console():
    """Rich Console that captures output to a StringIO buffer (no terminal output)."""
    buf = StringIO()
    return Console(file=buf, force_terminal=False, width=120, color_system=None)


@pytest.fixture
def sample_findings():
    """Sample findings covering all severity levels and categories."""
    return [
        {"timestamp": datetime.now().isoformat(), "severity": "critical", "category": "Path Traversal",
         "title": "Directory traversal in 'file'", "detail": "/etc/passwd leaked"},
        {"timestamp": datetime.now().isoformat(), "severity": "high", "category": "XSS",
         "title": "Reflected XSS in 'q'", "detail": "Payload reflected in HTML body"},
        {"timestamp": datetime.now().isoformat(), "severity": "high", "category": "SQLi",
         "title": "SQL Injection in 'id'", "detail": "Error pattern matched"},
        {"timestamp": datetime.now().isoformat(), "severity": "medium", "category": "CSRF",
         "title": "Missing CSRF token", "detail": "Form action: /login"},
        {"timestamp": datetime.now().isoformat(), "severity": "medium", "category": "missing_header",
         "title": "Missing HSTS", "detail": "Strict-Transport-Security not set"},
        {"timestamp": datetime.now().isoformat(), "severity": "low", "category": "info_disclosure",
         "title": "Server header", "detail": "Apache/2.4.52"},
        {"timestamp": datetime.now().isoformat(), "severity": "low", "category": "Cookie Security",
         "title": "Cookie flags", "detail": "Missing Secure flag"},
        {"timestamp": datetime.now().isoformat(), "severity": "info", "category": "dns",
         "key": "A", "value": "93.184.216.34"},
    ]


@pytest.fixture
def fixture_dir():
    """Path to the test fixtures directory."""
    return FIXTURES_DIR


def read_fixture(name: str) -> str:
    """Read a fixture file and return its contents."""
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return f.read()
