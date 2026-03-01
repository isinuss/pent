"""Tests for web/server.py — Flask API endpoints."""

import json
import os
import sys
from io import StringIO
from unittest.mock import patch, MagicMock

import pytest

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.server import app, scans


@pytest.fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        # Clear scan state between tests
        scans.clear()
        yield c


# ======================================================================
# Page routes
# ======================================================================

class TestPageRoutes:

    def test_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_scan_page(self, client):
        resp = client.get("/scan")
        assert resp.status_code == 200

    def test_results_page(self, client):
        resp = client.get("/results")
        assert resp.status_code == 200

    def test_guides_page(self, client):
        resp = client.get("/guides")
        assert resp.status_code == 200


# ======================================================================
# API: /api/scan/start
# ======================================================================

class TestAPIScanStart:

    def test_valid_target(self, client):
        resp = client.post("/api/scan/start",
                           json={"target": "example.com", "scan_type": "recon"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "scan_id" in data
        assert data["status"] == "queued"

    def test_missing_target(self, client):
        resp = client.post("/api/scan/start", json={"scan_type": "recon"})
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_empty_target(self, client):
        resp = client.post("/api/scan/start", json={"target": "", "scan_type": "recon"})
        assert resp.status_code == 400


# ======================================================================
# API: /api/scan/<id>
# ======================================================================

class TestAPIScanStatus:

    def test_valid_scan(self, client):
        # Start a scan first
        resp = client.post("/api/scan/start",
                           json={"target": "example.com", "scan_type": "recon"})
        scan_id = resp.get_json()["scan_id"]

        resp = client.get(f"/api/scan/{scan_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["id"] == scan_id

    def test_invalid_scan_id(self, client):
        resp = client.get("/api/scan/nonexistent")
        assert resp.status_code == 404


# ======================================================================
# API: /api/scans
# ======================================================================

class TestAPIListScans:

    def test_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_after_scan_started(self, client):
        client.post("/api/scan/start",
                     json={"target": "example.com", "scan_type": "recon"})
        resp = client.get("/api/scans")
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["target"] == "example.com"


# ======================================================================
# API: /api/scan/<id>/findings
# ======================================================================

class TestAPIScanFindings:

    def test_returns_findings(self, client):
        # Create a scan with pre-populated findings
        scans["test1"] = {
            "id": "test1",
            "target": "example.com",
            "scan_type": "recon",
            "status": "completed",
            "findings": [{"severity": "high", "title": "Test"}],
            "created_at": "2025-01-01",
        }
        resp = client.get("/api/scan/test1/findings")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1

    def test_not_found(self, client):
        resp = client.get("/api/scan/nope/findings")
        assert resp.status_code == 404


# ======================================================================
# API: /api/scan/<id>/report/<fmt>
# ======================================================================

class TestAPIReport:

    def test_json_report(self, client, tmp_path):
        scans["test2"] = {
            "id": "test2",
            "target": "example.com",
            "scan_type": "recon",
            "status": "completed",
            "findings": [{"severity": "high", "title": "XSS", "detail": "found"}],
            "created_at": "2025-01-01",
        }
        resp = client.get("/api/scan/test2/report/json")
        assert resp.status_code == 200

    def test_invalid_format(self, client):
        scans["test3"] = {
            "id": "test3",
            "target": "example.com",
            "scan_type": "recon",
            "status": "completed",
            "findings": [],
            "created_at": "2025-01-01",
        }
        resp = client.get("/api/scan/test3/report/pdf")
        assert resp.status_code == 400

    def test_scan_not_found(self, client):
        resp = client.get("/api/scan/nope/report/json")
        assert resp.status_code == 404


# ======================================================================
# API: /api/guides
# ======================================================================

class TestAPIGuides:

    def test_list_guides(self, client):
        resp = client.get("/api/guides")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 8
        keys = {g["key"] for g in data}
        assert "recon" in keys
        assert "web" in keys

    def test_get_valid_guide(self, client):
        resp = client.get("/api/guides/recon")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "title" in data

    def test_get_invalid_guide(self, client):
        resp = client.get("/api/guides/nonexistent")
        assert resp.status_code == 404


# ======================================================================
# Guide detail page
# ======================================================================

class TestGuideDetailPage:

    def test_valid_topic(self, client):
        resp = client.get("/guides/recon")
        assert resp.status_code == 200

    def test_invalid_topic(self, client):
        resp = client.get("/guides/nonexistent")
        assert resp.status_code == 404
