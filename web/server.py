#!/usr/bin/env python3
"""
PENT Web Server - Browser-based UI for the penetration testing assistant.

Provides a REST API (v1), WebSocket streaming, JWT authentication,
SQLite persistence, and serves the React SPA.
"""

import sys
import os
import json
import threading
import time
import uuid
from datetime import datetime
from io import StringIO
from collections import defaultdict
from functools import wraps

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (
    Flask, request, jsonify, send_file, send_from_directory, g,
)
from flask_socketio import SocketIO, emit

from web.database import Database
from web.auth import generate_token, verify_token, require_auth

from modules.recon import ReconModule
from modules.vuln_scanner import VulnScannerModule
from modules.web_tester import WebTesterModule
from modules.js_analyzer import JSAnalyzerModule
from modules.takeover import TakeoverModule
from modules.custom_checks import CustomChecksModule
from modules.reporter import ReporterModule
from modules.guide import METHODOLOGIES

from rich.console import Console


# ---------------------------------------------------------------------------
# App factory helpers
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WEB_DIR = os.path.dirname(os.path.abspath(__file__))
_DIST_DIR = os.path.join(_WEB_DIR, "dist")

db = Database()  # singleton database handle


def _create_app() -> Flask:
    """Build and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = os.environ.get("PENT_SECRET_KEY", os.urandom(24).hex())
    return app


app = _create_app()
# Attach the db handle so auth.py can find it via current_app.pent_db
app.pent_db = db

# CORS - only enabled when PENT_DEV=1
_dev_mode = os.environ.get("PENT_DEV", "") == "1"
_cors_origins = "*" if _dev_mode else None

socketio = SocketIO(
    app,
    async_mode="gevent",
    cors_allowed_origins=("*" if _dev_mode else "*"),
)

# In-memory scan cache (supplement to DB for live status + WebSocket streaming)
_scans_cache: dict = {}


# ---------------------------------------------------------------------------
# Rate limiter (simple in-memory, per-IP)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Token-bucket style rate limiter keyed by IP address."""

    def __init__(self):
        # ip -> list of timestamps
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, ip: str, limit: int, window: int = 60) -> bool:
        """Return True if the request is within the rate limit.

        Args:
            ip: Client IP address.
            limit: Maximum number of requests allowed in the window.
            window: Time window in seconds (default 60).
        """
        now = time.time()
        cutoff = now - window

        with self._lock:
            # Prune old entries
            self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
            if len(self._hits[ip]) >= limit:
                return False
            self._hits[ip].append(now)
            return True


_limiter = _RateLimiter()


def rate_limit(limit: int = 100, window: int = 60):
    """Decorator that applies per-IP rate limiting to a Flask route."""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            if not _limiter.is_allowed(ip, limit, window):
                return jsonify({
                    "data": None,
                    "error": "Rate limit exceeded. Try again later.",
                }), 429
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# JSON response helpers
# ---------------------------------------------------------------------------

def _ok(data):
    """Return a success JSON response."""
    return jsonify({"data": data, "error": None})


def _err(message: str, status: int = 400):
    """Return an error JSON response."""
    return jsonify({"data": None, "error": message}), status


# ---------------------------------------------------------------------------
# WebConsole: Rich console that streams output via SocketIO
# ---------------------------------------------------------------------------

class WebConsole(Console):
    """Console that captures output and sends it to the browser via WebSocket.

    Also intercepts _add_finding calls (patched onto modules) to emit
    live ``scan_finding`` events so the UI can display findings in real time.
    """

    def __init__(self, scan_id: str):
        self._ws_buf = StringIO()
        super().__init__(
            file=self._ws_buf,
            force_terminal=True,
            width=120,
            color_system="truecolor",
        )
        self.scan_id = scan_id
        self._finding_count = 0

    def print(self, *args, **kwargs):
        self._ws_buf.truncate(0)
        self._ws_buf.seek(0)
        super().print(*args, **kwargs)
        text = self._ws_buf.getvalue()
        if text.strip():
            socketio.emit("scan_output", {
                "scan_id": self.scan_id,
                "text": text,
            })

    def emit_finding(self, finding: dict):
        """Emit a single finding to the browser in real-time."""
        self._finding_count += 1
        socketio.emit("scan_finding", {
            "scan_id": self.scan_id,
            "finding": finding,
            "index": self._finding_count,
        })


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _apply_auth_profile(session, profile: dict):
    """Apply an authentication profile to a requests.Session."""
    ptype = profile.get("profile_type", "")
    config = profile.get("config", {})

    if ptype == "bearer":
        token = config.get("token", "")
        if token:
            session.headers["Authorization"] = f"Bearer {token}"
    elif ptype == "cookie":
        for name, value in config.get("cookies", {}).items():
            session.cookies.set(name, value)
    elif ptype == "header":
        for name, value in config.get("headers", {}).items():
            session.headers[name] = value
    elif ptype == "form":
        # Form-based login: post credentials to login URL, session will capture cookies
        login_url = config.get("login_url", "")
        form_data = config.get("form_data", {})
        if login_url and form_data:
            try:
                session.post(login_url, data=form_data, timeout=15, allow_redirects=True)
            except Exception:
                pass


def _patch_module_findings(module, web_console: 'WebConsole'):
    """Monkey-patch a module's _add_finding to also emit live findings via WebSocket."""
    original = getattr(module, '_add_finding', None)
    if original is None:
        return

    def patched(*args, **kwargs):
        original(*args, **kwargs)
        # The finding was appended to module.findings — grab the last one
        if hasattr(module, 'findings') and module.findings:
            web_console.emit_finding(module.findings[-1])

    module._add_finding = patched


def run_scan_thread(scan_id: str, scan_type: str, target: str, options: dict):
    """Run a scan in a background thread, streaming output via WebSocket
    and persisting results to the database."""

    console = WebConsole(scan_id)

    # Update in-memory cache
    _scans_cache[scan_id]["status"] = "running"
    _scans_cache[scan_id]["started_at"] = datetime.utcnow().isoformat()

    # Update database
    db.update_scan_status(scan_id, "running",
                          started_at=datetime.utcnow().isoformat())

    socketio.emit("scan_status", {"scan_id": scan_id, "status": "running"})

    findings = []
    try:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        url = target if target.startswith("http") else f"https://{target}"

        if scan_type == "recon":
            mod = ReconModule(console)
            _patch_module_findings(mod, console)
            passive = options.get("passive", False)
            findings = mod.run(target, passive_only=passive)

        elif scan_type == "vuln_scan":
            mod = VulnScannerModule(console)
            _patch_module_findings(mod, console)
            quick = options.get("quick", True)
            findings = mod.run(target, quick=quick)

        elif scan_type == "web_test":
            mod = WebTesterModule(console)
            _patch_module_findings(mod, console)
            full = options.get("full", False)
            # Apply auth profile if provided
            auth_profile_id = options.get("auth_profile_id")
            if auth_profile_id:
                profile = db.get_auth_profile(int(auth_profile_id))
                if profile:
                    _apply_auth_profile(mod.session, profile)
            findings = mod.run(url, full=full)

        elif scan_type == "js_analyze":
            mod = JSAnalyzerModule(console)
            _patch_module_findings(mod, console)
            findings = mod.analyze(url)

        elif scan_type == "takeover":
            recon_mod = ReconModule(console)
            _patch_module_findings(recon_mod, console)
            subs = recon_mod.subdomain_enum(domain)
            if subs:
                mod = TakeoverModule(console)
                _patch_module_findings(mod, console)
                findings = mod.check_subdomains(subs[:50])

        elif scan_type == "checks":
            mod = CustomChecksModule(console)
            _patch_module_findings(mod, console)
            findings = mod.run_all_builtin(target)

        elif scan_type == "full_auto":
            # Run all modules in sequence
            socketio.emit("scan_output", {
                "scan_id": scan_id,
                "text": "\n=== Phase 1/6: Reconnaissance ===\n",
            })
            recon_mod = ReconModule(console)
            findings.extend(recon_mod.run(target))

            socketio.emit("scan_output", {
                "scan_id": scan_id,
                "text": "\n=== Phase 2/6: Vulnerability Scanning ===\n",
            })
            vuln_mod = VulnScannerModule(console)
            findings.extend(vuln_mod.run(target, quick=True))

            socketio.emit("scan_output", {
                "scan_id": scan_id,
                "text": "\n=== Phase 3/6: Web Application Testing ===\n",
            })
            web_mod = WebTesterModule(console)
            findings.extend(web_mod.run(url, full=True))

            socketio.emit("scan_output", {
                "scan_id": scan_id,
                "text": "\n=== Phase 4/6: JavaScript Analysis ===\n",
            })
            js_mod = JSAnalyzerModule(console)
            findings.extend(js_mod.analyze(url))

            socketio.emit("scan_output", {
                "scan_id": scan_id,
                "text": "\n=== Phase 5/6: Security Checks ===\n",
            })
            checks_mod = CustomChecksModule(console)
            findings.extend(checks_mod.run_all_builtin(target))

            socketio.emit("scan_output", {
                "scan_id": scan_id,
                "text": "\n=== Phase 6/6: Subdomain Takeover ===\n",
            })
            subs = recon_mod.subdomain_enum(domain)
            if subs:
                takeover_mod = TakeoverModule(console)
                findings.extend(takeover_mod.check_subdomains(subs[:50]))

        # Mark completed
        completed_at = datetime.utcnow().isoformat()
        _scans_cache[scan_id]["status"] = "completed"
        _scans_cache[scan_id]["findings"] = findings
        _scans_cache[scan_id]["completed_at"] = completed_at

        db.update_scan_status(scan_id, "completed", completed_at=completed_at)
        db.save_findings(scan_id, findings)

    except Exception as e:
        _scans_cache[scan_id]["status"] = "error"
        _scans_cache[scan_id]["error"] = str(e)

        db.update_scan_status(scan_id, "error",
                              completed_at=datetime.utcnow().isoformat())

        socketio.emit("scan_output", {
            "scan_id": scan_id,
            "text": f"\n[ERROR] {e}\n",
        })

    socketio.emit("scan_status", {
        "scan_id": scan_id,
        "status": _scans_cache[scan_id]["status"],
        "finding_count": len(findings),
    })


# ===================================================================
#  API v1 Routes
# ===================================================================

# ------------------------------------------------------------------
# Auth endpoints  (rate-limited: 10/min)
# ------------------------------------------------------------------

@app.route("/api/v1/auth/login", methods=["POST"])
@rate_limit(limit=10, window=60)
def api_v1_login():
    """Authenticate a user and return a JWT."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return _err("Username and password are required")

    user = db.authenticate_user(username, password)
    if user is None:
        return _err("Invalid credentials", 401)

    token = generate_token(user["id"], user["role"], user["username"])
    return _ok({
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        },
    })


@app.route("/api/v1/auth/register", methods=["POST"])
@rate_limit(limit=10, window=60)
def api_v1_register():
    """Register a new user (default role: tester)."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "tester")

    if not username or not password:
        return _err("Username and password are required")

    if len(username) < 3:
        return _err("Username must be at least 3 characters")

    if len(password) < 6:
        return _err("Password must be at least 6 characters")

    # Only admins can create admin accounts
    if role == "admin":
        # Check if there's an auth header - if so, verify admin role
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            payload = verify_token(auth_header[7:].strip())
            if not payload or payload.get("role") != "admin":
                return _err("Only admins can create admin accounts", 403)
        else:
            return _err("Only admins can create admin accounts", 403)

    if role not in ("admin", "tester", "viewer"):
        return _err("Invalid role. Must be admin, tester, or viewer")

    user = db.create_user(username, password, role)
    if user is None:
        return _err("Username already taken", 409)

    token = generate_token(user["id"], user["role"], user["username"])
    return _ok({
        "token": token,
        "user": user,
    }), 201


# ------------------------------------------------------------------
# Scan endpoints  (require auth, rate-limited: 100/min)
# ------------------------------------------------------------------

@app.route("/api/v1/scans", methods=["POST"])
@rate_limit(limit=100)
@require_auth(roles=["admin", "tester"])
def api_v1_start_scan():
    """Start a new scan."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "recon")
    options = data.get("options", {})

    if not target:
        return _err("Target is required")

    valid_types = ("recon", "vuln_scan", "web_test", "js_analyze",
                   "takeover", "checks", "full_auto")
    if scan_type not in valid_types:
        return _err(f"Invalid scan_type. Must be one of: {', '.join(valid_types)}")

    scan_id = str(uuid.uuid4())[:8]
    user_id = g.current_user["id"]

    # Persist to database
    db.create_scan(scan_id, target, scan_type, options, user_id)

    # In-memory cache for live status
    _scans_cache[scan_id] = {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "options": options,
        "status": "queued",
        "findings": [],
        "created_at": datetime.utcnow().isoformat(),
        "user_id": user_id,
    }

    thread = threading.Thread(
        target=run_scan_thread,
        args=(scan_id, scan_type, target, options),
        daemon=True,
    )
    thread.start()

    return _ok({"scan_id": scan_id, "status": "queued"}), 201


@app.route("/api/v1/scans", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_list_scans():
    """List scans. Admins see all; others see only their own."""
    user = g.current_user
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)

    if user["role"] == "admin":
        scans = db.list_scans(user_id=None, limit=limit, offset=offset)
    else:
        scans = db.list_scans(user_id=user["id"], limit=limit, offset=offset)

    return _ok(scans)


@app.route("/api/v1/scans/<scan_id>", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_get_scan(scan_id):
    """Get a scan with its findings."""
    scan = db.get_scan(scan_id)
    if scan is None:
        return _err("Scan not found", 404)

    # Non-admins can only see their own scans
    user = g.current_user
    if user["role"] != "admin" and scan.get("user_id") != user["id"]:
        return _err("Scan not found", 404)

    # If the scan is still running, overlay live status from cache
    if scan_id in _scans_cache and _scans_cache[scan_id]["status"] == "running":
        scan["status"] = "running"

    return _ok(scan)


@app.route("/api/v1/scans/<scan_id>/findings", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_get_findings(scan_id):
    """Get findings for a scan."""
    scan = db.get_scan(scan_id)
    if scan is None:
        return _err("Scan not found", 404)

    user = g.current_user
    if user["role"] != "admin" and scan.get("user_id") != user["id"]:
        return _err("Scan not found", 404)

    findings = db.get_findings(scan_id)
    return _ok(findings)


@app.route("/api/v1/scans/<scan_id>/report/<fmt>", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_generate_report(scan_id, fmt):
    """Generate and download a report for a scan."""
    scan = db.get_scan(scan_id)
    if scan is None:
        return _err("Scan not found", 404)

    user = g.current_user
    if user["role"] != "admin" and scan.get("user_id") != user["id"]:
        return _err("Scan not found", 404)

    if fmt not in ("md", "html", "json"):
        return _err("Invalid format. Use md, html, or json")

    console = Console(file=StringIO())
    reporter = ReporterModule(console)
    reporter.target = scan["target"]
    reporter.tester = user.get("username", "PENT Web UI")
    reporter.add_findings(scan.get("findings", []))

    output_dir = os.path.join(_PROJECT_ROOT, "reports")
    filepath = reporter.run(output_dir=output_dir, fmt=fmt)

    mime_types = {
        "md": "text/markdown",
        "html": "text/html",
        "json": "application/json",
    }
    return send_file(filepath, mimetype=mime_types[fmt], as_attachment=True)


# ------------------------------------------------------------------
# Guide endpoints  (no auth, rate-limited: 100/min)
# ------------------------------------------------------------------

@app.route("/api/v1/guides", methods=["GET"])
@rate_limit(limit=100)
def api_v1_list_guides():
    """List all available methodology guides."""
    guides = []
    for key, data in METHODOLOGIES.items():
        guides.append({"key": key, "title": data["title"]})
    return _ok(guides)


@app.route("/api/v1/guides/<topic>", methods=["GET"])
@rate_limit(limit=100)
def api_v1_get_guide(topic):
    """Get a specific methodology guide."""
    guide = METHODOLOGIES.get(topic)
    if not guide:
        return _err("Guide not found", 404)
    return _ok(guide)


# ------------------------------------------------------------------
# Stats endpoint  (require auth, rate-limited: 100/min)
# ------------------------------------------------------------------

@app.route("/api/v1/stats", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_stats():
    """Get aggregate statistics: total scans, findings by severity, recent activity."""
    user = g.current_user
    if user["role"] == "admin":
        stats = db.get_stats(user_id=None)
    else:
        stats = db.get_stats(user_id=user["id"])
    return _ok(stats)


# ------------------------------------------------------------------
# API Key management  (require auth)
# ------------------------------------------------------------------

@app.route("/api/v1/api-keys", methods=["POST"])
@rate_limit(limit=100)
@require_auth()
def api_v1_create_api_key():
    """Create a new API key for the current user."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return _err("API key name is required")

    user = g.current_user
    key_info = db.create_api_key(user["id"], name)
    return _ok(key_info), 201


# ------------------------------------------------------------------
# Target endpoints  (require auth)
# ------------------------------------------------------------------

@app.route("/api/v1/targets", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_list_targets():
    """List saved targets."""
    user = g.current_user
    uid = None if user["role"] == "admin" else user["id"]
    return _ok(db.list_targets(user_id=uid))


@app.route("/api/v1/targets", methods=["POST"])
@rate_limit(limit=100)
@require_auth(roles=["admin", "tester"])
def api_v1_create_target():
    """Create a saved target."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    target_str = data.get("target", "").strip()
    project = data.get("project", "Default").strip()
    scope_notes = data.get("scope_notes", "")

    if not name or not target_str:
        return _err("Name and target are required")

    target_id = str(uuid.uuid4())[:8]
    result = db.create_target(target_id, name, target_str, project, scope_notes, g.current_user["id"])
    return _ok(result), 201


@app.route("/api/v1/targets/<target_id>", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_get_target(target_id):
    """Get a single target."""
    t = db.get_target(target_id)
    if t is None:
        return _err("Target not found", 404)
    return _ok(t)


@app.route("/api/v1/targets/<target_id>", methods=["DELETE"])
@rate_limit(limit=100)
@require_auth(roles=["admin", "tester"])
def api_v1_delete_target(target_id):
    """Delete a saved target."""
    t = db.get_target(target_id)
    if t is None:
        return _err("Target not found", 404)
    db.delete_target(target_id)
    return _ok({"deleted": True})


# ------------------------------------------------------------------
# Auth Profile endpoints  (require auth)
# ------------------------------------------------------------------

@app.route("/api/v1/auth-profiles", methods=["GET"])
@rate_limit(limit=100)
@require_auth()
def api_v1_list_auth_profiles():
    """List auth profiles."""
    user = g.current_user
    uid = None if user["role"] == "admin" else user["id"]
    return _ok(db.list_auth_profiles(user_id=uid))


@app.route("/api/v1/auth-profiles", methods=["POST"])
@rate_limit(limit=100)
@require_auth(roles=["admin", "tester"])
def api_v1_create_auth_profile():
    """Create an auth profile (bearer, cookie, header, form)."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    profile_type = data.get("profile_type", "bearer")
    config = data.get("config", {})
    target_id = data.get("target_id")

    if not name:
        return _err("Name is required")
    if profile_type not in ("bearer", "cookie", "header", "form"):
        return _err("Invalid profile_type")

    result = db.create_auth_profile(name, profile_type, config, target_id, g.current_user["id"])
    return _ok(result), 201


@app.route("/api/v1/auth-profiles/<int:profile_id>", methods=["DELETE"])
@rate_limit(limit=100)
@require_auth(roles=["admin", "tester"])
def api_v1_delete_auth_profile(profile_id):
    """Delete an auth profile."""
    p = db.get_auth_profile(profile_id)
    if p is None:
        return _err("Profile not found", 404)
    db.delete_auth_profile(profile_id)
    return _ok({"deleted": True})


# ===================================================================
#  Legacy API routes (for backward compatibility)
# ===================================================================

@app.route("/api/scan/start", methods=["POST"])
@rate_limit(limit=100)
def api_legacy_start_scan():
    """Legacy scan start - no auth required for backward compat."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "recon")
    options = data.get("options", {})

    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_id = str(uuid.uuid4())[:8]

    # Persist to database (no user)
    db.create_scan(scan_id, target, scan_type, options, user_id=None)

    _scans_cache[scan_id] = {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "options": options,
        "status": "queued",
        "findings": [],
        "created_at": datetime.utcnow().isoformat(),
    }

    thread = threading.Thread(
        target=run_scan_thread,
        args=(scan_id, scan_type, target, options),
        daemon=True,
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "queued"})


@app.route("/api/scan/<scan_id>")
@rate_limit(limit=100)
def api_legacy_scan_status(scan_id):
    """Legacy scan status."""
    # Try in-memory cache first (for live running scans)
    if scan_id in _scans_cache:
        return jsonify(_scans_cache[scan_id])
    # Fall back to database
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scans")
@rate_limit(limit=100)
def api_legacy_list_scans():
    """Legacy scan list."""
    scans = db.list_scans()
    return jsonify(scans)


@app.route("/api/scan/<scan_id>/findings")
@rate_limit(limit=100)
def api_legacy_scan_findings(scan_id):
    """Legacy findings endpoint."""
    findings = db.get_findings(scan_id)
    return jsonify(findings)


@app.route("/api/scan/<scan_id>/report/<fmt>")
@rate_limit(limit=100)
def api_legacy_generate_report(scan_id, fmt):
    """Legacy report generation."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if fmt not in ("md", "html", "json"):
        return jsonify({"error": "Invalid format. Use md, html, or json"}), 400

    console = Console(file=StringIO())
    reporter = ReporterModule(console)
    reporter.target = scan["target"]
    reporter.tester = "PENT Web UI"
    reporter.add_findings(scan.get("findings", []))

    output_dir = os.path.join(_PROJECT_ROOT, "reports")
    filepath = reporter.run(output_dir=output_dir, fmt=fmt)

    mime_types = {
        "md": "text/markdown",
        "html": "text/html",
        "json": "application/json",
    }
    return send_file(filepath, mimetype=mime_types[fmt], as_attachment=True)


@app.route("/api/guides")
@rate_limit(limit=100)
def api_legacy_list_guides():
    """Legacy guides list."""
    guides = []
    for key, data in METHODOLOGIES.items():
        guides.append({"key": key, "title": data["title"]})
    return jsonify(guides)


@app.route("/api/guides/<topic>")
@rate_limit(limit=100)
def api_legacy_get_guide(topic):
    """Legacy guide detail."""
    guide = METHODOLOGIES.get(topic)
    if not guide:
        return jsonify({"error": "Guide not found"}), 404
    return jsonify(guide)


# ===================================================================
#  SPA serving & template fallbacks
# ===================================================================

@app.route("/")
def index():
    """Serve the React SPA index.html, or fall back to the template."""
    if os.path.isdir(_DIST_DIR) and os.path.isfile(os.path.join(_DIST_DIR, "index.html")):
        return send_from_directory(_DIST_DIR, "index.html")
    return send_from_directory(os.path.join(_WEB_DIR, "templates"), "index.html")


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    """Serve Vite build assets."""
    return send_from_directory(os.path.join(_DIST_DIR, "assets"), filename)


# SPA catch-all: any path that doesn't match an API route serves the SPA
@app.route("/<path:path>")
def catch_all(path):
    """Serve static files from dist/ or fall back to SPA index.html."""
    # Try to serve a static file from dist/
    if os.path.isdir(_DIST_DIR):
        full_path = os.path.join(_DIST_DIR, path)
        if os.path.isfile(full_path):
            return send_from_directory(_DIST_DIR, path)
        # For SPA client-side routing, return index.html
        index_path = os.path.join(_DIST_DIR, "index.html")
        if os.path.isfile(index_path):
            return send_from_directory(_DIST_DIR, "index.html")

    # Fallback: try old templates/static for backward compat
    static_path = os.path.join(_WEB_DIR, "static", path)
    if os.path.isfile(static_path):
        return send_from_directory(os.path.join(_WEB_DIR, "static"), path)

    return _err("Not found", 404)


# ===================================================================
#  WebSocket events
# ===================================================================

@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "ok"})


@socketio.on("subscribe_scan")
def handle_subscribe(data):
    scan_id = data.get("scan_id")
    if scan_id and scan_id in _scans_cache:
        emit("scan_status", {
            "scan_id": scan_id,
            "status": _scans_cache[scan_id]["status"],
        })


# ===================================================================
#  CORS handling (dev mode only)
# ===================================================================

if _dev_mode:
    @app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-API-Key"
        )
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, PUT, DELETE, OPTIONS"
        )
        return response

    @app.route("/api/v1/<path:path>", methods=["OPTIONS"])
    @app.route("/api/<path:path>", methods=["OPTIONS"])
    def handle_options(path):
        """Handle CORS preflight requests in dev mode."""
        return "", 204


# ===================================================================
#  Main
# ===================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="PENT Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "--db", default=None,
        help="Path to SQLite database file (default: <project_root>/pent.db)",
    )
    args = parser.parse_args()

    # Reconfigure DB path if specified
    if args.db:
        db.db_path = args.db

    # Initialize database (create tables, seed default admin)
    db.init_db()

    dev_flag = " [DEV MODE]" if _dev_mode else ""
    print(f"""
    ____  _______   ________
   / __ \\/ ____/ | / /_  __/
  / /_/ / __/ /  |/ / / /
 / ____/ /___/ /|  / / /
/_/   /_____/_/ |_/ /_/

  Web UI starting on http://{args.host}:{args.port}{dev_flag}
  API base: http://{args.host}:{args.port}/api/v1/
  Default login: admin / admin
  Open your browser and navigate to the URL above.
    """)

    socketio.run(app, host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
