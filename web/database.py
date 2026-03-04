"""
PENT Database Layer - SQLite-based persistence for users, scans, findings, and API keys.
"""

import os
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime
from contextlib import contextmanager


# ---------------------------------------------------------------------------
# Password hashing using hashlib + secrets (no external dependency)
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """Hash a password with a random salt using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 260_000)
    return f"{salt}${dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    try:
        salt, dk_hex = stored_hash.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 260_000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


def _hash_api_key(key: str) -> str:
    """One-way hash for API key storage (SHA-256)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# SQL Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    password_hash TEXT  NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'tester' CHECK(role IN ('admin','tester','viewer')),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id           TEXT    PRIMARY KEY,
    target       TEXT    NOT NULL,
    scan_type    TEXT    NOT NULL,
    options      TEXT    DEFAULT '{}',
    status       TEXT    NOT NULL DEFAULT 'queued',
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    started_at   TEXT,
    completed_at TEXT,
    user_id      INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title       TEXT,
    severity    TEXT,
    category    TEXT,
    detail      TEXT,
    evidence    TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT    NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used   TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    project     TEXT    NOT NULL DEFAULT 'Default',
    scope_notes TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    user_id     INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS auth_profiles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    profile_type TEXT   NOT NULL DEFAULT 'bearer' CHECK(profile_type IN ('bearer','cookie','header','form')),
    config      TEXT    NOT NULL DEFAULT '{}',
    target_id   TEXT    REFERENCES targets(id) ON DELETE SET NULL,
    user_id     INTEGER REFERENCES users(id),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """SQLite database wrapper for PENT."""

    def __init__(self, db_path: str | None = None):
        if db_path is None:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(project_root, "pent.db")
        self.db_path = db_path

    @contextmanager
    def _connect(self):
        """Context manager that yields a connection with WAL mode and foreign keys."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def init_db(self):
        """Create tables if they don't exist and seed a default admin user."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

            # Create default admin/admin if no users exist
            row = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
            if row["cnt"] == 0:
                pw_hash = _hash_password("admin")
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    ("admin", pw_hash, "admin"),
                )

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def create_user(self, username: str, password: str, role: str = "tester") -> dict | None:
        """Create a new user.  Returns the user dict or None if username taken."""
        if role not in ("admin", "tester", "viewer"):
            raise ValueError(f"Invalid role: {role}")
        pw_hash = _hash_password(password)
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, pw_hash, role),
                )
                return {
                    "id": cur.lastrowid,
                    "username": username,
                    "role": role,
                }
        except sqlite3.IntegrityError:
            return None

    def authenticate_user(self, username: str, password: str) -> dict | None:
        """Verify credentials.  Returns user dict or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None:
            return None
        if not _verify_password(password, row["password_hash"]):
            return None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}

    def get_user(self, user_id: int) -> dict | None:
        """Look up a user by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, username, role, created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(self, scan_id: str, target: str, scan_type: str,
                    options: dict | None = None, user_id: int | None = None) -> dict:
        """Insert a new scan record."""
        opts_json = json.dumps(options or {})
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans (id, target, scan_type, options, status, user_id) "
                "VALUES (?, ?, ?, ?, 'queued', ?)",
                (scan_id, target, scan_type, opts_json, user_id),
            )
        return {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "options": options or {},
            "status": "queued",
            "user_id": user_id,
        }

    def update_scan_status(self, scan_id: str, status: str, **kwargs):
        """Update scan status and optional timestamp fields.

        Accepted kwargs: started_at, completed_at, error.
        """
        fields = ["status = ?"]
        params: list = [status]
        if "started_at" in kwargs:
            fields.append("started_at = ?")
            params.append(kwargs["started_at"])
        if "completed_at" in kwargs:
            fields.append("completed_at = ?")
            params.append(kwargs["completed_at"])
        params.append(scan_id)

        with self._connect() as conn:
            conn.execute(
                f"UPDATE scans SET {', '.join(fields)} WHERE id = ?",
                params,
            )

    def get_scan(self, scan_id: str) -> dict | None:
        """Retrieve a single scan with its findings."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            scan = dict(row)
            scan["options"] = json.loads(scan.get("options") or "{}")

            findings = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
            scan["findings"] = [self._normalize_finding(dict(f)) for f in findings]
        return scan

    def list_scans(self, user_id: int | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        """List scans, optionally filtered by user.  Most recent first."""
        with self._connect() as conn:
            if user_id is not None:
                rows = conn.execute(
                    "SELECT id, target, scan_type, status, created_at, started_at, completed_at, user_id "
                    "FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (user_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, target, scan_type, status, created_at, started_at, completed_at, user_id "
                    "FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            # Attach finding count without fetching entire findings
            with self._connect() as conn:
                cnt = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM findings WHERE scan_id = ?", (d["id"],)
                ).fetchone()
            d["finding_count"] = cnt["cnt"] if cnt else 0
            results.append(d)
        return results

    def get_findings(self, scan_id: str) -> list[dict]:
        """Get all findings for a scan, normalized for the frontend."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        return [self._normalize_finding(dict(r)) for r in rows]

    @staticmethod
    def _normalize_finding(f: dict) -> dict:
        """Map DB columns to the shape the React frontend expects.

        DB has: title, severity, category, detail, evidence (JSON)
        Frontend expects: title, severity, category, description, evidence (str), recommendation
        """
        # detail -> description
        f["description"] = f.pop("detail", "") or ""

        # Parse evidence JSON into readable text
        raw_ev = f.get("evidence") or ""
        if raw_ev:
            try:
                ev = json.loads(raw_ev)
                if isinstance(ev, dict):
                    f["evidence"] = "\n".join(f"{k}: {v}" for k, v in ev.items())
                else:
                    f["evidence"] = str(ev)
            except (json.JSONDecodeError, TypeError):
                f["evidence"] = raw_ev
        else:
            f["evidence"] = ""

        # Generate recommendation
        sev = (f.get("severity") or "info").lower()
        title = (f.get("title") or "").lower()
        cat = (f.get("category") or "").lower()

        rec = ""
        if "missing" in title or "missing" in cat:
            header_name = f.get("title", "").replace("Missing ", "")
            rec = f"Add the {header_name} header to your server configuration to improve security posture."
        elif "cors" in title:
            rec = "Restrict Access-Control-Allow-Origin to trusted domains only. Avoid using wildcard (*)."
        elif "cookie" in title or "cookie" in cat:
            rec = "Set Secure, HttpOnly, and SameSite attributes on all session cookies."
        elif "ssl" in cat or "tls" in title:
            rec = "Disable deprecated TLS versions (1.0, 1.1) and enable TLS 1.2+ with strong cipher suites."
        elif "xss" in title:
            rec = "Implement Content-Security-Policy, sanitize user input, and encode output."
        elif "sql" in title:
            rec = "Use parameterized queries / prepared statements. Never concatenate user input into SQL."
        elif "redirect" in title:
            rec = "Validate redirect URLs against an allowlist. Never redirect to user-supplied URLs directly."
        elif "info_disclosure" in cat or "disclosure" in title:
            rec = "Remove version information from server headers. Configure your web server to hide Server/X-Powered-By."
        elif "port" in cat:
            rec = "Close unnecessary ports. Use firewall rules to restrict access to essential services only."
        elif "takeover" in cat or "takeover" in title:
            rec = "Remove dangling DNS records pointing to deprovisioned services."
        elif sev in ("critical", "high"):
            rec = "This is a high-severity finding. Investigate and remediate as soon as possible."
        elif sev == "medium":
            rec = "Review this finding and apply the appropriate fix based on your environment."
        else:
            rec = "Informational finding. Review and address if applicable to your security posture."

        f["recommendation"] = rec
        return f

    def save_findings(self, scan_id: str, findings: list[dict]):
        """Persist a list of finding dicts from a scan module.

        Handles the various finding dict shapes produced by different modules:
        - Some use 'key'/'value' instead of 'title'/'detail'
        - Some include 'category', some don't
        - Some include 'url' as evidence
        """
        with self._connect() as conn:
            for f in findings:
                title = f.get("title") or f.get("key") or "Untitled"
                severity = f.get("severity", "info")
                category = f.get("category", "General")
                detail = f.get("detail") or f.get("value") or ""
                # Collect extra fields as evidence JSON
                evidence_parts = {}
                if f.get("url"):
                    evidence_parts["url"] = f["url"]
                if f.get("timestamp"):
                    evidence_parts["timestamp"] = f["timestamp"]
                # Store any other keys not already captured
                for k, v in f.items():
                    if k not in ("title", "key", "severity", "category", "detail", "value",
                                 "url", "timestamp"):
                        evidence_parts[k] = v
                evidence = json.dumps(evidence_parts) if evidence_parts else None

                conn.execute(
                    "INSERT INTO findings (scan_id, title, severity, category, detail, evidence) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (scan_id, title, severity, category, detail, evidence),
                )

    # ------------------------------------------------------------------
    # API Keys
    # ------------------------------------------------------------------

    def create_api_key(self, user_id: int, name: str) -> dict:
        """Generate a new API key. Returns dict with the raw key (shown once)."""
        raw_key = f"pent_{secrets.token_hex(24)}"
        key_hash = _hash_api_key(raw_key)
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO api_keys (key_hash, user_id, name) VALUES (?, ?, ?)",
                (key_hash, user_id, name),
            )
        return {"id": cur.lastrowid, "key": raw_key, "name": name}

    def validate_api_key(self, raw_key: str) -> dict | None:
        """Validate an API key. Returns the associated user dict or None."""
        key_hash = _hash_api_key(raw_key)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT ak.id AS key_id, ak.user_id, u.username, u.role "
                "FROM api_keys ak JOIN users u ON ak.user_id = u.id "
                "WHERE ak.key_hash = ?",
                (key_hash,),
            ).fetchone()
            if row is None:
                return None
            # Update last_used timestamp
            conn.execute(
                "UPDATE api_keys SET last_used = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), row["key_id"]),
            )
        return {"id": row["user_id"], "username": row["username"], "role": row["role"]}

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def create_target(self, target_id: str, name: str, target: str, project: str = "Default",
                      scope_notes: str = "", user_id: int | None = None) -> dict:
        """Create a saved target."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO targets (id, name, target, project, scope_notes, user_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (target_id, name, target, project, scope_notes, user_id),
            )
        return {
            "id": target_id, "name": name, "target": target,
            "project": project, "scope_notes": scope_notes,
        }

    def list_targets(self, user_id: int | None = None) -> list[dict]:
        """List all targets, enriched with last scan date and finding count."""
        with self._connect() as conn:
            if user_id is not None:
                rows = conn.execute(
                    "SELECT * FROM targets WHERE user_id = ? ORDER BY created_at DESC",
                    (user_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM targets ORDER BY created_at DESC"
                ).fetchall()

            results = []
            for row in rows:
                d = dict(row)
                # Last scan
                last = conn.execute(
                    "SELECT created_at FROM scans WHERE target = ? ORDER BY created_at DESC LIMIT 1",
                    (d["target"],),
                ).fetchone()
                d["last_scan_at"] = last["created_at"] if last else None
                # Finding count
                cnt = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM findings f "
                    "JOIN scans s ON f.scan_id = s.id WHERE s.target = ?",
                    (d["target"],),
                ).fetchone()
                d["finding_count"] = cnt["cnt"] if cnt else 0
                results.append(d)
        return results

    def get_target(self, target_id: str) -> dict | None:
        """Get a single target."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return dict(row) if row else None

    def delete_target(self, target_id: str):
        """Delete a target."""
        with self._connect() as conn:
            conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))

    # ------------------------------------------------------------------
    # Auth Profiles
    # ------------------------------------------------------------------

    def create_auth_profile(self, name: str, profile_type: str, config: dict,
                            target_id: str | None = None, user_id: int | None = None) -> dict:
        """Create an authentication profile."""
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO auth_profiles (name, profile_type, config, target_id, user_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, profile_type, json.dumps(config), target_id, user_id),
            )
        return {"id": cur.lastrowid, "name": name, "profile_type": profile_type, "config": config}

    def list_auth_profiles(self, user_id: int | None = None) -> list[dict]:
        """List auth profiles."""
        with self._connect() as conn:
            if user_id is not None:
                rows = conn.execute(
                    "SELECT * FROM auth_profiles WHERE user_id = ? ORDER BY created_at DESC",
                    (user_id,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM auth_profiles ORDER BY created_at DESC").fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["config"] = json.loads(d.get("config") or "{}")
            results.append(d)
        return results

    def get_auth_profile(self, profile_id: int) -> dict | None:
        """Get a single auth profile."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM auth_profiles WHERE id = ?", (profile_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["config"] = json.loads(d.get("config") or "{}")
        return d

    def delete_auth_profile(self, profile_id: int):
        """Delete an auth profile."""
        with self._connect() as conn:
            conn.execute("DELETE FROM auth_profiles WHERE id = ?", (profile_id,))

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self, user_id: int | None = None) -> dict:
        """Return aggregate stats. If user_id is given, scope to that user."""
        with self._connect() as conn:
            where = ""
            params: tuple = ()
            if user_id is not None:
                where = "WHERE s.user_id = ?"
                params = (user_id,)

            total_scans = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM scans s {where}", params
            ).fetchone()["cnt"]

            severity_rows = conn.execute(
                f"SELECT f.severity, COUNT(*) AS cnt "
                f"FROM findings f JOIN scans s ON f.scan_id = s.id {where} "
                f"GROUP BY f.severity",
                params,
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

            recent = conn.execute(
                f"SELECT s.id, s.target, s.scan_type, s.status, s.created_at "
                f"FROM scans s {where} ORDER BY s.created_at DESC LIMIT 10",
                params,
            ).fetchall()

        return {
            "total_scans": total_scans,
            "findings_by_severity": by_severity,
            "recent_scans": [dict(r) for r in recent],
        }
