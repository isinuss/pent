"""
PENT Auth Layer - JWT-based authentication and authorization.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import request, jsonify, g

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Secret key: prefer env var, fall back to a random key (ephemeral per process)
_SECRET_KEY = os.environ.get("PENT_SECRET_KEY") or secrets.token_hex(32)
_ALGORITHM = "HS256"
_TOKEN_EXPIRY_HOURS = 24


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def generate_token(user_id: int, role: str, username: str = "") -> str:
    """Create a signed JWT for the given user."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "username": username,
        "iat": now,
        "exp": now + timedelta(hours=_TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def verify_token(token: str) -> dict | None:
    """Decode and verify a JWT.  Returns the payload dict or None."""
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ---------------------------------------------------------------------------
# Flask decorator
# ---------------------------------------------------------------------------

def require_auth(roles: list[str] | None = None):
    """Flask route decorator that enforces authentication.

    Checks (in order):
      1. Authorization: Bearer <token>  header (JWT)
      2. X-API-Key header               (database-validated API key)

    On success, sets ``g.current_user`` with keys: id, username, role.

    Args:
        roles: If provided, restrict to these roles (e.g. ['admin', 'tester']).
               ``None`` means any authenticated user is allowed.
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = None

            # --- Try Bearer token first ---
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
                payload = verify_token(token)
                if payload:
                    user = {
                        "id": int(payload["sub"]),
                        "username": payload.get("username", ""),
                        "role": payload.get("role", "viewer"),
                    }

            # --- Try API key ---
            if user is None:
                api_key = request.headers.get("X-API-Key", "").strip()
                if api_key:
                    # Use the db instance stored on the Flask app by server.py,
                    # or fall back to a default Database() if not set.
                    from flask import current_app
                    _db = getattr(current_app, "pent_db", None)
                    if _db is None:
                        from web.database import Database
                        _db = Database()
                    user = _db.validate_api_key(api_key)

            if user is None:
                return jsonify({"data": None, "error": "Authentication required"}), 401

            # Role check
            if roles and user.get("role") not in roles:
                return jsonify({"data": None, "error": "Insufficient permissions"}), 403

            g.current_user = user
            return f(*args, **kwargs)

        return decorated
    return decorator
