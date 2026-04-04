"""OpenHost auth bridge for Split-Pro.

Runs inside the container alongside Next.js and Postgres.
Caddy's forward_auth checks /check-session on every request.
If the user is the zone owner (X-OpenHost-Is-Owner: true) and has no
NextAuth session, this creates one directly in Postgres and sets the
session cookie.

Based on the pattern from openhost-plane.so.
"""

import logging
import os
import secrets
import string
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
from flask import Flask, Response, redirect, request

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres@127.0.0.1:5432/splitpro")
ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "localhost")
OWNER_EMAIL = os.environ.get("OPENHOST_OWNER_EMAIL", f"owner@{ZONE_DOMAIN}")

# NextAuth session cookie name (HTTPS uses __Secure- prefix)
SESSION_COOKIE = "next-auth.session-token"
SESSION_COOKIE_SECURE = "__Secure-next-auth.session-token"


def _db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def _is_owner(req):
    return req.headers.get("X-OpenHost-Is-Owner") == "true"


def _generate_session_token():
    """Generate a random session token like NextAuth does (UUID-style)."""
    return secrets.token_urlsafe(32)


def _find_or_create_user():
    """Find or create the owner's Split-Pro user. Returns user id."""
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT id FROM "User" WHERE email = %s', (OWNER_EMAIL,))
        row = cur.fetchone()
        if row:
            return row["id"]

        # Create user
        cur.execute(
            'INSERT INTO "User" (name, email, "emailVerified", currency) VALUES (%s, %s, %s, %s) RETURNING id',
            ("Owner", OWNER_EMAIL, datetime.now(timezone.utc), "USD"),
        )
        user_id = cur.fetchone()["id"]
        conn.commit()
        log.info("Created Split-Pro user %s for %s", user_id, OWNER_EMAIL)
        return user_id
    finally:
        conn.close()


def _create_session(user_id):
    """Create a NextAuth session in the DB. Returns session token."""
    token = _generate_session_token()
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    session_id = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(25))

    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO "Session" (id, "sessionToken", "userId", expires) VALUES (%s, %s, %s, %s)',
            (session_id, token, user_id, expires),
        )
        conn.commit()
        log.info("Created NextAuth session for user %s", user_id)
        return token, expires
    finally:
        conn.close()


def _validate_session(token):
    """Check if a session token is valid (exists and not expired)."""
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute(
            'SELECT "userId" FROM "Session" WHERE "sessionToken" = %s AND expires > NOW()',
            (token,),
        )
        return cur.fetchone() is not None
    except Exception:
        return False
    finally:
        conn.close()


@app.route("/check-session")
def check_session():
    """Forward-auth endpoint: auto-login zone owner into Split-Pro."""
    # Check existing session cookie
    existing = request.cookies.get(SESSION_COOKIE_SECURE) or request.cookies.get(SESSION_COOKIE)
    if existing and _validate_session(existing):
        return Response("ok", status=200)

    # Not the owner? Let them through (Split-Pro will show its own login)
    if not _is_owner(request):
        return Response("ok", status=200)

    # Owner without valid session — create one
    try:
        user_id = _find_or_create_user()
        token, expires = _create_session(user_id)
    except Exception as e:
        log.error("Failed to create session: %s", e)
        return Response("ok", status=200)

    # Redirect to the original URL with the new session cookie
    original_uri = request.headers.get("X-Forwarded-Uri", "/")
    resp = redirect(original_uri)

    # Set both secure and non-secure cookie names for compatibility
    resp.set_cookie(
        SESSION_COOKIE_SECURE,
        token,
        expires=expires,
        path="/",
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        expires=expires,
        path="/",
        httponly=True,
        samesite="Lax",
    )
    log.info("Auto-logged in zone owner")
    return resp


@app.route("/healthz")
def healthz():
    """Health check."""
    try:
        conn = _db()
        conn.cursor().execute("SELECT 1")
        conn.close()
        return Response("ok", status=200)
    except Exception:
        return Response("db not ready", status=503)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3006)
