"""OpenHost auth bridge for Split-Pro.

Runs inside the container alongside Next.js and Postgres.
Caddy's forward_auth checks /check-session on every request.
If the user is the zone owner (X-OpenHost-Is-Owner: true) and has no
NextAuth session, this creates one directly in Postgres and sets the
session cookie.

Based on the pattern from openhost-plane.so.
"""

import json
import logging
import os
import secrets
import string
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
from flask import Flask, Response, redirect, request, render_template_string

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres@127.0.0.1:5432/splitpro")
ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "localhost")
APP_NAME = os.environ.get("OPENHOST_APP_NAME", "split-pro")
OWNER_EMAIL = os.environ.get("OPENHOST_OWNER_EMAIL", f"owner@{ZONE_DOMAIN}")

# File to persist invite tokens
DATA_DIR = os.environ.get("OPENHOST_APP_DATA_DIR", "/app/data")
INVITES_FILE = os.path.join(DATA_DIR, "invites.json")

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


def _load_invites():
    if os.path.exists(INVITES_FILE):
        with open(INVITES_FILE) as f:
            return json.load(f)
    return {}


def _save_invites(invites):
    os.makedirs(os.path.dirname(INVITES_FILE), exist_ok=True)
    with open(INVITES_FILE, "w") as f:
        json.dump(invites, f, indent=2)


def _find_or_create_guest(name):
    """Find or create a guest user by name. Returns user id."""
    email = f"{name.lower().replace(' ', '-')}@guest.{ZONE_DOMAIN}"
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT id FROM "User" WHERE email = %s', (email,))
        row = cur.fetchone()
        if row:
            return row["id"]

        cur.execute(
            'INSERT INTO "User" (name, email, "emailVerified", currency) VALUES (%s, %s, %s, %s) RETURNING id',
            (name, email, datetime.now(timezone.utc), "USD"),
        )
        user_id = cur.fetchone()["id"]
        conn.commit()
        log.info("Created guest user %s (%s)", name, email)
        return user_id
    finally:
        conn.close()


def _add_user_to_group(guest_user_id, group_id):
    """Add a user to a group if not already a member."""
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute(
            'SELECT 1 FROM "GroupUser" WHERE "groupId" = %s AND "userId" = %s',
            (group_id, guest_user_id),
        )
        if cur.fetchone():
            return  # already a member
        cur.execute(
            'INSERT INTO "GroupUser" ("groupId", "userId") VALUES (%s, %s)',
            (group_id, guest_user_id),
        )
        conn.commit()
        log.info("Added user %s to group %s", guest_user_id, group_id)
    finally:
        conn.close()


def _get_owner_groups():
    """Get all groups the owner belongs to."""
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT id FROM "User" WHERE email = %s', (OWNER_EMAIL,))
        owner_row = cur.fetchone()
        if not owner_row:
            return []
        cur.execute(
            'SELECT g.id, g.name, g."publicId" FROM "Group" g '
            'JOIN "GroupUser" gu ON g.id = gu."groupId" '
            'WHERE gu."userId" = %s ORDER BY g."createdAt" DESC',
            (owner_row["id"],),
        )
        return cur.fetchall()
    finally:
        conn.close()


def _app_url():
    proto = "https" if ZONE_DOMAIN != "localhost" else "http"
    host = f"{APP_NAME}.{ZONE_DOMAIN}" if ZONE_DOMAIN != "localhost" else "localhost:8080"
    return f"{proto}://{host}"


@app.route("/invite")
def invite_page():
    """Owner page to create and manage guest invite links."""
    if not _is_owner(request):
        return Response("Only the zone owner can manage invites", status=403)

    invites = _load_invites()
    groups = _get_owner_groups()
    base_url = _app_url()
    return render_template_string(INVITE_TEMPLATE, invites=invites, groups=groups, base_url=base_url)


@app.route("/invite/create", methods=["POST"])
def create_invite():
    """Owner creates an invite link for a friend."""
    if not _is_owner(request):
        return Response("Unauthorized", status=401)

    name = request.form.get("name", "").strip()
    group_id = request.form.get("group_id", "").strip()
    if not name:
        return Response("Name is required", status=400)

    token = secrets.token_urlsafe(16)
    invites = _load_invites()
    invite_data = {
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if group_id:
        # Store group info for display
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute('SELECT name, "publicId" FROM "Group" WHERE id = %s', (int(group_id),))
            group_row = cur.fetchone()
            if group_row:
                invite_data["group_id"] = int(group_id)
                invite_data["group_name"] = group_row["name"]
                invite_data["group_public_id"] = group_row["publicId"]
        finally:
            conn.close()

    invites[token] = invite_data
    _save_invites(invites)
    log.info("Created invite for %s (group: %s)", name, invite_data.get("group_name", "none"))
    return redirect("/invite")


@app.route("/invite/remove", methods=["POST"])
def remove_invite():
    """Owner removes an invite."""
    if not _is_owner(request):
        return Response("Unauthorized", status=401)

    token = request.form.get("token", "")
    invites = _load_invites()
    invites.pop(token, None)
    _save_invites(invites)
    return redirect("/invite")


@app.route("/invite/join")
def join_via_invite():
    """Guest clicks an invite link → gets a session."""
    token = request.args.get("t", "")
    invites = _load_invites()

    if token not in invites:
        return Response("Invalid or expired invite link", status=403)

    invite = invites[token]
    name = invite["name"]
    user_id = _find_or_create_guest(name)
    session_token, expires = _create_session(user_id)

    # Add guest to the specified group
    group_id = invite.get("group_id")
    if group_id:
        _add_user_to_group(user_id, group_id)

    # Redirect to the group page if specified, otherwise balances
    if group_id:
        redirect_to = f"/en/groups/{group_id}"
    else:
        redirect_to = "/en/balances"
    resp = redirect(redirect_to)
    # Set both cookie variants — Safari needs the non-__Secure- one
    resp.set_cookie(
        SESSION_COOKIE_SECURE, session_token,
        expires=expires, path="/", httponly=True, secure=True, samesite="Lax",
    )
    resp.set_cookie(
        SESSION_COOKIE, session_token,
        expires=expires, path="/", httponly=True, samesite="Lax",
    )
    log.info("Guest %s logged in via invite", name)
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


INVITE_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
  <title>Invite Friends - SplitPro</title>
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; background: #1a1a2e; color: #e0e0e0; }
    h2 { color: #4ecdc4; }
    table { width: 100%; border-collapse: collapse; margin: 1em 0; }
    th, td { text-align: left; padding: 0.5em; border-bottom: 1px solid #333; }
    .add-form { margin: 1.5em 0; display: flex; flex-wrap: wrap; gap: 0.5em; }
    .add-form input[type=text] { flex: 1; min-width: 150px; padding: 0.5em; border-radius: 4px; border: 1px solid #444; background: #2a2a3e; color: #e0e0e0; }
    .add-form select { padding: 0.5em; border-radius: 4px; border: 1px solid #444; background: #2a2a3e; color: #e0e0e0; }
    button { padding: 0.5em 1em; border-radius: 4px; border: none; cursor: pointer; }
    .add-btn { background: #4ecdc4; color: #1a1a2e; font-weight: bold; }
    .remove-btn { background: #333; color: #c00; font-size: 0.85em; border: 1px solid #c00; }
    .link { font-family: monospace; font-size: 0.85em; word-break: break-all; color: #4ecdc4; }
    .copy-btn { background: #333; color: #4ecdc4; font-size: 0.8em; border: 1px solid #4ecdc4; margin-left: 0.5em; }
    .group-tag { font-size: 0.8em; color: #888; }
    a { color: #4ecdc4; }
    .hint { color: #888; font-size: 0.9em; margin-top: 0.5em; }
  </style>
</head>
<body>
  <h2>Invite Friends to SplitPro</h2>
  <p>Create invite links for friends. Each link logs them in and adds them to the group.</p>

  <form method="post" action="/invite/create" class="add-form">
    <input type="text" name="name" placeholder="Friend's name" required>
    <select name="group_id">
      <option value="">No group</option>
      {% for g in groups %}
      <option value="{{ g.id }}">{{ g.name }}</option>
      {% endfor %}
    </select>
    <button type="submit" class="add-btn">Create Link</button>
  </form>
  {% if not groups %}
  <p class="hint">No groups yet. <a href="/en/groups">Create a group</a> in SplitPro first, then invite friends to it.</p>
  {% endif %}

  {% if invites %}
  <table>
    <tr><th>Name</th><th>Invite Link</th><th></th></tr>
    {% for token, info in invites.items() %}
    <tr>
      <td>{{ info.name }}{% if info.group_name %}<br><span class="group-tag">→ {{ info.group_name }}</span>{% endif %}</td>
      <td>
        <span class="link" id="link-{{ loop.index }}">{{ base_url }}/invite/join?t={{ token }}</span>
        <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('link-{{ loop.index }}').textContent)">Copy</button>
      </td>
      <td>
        <form method="post" action="/invite/remove" style="display:inline">
          <input type="hidden" name="token" value="{{ token }}">
          <button type="submit" class="remove-btn">Remove</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p style="color:#888">No invites yet. Create one above.</p>
  {% endif %}

  <a href="/">&larr; Back to SplitPro</a>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3006)
