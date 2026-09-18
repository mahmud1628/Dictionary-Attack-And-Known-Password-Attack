"""
victim_server.py — the target web server (Part 1).

A deliberately minimal Flask login app. It is the *target* of the attack tool.

Endpoints:
  GET  /login  -> a tiny HTML form so a human can test in a browser
  POST /login  -> checks username/password against users.db; logs every attempt

Defense mechanism (two layers, behind ENABLE_DEFENSE, default OFF):
  * Per-IP cooldown : after too many failed attempts from one IP, that IP is
                      temporarily rate-limited (HTTP 429) for a cooldown window.
                      Catches the known-password attack (many users, one IP).
  * Per-user lock   : after too many failed attempts on one username, that
                      account is locked (HTTP 403) for the rest of the run.
                      Catches the dictionary attack (many guesses, one user).

Enable the defense without editing code:
    ENABLE_DEFENSE=1 python victim_server.py

Before running, seed the database once:
    python seed_db.py
"""

import os
import sqlite3
import time
from datetime import datetime

from flask import Flask, request, Response

import auth

# --- Configuration -----------------------------------------------------------

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))

# users.db lives next to this file, inside server/ (overridable for testing).
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db"),
)

# Defense toggle. Default OFF so the attacks succeed cleanly first; turn ON to
# demonstrate the defense. Read from the environment so run_server.sh --defense
# can flip it without editing this file.
ENABLE_DEFENSE = os.environ.get("ENABLE_DEFENSE", "0") == "1"

# Per-IP cooldown: after this many failed attempts from one IP, rate-limit that
# IP (429) for IP_COOLDOWN_SECONDS, then reset and let it try again.
IP_FAIL_THRESHOLD = 10
IP_COOLDOWN_SECONDS = 30

# Per-user lock: after this many failed attempts on one username, lock that
# account (403) for the rest of the server's run.
USER_FAIL_THRESHOLD = 5

app = Flask(__name__)


# --- Defense state (in-memory; fine for a single-threaded demo server) --------

_ip_failures = {}          # ip -> running count of failed attempts
_ip_cooldown_until = {}    # ip -> unix time until which the IP is rate-limited
_user_failures = {}        # username -> running count of failed attempts
_locked_users = set()      # usernames locked for the rest of this run


def ip_in_cooldown(ip: str) -> bool:
    """Return True if this IP is currently rate-limited. Clears expired cooldowns."""
    until = _ip_cooldown_until.get(ip, 0)
    if until == 0:
        return False
    if time.time() < until:
        return True
    # Cooldown has expired: clear it and reset the IP's failure count so the
    # attacker must accumulate the threshold again (attack proceeds in bursts).
    _ip_cooldown_until.pop(ip, None)
    _ip_failures[ip] = 0
    return False


def register_failure(ip: str, username: str) -> None:
    """Record a failed attempt and trip the per-IP / per-user defenses if crossed."""
    _ip_failures[ip] = _ip_failures.get(ip, 0) + 1
    if _ip_failures[ip] >= IP_FAIL_THRESHOLD:
        _ip_cooldown_until[ip] = time.time() + IP_COOLDOWN_SECONDS

    _user_failures[username] = _user_failures.get(username, 0) + 1
    if _user_failures[username] >= USER_FAIL_THRESHOLD:
        _locked_users.add(username)


def clear_failures(ip: str, username: str) -> None:
    """Reset counters after a successful login (legitimate users aren't penalized)."""
    _ip_failures[ip] = 0
    _user_failures[username] = 0


# --- Database helpers --------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """Open a fresh SQLite connection for the current request."""
    return sqlite3.connect(DB_PATH)


def check_credentials(username: str, password: str) -> bool:
    """
    Return True only if `username` exists AND `password` matches the stored hash.

    Uses a parameterized query (? placeholder) so the username can never be used
    for SQL injection.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT salt, password_hash FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        # Unknown username -> same failure response as a wrong password, so we
        # don't leak which usernames exist.
        return False

    salt, password_hash = row
    return auth.verify_password(password, salt, password_hash)


def log_attempt(client_ip: str, username: str, password: str, result: str) -> None:
    """Append one row describing this attempt to the `log` table.

    `result` is SUCCESS, FAIL, BLOCKED_IP, or LOCKED_USER.
    """
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO log (timestamp, client_ip, username, password, result) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now().isoformat(timespec="seconds"),
                client_ip,
                username,
                password,
                result,
            ),
        )
        conn.commit()
    finally:
        conn.close()


# --- Routes ------------------------------------------------------------------

LOGIN_FORM_HTML = """<!doctype html>
<html>
  <head><title>Login</title></head>
  <body>
    <h1>Login</h1>
    <form method="POST" action="/login">
      <p><label>Username: <input type="text" name="username"></label></p>
      <p><label>Password: <input type="password" name="password"></label></p>
      <p><button type="submit">Log in</button></p>
    </form>
  </body>
</html>
"""


@app.get("/login")
def login_form():
    """Serve the human-facing HTML login form. No auth, no logging."""
    return Response(LOGIN_FORM_HTML, status=200, mimetype="text/html")


@app.post("/login")
def login():
    """
    Authenticate a POSTed username/password.

    Success -> 200 + 'Welcome'
    Failure -> 401 + 'Invalid'   (same response for unknown user or wrong password)

    With ENABLE_DEFENSE on, an IP in cooldown gets 429 and a locked account gets
    403, both short-circuiting before the credential check. Every attempt is
    logged (SUCCESS / FAIL / BLOCKED_IP / LOCKED_USER).
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip = request.remote_addr

    if ENABLE_DEFENSE:
        # Layer 1: per-IP cooldown (broad — catches high volume from one source).
        if ip_in_cooldown(ip):
            log_attempt(ip, username, password, "BLOCKED_IP")
            return Response(
                "Too many requests from your IP. Try again later.",
                status=429, mimetype="text/plain",
            )
        # Layer 2: per-user lock (targeted — catches many guesses on one account).
        if username in _locked_users:
            log_attempt(ip, username, password, "LOCKED_USER")
            return Response(
                "Account locked due to too many failed attempts.",
                status=403, mimetype="text/plain",
            )

    success = check_credentials(username, password)

    if ENABLE_DEFENSE:
        if success:
            clear_failures(ip, username)
        else:
            register_failure(ip, username)

    log_attempt(ip, username, password, "SUCCESS" if success else "FAIL")

    if success:
        return Response(f"Welcome, {username}!", status=200, mimetype="text/plain")
    return Response("Invalid username or password.", status=401, mimetype="text/plain")


# --- Entry point -------------------------------------------------------------

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        raise SystemExit(
            f"Database not found at {DB_PATH}. Run 'python seed_db.py' first."
        )
    print("[*] Defense mechanism:", "ENABLED" if ENABLE_DEFENSE else "disabled")
    if ENABLE_DEFENSE:
        print("    per-IP  : %d fails -> %ds cooldown (429)"
              % (IP_FAIL_THRESHOLD, IP_COOLDOWN_SECONDS))
        print("    per-user: %d fails -> account locked (403)" % USER_FAIL_THRESHOLD)
    app.run(host=HOST, port=PORT, threaded=False)
