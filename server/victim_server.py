"""
victim_server.py — the target web server (Part 1).

A deliberately minimal Flask login app. It is the *target* of the attack tool,
not the focus of the project, so it is kept simple.

Endpoints:
  GET  /login  -> a tiny HTML form so a human can test in a browser
  POST /login  -> checks username/password against users.db; logs every attempt

Before running this, seed the database once:
    python seed_db.py

Then:
    python victim_server.py
"""

import os
import sqlite3
from datetime import datetime

from flask import Flask, request, Response

import auth

# --- Configuration -----------------------------------------------------------

HOST = "0.0.0.0"
PORT = 8080

# users.db lives next to this file, inside server/.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

app = Flask(__name__)


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
        # Unknown username. We still return the same failure response as a wrong
        # password (see login()), so we don't leak which usernames exist.
        return False

    salt, password_hash = row
    return auth.verify_password(password, salt, password_hash)


def log_attempt(client_ip: str, username: str, password: str, success: bool) -> None:
    """Append one row describing this login attempt to the `log` table."""
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
                "SUCCESS" if success else "FAIL",
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
    Every attempt is logged to the `log` table.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    success = check_credentials(username, password)
    log_attempt(request.remote_addr, username, password, success)

    if success:
        return Response(f"Welcome, {username}!", status=200, mimetype="text/plain")
    return Response("Invalid username or password.", status=401, mimetype="text/plain")


# --- Entry point -------------------------------------------------------------

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        raise SystemExit(
            f"Database not found at {DB_PATH}. Run 'python seed_db.py' first."
        )
    # threaded=False keeps SQLite access on one thread; sequential attacks don't
    # need concurrency anyway.
    app.run(host=HOST, port=PORT, threaded=False)
