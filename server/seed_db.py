"""
seed_db.py — create and seed the SQLite database (users.db).

Run this ONCE before starting the victim server:

    cd server
    python seed_db.py

It creates two tables:
  * users : account credentials, stored as salted PBKDF2 hashes (never plaintext)
  * log   : one row per POST /login attempt (written by the server at runtime)

Re-running is safe: it resets both tables to a clean seeded state.
"""

import os
import sqlite3

import auth

# The database file lives next to this script, inside server/.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

# The accounts to seed. Passwords here are PLAINTEXT only so we can hash them
# on the way into the database — nothing plaintext is ever stored.
SEED_ACCOUNTS = {
    "admin": "hello123",
    "john@mail.com": "sunshine99",
    "mary@mail.com": "football22",
    "me@example.com": "optimus",
    "I2b2workdata2" : "i2b2workdata2",
    "webadmin" : "password",
    "allan.marshall" : "sunflower69"
}


def create_tables(conn: sqlite3.Connection) -> None:
    """Create the users and log tables from scratch (dropping any old ones)."""
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS log")
    cur.execute(
        """
        CREATE TABLE users (
            username      TEXT PRIMARY KEY,
            salt          TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            username  TEXT,
            password  TEXT,
            result    TEXT NOT NULL
        )
        """
    )
    conn.commit()


def seed_accounts(conn: sqlite3.Connection) -> None:
    """Insert each seed account with its own random salt and hashed password."""
    cur = conn.cursor()
    for username, plaintext in SEED_ACCOUNTS.items():
        salt = auth.generate_salt()
        password_hash = auth.hash_password(plaintext, salt)
        cur.execute(
            "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
            (username, salt, password_hash),
        )
    conn.commit()


def main() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        create_tables(conn)
        seed_accounts(conn)
    finally:
        conn.close()

    print(f"Seeded {len(SEED_ACCOUNTS)} accounts into {DB_PATH}")
    for username in SEED_ACCOUNTS:
        print(f"  - {username}")


if __name__ == "__main__":
    main()
