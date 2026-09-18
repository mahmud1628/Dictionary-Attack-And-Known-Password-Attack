"""
query.py — run an ad-hoc SQL query against users.db and print the result.

Usage (from the project root):
    ./venv/bin/python server/query.py "SELECT * FROM log LIMIT 10"
    ./venv/bin/python server/query.py "SELECT result, COUNT(*) FROM log GROUP BY result"

With no query given, it prints the tables and a quick summary.
"""

import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def run(sql: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(sql)
        # Print column headers if the query returns rows.
        if cur.description:
            headers = [d[0] for d in cur.description]
            print(" | ".join(headers))
            print("-" * (len(" | ".join(headers))))
            for row in cur.fetchall():
                print(" | ".join(str(c) for c in row))
        conn.commit()
    finally:
        conn.close()


def summary() -> None:
    print("Tables: users, log")
    print()
    run("SELECT result, COUNT(*) AS count FROM log GROUP BY result ORDER BY count DESC")
    print()
    print('Give a query as an argument, e.g.:')
    print('  ./venv/bin/python server/query.py "SELECT * FROM log LIMIT 10"')


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        summary()
