#!/usr/bin/env bash
# run_server.sh — one command to set up and launch the victim server.
#
#   ./run_server.sh           start the server (seeds users.db if missing)
#   ./run_server.sh --reset   wipe and re-seed the database first (clears the log)
#
# Handles venv creation + Flask install automatically.

set -e
cd "$(dirname "$0")"

VENV_PY="./venv/bin/python"

# 1. Create the virtual environment and install Flask if not already present.
if [ ! -x "$VENV_PY" ]; then
    echo "[setup] creating virtual environment + installing Flask..."
    python3 -m venv venv
    "$VENV_PY" -m pip install --quiet --upgrade pip flask
fi

# 2. Seed the database (always on --reset, otherwise only if it doesn't exist).
if [ "$1" = "--reset" ] || [ ! -f "server/users.db" ]; then
    echo "[setup] seeding database..."
    (cd server && "../$VENV_PY" seed_db.py)
fi

# 3. Start the server.
echo "[run] starting victim server on http://127.0.0.1:8080/login ..."
cd server && exec "../$VENV_PY" victim_server.py
