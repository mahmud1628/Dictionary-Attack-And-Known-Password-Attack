#!/usr/bin/env bash
# run_server.sh — one command to set up and launch the victim server.
#
#   ./run_server.sh                     start the server (seeds users.db if missing)
#   ./run_server.sh --reset             wipe and re-seed the database first (clears log)
#   ./run_server.sh --defense           start with the defense mechanism ENABLED
#   ./run_server.sh --reset --defense   both (flags may be given in any order)
#
# Handles venv creation + Flask install automatically.

set -e
cd "$(dirname "$0")"

VENV_PY="./venv/bin/python"

# Parse flags (order-independent).
DO_RESET=0
DEFENSE=0
for arg in "$@"; do
    case "$arg" in
        --reset)   DO_RESET=1 ;;
        --defense) DEFENSE=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

# 1. Create the virtual environment and install Flask if not already present.
if [ ! -x "$VENV_PY" ]; then
    echo "[setup] creating virtual environment + installing Flask..."
    python3 -m venv venv
    "$VENV_PY" -m pip install --quiet --upgrade pip flask
fi

# 2. Seed the database (on --reset, or if it doesn't exist yet).
if [ "$DO_RESET" = "1" ] || [ ! -f "server/users.db" ]; then
    echo "[setup] seeding database..."
    (cd server && "../$VENV_PY" seed_db.py)
fi

# 3. Start the server (exporting the defense toggle the server reads).
echo "[run] starting victim server on http://127.0.0.1:8080/login ..."
export ENABLE_DEFENSE="$DEFENSE"
cd server && exec "../$VENV_PY" victim_server.py
