#!/usr/bin/env bash
# FIND EVIL — Web GUI Launcher
# ════════════════════════════════════════════════════
# Starts the local-only web interface on 127.0.0.1.
# NEVER exposes the server to the network.
#
# Usage:
#   bash start.sh              (default port 8080)
#   PORT=9090 bash start.sh   (custom port)
# ════════════════════════════════════════════════════

set -euo pipefail

WEB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8080}"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           FIND EVIL — Web GUI                        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Install Python deps ───────────────────────────────────────
echo "[1/3] Checking Python dependencies..."
if ! python3 -c "import flask, bcrypt, dotenv" 2>/dev/null; then
  echo "      Installing: flask bcrypt python-dotenv"
  pip3 install --quiet -r "$WEB_DIR/requirements.txt"
  echo "      ✓ Dependencies installed"
else
  echo "      ✓ Dependencies OK"
fi

# ── Ensure cases directory exists ─────────────────────────────
CASES_DIR="${CASES_DIR:-/cases}"
echo "[2/3] Cases directory: $CASES_DIR"
if [ ! -d "$CASES_DIR" ]; then
  echo "      Creating $CASES_DIR..."
  mkdir -p "$CASES_DIR" || sudo mkdir -p "$CASES_DIR"
fi

# ── Verify localhost-only binding ─────────────────────────────
echo "[3/3] Starting server..."
echo ""
echo "  Address:   http://127.0.0.1:${PORT}"
echo "  Binding:   localhost ONLY — not reachable from network"
echo "  Cases:     $CASES_DIR"
echo ""
echo "  Press Ctrl+C to stop."
echo ""

cd "$WEB_DIR"
PORT="$PORT" python3 app.py
