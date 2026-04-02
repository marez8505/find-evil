#!/usr/bin/env bash
# FIND EVIL — Installation Script
# Installs on SANS SIFT Workstation (Ubuntu x86-64)
# Usage: bash install.sh

set -euo pipefail

INSTALL_DIR="/opt/find-evil"
CLAUDE_DIR="$HOME/.claude"

echo "╔══════════════════════════════════════╗"
echo "║       FIND EVIL — Installer          ║"
echo "╚══════════════════════════════════════╝"

# ── Preflight checks ────────────────────────────────────────────────────────
echo "[1/6] Checking prerequisites..."

if ! command -v python3 &>/dev/null; then
  echo "[ERROR] python3 not found. Are you on a SIFT workstation?"
  exit 1
fi

if ! command -v dotnet &>/dev/null; then
  echo "[WARN] dotnet not found — EZ Tools (AmcacheParser, MFTECmd, etc.) require dotnet."
  echo "       Install: sudo apt-get install -y dotnet-runtime-6.0"
fi

if ! command -v vol &>/dev/null && ! command -v vol.py &>/dev/null; then
  echo "[WARN] Volatility 3 (vol) not found. Install: pip3 install volatility3"
fi

if ! command -v yara &>/dev/null; then
  echo "[WARN] YARA not found. Install: sudo apt-get install -y yara"
fi

# ── Python dependencies ──────────────────────────────────────────────────────
echo "[2/6] Installing Python dependencies..."
pip3 install --quiet weasyprint

# ── Copy project files ───────────────────────────────────────────────────────
echo "[3/6] Installing to $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR"
sudo cp -r . "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/agent/loop.py"
sudo chmod +x "$INSTALL_DIR/validator/run_benchmark.py"
sudo chmod +x "$INSTALL_DIR/analysis-scripts/generate_pdf_report.py"
sudo chmod +x "$INSTALL_DIR/analysis-scripts/audit_hook.py"

# ── Configure Claude Code ────────────────────────────────────────────────────
echo "[4/6] Configuring Claude Code..."
mkdir -p "$CLAUDE_DIR"

# Backup existing configs
if [ -f "$CLAUDE_DIR/CLAUDE.md" ]; then
  cp "$CLAUDE_DIR/CLAUDE.md" "$CLAUDE_DIR/CLAUDE.md.bak.$(date +%Y%m%d)"
  echo "  Backed up existing CLAUDE.md"
fi
if [ -f "$CLAUDE_DIR/settings.json" ]; then
  cp "$CLAUDE_DIR/settings.json" "$CLAUDE_DIR/settings.json.bak.$(date +%Y%m%d)"
fi

cp "$INSTALL_DIR/agent/CLAUDE.md"    "$CLAUDE_DIR/CLAUDE.md"
cp "$INSTALL_DIR/agent/settings.json" "$CLAUDE_DIR/settings.json"

# ── Create case directory structure ─────────────────────────────────────────
echo "[5/6] Creating case directory structure..."
sudo mkdir -p /cases
sudo chown "$USER:$USER" /cases
echo "  Case directory: /cases/"
echo "  Usage: mkdir /cases/CASENAME && cd /cases/CASENAME && claude"

# ── Verify installation ──────────────────────────────────────────────────────
echo "[6/6] Verifying installation..."
python3 -c "import weasyprint; print('  ✓ WeasyPrint OK')"
[ -f "$CLAUDE_DIR/CLAUDE.md" ]    && echo "  ✓ CLAUDE.md installed"
[ -f "$CLAUDE_DIR/settings.json" ] && echo "  ✓ settings.json installed"
[ -d "$INSTALL_DIR/sift-mcp-server" ] && echo "  ✓ MCP server installed"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║     Installation Complete!           ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Quick start:"
echo "  mkdir /cases/CASE01"
echo "  cp $INSTALL_DIR/case-templates/CLAUDE.md /cases/CASE01/"
echo "  cd /cases/CASE01"
echo "  python3 $INSTALL_DIR/agent/loop.py --case /cases/CASE01 \\"
echo "    --disk /mnt/case_disk --memory /cases/CASE01/memory.raw"
echo ""
echo "Or run Claude Code directly:"
echo "  cd /cases/CASE01 && claude"
