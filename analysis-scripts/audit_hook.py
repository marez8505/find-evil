#!/usr/bin/env python3
"""
FIND EVIL — Audit Hook (Stop hook for Claude Code)

Called automatically after every Claude session ends.
Appends a structured summary to forensic_audit.log.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG = Path("analysis/forensic_audit.log")
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

# Claude Code passes session summary via stdin (JSON or plain text)
raw = sys.stdin.read().strip()

entry = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "session_end":   True,
    "cwd":           os.getcwd(),
    "summary":       raw[:2000] if raw else "(no summary provided)",
}

with open(AUDIT_LOG, "a") as f:
    f.write(json.dumps(entry) + "\n")

# Also write human-readable separator
with open(AUDIT_LOG, "a") as f:
    f.write(f"--- Session ended {entry['timestamp_utc']} ---\n")
