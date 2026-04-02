"""
Tool: get_event_logs
Wraps EvtxECmd (EZ Tools) to parse Windows Event Log .evtx files.
Filters by Event ID and optional date range.
"""

import csv
import glob
from pathlib import Path
from parsers.common import safe_run

EVTXECMD    = "/opt/zimmermantools/EvtxECmd.exe"
EVTX_SUBDIR = "Windows/System32/winevt/Logs"


def get_event_logs(
    image_path: str,
    event_ids:  list = None,
    start_date: str  = None,
    end_date:   str  = None,
) -> dict:
    """
    Parse Windows Event Logs from a mounted image or raw .evtx file.

    Args:
        image_path:  Path to mounted image root OR path to a single .evtx file
        event_ids:   List of integer Event IDs to include (e.g. [4624, 4625])
        start_date:  ISO 8601 date string (YYYY-MM-DD), optional
        end_date:    ISO 8601 date string (YYYY-MM-DD), optional

    Returns:
        dict with:
          - events: list of structured event dicts
          - count: int
          - sources: list of .evtx files parsed
          - errors: list of non-fatal errors
    """
    errors = []
    out_dir = Path("/tmp/evtx_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    image_root = Path(image_path)

    # Determine input: single .evtx or directory of logs
    if image_root.suffix.lower() == ".evtx":
        evtx_arg = ["-f", str(image_root)]
        sources  = [str(image_root)]
    else:
        log_dir  = image_root / EVTX_SUBDIR
        if not log_dir.exists():
            return {
                "events": [], "count": 0, "sources": [],
                "errors": [f"Event log directory not found: {log_dir}"],
            }
        evtx_arg = ["-d", str(log_dir)]
        sources  = [str(p) for p in log_dir.glob("*.evtx")]

    cmd = [
        "dotnet", EVTXECMD,
        *evtx_arg,
        "--csv", str(out_dir),
        "--csvf", "evtx_results",
        "--sd", (start_date or "2000-01-01"),
        "--ed", (end_date   or "2100-01-01"),
    ]

    r = safe_run(cmd, timeout=300)
    if r["returncode"] != 0:
        errors.append(r["stderr"][:500])

    # Parse CSV
    event_id_set = set(event_ids) if event_ids else None
    events = []

    for csv_file in out_dir.glob("evtx_results*.csv"):
        with open(csv_file, newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    eid = int(row.get("EventId", 0))
                except ValueError:
                    eid = 0
                if event_id_set and eid not in event_id_set:
                    continue
                events.append({
                    "timestamp":    row.get("TimeCreated", ""),
                    "event_id":     eid,
                    "channel":      row.get("Channel", ""),
                    "computer":     row.get("Computer", ""),
                    "provider":     row.get("Provider", ""),
                    "level":        row.get("Level", ""),
                    "user_sid":     row.get("UserId", ""),
                    "payload":      row.get("PayloadData1", ""),
                    "payload2":     row.get("PayloadData2", ""),
                    "executable":   row.get("ExecutableInfo", ""),
                    "map_desc":     row.get("MapDescription", ""),
                })

    # Sort by timestamp ascending
    events.sort(key=lambda e: e["timestamp"])

    return {
        "events":  events,
        "count":   len(events),
        "sources": sources,
        "errors":  errors,
    }
