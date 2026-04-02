"""
Tool: extract_mft_timeline
Wraps MFTECmd (EZ Tools) + mactime for timeline generation.
Filters by date range and optional path substring.
"""

import csv
from pathlib import Path
from datetime import datetime
from parsers.common import safe_run, find_file

MFT_PARSER   = "/opt/zimmermantools/MFTECmd.exe"
MACTIME      = "mactime"
MFT_FILENAME = "$MFT"


def extract_mft_timeline(
    image_path: str,
    start_date: str = None,
    end_date:   str = None,
    filter_path: str = None,
) -> dict:
    """
    Extract and filter the Master File Table timeline.

    Args:
        image_path:  Path to .E01 or raw image (or mounted root)
        start_date:  ISO 8601 date string (YYYY-MM-DD), optional
        end_date:    ISO 8601 date string (YYYY-MM-DD), optional
        filter_path: Substring to filter file paths, optional

    Returns:
        dict with:
          - events: list of timeline events (dicts)
          - count: total events returned
          - filtered: whether date/path filter was applied
          - errors: list of non-fatal errors
    """
    image_root = Path(image_path)
    errors = []
    out_dir = Path("/tmp/mft_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Locate $MFT
    mft_file = find_file(image_root, [MFT_FILENAME])
    if not mft_file:
        # Try treating image_path as a raw image — use mmls + icat
        errors.append(f"$MFT not found directly under {image_path}. Ensure image is mounted.")
        return {"events": [], "count": 0, "filtered": False, "errors": errors}

    # Step 1: MFTECmd → CSV body file
    body_file = out_dir / "mft_body.txt"
    cmd_mft = [
        "dotnet", MFT_PARSER,
        "-f", str(mft_file),
        "--body", str(out_dir),
        "--bodyf", "mft_body",
        "--blf",  # include logged file entries
    ]
    r1 = safe_run(cmd_mft)
    if r1["returncode"] != 0:
        errors.append(r1["stderr"])

    # Step 2: mactime → sorted timeline
    timeline_file = out_dir / "timeline.csv"
    mactime_cmd = [MACTIME, "-b", str(body_file), "-d"]
    if start_date:
        mactime_cmd += ["-s", start_date]
    if end_date:
        mactime_cmd += ["-e", end_date]

    r2 = safe_run(mactime_cmd)
    if r2["returncode"] != 0:
        errors.append(r2["stderr"])
    else:
        timeline_file.write_text(r2["stdout"])

    # Step 3: Parse and filter
    events = []
    if timeline_file.exists():
        with open(timeline_file, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 11:
                    continue
                date, size, mtype, mode, uid, gid, meta, file_path = (
                    row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[10]
                )
                if filter_path and filter_path.lower() not in file_path.lower():
                    continue
                events.append({
                    "timestamp":  date,
                    "size":       size,
                    "macb_type":  mtype,   # M=modified A=accessed C=changed B=born
                    "file_path":  file_path,
                    "inode":      meta,
                })

    return {
        "events":   events,
        "count":    len(events),
        "filtered": bool(start_date or end_date or filter_path),
        "errors":   errors,
    }
