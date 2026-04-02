"""
Tool: get_amcache
Wraps AmcacheParser (Eric Zimmermann / EZ Tools)
Returns structured list of program execution records.
Evidence is NEVER modified — read-only operation.
"""

import subprocess
import csv
import io
import os
from pathlib import Path
from parsers.common import safe_run, find_file


AMCACHE_PATHS = [
    "Windows/AppCompat/Programs/Amcache.hve",
    "Windows/appcompat/Programs/Amcache.hve",
]

AMCACHE_PARSER = "/opt/zimmermantools/AmcacheParser.exe"


def get_amcache(image_path: str) -> dict:
    """
    Parse the Amcache hive from a mounted Windows image root.

    Args:
        image_path: Absolute path to mounted image root (e.g. /mnt/case01)

    Returns:
        dict with keys:
          - records: list of dicts (each = one executed program)
          - count: total number of records
          - hive_path: resolved path to hive file
          - errors: list of any non-fatal errors
    """
    image_root = Path(image_path)
    errors = []

    # Locate the hive
    hive = find_file(image_root, AMCACHE_PATHS)
    if not hive:
        return {
            "records": [],
            "count": 0,
            "hive_path": None,
            "errors": [f"Amcache.hve not found under {image_path}"],
        }

    # Build command — write output to /tmp to avoid evidence dirs
    out_dir = Path("/tmp/amcache_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "dotnet", AMCACHE_PARSER,
        "-f", str(hive),
        "--csv", str(out_dir),
        "--csvf", "amcache_results",
    ]

    result = safe_run(cmd)
    if result["returncode"] != 0:
        errors.append(result["stderr"])

    # Parse CSV output
    records = []
    csv_file = out_dir / "amcache_results_UnassociatedFileEntries.csv"
    if csv_file.exists():
        with open(csv_file, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append({
                    "name":          row.get("Name", ""),
                    "full_path":     row.get("Full Path", ""),
                    "sha1":          row.get("SHA1", ""),
                    "file_size":     row.get("File Size", ""),
                    "last_modified": row.get("File Modified Time (UTC)", ""),
                    "key_last_write":row.get("Key Last Write Timestamp (UTC)", ""),
                    "publisher":     row.get("Publisher", ""),
                    "product_name":  row.get("Product Name", ""),
                    "product_ver":   row.get("Product Version", ""),
                })

    return {
        "records": records,
        "count": len(records),
        "hive_path": str(hive),
        "errors": errors,
    }
