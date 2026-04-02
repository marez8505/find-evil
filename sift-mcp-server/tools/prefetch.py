"""
Tool: get_prefetch
Wraps PECmd (EZ Tools) to parse Windows Prefetch files.
Returns execution records: name, run count, last run time, files loaded.
"""

import csv
from pathlib import Path
from parsers.common import safe_run

PECMD = "/opt/zimmermantools/PECmd.exe"

PREFETCH_PATHS = [
    "Windows/Prefetch",
    "Windows/prefetch",
]


def get_prefetch(image_path: str) -> dict:
    """
    Parse all Windows Prefetch files from a mounted image.

    Args:
        image_path: Path to mounted image root OR path to Prefetch directory

    Returns:
        dict with:
          - records: list of execution records
          - count: int
          - prefetch_dir: resolved prefetch directory path
          - errors: list of non-fatal errors
    """
    errors = []
    out_dir = Path("/tmp/prefetch_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    image_root = Path(image_path)

    # Resolve prefetch dir
    pf_dir = None
    if image_root.is_dir():
        for subpath in PREFETCH_PATHS:
            candidate = image_root / subpath
            if candidate.exists():
                pf_dir = candidate
                break
    if not pf_dir and image_root.is_dir():
        # Maybe image_path IS the prefetch dir
        if any(image_root.glob("*.pf")):
            pf_dir = image_root

    if not pf_dir:
        return {
            "records": [], "count": 0, "prefetch_dir": None,
            "errors": [f"Prefetch directory not found under {image_path}"],
        }

    cmd = [
        "dotnet", PECMD,
        "-d", str(pf_dir),
        "--csv", str(out_dir),
        "--csvf", "prefetch_results",
        "-q",   # quiet
    ]

    r = safe_run(cmd, timeout=120)
    if r["returncode"] != 0:
        errors.append(r["stderr"][:500])

    records = []
    csv_file = out_dir / "prefetch_results.csv"
    if csv_file.exists():
        with open(csv_file, newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Parse up to 8 run times
                run_times = [
                    row.get(f"RunTime{i}", "")
                    for i in range(1, 9)
                    if row.get(f"RunTime{i}")
                ]
                records.append({
                    "executable":     row.get("ExecutableName", ""),
                    "run_count":      row.get("RunCount", ""),
                    "last_run":       row.get("LastRun", ""),
                    "all_run_times":  run_times,
                    "size":           row.get("Size", ""),
                    "hash":           row.get("Hash", ""),
                    "files_loaded":   _split_files(row.get("FilesLoaded", "")),
                    "directories":    _split_files(row.get("Directories", "")),
                })

    # Sort by last run descending (most recent first)
    records.sort(key=lambda r: r["last_run"], reverse=True)

    return {
        "records":      records,
        "count":        len(records),
        "prefetch_dir": str(pf_dir),
        "errors":       errors,
    }


def _split_files(raw: str) -> list:
    """Split pipe- or newline-delimited file list into a clean list."""
    if not raw:
        return []
    return [f.strip() for f in raw.replace("|", "\n").splitlines() if f.strip()]
