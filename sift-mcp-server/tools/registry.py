"""
Tool: get_registry_key
Wraps RECmd (EZ Tools) to extract registry keys from hive files.
Read-only — hive files are never written to.
"""

import csv
from pathlib import Path
from parsers.common import safe_run

RECMD = "/opt/zimmermantools/RECmd.exe"


def get_registry_key(
    hive_path: str,
    key_path:  str,
    recursive: bool = False,
) -> dict:
    """
    Extract a registry key and its values.

    Args:
        hive_path: Absolute path to registry hive file
                   (e.g. /mnt/case01/Windows/System32/config/SOFTWARE)
        key_path:  Registry key path relative to hive root
                   (e.g. 'Microsoft\\Windows\\CurrentVersion\\Run')
        recursive: Include subkeys (default False)

    Returns:
        dict with:
          - key: the queried key path
          - values: list of {name, type, data}
          - subkeys: list of subkey names (if recursive=False) or full subkey dicts
          - last_write: key last write timestamp (UTC)
          - errors: list of non-fatal errors
    """
    errors = []
    out_dir = Path("/tmp/registry_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    hive = Path(hive_path)
    if not hive.exists():
        return {
            "key": key_path, "values": [], "subkeys": [],
            "last_write": None,
            "errors": [f"Hive not found: {hive_path}"],
        }

    cmd = [
        "dotnet", RECMD,
        "-f", str(hive),
        "--kn", key_path,
        "--csv", str(out_dir),
        "--csvf", "reg_results",
    ]
    if recursive:
        cmd.append("--recurse")

    r = safe_run(cmd, timeout=120)
    if r["returncode"] != 0:
        errors.append(r["stderr"][:500])

    values   = []
    subkeys  = []
    last_write = None

    csv_file = out_dir / "reg_results.csv"
    if csv_file.exists():
        with open(csv_file, newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_type = row.get("Type", "").lower()
                if row_type == "key":
                    last_write = row.get("LastWrite", "")
                elif "valuename" in row:
                    values.append({
                        "name": row.get("ValueName", ""),
                        "type": row.get("Type", ""),
                        "data": row.get("ValueData", ""),
                    })
                if row.get("SubkeyName"):
                    subkeys.append(row["SubkeyName"])

    return {
        "key":        key_path,
        "values":     values,
        "subkeys":    list(set(subkeys)),
        "last_write": last_write,
        "errors":     errors,
    }
