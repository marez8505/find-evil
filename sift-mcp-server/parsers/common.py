"""
Shared utilities for safe subprocess execution and file discovery.
"""

import subprocess
from pathlib import Path


def safe_run(cmd: list, timeout: int = 120) -> dict:
    """
    Run a subprocess safely. Returns stdout, stderr, returncode.
    Never raises — all errors captured in returncode + stderr.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout":     proc.stdout,
            "stderr":     proc.stderr,
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout":     "",
            "stderr":     f"Command timed out after {timeout}s: {' '.join(cmd)}",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "stdout":     "",
            "stderr":     f"Binary not found: {cmd[0]}",
            "returncode": -1,
        }
    except Exception as e:
        return {
            "stdout":     "",
            "stderr":     str(e),
            "returncode": -1,
        }


def find_file(root: Path, candidates: list) -> Path | None:
    """
    Search for the first existing file from a list of relative paths under root.
    Case-insensitive on Linux via glob.
    """
    for rel in candidates:
        # Direct match
        full = root / rel
        if full.exists():
            return full
        # Case-insensitive glob fallback
        parts = Path(rel).parts
        current = root
        for part in parts:
            matches = list(current.glob(part)) + list(current.glob(part.lower())) + list(current.glob(part.upper()))
            if not matches:
                current = None
                break
            current = matches[0]
        if current and current.exists():
            return current
    return None
