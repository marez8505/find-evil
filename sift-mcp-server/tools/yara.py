"""
Tool: scan_yara
Wraps the yara CLI for threat hunting.
Returns structured match list with rule name, file, and offset.
"""

import re
from pathlib import Path
from parsers.common import safe_run

YARA_BIN = "yara"


def scan_yara(
    rule_file:  str,
    target:     str,
    recursive:  bool = True,
) -> dict:
    """
    Scan a file or directory with a YARA rule file.

    Args:
        rule_file:  Path to .yar / .yara rule file
        target:     Path to file or directory to scan
        recursive:  Scan subdirectories (default True)

    Returns:
        dict with:
          - matches: list of {rule, file_path, offset, tags, meta}
          - match_count: int
          - scanned_files: int (estimated from output)
          - errors: list of non-fatal errors
    """
    errors = []

    rule_path   = Path(rule_file)
    target_path = Path(target)

    if not rule_path.exists():
        return {"matches": [], "match_count": 0, "scanned_files": 0,
                "errors": [f"Rule file not found: {rule_file}"]}
    if not target_path.exists():
        return {"matches": [], "match_count": 0, "scanned_files": 0,
                "errors": [f"Target not found: {target}"]}

    cmd = [YARA_BIN, "--print-meta", "--print-tags", "--print-strings"]
    if recursive and target_path.is_dir():
        cmd.append("-r")
    cmd += [str(rule_path), str(target_path)]

    result = safe_run(cmd, timeout=600)
    if result["returncode"] not in (0, 1):  # yara returns 1 on match
        errors.append(result["stderr"][:500])

    matches      = _parse_yara_output(result["stdout"])
    scanned_est  = _estimate_scanned(result["stderr"])

    return {
        "matches":       matches,
        "match_count":   len(matches),
        "scanned_files": scanned_est,
        "errors":        errors,
    }


# ── Parsers ─────────────────────────────────────────────────────────────────

_MATCH_RE = re.compile(
    r'^(?P<rule>\S+)\s+(?P<file>.+?)(?:\s+\[(?P<tags>[^\]]*)\])?$'
)
_STRING_RE = re.compile(r'^\s+0x(?P<offset>[0-9a-f]+):\s+\$\S+:\s+(?P<value>.+)$')


def _parse_yara_output(raw: str) -> list:
    matches = []
    current = None

    for line in raw.splitlines():
        m = _MATCH_RE.match(line)
        if m:
            if current:
                matches.append(current)
            current = {
                "rule":      m.group("rule"),
                "file_path": m.group("file").strip(),
                "tags":      [t.strip() for t in (m.group("tags") or "").split(",") if t.strip()],
                "strings":   [],
            }
        elif current:
            s = _STRING_RE.match(line)
            if s:
                current["strings"].append({
                    "offset": int(s.group("offset"), 16),
                    "value":  s.group("value").strip(),
                })

    if current:
        matches.append(current)

    return matches


def _estimate_scanned(stderr: str) -> int:
    m = re.search(r'(\d+)\s+file', stderr or "")
    return int(m.group(1)) if m else 0
