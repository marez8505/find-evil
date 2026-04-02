"""
Volatility 3 output parsers.
Converts raw text plugin output into structured list-of-dicts.
Prevents context window flooding by extracting only meaningful fields.
"""

import re
from typing import List, Dict


def parse_plugin_output(plugin: str, raw: str) -> List[Dict]:
    """
    Route to the correct parser for a given plugin name.
    Falls back to a generic table parser if no specific parser exists.
    """
    parsers = {
        "windows.pslist":           _parse_pslist,
        "windows.pstree":           _parse_pslist,   # same columns
        "windows.cmdline":          _parse_cmdline,
        "windows.netscan":          _parse_netscan,
        "windows.malfind":          _parse_malfind,
        "windows.dlllist":          _parse_dlllist,
        "windows.registry.hivelist":_parse_hivelist,
    }
    fn = parsers.get(plugin, _parse_generic_table)
    return fn(raw)


# ── Specific parsers ─────────────────────────────────────────────────────────

def _parse_pslist(raw: str) -> List[Dict]:
    rows = []
    for line in raw.splitlines():
        # Skip headers and blank lines
        if not line.strip() or line.startswith("Volatility") or line.startswith("PID"):
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            rows.append({
                "pid":         int(parts[0]),
                "ppid":        int(parts[1]),
                "name":        parts[2],
                "offset":      parts[3],
                "threads":     parts[4],
                "handles":     parts[5],
                "session_id":  parts[6],
                "create_time": " ".join(parts[7:9]) if len(parts) > 8 else "",
            })
        except (ValueError, IndexError):
            continue
    return rows


def _parse_cmdline(raw: str) -> List[Dict]:
    rows = []
    current = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        # PID + process name header line
        m = re.match(r'^(\d+)\s+(\S+)\s+PID:\s*\d+', line)
        if m:
            if current:
                rows.append(current)
            current = {"pid": int(m.group(1)), "name": m.group(2), "cmdline": ""}
        elif current and "CommandLine:" in line:
            current["cmdline"] = line.split("CommandLine:")[-1].strip()
        elif current and current["cmdline"] == "" and line.strip():
            # Some versions just print cmdline after name
            current["cmdline"] = line.strip()
    if current:
        rows.append(current)
    return rows


def _parse_netscan(raw: str) -> List[Dict]:
    rows = []
    for line in raw.splitlines():
        if not line.strip() or line.startswith("Volatility") or "Offset" in line:
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            rows.append({
                "offset":      parts[0],
                "proto":       parts[1],
                "local_addr":  parts[2],
                "foreign_addr":parts[3],
                "state":       parts[4],
                "pid":         int(parts[5]) if parts[5].isdigit() else None,
                "owner":       parts[6] if len(parts) > 6 else "",
                "created":     " ".join(parts[7:]) if len(parts) > 7 else "",
            })
        except (ValueError, IndexError):
            continue
    return rows


def _parse_malfind(raw: str) -> List[Dict]:
    rows = []
    current = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        m = re.match(r'^(\d+)\s+(\S+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)', line)
        if m:
            if current:
                rows.append(current)
            current = {
                "pid":        int(m.group(1)),
                "process":    m.group(2),
                "start_addr": "0x" + m.group(3),
                "end_addr":   "0x" + m.group(4),
                "tag":        "",
                "protection": "",
                "hex_dump":   [],
            }
        elif current:
            if "Tag:" in line:
                current["tag"] = line.split("Tag:")[-1].strip()
            elif "Protection:" in line:
                current["protection"] = line.split("Protection:")[-1].strip()
            elif re.match(r'^[0-9a-fA-F]{4}\s', line):
                current["hex_dump"].append(line.strip())
    if current:
        rows.append(current)
    return rows


def _parse_dlllist(raw: str) -> List[Dict]:
    rows = []
    current_pid = None
    current_proc = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        m = re.match(r'^(\d+)\s+(\S+)', line)
        if m and "." in m.group(2):
            current_pid  = int(m.group(1))
            current_proc = m.group(2)
        elif current_pid and re.match(r'^0x', line.strip()):
            parts = line.split()
            if len(parts) >= 3:
                rows.append({
                    "pid":     current_pid,
                    "process": current_proc,
                    "base":    parts[0],
                    "size":    parts[1],
                    "name":    " ".join(parts[2:]),
                })
    return rows


def _parse_hivelist(raw: str) -> List[Dict]:
    rows = []
    for line in raw.splitlines():
        if not line.strip() or "Offset" in line or line.startswith("Volatility"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            rows.append({
                "offset":    parts[0],
                "file_full": parts[1] if len(parts) > 1 else "",
                "name":      parts[2].strip() if len(parts) > 2 else "",
            })
    return rows


def _parse_generic_table(raw: str) -> List[Dict]:
    """
    Generic tab/space-separated table parser.
    Uses the first non-empty line as headers.
    """
    lines = [l for l in raw.splitlines() if l.strip() and not l.startswith("Volatility")]
    if not lines:
        return []

    headers = re.split(r'\s{2,}|\t', lines[0].strip())
    rows = []
    for line in lines[1:]:
        parts = re.split(r'\s{2,}|\t', line.strip())
        if len(parts) >= len(headers):
            rows.append(dict(zip(headers, parts)))
    return rows
