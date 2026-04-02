#!/usr/bin/env python3
"""
FIND EVIL — Custom MCP Server
Wraps SANS SIFT forensic tools as typed, read-only functions.
Architectural guardrail: destructive commands are never exposed.
"""

import json
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path

from tools.amcache    import get_amcache
from tools.mft        import extract_mft_timeline
from tools.volatility import run_volatility
from tools.yara       import scan_yara
from tools.evtx       import get_event_logs
from tools.registry   import get_registry_key
from tools.prefetch   import get_prefetch
from tools.network    import get_network_connections

# ── Audit log ──────────────────────────────────────────────────────────────
LOG_PATH = Path("logs/mcp_audit.log")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s UTC | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

def audit(tool: str, args: dict, result_hash: str, tokens_est: int):
    logging.info(
        json.dumps({
            "tool": tool,
            "args": args,
            "result_sha256": result_hash,
            "tokens_estimated": tokens_est,
        })
    )

# ── Tool registry ───────────────────────────────────────────────────────────
# Maps MCP tool names → (handler_fn, description, param_schema)
TOOL_REGISTRY = {
    "get_amcache": {
        "fn": get_amcache,
        "description": (
            "Parse the Amcache hive from a mounted Windows image. "
            "Returns a list of executed programs with timestamps and SHA1 hashes. "
            "Read-only. Evidence is never modified."
        ),
        "params": {
            "image_path": "str — absolute path to mounted image root (e.g. /mnt/case01)",
        },
    },
    "extract_mft_timeline": {
        "fn": extract_mft_timeline,
        "description": (
            "Extract and filter the MFT timeline from a disk image. "
            "Returns filesystem events sorted by timestamp within the given date range."
        ),
        "params": {
            "image_path": "str — absolute path to .E01 or raw image",
            "start_date": "str — ISO 8601 (YYYY-MM-DD), optional",
            "end_date":   "str — ISO 8601 (YYYY-MM-DD), optional",
            "filter_path":"str — optional path substring filter (e.g. 'Windows/System32')",
        },
    },
    "run_volatility": {
        "fn": run_volatility,
        "description": (
            "Run a Volatility 3 plugin against a memory image. "
            "Returns structured, pre-parsed plugin output. "
            "Available plugins: pslist, pstree, cmdline, dlllist, netscan, "
            "malfind, handles, filescan, dumpfiles."
        ),
        "params": {
            "memory_path": "str — absolute path to memory image (.raw, .mem, .vmem)",
            "plugin":      "str — Volatility 3 plugin name (e.g. 'windows.pslist')",
            "extra_args":  "dict — optional plugin-specific arguments",
        },
    },
    "scan_yara": {
        "fn": scan_yara,
        "description": (
            "Scan a file or directory with a YARA rule file. "
            "Returns matches with rule name, file path, and byte offset."
        ),
        "params": {
            "rule_file": "str — path to .yar rule file",
            "target":    "str — path to file or directory to scan",
            "recursive": "bool — scan directory recursively (default true)",
        },
    },
    "get_event_logs": {
        "fn": get_event_logs,
        "description": (
            "Parse Windows Event Log (.evtx) files using EvtxECmd. "
            "Filters by Event IDs and optional time range. "
            "Returns structured log entries."
        ),
        "params": {
            "image_path":  "str — path to mounted image root or raw .evtx file",
            "event_ids":   "list[int] — Event IDs to filter (e.g. [4624, 4625, 4688])",
            "start_date":  "str — ISO 8601, optional",
            "end_date":    "str — ISO 8601, optional",
        },
    },
    "get_registry_key": {
        "fn": get_registry_key,
        "description": (
            "Extract a registry key and its values from a hive file using RECmd. "
            "Returns key metadata and value list."
        ),
        "params": {
            "hive_path": "str — absolute path to registry hive file",
            "key_path":  "str — registry key path (e.g. 'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run')",
            "recursive": "bool — include subkeys (default false)",
        },
    },
    "get_prefetch": {
        "fn": get_prefetch,
        "description": (
            "Parse Windows Prefetch files using PECmd. "
            "Returns execution records: executable name, run count, last run time, files loaded."
        ),
        "params": {
            "image_path": "str — path to mounted image root or Prefetch directory",
        },
    },
    "get_network_connections": {
        "fn": get_network_connections,
        "description": (
            "Extract network connection artifacts from a memory image using Volatility netscan. "
            "Returns active and closed connections with PID, local/remote addr, port, state."
        ),
        "params": {
            "memory_path": "str — absolute path to memory image",
            "filter_state":"str — optional filter: 'ESTABLISHED', 'CLOSE_WAIT', 'LISTEN', etc.",
        },
    },
}

# ── MCP protocol handlers ───────────────────────────────────────────────────

def handle_list_tools() -> dict:
    tools = []
    for name, meta in TOOL_REGISTRY.items():
        tools.append({
            "name": name,
            "description": meta["description"],
            "inputSchema": {
                "type": "object",
                "properties": {
                    k: {"type": "string", "description": v}
                    for k, v in meta["params"].items()
                },
            },
        })
    return {"tools": tools}


def handle_call_tool(name: str, arguments: dict) -> dict:
    if name not in TOOL_REGISTRY:
        return {"error": f"Unknown tool: {name}"}

    handler = TOOL_REGISTRY[name]["fn"]
    ts_start = datetime.now(timezone.utc).isoformat()

    try:
        result = handler(**arguments)
    except TypeError as e:
        return {"error": f"Bad arguments for {name}: {e}"}
    except Exception as e:
        return {"error": f"Tool execution failed: {e}"}

    # Hash result for audit trail
    import hashlib
    result_str  = json.dumps(result, default=str)
    result_hash = hashlib.sha256(result_str.encode()).hexdigest()
    tokens_est  = len(result_str) // 4  # rough 4-chars-per-token estimate

    audit(name, arguments, result_hash, tokens_est)

    return {
        "content": [{
            "type": "text",
            "text": result_str,
        }],
        "metadata": {
            "tool": name,
            "timestamp_utc": ts_start,
            "result_sha256": result_hash,
            "tokens_estimated": tokens_est,
        },
    }


# ── stdio MCP loop ──────────────────────────────────────────────────────────

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps({"error": "Invalid JSON"}) + "\n")
            sys.stdout.flush()
            continue

        method = request.get("method", "")
        req_id = request.get("id")

        if method == "tools/list":
            response = handle_list_tools()
        elif method == "tools/call":
            params = request.get("params", {})
            response = handle_call_tool(
                name=params.get("name", ""),
                arguments=params.get("arguments", {}),
            )
        else:
            response = {"error": f"Unknown method: {method}"}

        envelope = {"jsonrpc": "2.0", "id": req_id, "result": response}
        sys.stdout.write(json.dumps(envelope) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
