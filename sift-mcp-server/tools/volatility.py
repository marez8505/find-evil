"""
Tool: run_volatility
Wraps Volatility 3 for memory forensics.
Parses plugin output before returning — prevents context window flooding.
"""

import json
import csv
import io
from pathlib import Path
from parsers.common import safe_run
from parsers.volatility_parsers import parse_plugin_output

VOL3 = "vol"   # Volatility 3 binary on SIFT

ALLOWED_PLUGINS = {
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.dlllist",
    "windows.netscan",
    "windows.malfind",
    "windows.handles",
    "windows.filescan",
    "windows.dumpfiles",
    "windows.registry.hivelist",
    "windows.registry.printkey",
    "linux.pslist",
    "linux.bash",
    "linux.netstat",
}


def run_volatility(
    memory_path: str,
    plugin: str,
    extra_args: dict = None,
) -> dict:
    """
    Run a Volatility 3 plugin against a memory image.

    Args:
        memory_path: Absolute path to memory dump (.raw, .mem, .vmem)
        plugin:      Plugin name (e.g. 'windows.pslist')
        extra_args:  Optional dict of extra plugin arguments

    Returns:
        dict with:
          - plugin: name of plugin run
          - rows: list of parsed result dicts
          - count: number of rows
          - raw_truncated: bool — whether raw output was truncated before parsing
          - errors: list of non-fatal errors
    """
    errors = []

    if plugin not in ALLOWED_PLUGINS:
        return {
            "plugin": plugin,
            "rows":   [],
            "count":  0,
            "raw_truncated": False,
            "errors": [
                f"Plugin '{plugin}' is not in the allowed list. "
                f"Permitted: {sorted(ALLOWED_PLUGINS)}"
            ],
        }

    mem = Path(memory_path)
    if not mem.exists():
        return {
            "plugin": plugin,
            "rows":   [],
            "count":  0,
            "raw_truncated": False,
            "errors": [f"Memory image not found: {memory_path}"],
        }

    # Build command
    cmd = [VOL3, "-f", str(mem), plugin]
    if extra_args:
        for k, v in extra_args.items():
            cmd += [f"--{k}", str(v)]

    result = safe_run(cmd, timeout=300)
    if result["returncode"] != 0:
        errors.append(result["stderr"][:500])

    raw_output = result["stdout"]
    truncated  = False

    # Hard cap: if output > 200KB, truncate before parsing
    MAX_BYTES = 200_000
    if len(raw_output.encode()) > MAX_BYTES:
        raw_output  = raw_output[:MAX_BYTES]
        truncated   = True
        errors.append(f"Raw output truncated to {MAX_BYTES} bytes before parsing.")

    rows = parse_plugin_output(plugin, raw_output)

    return {
        "plugin":        plugin,
        "rows":          rows,
        "count":         len(rows),
        "raw_truncated": truncated,
        "errors":        errors,
    }
