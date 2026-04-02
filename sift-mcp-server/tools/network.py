"""
Tool: get_network_connections
Wraps Volatility 3 windows.netscan to extract network artifacts from memory.
"""

from tools.volatility import run_volatility


def get_network_connections(
    memory_path:  str,
    filter_state: str = None,
) -> dict:
    """
    Extract network connections from a memory image.

    Args:
        memory_path:  Absolute path to memory image
        filter_state: Optional connection state filter
                      ('ESTABLISHED', 'CLOSE_WAIT', 'LISTEN', 'TIME_WAIT', etc.)

    Returns:
        dict with:
          - connections: list of connection dicts
          - count: int
          - filter_applied: bool
          - errors: list of non-fatal errors
    """
    result = run_volatility(memory_path, "windows.netscan")

    conns = result.get("rows", [])
    errors = result.get("errors", [])

    if filter_state:
        conns = [c for c in conns if c.get("state", "").upper() == filter_state.upper()]

    return {
        "connections":    conns,
        "count":          len(conns),
        "filter_applied": filter_state is not None,
        "errors":         errors,
    }
