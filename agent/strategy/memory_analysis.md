# SKILL: Memory Analysis

## Goal
Identify malicious processes, injected code, network connections, and persistence mechanisms from a memory image.

## Step 1: Process Enumeration
```
run_volatility(memory_path="<PATH>", plugin="windows.pslist")
run_volatility(memory_path="<PATH>", plugin="windows.pstree")
```

### What to Look For
| Indicator | Suspicion Level |
|---|---|
| Process with no parent (PPID not in pslist) | HIGH |
| `svchost.exe` with parent other than `services.exe` | HIGH |
| `cmd.exe` or `powershell.exe` spawned by browser/office app | HIGH |
| Process with name similar to legit process (e.g. `scvhost.exe`) | HIGH |
| Multiple instances of single-instance processes (`lsass.exe`, `winlogon.exe`) | HIGH |
| Process with no command line (hollow process) | MEDIUM |

## Step 2: Command Lines
```
run_volatility(memory_path="<PATH>", plugin="windows.cmdline")
```
- Look for base64-encoded PowerShell (`-EncodedCommand`)
- Look for download cradles (`IEX`, `Invoke-Expression`, `DownloadString`)
- Look for `-NonInteractive -WindowStyle Hidden`

## Step 3: Injected Code Detection
```
run_volatility(memory_path="<PATH>", plugin="windows.malfind")
```
- MZ headers in unexpected memory regions → possible injected PE
- RWX (read/write/execute) memory pages in unexpected processes → shellcode
- Cross-reference malfind results with process list — same PID?

## Step 4: Network Connections
```
get_network_connections(memory_path="<PATH>")
```
- Identify external IPs (non-RFC1918)
- Cross-reference PIDs with process list
- Flag any process that shouldn't have network access (notepad, calc, etc.)
- Look for connections on unusual high ports (> 49151) to external IPs

## Step 5: DLL Analysis (Targeted)
For any suspicious PID from steps 1–4:
```
run_volatility(memory_path="<PATH>", plugin="windows.dlllist", extra_args={"pid": <PID>})
```
- Unknown DLLs loaded from Temp, AppData, or root of C:
- DLLs with no path (in-memory only)
- DLLs with names that mimic system DLLs

## Step 6: Memory ↔ Disk Cross-Reference

After memory analysis, for each suspicious process:
1. Does a corresponding Prefetch file exist? If no → possible fileless malware
2. Does a corresponding Amcache entry exist? If no → possible process hollowing or injection
3. Does the executable path in memory match the MFT? If path doesn't exist on disk → file was deleted after execution

Document every discrepancy in the **Discrepancies Detected** section.

## Self-Check
- [ ] Every suspicious PID cross-referenced with disk artifacts
- [ ] All external IPs documented with owning process
- [ ] Malfind results reviewed — false positives filtered (e.g. .NET JIT regions)
- [ ] Any process missing from both Prefetch and Amcache flagged
