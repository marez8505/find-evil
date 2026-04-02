# SKILL: Disk Timeline Analysis

## Goal
Build a filtered MFT timeline. Identify T0 (earliest suspicious event) and track attacker activity through filesystem artifacts.

## Step 1: Extract MFT Timeline

Use the MCP tool with the suspected incident time range:
```
extract_mft_timeline(
  image_path="/mnt/case_disk",
  start_date="YYYY-MM-DD",   # 48h before suspected T0
  end_date="YYYY-MM-DD",     # end of suspected activity
)
```

## Step 2: Filter for Suspicious Paths

Re-run with targeted path filters. Run once per suspicious area:

| Filter | What It Catches |
|---|---|
| `Temp` | Dropper staging, packed executables |
| `AppData/Roaming` | Persistence via user profile |
| `Windows/System32` | DLL hijacking, system binary replacement |
| `ProgramData` | Fileless malware staging |
| `Users/Public` | Lateral movement staging |
| `Recycle.Bin` | Evidence of file deletion |
| `Downloads` | Initial access artifacts |

## Step 3: Identify Key Timestamps

For each suspicious file:
- **B** (Birth) = file created → possible dropper activity
- **M** (Modified) = file content changed → compilation or packing
- **A** (Accessed) = file accessed → execution or opening
- **C** (Changed) = metadata changed → timestomping if M≠C by large margin

⚠️ **Timestomping check:** If Modified time is earlier than Birth time, or if MACB times are suspiciously round (exactly midnight, exactly on the hour) → flag as possible anti-forensics.

## Step 4: Cross-Reference

After timeline is built:
1. Take suspicious file paths → check Prefetch for execution evidence
2. Take suspicious file SHA1s → check VirusTotal (if network available)
3. Take suspicious timestamps → correlate with Event Log entries (4688 process creation)

## Step 5: Build Incident Timeline

Create a chronological table:
```
| Timestamp (UTC) | Event | Source | Confidence |
|---|---|---|---|
| YYYY-MM-DD HH:MM | File dropped to Temp\ | MFT | CONFIRMED |
| YYYY-MM-DD HH:MM | Process executed (Prefetch) | Prefetch | CONFIRMED |
| YYYY-MM-DD HH:MM | Registry run key modified | Registry | CONFIRMED |
```

## Self-Check (Must Pass Before Proceeding)
- [ ] Is T0 identified and CONFIRMED by at least one source?
- [ ] Is every entry in the incident timeline labeled by confidence?
- [ ] Are there gaps > 30 min between events? If so, expand time range and re-query.
- [ ] Did any path filter return zero results? Re-check mount and path case sensitivity.
