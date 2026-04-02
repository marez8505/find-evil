# FIND EVIL — Case Context Template

Copy this file to /cases/<CASENAME>/CLAUDE.md and fill in all sections before running the agent.

---

## Case Overview

- **Case ID:** CASE-XXXX
- **Analyst (Agent):** FIND EVIL Autonomous Agent
- **Date Started:** YYYY-MM-DD
- **Suspected Incident Type:** (Ransomware / Lateral Movement / Data Exfiltration / Malware / Unknown)
- **Time Zone of Evidence:** UTC (or specify offset)

---

## Evidence Files

| File | Type | Size | Hash (SHA256) | Verified |
|---|---|---|---|---|
| case.E01 | Disk image | | | [ ] |
| memory.raw | Memory dump | | | [ ] |

---

## Mount Points

```bash
# Disk (read-only — NEVER omit -o ro)
sudo ewfmount /cases/CASENAME/case.E01 /mnt/ewf/
sudo mount -o ro,loop,noatime /mnt/ewf/ewf1 /mnt/case_disk

# Verify read-only
mount | grep case_disk
```

---

## Known IOCs (Pre-Investigation)

List any IOCs provided by the client or threat intel before analysis begins:
- IP addresses: (none)
- File hashes: (none)
- Domain names: (none)
- Process names: (none)

---

## System Information (Fill During Triage)

- **OS:** (e.g. Windows 10 Pro 21H2)
- **Architecture:** (x86-64)
- **Hostname:** 
- **Incident Time Range (estimated):** 
- **Timezone Offset from UTC:** 

---

## Network Topology (If Known)

- Internal subnet: 
- Gateway: 
- DNS: 

---

## Domain / Account Context (If Known)

- Domain name: 
- Known admin accounts: 
- Known service accounts: 

---

## Investigation Notes

Use this section during analysis for quick notes. Full findings go to analysis/findings.json.
