# SKILL: Triage

## Goal
Establish scope, evidence type, and suspected incident type before deeper analysis.

## Triage Checklist

Run through these in order. Record answers before proceeding.

### 1. Evidence Inventory
- What images/files are in the case directory?
- File types: `.E01`, `.raw`, `.vmem`, `.evtx`, `.img`, network captures?
- File sizes (large memory images need different handling)

### 2. Image Verification
```bash
# Verify E01 integrity before anything else
ewfverify /cases/<CASE>/<IMAGE>.E01

# Get partition layout
mmls /cases/<CASE>/<IMAGE>.E01

# Or for raw images:
mmls /cases/<CASE>/<IMAGE>.img
```

### 3. Mount Evidence (Read-Only)
```bash
# Mount E01 — ALWAYS read-only
sudo mkdir -p /mnt/case_disk
sudo ewfmount /cases/<CASE>/<IMAGE>.E01 /mnt/ewf/
sudo mount -o ro,loop,noatime /mnt/ewf/ewf1 /mnt/case_disk

# Confirm read-only
mount | grep case_disk
```

### 4. OS Identification
- Check for `Windows/System32` → Windows image
- Check for `etc/os-release` → Linux image
- Check `Windows/System32/config/SOFTWARE` hive → get OS version

### 5. Time Range Estimation
- Check oldest and newest MFT entries for rough time bounds
- Note timezone: check `SYSTEM` hive → `CurrentControlSet\Control\TimeZoneInformation`

### 6. Incident Type Hypothesis
Based on initial findings, form an initial hypothesis:
- Ransomware? (look for ransom notes, encrypted files)
- Lateral movement? (look for remote admin tools, scheduled tasks)
- Data exfiltration? (look for compression tools, unusual network activity)
- Malware persistence? (look for run keys, services, startup folder)

Document hypothesis as UNCONFIRMED until evidence supports it.

## Outputs
Record in case CLAUDE.md:
- Evidence file list
- OS version + architecture
- Suspected time range of incident
- Initial hypothesis (labeled UNCONFIRMED)
- Timezone offset
