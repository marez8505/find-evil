# FIND EVIL — Autonomous DFIR Agent

> AI threats strike in minutes. This agent responds in seconds.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A fully autonomous incident response agent built on the SANS SIFT Workstation and Protocol SIFT. Uses a **custom MCP server** with typed, read-only forensic tool wrappers and a **persistent self-correcting analysis loop** to investigate disk images, memory captures, and Windows artifacts without human intervention.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Case Data                           │
│  .E01 disk image │ .raw memory │ .evtx logs │ YARA rules│
└──────────────────────────┬──────────────────────────────┘
                           │ read-only
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Custom MCP Server                          │
│  get_amcache()    extract_mft_timeline()                │
│  run_volatility() scan_yara()                           │
│  get_event_logs() get_registry_key()                    │
│  get_prefetch()   get_network_connections()             │
│                                                         │
│  ✓ Architectural guardrails — no shell execution        │
│  ✓ Output parsed before LLM receives it                 │
│  ✓ All writes to /tmp — evidence never touched          │
└──────────────────────────┬──────────────────────────────┘
                           │ structured JSON
                           ▼
┌─────────────────────────────────────────────────────────┐
│           Agent Orchestrator (Claude Code)              │
│  Phase 1: Triage       Phase 2: Disk Timeline           │
│  Phase 3: Memory       Phase 4: Persistence/Artifacts   │
│  Phase 5: Correlation & Synthesis                       │
│                                                         │
│  Self-Correction Loop:                                  │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Execute phase → Self-evaluate → Correct/Retry   │   │
│  │  Log iteration → Check success criteria → Done?  │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│               Outputs                                   │
│  analysis/findings.json   — structured findings         │
│  analysis/progress.log    — iteration trace             │
│  analysis/forensic_audit.log — full audit trail         │
│  logs/mcp_audit.log       — per-tool-call trace         │
│  reports/accuracy_report.json — precision/recall/F1     │
│  reports/incident_report.pdf  — final PDF report        │
└─────────────────────────────────────────────────────────┘
```

**Architectural pattern:** Custom MCP Server (Pattern 2) + Persistent Learning Loop (Starter Idea 7)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| SANS SIFT Workstation | Ubuntu x86-64, standard SIFT tool set |
| Claude Code CLI | `npm install -g @anthropic-ai/claude-code` |
| Anthropic API key | Set in `~/.claude/.credentials.json` |
| Python 3 + WeasyPrint | Installed automatically by `install.sh` |
| dotnet runtime v6 | Pre-installed on SIFT (for EZ Tools) |
| Volatility 3 | `pip3 install volatility3` |

---

## Installation

```bash
# Option 1: One-liner (on SIFT Workstation)
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/find-evil/main/install.sh | bash

# Option 2: Clone and install
git clone https://github.com/YOUR_USERNAME/find-evil.git
cd find-evil
bash install.sh
```

---

## Quick Start

```bash
# 1. Create a case directory
mkdir /cases/CASE01

# 2. Copy case template
cp /opt/find-evil/case-templates/CLAUDE.md /cases/CASE01/

# 3. Edit the template with your evidence details
nano /cases/CASE01/CLAUDE.md

# 4. Mount evidence (read-only)
sudo ewfmount /cases/CASE01/evidence.E01 /mnt/ewf/
sudo mount -o ro,loop,noatime /mnt/ewf/ewf1 /mnt/case_disk

# 5. Run the autonomous analysis loop
python3 /opt/find-evil/agent/loop.py \
  --case /cases/CASE01 \
  --disk /mnt/case_disk \
  --memory /cases/CASE01/memory.raw \
  --max-iterations 10

# 6. Score accuracy against ground truth
python3 /opt/find-evil/validator/run_benchmark.py \
  --findings /cases/CASE01/analysis/findings.json \
  --ground-truth /opt/find-evil/validator/ground_truth/case01_template.json

# 7. Generate PDF report
python3 /opt/find-evil/analysis-scripts/generate_pdf_report.py \
  --case /cases/CASE01
```

---

## What the Agent Does

1. **Triage** — identifies evidence type, OS, time range, initial hypothesis
2. **Disk Timeline** — extracts MFT, filters by suspicious paths, identifies T0
3. **Memory Analysis** — runs Volatility plugins, detects injected code, maps network connections
4. **Persistence & Artifacts** — checks registry run keys, scheduled tasks, Prefetch, Amcache
5. **Correlation** — cross-references disk/memory/registry findings, flags discrepancies
6. **Self-Correction** — after each phase, evaluates its own output and re-runs if inconsistencies are found
7. **Reporting** — produces structured findings, iteration trace, accuracy report, and PDF

---

## Evidence Integrity

All guardrails are **architectural**, not prompt-based:

- The MCP server physically cannot run `rm`, `dd`, `shred`, `wget`, `curl`, or `ssh`
- Evidence directories (`/cases/`, `/mnt/`, `/media/`) are blocked from writes in `settings.json`
- Tool outputs are parsed to JSON before reaching the LLM — no raw shell output injection
- Every tool call is logged with timestamp, arguments, and SHA256 of output

---

## Project Structure

```
find-evil/
├── install.sh                          ← One-liner setup
├── LICENSE                             ← MIT
├── README.md                           ← This file
├── sift-mcp-server/
│   ├── server.py                       ← MCP server (stdio transport)
│   ├── tools/                          ← One file per forensic tool
│   │   ├── amcache.py                  ← AmcacheParser wrapper
│   │   ├── mft.py                      ← MFTECmd + mactime wrapper
│   │   ├── volatility.py               ← Volatility 3 wrapper
│   │   ├── yara.py                     ← YARA wrapper
│   │   ├── evtx.py                     ← EvtxECmd wrapper
│   │   ├── registry.py                 ← RECmd wrapper
│   │   ├── prefetch.py                 ← PECmd wrapper
│   │   └── network.py                  ← netscan wrapper
│   └── parsers/
│       ├── common.py                   ← Shared subprocess utilities
│       └── volatility_parsers.py       ← Plugin-specific output parsers
├── agent/
│   ├── CLAUDE.md                       ← Global behavioral rules
│   ├── settings.json                   ← Tool permissions + MCP config
│   ├── loop.py                         ← Persistent self-correcting loop
│   └── strategy/
│       ├── triage.md
│       ├── disk_timeline.md
│       └── memory_analysis.md
├── validator/
│   ├── run_benchmark.py                ← Accuracy benchmark runner
│   ├── score.py                        ← Precision/recall/F1 scorer
│   └── ground_truth/
│       └── case01_template.json        ← Ground truth template
├── case-templates/
│   └── CLAUDE.md                       ← Per-case context template
├── analysis-scripts/
│   ├── audit_hook.py                   ← Claude Code Stop hook
│   └── generate_pdf_report.py          ← PDF report generator
├── logs/                               ← MCP audit logs (git-ignored)
└── docs/
    ├── architecture.png                ← Architecture diagram (add yours)
    └── accuracy-report-template.md     ← Accuracy report template
```

---

## Judging Criteria Alignment

| Criterion | How Addressed |
|---|---|
| Autonomous Execution Quality | Self-correction loop; agent re-runs tools when findings are inconsistent |
| IR Accuracy | Accuracy validator scores every run against ground truth (precision/recall/F1) |
| Breadth & Depth | 8 MCP tools covering disk, memory, registry, network, YARA |
| Constraint Implementation | **Architectural** — MCP server never exposes destructive commands |
| Audit Trail Quality | Every MCP call logged: timestamp, args, SHA256 of output, token estimate |
| Usability & Documentation | One-liner install, case templates, full README |

---

## License

MIT License — see [LICENSE](LICENSE)
