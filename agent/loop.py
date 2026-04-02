#!/usr/bin/env python3
"""
FIND EVIL — Persistent Self-Correcting Analysis Loop

Drives the agent through investigation phases with:
  - Iteration tracking
  - Self-evaluation after each phase
  - Progress logging
  - Hard max-iterations cap (never runs away)
  - Graceful degradation on failure

Usage:
  python3 loop.py --case /cases/CASE01 --max-iterations 10
  python3 loop.py --case /cases/CASE01 --disk /mnt/case_disk --memory /cases/CASE01/memory.raw
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_MAX_ITERATIONS = 10
PROGRESS_FILE          = "analysis/progress.log"
FINDINGS_FILE          = "analysis/findings.json"
AUDIT_LOG              = "analysis/forensic_audit.log"

# Investigation phases in order
PHASES = [
    "triage",
    "disk_timeline",
    "memory_analysis",
    "persistence_artifacts",
    "correlation_synthesis",
]

# Success criteria — all must be True to stop early
SUCCESS_CRITERIA = {
    "t0_identified":          False,  # Earliest suspicious event identified
    "attack_vector_confirmed":False,  # How attacker got in
    "persistence_checked":    False,  # Registry/services/scheduled tasks reviewed
    "memory_correlated":      False,  # Memory findings cross-referenced with disk
    "timeline_complete":      False,  # Full incident timeline built
}


# ── Progress tracker ─────────────────────────────────────────────────────────

class ProgressTracker:
    def __init__(self, case_dir: Path):
        self.case_dir      = case_dir
        self.progress_file = case_dir / PROGRESS_FILE
        self.findings_file = case_dir / FINDINGS_FILE
        self.progress_file.parent.mkdir(parents=True, exist_ok=True)

        self.iterations    = []
        self.findings      = []
        self.criteria      = SUCCESS_CRITERIA.copy()

    def log_iteration(self, num: int, phase: str, tools_called: list,
                      new_findings: list, corrections: list, duration_s: float):
        entry = {
            "iteration":    num,
            "phase":        phase,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "tools_called": tools_called,
            "new_findings": new_findings,
            "corrections":  corrections,
            "duration_s":   round(duration_s, 2),
        }
        self.iterations.append(entry)
        self.findings.extend(new_findings)

        # Append to progress log (human-readable)
        with open(self.progress_file, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"ITERATION {num} | PHASE: {phase}\n")
            f.write(f"Time: {entry['timestamp']}\n")
            f.write(f"Duration: {duration_s:.1f}s\n")
            f.write(f"Tools called: {', '.join(tools_called) or 'none'}\n")
            f.write(f"New findings: {len(new_findings)}\n")
            f.write(f"Corrections: {len(corrections)}\n")
            for c in corrections:
                f.write(f"  CORRECTION: {c}\n")
            for fnd in new_findings:
                conf = fnd.get("confidence", "UNCONFIRMED")
                f.write(f"  [{conf}] {fnd.get('finding', '')}\n")

        # Save structured findings
        with open(self.findings_file, "w") as f:
            json.dump({
                "iterations": self.iterations,
                "findings":   self.findings,
                "criteria":   self.criteria,
            }, f, indent=2, default=str)

    def update_criteria(self, updates: dict):
        self.criteria.update(updates)

    def all_criteria_met(self) -> bool:
        return all(self.criteria.values())

    def summary(self) -> dict:
        confirmed   = [f for f in self.findings if f.get("confidence") == "CONFIRMED"]
        inferred    = [f for f in self.findings if f.get("confidence") == "INFERRED"]
        unconfirmed = [f for f in self.findings if f.get("confidence") == "UNCONFIRMED"]
        return {
            "total_iterations": len(self.iterations),
            "total_findings":   len(self.findings),
            "confirmed":        len(confirmed),
            "inferred":         len(inferred),
            "unconfirmed":      len(unconfirmed),
            "criteria_met":     self.all_criteria_met(),
            "criteria_detail":  self.criteria,
        }


# ── Claude Code runner ───────────────────────────────────────────────────────

def run_claude_phase(case_dir: Path, phase: str, context: dict) -> dict:
    """
    Run Claude Code for one investigation phase.
    Returns structured output: findings, tools_called, corrections, criteria_updates.
    """
    prompt = _build_phase_prompt(phase, context)
    prompt_file = case_dir / "analysis" / f"prompt_{phase}.txt"
    prompt_file.write_text(prompt)

    cmd = [
        "claude",
        "--print",           # non-interactive, print output to stdout
        "--output-format", "json",
        prompt,
    ]

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            cwd=str(case_dir),
            capture_output=True,
            text=True,
            timeout=600,
        )
        duration = time.time() - start

        if result.returncode != 0:
            return _error_result(phase, result.stderr, duration)

        return _parse_claude_output(result.stdout, duration)

    except subprocess.TimeoutExpired:
        return _error_result(phase, "Claude Code timed out after 600s", time.time() - start)
    except FileNotFoundError:
        return _error_result(phase, "claude binary not found — is Claude Code installed?", 0)


def _build_phase_prompt(phase: str, context: dict) -> str:
    disk    = context.get("disk_path", "NOT_PROVIDED")
    memory  = context.get("memory_path", "NOT_PROVIDED")
    prev    = context.get("previous_findings", [])
    iters   = context.get("iteration_num", 1)
    corrections = context.get("pending_corrections", [])

    prev_str = "\n".join(f"  - [{f['confidence']}] {f['finding']}" for f in prev[-10:])
    corr_str = "\n".join(f"  - {c}" for c in corrections)

    return f"""## Investigation Phase: {phase.upper().replace('_', ' ')}

Iteration: {iters}
Disk image (mounted): {disk}
Memory image: {memory}

### Previous Findings (last 10)
{prev_str or "  (none yet)"}

### Pending Corrections to Address
{corr_str or "  (none)"}

### Your Task
Execute the {phase} investigation phase per your CLAUDE.md strategy files.
After completing analysis, output a JSON object with this exact structure:

{{
  "findings": [
    {{"finding": "...", "confidence": "CONFIRMED|INFERRED|UNCONFIRMED", "source_tool": "...", "timestamp_utc": "..."}}
  ],
  "tools_called": ["tool_name_1", "tool_name_2"],
  "corrections": ["description of any self-correction made"],
  "criteria_updates": {{
    "t0_identified": true|false,
    "attack_vector_confirmed": true|false,
    "persistence_checked": true|false,
    "memory_correlated": true|false,
    "timeline_complete": true|false
  }},
  "phase_complete": true|false,
  "reason_incomplete": "if phase_complete is false, explain what's missing"
}}
"""


def _parse_claude_output(raw: str, duration: float) -> dict:
    """Extract JSON block from Claude's output."""
    import re
    # Try to find JSON block
    match = re.search(r'\{[\s\S]+\}', raw)
    if match:
        try:
            data = json.loads(match.group())
            data["duration_s"] = duration
            return data
        except json.JSONDecodeError:
            pass
    # Fallback — return raw as unconfirmed finding
    return {
        "findings":        [{"finding": raw[:500], "confidence": "UNCONFIRMED", "source_tool": "claude_raw"}],
        "tools_called":    [],
        "corrections":     [],
        "criteria_updates":{},
        "phase_complete":  False,
        "reason_incomplete": "Could not parse structured output from Claude",
        "duration_s":      duration,
    }


def _error_result(phase: str, error: str, duration: float) -> dict:
    return {
        "findings":        [],
        "tools_called":    [],
        "corrections":     [f"ERROR in {phase}: {error}"],
        "criteria_updates":{},
        "phase_complete":  False,
        "reason_incomplete": error,
        "duration_s":      duration,
        "error":           error,
    }


# ── Main loop ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="FIND EVIL persistent analysis loop")
    parser.add_argument("--case",           required=True,  help="Path to case directory")
    parser.add_argument("--disk",           default=None,   help="Path to mounted disk image")
    parser.add_argument("--memory",         default=None,   help="Path to memory image")
    parser.add_argument("--max-iterations", type=int, default=DEFAULT_MAX_ITERATIONS)
    parser.add_argument("--phase",          default=None,   help="Run a single specific phase")
    args = parser.parse_args()

    case_dir = Path(args.case)
    if not case_dir.exists():
        print(f"[ERROR] Case directory not found: {args.case}", file=sys.stderr)
        sys.exit(1)

    tracker = ProgressTracker(case_dir)
    phases  = [args.phase] if args.phase else PHASES

    print(f"[FIND EVIL] Starting analysis | Case: {case_dir.name}")
    print(f"[FIND EVIL] Max iterations: {args.max_iterations}")
    print(f"[FIND EVIL] Phases: {phases}")
    print()

    iteration = 0
    for phase in phases:
        phase_done    = False
        phase_retries = 0
        MAX_PHASE_RETRIES = 3

        while not phase_done and phase_retries < MAX_PHASE_RETRIES:
            iteration += 1

            if iteration > args.max_iterations:
                print(f"[FIND EVIL] ⚠ Max iterations ({args.max_iterations}) reached. Stopping.")
                _print_summary(tracker)
                sys.exit(0)

            print(f"[FIND EVIL] Iteration {iteration}/{args.max_iterations} | Phase: {phase}")

            context = {
                "disk_path":          args.disk,
                "memory_path":        args.memory,
                "previous_findings":  tracker.findings,
                "iteration_num":      iteration,
                "pending_corrections":[
                    c for entry in tracker.iterations
                    for c in entry.get("corrections", [])
                    if entry.get("phase") == phase
                ],
            }

            result = run_claude_phase(case_dir, phase, context)

            tracker.log_iteration(
                num=iteration,
                phase=phase,
                tools_called=result.get("tools_called", []),
                new_findings=result.get("findings", []),
                corrections=result.get("corrections", []),
                duration_s=result.get("duration_s", 0),
            )

            if result.get("criteria_updates"):
                tracker.update_criteria(result["criteria_updates"])

            if result.get("phase_complete"):
                phase_done = True
                print(f"  ✓ Phase complete | Findings: {len(result.get('findings',[]))}")
            else:
                phase_retries += 1
                reason = result.get("reason_incomplete", "unknown")
                print(f"  ↺ Phase incomplete ({phase_retries}/{MAX_PHASE_RETRIES}): {reason}")

        if not phase_done:
            print(f"  ✗ Phase {phase} could not complete after {MAX_PHASE_RETRIES} attempts — continuing.")

        if tracker.all_criteria_met():
            print(f"\n[FIND EVIL] ✓ All success criteria met after {iteration} iterations.")
            break

    _print_summary(tracker)


def _print_summary(tracker: ProgressTracker):
    s = tracker.summary()
    print("\n" + "="*60)
    print("FIND EVIL — Analysis Complete")
    print("="*60)
    print(f"Iterations run:    {s['total_iterations']}")
    print(f"Total findings:    {s['total_findings']}")
    print(f"  CONFIRMED:       {s['confirmed']}")
    print(f"  INFERRED:        {s['inferred']}")
    print(f"  UNCONFIRMED:     {s['unconfirmed']}")
    print(f"All criteria met:  {s['criteria_met']}")
    print("\nCriteria detail:")
    for k, v in s["criteria_detail"].items():
        status = "✓" if v else "✗"
        print(f"  {status} {k}")
    print("="*60)


if __name__ == "__main__":
    main()
