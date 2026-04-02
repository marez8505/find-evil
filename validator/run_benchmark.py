#!/usr/bin/env python3
"""
FIND EVIL — Accuracy Benchmark Runner

Runs the agent against a known-good dataset (ground truth) and scores:
  - True Positives  (agent found it, ground truth confirms it)
  - False Positives (agent found it, ground truth says no)
  - False Negatives (ground truth has it, agent missed it)
  - Hallucination Rate (findings with no source tool cited)

Usage:
  python3 run_benchmark.py \
    --findings /cases/CASE01/analysis/findings.json \
    --ground-truth ground_truth/case01.json \
    --output reports/accuracy_report.json
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from score import compute_scores, print_scorecard


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="FIND EVIL accuracy benchmark")
    parser.add_argument("--findings",     required=True, help="Path to agent findings.json")
    parser.add_argument("--ground-truth", required=True, help="Path to ground truth JSON")
    parser.add_argument("--output",       default="reports/accuracy_report.json")
    args = parser.parse_args()

    findings_path = Path(args.findings)
    gt_path       = Path(args.ground_truth)
    output_path   = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[Benchmark] Loading findings:     {findings_path}")
    print(f"[Benchmark] Loading ground truth: {gt_path}")

    findings_data = load_json(findings_path)
    ground_truth  = load_json(gt_path)

    agent_findings = findings_data.get("findings", [])
    gt_artifacts   = ground_truth.get("artifacts", [])
    gt_iocs        = ground_truth.get("iocs", [])

    scores = compute_scores(agent_findings, gt_artifacts, gt_iocs)

    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "findings_file":   str(findings_path),
        "ground_truth_file": str(gt_path),
        "agent_stats": {
            "total_findings":      len(agent_findings),
            "confirmed_findings":  sum(1 for f in agent_findings if f.get("confidence") == "CONFIRMED"),
            "inferred_findings":   sum(1 for f in agent_findings if f.get("confidence") == "INFERRED"),
            "unconfirmed_findings":sum(1 for f in agent_findings if f.get("confidence") == "UNCONFIRMED"),
            "iterations_run":      len(findings_data.get("iterations", [])),
        },
        "scores": scores,
        "evidence_integrity": _check_evidence_integrity(findings_data),
        "false_positives":    scores.get("false_positives_detail", []),
        "false_negatives":    scores.get("false_negatives_detail", []),
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print_scorecard(report)
    print(f"\n[Benchmark] Full report saved to: {output_path}")


def _check_evidence_integrity(findings_data: dict) -> dict:
    """
    Verify that findings are traceable and no evidence-modification
    commands appear in tool call logs.
    """
    iterations  = findings_data.get("iterations", [])
    all_tools   = [t for it in iterations for t in it.get("tools_called", [])]

    # Dangerous tools that should NEVER appear
    FORBIDDEN = {"rm", "dd", "shred", "mkfs", "mount -o rw", "wget", "curl"}
    violations = [t for t in all_tools if any(f in t for f in FORBIDDEN)]

    # Check traceability: findings with no source_tool
    all_findings     = findings_data.get("findings", [])
    untraceable      = [f for f in all_findings if not f.get("source_tool")]

    return {
        "forbidden_tool_violations": violations,
        "untraceable_findings":      len(untraceable),
        "untraceable_details":       [f.get("finding", "")[:100] for f in untraceable[:10]],
        "integrity_passed":          len(violations) == 0,
    }


if __name__ == "__main__":
    main()
