#!/usr/bin/env python3
"""
FIND EVIL — Scoring Engine

Computes precision, recall, F1, and hallucination rate
by comparing agent findings against a ground truth dataset.
"""

from difflib import SequenceMatcher


def _similarity(a: str, b: str) -> float:
    """Fuzzy string similarity 0–1."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


MATCH_THRESHOLD = 0.70   # similarity score to count as a match


def compute_scores(
    agent_findings: list,
    gt_artifacts:   list,
    gt_iocs:        list,
) -> dict:
    """
    Compare agent findings against ground truth.

    Args:
        agent_findings: List of finding dicts from findings.json
        gt_artifacts:   Ground truth artifact list (dicts with 'description' key)
        gt_iocs:        Ground truth IOC list (strings: IPs, hashes, filenames)

    Returns:
        dict with precision, recall, f1, hallucination_rate, and detail lists
    """
    gt_texts = (
        [a.get("description", "") for a in gt_artifacts]
        + [str(ioc) for ioc in gt_iocs]
    )

    agent_texts = [f.get("finding", "") for f in agent_findings]

    # Match each ground truth item to best agent finding
    true_positives  = []
    false_negatives = []

    for gt in gt_texts:
        best_score = 0.0
        best_match = None
        for af in agent_texts:
            s = _similarity(gt, af)
            if s > best_score:
                best_score = s
                best_match = af
        if best_score >= MATCH_THRESHOLD:
            true_positives.append({"ground_truth": gt, "agent_finding": best_match, "score": round(best_score, 3)})
        else:
            false_negatives.append({"ground_truth": gt, "best_score": round(best_score, 3)})

    # Match each agent finding to best ground truth
    false_positives  = []
    confirmed_correct = []

    for af_dict in agent_findings:
        af = af_dict.get("finding", "")
        best_score = 0.0
        for gt in gt_texts:
            s = _similarity(af, gt)
            if s > best_score:
                best_score = s
        if best_score < MATCH_THRESHOLD:
            false_positives.append({
                "agent_finding": af[:200],
                "confidence":    af_dict.get("confidence", "UNKNOWN"),
                "source_tool":   af_dict.get("source_tool", "none"),
                "best_gt_score": round(best_score, 3),
            })
        else:
            confirmed_correct.append(af[:200])

    # Hallucination: agent findings with no source_tool cited
    hallucinations = [
        f for f in agent_findings
        if not f.get("source_tool") or f.get("source_tool") == "none"
    ]

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    hallucination_rate = len(hallucinations) / len(agent_findings) if agent_findings else 0.0

    return {
        "true_positives":       tp,
        "false_positives":      fp,
        "false_negatives":      fn,
        "precision":            round(precision, 4),
        "recall":               round(recall, 4),
        "f1_score":             round(f1, 4),
        "hallucination_rate":   round(hallucination_rate, 4),
        "hallucination_count":  len(hallucinations),
        "ground_truth_size":    len(gt_texts),
        "agent_finding_count":  len(agent_findings),
        "true_positives_detail": true_positives,
        "false_positives_detail": false_positives,
        "false_negatives_detail": false_negatives,
    }


def print_scorecard(report: dict):
    scores = report.get("scores", {})
    stats  = report.get("agent_stats", {})
    integ  = report.get("evidence_integrity", {})

    print("\n" + "="*60)
    print("FIND EVIL — ACCURACY SCORECARD")
    print("="*60)
    print(f"{'Ground truth items:':<30} {scores.get('ground_truth_size', 0)}")
    print(f"{'Agent findings total:':<30} {stats.get('total_findings', 0)}")
    print(f"  {'CONFIRMED:':<28} {stats.get('confirmed_findings', 0)}")
    print(f"  {'INFERRED:':<28} {stats.get('inferred_findings', 0)}")
    print(f"  {'UNCONFIRMED:':<28} {stats.get('unconfirmed_findings', 0)}")
    print()
    print(f"{'True Positives:':<30} {scores.get('true_positives', 0)}")
    print(f"{'False Positives:':<30} {scores.get('false_positives', 0)}")
    print(f"{'False Negatives:':<30} {scores.get('false_negatives', 0)}")
    print()
    print(f"{'Precision:':<30} {scores.get('precision', 0):.1%}")
    print(f"{'Recall:':<30} {scores.get('recall', 0):.1%}")
    print(f"{'F1 Score:':<30} {scores.get('f1_score', 0):.4f}")
    print(f"{'Hallucination Rate:':<30} {scores.get('hallucination_rate', 0):.1%}")
    print()
    print(f"{'Evidence Integrity:':<30} {'PASS ✓' if integ.get('integrity_passed') else 'FAIL ✗'}")
    if integ.get("forbidden_tool_violations"):
        print(f"  VIOLATIONS: {integ['forbidden_tool_violations']}")
    if integ.get("untraceable_findings", 0) > 0:
        print(f"  Untraceable findings: {integ['untraceable_findings']}")
    print("="*60)
