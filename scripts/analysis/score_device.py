#!/usr/bin/env python3
"""
score_device.py — IoT Device Vulnerability Scorer
IoT Security Research

Aggregates test log JSON files for a device across all three configuration states
and computes the weighted vulnerability score per the research rubric.
Outputs a comparative table and highlights mitigation effectiveness.

Usage:
    python score_device.py --logs experiments/ip-camera/logs/ --label "TP-Link Tapo Camera"
"""

import argparse
import json
import os
import glob
from datetime import datetime

# ── Scoring rubric (weights must sum to 1.0) ─────────────────────────────────
RUBRIC = {
    "authentication_strength": {"weight": 0.20, "label": "Authentication Strength"},
    "data_encryption":         {"weight": 0.20, "label": "Data Encryption"},
    "attack_surface":          {"weight": 0.15, "label": "Attack Surface"},
    "update_mechanism":        {"weight": 0.15, "label": "Update Mechanism"},
    "privacy_controls":        {"weight": 0.15, "label": "Privacy Controls"},
    "physical_security":       {"weight": 0.10, "label": "Physical Security"},
    "vendor_response":         {"weight": 0.05, "label": "Vendor Response"},
}

STATE_LABELS = {1: "State 1: Factory Default", 2: "State 2: Vendor Hardened", 3: "State 3: Best Practice"}

RESULT_COLORS = {
    "SUCCESS": "🔴",
    "PARTIAL": "🟡",
    "FAILURE": "🟢",  # attack failed = good
    "INCONCLUSIVE": "⚪",
}

MITIGATION_SYMBOLS = {
    "PREVENTED":           "✓ PREVENTED",
    "PARTIALLY_MITIGATED": "~ PARTIAL",
    "FAILED_TO_MITIGATE":  "✗ FAILED",
    "N/A":                 "—",
}


def load_logs(log_dir: str) -> list[dict]:
    """Load all test log JSON files from directory."""
    logs = []
    for path in glob.glob(os.path.join(log_dir, "*.json")):
        try:
            with open(path) as f:
                data = json.load(f)
            # Handle both individual logs and schema files
            if "test_id" in data and "configuration_state" in data:
                logs.append(data)
        except (json.JSONDecodeError, KeyError):
            continue
    return logs


def compute_weighted_score(scores: dict) -> float:
    total = 0.0
    for key, meta in RUBRIC.items():
        val = scores.get(key, 0)
        total += val * meta["weight"]
    return round(total, 2)


def group_by_state(logs: list[dict]) -> dict[int, list[dict]]:
    groups: dict[int, list] = {1: [], 2: [], 3: []}
    for log in logs:
        state = log.get("configuration_state")
        if state in groups:
            groups[state].append(log)
    return groups


def summarize_state(logs: list[dict]) -> dict:
    """Build a summary dict for one configuration state."""
    if not logs:
        return {}

    attacks_succeeded = sum(1 for l in logs if l.get("result") == "SUCCESS")
    attacks_partial   = sum(1 for l in logs if l.get("result") == "PARTIAL")
    attacks_failed    = sum(1 for l in logs if l.get("result") == "FAILURE")
    total_attacks     = len(logs)

    # Average scores if present
    score_fields = list(RUBRIC.keys())
    avg_scores = {}
    for field in score_fields:
        vals = [l.get("vulnerability_score", {}).get(field, None) for l in logs]
        vals = [v for v in vals if v is not None]
        avg_scores[field] = round(sum(vals) / len(vals), 1) if vals else None

    weighted = compute_weighted_score({k: v for k, v in avg_scores.items() if v is not None})

    # Time to compromise
    ttc_vals = [l.get("time_to_compromise_minutes") for l in logs if l.get("time_to_compromise_minutes") is not None]
    avg_ttc = round(sum(ttc_vals) / len(ttc_vals), 1) if ttc_vals else None

    return {
        "total_tests": total_attacks,
        "attacks_succeeded": attacks_succeeded,
        "attacks_partial": attacks_partial,
        "attacks_failed": attacks_failed,
        "attack_success_rate": round(attacks_succeeded / total_attacks * 100, 1) if total_attacks else 0,
        "avg_time_to_compromise_minutes": avg_ttc,
        "criterion_scores": avg_scores,
        "weighted_security_score": weighted,
        "attack_results": [
            {
                "attack": l.get("attack_vector"),
                "result": l.get("result"),
                "mitigation": l.get("mitigation_outcome", "N/A"),
                "ttc_min": l.get("time_to_compromise_minutes"),
                "owasp": l.get("owasp_category", ""),
            }
            for l in logs
        ]
    }


def print_comparison_table(by_state: dict, label: str) -> None:
    print(f"\n{'='*70}")
    print(f"  Device: {label}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*70}")

    # Per-state summary
    summaries = {s: summarize_state(logs) for s, logs in by_state.items() if logs}

    print(f"\n{'Criterion':<30} {'State 1':>10} {'State 2':>10} {'State 3':>10}")
    print("-" * 63)

    for key, meta in RUBRIC.items():
        row = f"{meta['label']:<30}"
        for state in [1, 2, 3]:
            val = summaries.get(state, {}).get("criterion_scores", {}).get(key)
            row += f" {'—' if val is None else f'{val:.1f}/10':>10}"
        print(row)

    print("-" * 63)
    row = f"{'Weighted Security Score':<30}"
    for state in [1, 2, 3]:
        val = summaries.get(state, {}).get("weighted_security_score", 0)
        row += f" {f'{val:.2f}/10':>10}"
    print(row + "  ←")

    print(f"\n{'Attack Success Rate':<30}", end="")
    for state in [1, 2, 3]:
        val = summaries.get(state, {}).get("attack_success_rate", 0)
        print(f" {f'{val}%':>10}", end="")
    print()

    # Risk reduction
    s1_rate = summaries.get(1, {}).get("attack_success_rate", 0)
    s2_rate = summaries.get(2, {}).get("attack_success_rate", 0)
    s3_rate = summaries.get(3, {}).get("attack_success_rate", 0)

    if s1_rate > 0:
        arr_s2 = round((s1_rate - s2_rate) / s1_rate * 100, 1)
        arr_s3 = round((s1_rate - s3_rate) / s1_rate * 100, 1)
        print(f"\n  Absolute Risk Reduction (vs State 1):")
        print(f"    State 2 (vendor hardening) : {s1_rate - s2_rate:.1f}% absolute | {arr_s2}% relative")
        print(f"    State 3 (best practice)    : {s1_rate - s3_rate:.1f}% absolute | {arr_s3}% relative")

    # Attack matrix
    print(f"\n{'─'*70}")
    print("  Attack Results by State")
    print(f"{'─'*70}")
    print(f"  {'Attack Vector':<30} {'S1':>4} {'S2':>4} {'S3':>4}  OWASP")
    print(f"  {'─'*28} {'─'*4} {'─'*4} {'─'*4}  {'─'*10}")

    # Collect all unique attacks
    all_attacks = set()
    attack_by_state: dict[int, dict] = {1: {}, 2: {}, 3: {}}
    for state, logs in by_state.items():
        for log in logs:
            av = log.get("attack_vector", "UNKNOWN")
            all_attacks.add(av)
            attack_by_state[state][av] = {
                "result": log.get("result", "—"),
                "owasp": log.get("owasp_category", ""),
            }

    for attack in sorted(all_attacks):
        row = f"  {attack:<30}"
        owasp = ""
        for state in [1, 2, 3]:
            entry = attack_by_state[state].get(attack, {})
            res = entry.get("result", "—")
            sym = RESULT_COLORS.get(res, "⚪")
            owasp = entry.get("owasp", owasp)
            row += f" {sym:>4}"
        print(f"{row}  {owasp}")

    print(f"\n  Legend: 🔴 Attack Succeeded | 🟡 Partial | 🟢 Attack Failed | ⚪ Not Tested")


def main():
    parser = argparse.ArgumentParser(description="IoT Device Vulnerability Scorer")
    parser.add_argument("--logs", required=True, help="Directory containing test log JSON files")
    parser.add_argument("--label", default="IoT Device", help="Device display name")
    parser.add_argument("--out", help="Save JSON results to this directory")
    args = parser.parse_args()

    logs = load_logs(args.logs)
    print(f"Loaded {len(logs)} test log entries from {args.logs}")

    if not logs:
        print("No test logs found. Ensure logs match the test-log.json schema.")
        return

    by_state = group_by_state(logs)
    print_comparison_table(by_state, args.label)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summaries = {
            STATE_LABELS[s]: summarize_state(l)
            for s, l in by_state.items() if l
        }
        out_file = os.path.join(args.out, f"scores_{timestamp}.json")
        with open(out_file, "w") as f:
            json.dump({"device": args.label, "states": summaries}, f, indent=2)
        print(f"\nScores saved: {out_file}")


if __name__ == "__main__":
    main()
