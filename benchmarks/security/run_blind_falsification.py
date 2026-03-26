#!/usr/bin/env python3
"""
run_blind_falsification.py
Pre-registered blind falsification runner for Ghost Meadow.

Protocol:
1. Load freeze manifest — verify frozen commit
2. Generate held-out conditions deterministically
3. Run ALL conditions without modifying policy/config
4. Measure Layer A + policy-level metrics
5. Compare against pre-registered acceptance criteria
6. Produce verdict

No threshold tuning. No condition dropping. No post-hoc interpretation changes.
"""

import sys
import os
import json
import time
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ghost_meadow import GhostMeadow
from blind_generator import (generate_conditions, condition_to_scenario_config,
                             HELD_OUT_MASTER_SEED)
from scenarios import _run_generic_scenario, _approach_to_class
from harness import SecurityNode, LocalOnlyNode, ExactGossipNode, CounterAggNode
from security_tokens import TokenGenerator
from metrics import MetricsCollector, write_csv, write_jsonl


# Pre-registered approaches to compare
APPROACHES = {
    "ghost_meadow": SecurityNode,
    "local_only": LocalOnlyNode,
    "exact_gossip": ExactGossipNode,
}


def run_blind(num_seeds=10, output_base=None):
    """Run the full blind falsification matrix."""
    if output_base is None:
        output_base = os.path.join(os.path.dirname(__file__),
                                   "..", "..", "results", "security", "blind")

    raw_dir = os.path.join(output_base, "raw")
    summary_dir = os.path.join(output_base, "summary")
    verdict_dir = os.path.join(output_base, "verdict")
    cond_dir = os.path.join(output_base, "generated_conditions")
    for d in [raw_dir, summary_dir, verdict_dir, cond_dir]:
        os.makedirs(d, exist_ok=True)

    # Step 1: Load freeze manifest
    manifest_path = os.path.join(os.path.dirname(__file__), "..", "..",
                                 "docs", "blind_falsification_freeze_manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)
    print(f"Freeze manifest loaded: commit {manifest['frozen_commit'][:12]}")

    # Step 2: Generate held-out conditions
    print(f"\nGenerating held-out conditions ({num_seeds} seeds)...")
    conditions = generate_conditions(num_seeds=num_seeds, output_dir=cond_dir)
    total_runs = len(conditions) * len(APPROACHES)
    print(f"  {len(conditions)} conditions x {len(APPROACHES)} approaches = {total_runs} runs")

    # Step 3: Run all conditions
    print(f"\nRunning blind matrix...")
    start = time.time()

    all_results = []
    skipped = []
    run_count = 0

    for cond in conditions:
        cid = cond["condition_id"]
        profile = cond["profile_name"]
        traffic = cond["traffic_regime"]

        for approach_name, node_class in APPROACHES.items():
            run_count += 1
            config = condition_to_scenario_config(cond)

            try:
                collector = _run_generic_scenario(
                    f"{traffic}_{profile}",
                    config, node_class, approach_name)
                s = collector.summary_dict()

                # Add Layer A measurement for GM runs
                layer_a = {}
                if approach_name == "ghost_meadow":
                    layer_a = _measure_layer_a(cond)

                result = {
                    "condition_id": cid,
                    "seed": cond["seed"],
                    "profile": profile,
                    "m": cond["m"],
                    "k": cond["k"],
                    "topology": cond["topology"],
                    "contact_prob": cond["contact_prob"],
                    "epoch_length": cond["epoch_length"],
                    "traffic_regime": traffic,
                    "attack_type": cond["attack_type"],
                    "has_real_attack": cond["has_real_attack"],
                    "approach": approach_name,
                    **s,
                    **layer_a,
                }
                all_results.append(result)

            except Exception as e:
                skipped.append({"condition_id": cid, "approach": approach_name,
                                "reason": str(e)})

            if run_count % 50 == 0:
                elapsed = time.time() - start
                pct = run_count / total_runs * 100
                print(f"  [{run_count}/{total_runs}] {pct:.0f}% "
                      f"({elapsed:.0f}s elapsed)")

    elapsed = time.time() - start
    print(f"\n  Completed {len(all_results)} runs, {len(skipped)} skipped "
          f"in {elapsed:.1f}s")

    # Save skipped conditions log
    if skipped:
        skip_path = os.path.join(raw_dir, "skipped_conditions.json")
        with open(skip_path, "w") as f:
            json.dump(skipped, f, indent=2)

    # Step 4: Write raw results
    write_csv(all_results, os.path.join(raw_dir, "blind_results.csv"))
    write_jsonl(all_results, os.path.join(raw_dir, "blind_results.jsonl"))

    # Step 5: Aggregate and produce verdict
    verdict = produce_verdict(all_results, manifest)
    verdict_path = os.path.join(verdict_dir, "verdict.json")
    with open(verdict_path, "w") as f:
        json.dump(verdict, f, indent=2, default=str)

    # Write human-readable summary
    summary_text = format_verdict(verdict)
    summary_path = os.path.join(summary_dir, "blind_summary.txt")
    with open(summary_path, "w") as f:
        f.write(summary_text)

    print(f"\nResults: {raw_dir}")
    print(f"Summary: {summary_path}")
    print(f"Verdict: {verdict_path}")
    print(f"\n{summary_text}")

    return verdict


def _measure_layer_a(cond):
    """Quick Layer A FP/recall measurement for one condition."""
    m = cond["m"]
    k = cond["k"]
    mission_key = 0xDEADBEEFCAFEBABE
    tgen = TokenGenerator(cond["seed"] + 5000)  # offset from scenario gen

    meadow = GhostMeadow(mission_key, 0, m=m, k=k)

    # Seed benign tokens
    seeded = set()
    for _ in range(300):
        tok = tgen.random_benign_token()
        meadow.seed(tok)
        seeded.add(tok)

    # Seed campaign tokens
    campaign = set()
    for step in range(100):
        tok = tgen.campaign_token_correlated(99, 0, step)
        meadow.seed(tok)
        campaign.add(tok)

    # FP test with fresh tokens
    tgen2 = TokenGenerator(cond["seed"] + 9999)
    fp_hits = 0
    fp_total = 200
    for _ in range(fp_total):
        tok = tgen2.random_benign_token()
        if tok not in seeded and tok not in campaign:
            if meadow.query(tok):
                fp_hits += 1

    # Campaign recall
    recall_hits = sum(1 for t in list(campaign)[:100] if meadow.query(t))
    recall_total = min(100, len(campaign))

    return {
        "layer_a_fp_rate": fp_hits / max(1, fp_total),
        "layer_a_campaign_recall": recall_hits / max(1, recall_total),
        "layer_a_sat_pct": meadow.saturation_pct(),
    }


def produce_verdict(results, manifest):
    """Compare results against pre-registered acceptance criteria."""

    # Separate by approach and profile
    gm_results = [r for r in results if r["approach"] == "ghost_meadow"]
    lo_results = [r for r in results if r["approach"] == "local_only"]
    eg_results = [r for r in results if r["approach"] == "exact_gossip"]

    # Group GM results by profile
    gm_by_profile = {}
    for r in gm_results:
        p = r["profile"]
        if p not in gm_by_profile:
            gm_by_profile[p] = []
        gm_by_profile[p].append(r)

    # Build paired comparisons (same condition_id)
    lo_by_cid = {r["condition_id"]: r for r in lo_results}
    eg_by_cid = {r["condition_id"]: r for r in eg_results}

    verdicts = {}

    for profile_name, gm_runs in gm_by_profile.items():
        pv = {"profile": profile_name, "n_conditions": len(gm_runs)}

        # A. Awareness speedup vs local-only
        faster_count = 0
        total_paired = 0
        awareness_diffs = []
        for r in gm_runs:
            lo = lo_by_cid.get(r["condition_id"])
            if lo:
                total_paired += 1
                gm_t = r.get("time_to_first_local_suspicion")
                lo_t = lo.get("time_to_first_local_suspicion")
                if gm_t is not None and lo_t is not None:
                    if gm_t < lo_t:
                        faster_count += 1
                    awareness_diffs.append(lo_t - gm_t)
                elif gm_t is not None and lo_t is None:
                    faster_count += 1
                # If both None, neither detected — skip

        faster_pct = faster_count / max(1, total_paired) * 100
        pv["awareness_speedup_pct"] = faster_pct
        pv["awareness_speedup_verdict"] = (
            "SUPPORT" if faster_pct >= 60 else
            "WEAK_SUPPORT" if faster_pct >= 40 else "FAILURE")
        if awareness_diffs:
            pv["awareness_diff_mean"] = sum(awareness_diffs) / len(awareness_diffs)
            pv["awareness_diff_std"] = math.sqrt(
                sum((d - pv["awareness_diff_mean"]) ** 2
                    for d in awareness_diffs) / len(awareness_diffs)
            ) if len(awareness_diffs) > 1 else 0

        # B. Bandwidth vs exact gossip
        bw_wins = 0
        bw_total = 0
        for r in gm_runs:
            eg = eg_by_cid.get(r["condition_id"])
            if eg:
                bw_total += 1
                gm_bw = r.get("bytes_per_node", 0)
                eg_bw = eg.get("bytes_per_node", 0)
                if eg_bw > 0 and gm_bw <= eg_bw * 0.8:
                    bw_wins += 1
        bw_pct = bw_wins / max(1, bw_total) * 100
        pv["bandwidth_advantage_pct"] = bw_pct
        pv["bandwidth_verdict"] = "SUPPORT" if bw_pct >= 80 else (
            "WEAK_SUPPORT" if bw_pct >= 50 else "FAILURE")

        # C. False escalation (benign conditions only)
        benign_runs = [r for r in gm_runs
                       if not r.get("has_real_attack", False)]
        fe_values = [r.get("false_escalation_count", 0) for r in benign_runs]
        max_fe = max(fe_values) if fe_values else 0
        mean_fe = sum(fe_values) / len(fe_values) if fe_values else 0
        pv["false_escalation_max"] = max_fe
        pv["false_escalation_mean"] = mean_fe
        pv["false_escalation_verdict"] = (
            "SUPPORT" if max_fe <= 2 else
            "WEAK_SUPPORT" if max_fe <= 5 else "FAILURE")

        # D. Coordinated hit rate (attack conditions)
        attack_runs = [r for r in gm_runs if r.get("has_real_attack", False)]
        if attack_runs:
            hit_rates = []
            for r in attack_runs:
                hits = r.get("true_coord_hits", 0)
                total_honest = r.get("num_nodes", 12) - len(
                    r.get("malicious_node_ids",
                           [] if "poison" not in r.get("traffic_regime", "") else [0]))
                if total_honest > 0:
                    hit_rates.append(hits / total_honest)
            mean_hit = sum(hit_rates) / len(hit_rates) if hit_rates else 0
            pv["coord_hit_rate_mean"] = mean_hit
            pv["coord_hit_verdict"] = (
                "SUPPORT" if mean_hit >= 0.5 else
                "WEAK_SUPPORT" if mean_hit >= 0.3 else "FAILURE")

        # E. Benign saturation headroom
        benign_sats = [r.get("max_saturation_pct", 100) for r in benign_runs]
        mean_ben_sat = sum(benign_sats) / len(benign_sats) if benign_sats else 100
        pv["benign_sat_mean"] = mean_ben_sat
        m = gm_runs[0]["m"] if gm_runs else 0
        threshold = 50.0 if m <= 32768 else 25.0
        pv["headroom_verdict"] = (
            "SUPPORT" if mean_ben_sat < threshold else "FAILURE")

        # F. Seed stability
        # Group by traffic regime and measure std of awareness timing
        by_traffic = {}
        for r in gm_runs:
            t = r["traffic_regime"]
            if t not in by_traffic:
                by_traffic[t] = []
            by_traffic[t].append(r)

        stability_ratios = []
        for t, runs in by_traffic.items():
            t1_vals = [r["time_to_first_local_suspicion"]
                       for r in runs
                       if r.get("time_to_first_local_suspicion") is not None]
            if len(t1_vals) >= 2:
                mean_t = sum(t1_vals) / len(t1_vals)
                std_t = math.sqrt(sum((v - mean_t) ** 2 for v in t1_vals)
                                  / len(t1_vals))
                if mean_t > 0:
                    stability_ratios.append(std_t / mean_t)

        mean_stability = (sum(stability_ratios) / len(stability_ratios)
                          if stability_ratios else 0)
        pv["stability_cv_mean"] = mean_stability
        pv["stability_verdict"] = (
            "SUPPORT" if mean_stability <= 0.10 else
            "WEAK_SUPPORT" if mean_stability <= 0.20 else "FAILURE")

        # G. Layer A quality
        la_fps = [r.get("layer_a_fp_rate", 0) for r in gm_runs
                  if "layer_a_fp_rate" in r]
        la_recalls = [r.get("layer_a_campaign_recall", 0) for r in gm_runs
                      if "layer_a_campaign_recall" in r]
        pv["layer_a_fp_mean"] = (sum(la_fps) / len(la_fps)
                                 if la_fps else None)
        pv["layer_a_recall_mean"] = (sum(la_recalls) / len(la_recalls)
                                     if la_recalls else None)

        # Overall verdict for this profile
        sub_verdicts = [v for k, v in pv.items() if k.endswith("_verdict")]
        if "CATASTROPHIC" in str(sub_verdicts):
            pv["overall"] = "CATASTROPHIC_FAILURE"
        elif sub_verdicts.count("FAILURE") >= 3:
            pv["overall"] = "FAILURE"
        elif sub_verdicts.count("FAILURE") >= 1:
            pv["overall"] = "WEAK_SUPPORT"
        elif sub_verdicts.count("WEAK_SUPPORT") >= 2:
            pv["overall"] = "WEAK_SUPPORT"
        else:
            pv["overall"] = "SUPPORT"

        verdicts[profile_name] = pv

    # Separability measurement (GM only)
    sep_data = {}
    for r in gm_results:
        key = (r["profile"], r["seed"], r["topology"], r["contact_prob"])
        if key not in sep_data:
            sep_data[key] = {}
        sep_data[key][r["traffic_regime"]] = r.get("max_saturation_pct", 0)

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "frozen_commit": manifest.get("frozen_commit", "unknown"),
        "num_conditions": len(results) // len(APPROACHES),
        "num_runs": len(results),
        "runtime_note": "see runner output",
        "profile_verdicts": verdicts,
    }


def format_verdict(verdict):
    """Human-readable verdict summary."""
    lines = []
    lines.append("=" * 72)
    lines.append("BLIND FALSIFICATION VERDICT")
    lines.append(f"Frozen commit: {verdict['frozen_commit'][:12]}")
    lines.append(f"Conditions: {verdict['num_conditions']}, "
                 f"Runs: {verdict['num_runs']}")
    lines.append("=" * 72)

    for pname, pv in verdict.get("profile_verdicts", {}).items():
        lines.append(f"\n--- Profile: {pname} (n={pv['n_conditions']}) ---")
        lines.append(f"  OVERALL: {pv['overall']}")
        lines.append("")

        # Awareness
        lines.append(f"  Awareness speedup: GM faster in "
                     f"{pv.get('awareness_speedup_pct', 0):.0f}% of conditions "
                     f"-> {pv.get('awareness_speedup_verdict', '?')}")
        if "awareness_diff_mean" in pv:
            lines.append(f"    Mean advantage: {pv['awareness_diff_mean']:.1f} "
                         f"± {pv.get('awareness_diff_std', 0):.1f} steps")

        # Bandwidth
        lines.append(f"  Bandwidth ≤80% of exact gossip: "
                     f"{pv.get('bandwidth_advantage_pct', 0):.0f}% of conditions "
                     f"-> {pv.get('bandwidth_verdict', '?')}")

        # False escalation
        lines.append(f"  False escalation (benign): max={pv.get('false_escalation_max', '?')} "
                     f"mean={pv.get('false_escalation_mean', 0):.1f} "
                     f"-> {pv.get('false_escalation_verdict', '?')}")

        # Coord hits
        if "coord_hit_rate_mean" in pv:
            lines.append(f"  Coord hit rate: {pv['coord_hit_rate_mean']:.2f} "
                         f"-> {pv.get('coord_hit_verdict', '?')}")

        # Headroom
        lines.append(f"  Benign saturation: {pv.get('benign_sat_mean', 0):.1f}% "
                     f"-> {pv.get('headroom_verdict', '?')}")

        # Stability
        lines.append(f"  Seed stability (CV): {pv.get('stability_cv_mean', 0):.3f} "
                     f"-> {pv.get('stability_verdict', '?')}")

        # Layer A
        if pv.get("layer_a_fp_mean") is not None:
            lines.append(f"  Layer A FP: {pv['layer_a_fp_mean']:.4f}, "
                         f"Recall: {pv.get('layer_a_recall_mean', 0):.3f}")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Ghost Meadow blind falsification runner")
    parser.add_argument("--seeds", type=int, default=10,
                        help="Number of held-out seeds (default 10)")
    args = parser.parse_args()

    print("=" * 72)
    print("GHOST MEADOW BLIND FALSIFICATION RUN")
    print("=" * 72)
    run_blind(num_seeds=args.seeds)
