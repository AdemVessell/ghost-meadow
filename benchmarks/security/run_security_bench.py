#!/usr/bin/env python3
"""
run_security_bench.py
Main entry point for Ghost Meadow security evaluation benchmark.

Runs all threat scenarios across all approaches (Ghost Meadow, local-only,
exact gossip, counter aggregation) for configurable deployment profiles.

Usage:
    python3 benchmarks/security/run_security_bench.py [--profile PROFILE] [--quick]

Profiles: edge_pop, branch_iot, east_west, low_power
Default: edge_pop
"""

import sys
import os
import json
import time
import argparse

# Add benchmark dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scenarios import run_all, ALL_SCENARIOS, ALL_APPROACHES
from metrics import format_summary_table, write_csv, write_jsonl


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Ghost Meadow security evaluation benchmark")
    parser.add_argument("--profile", default="edge_pop",
                        choices=["edge_pop", "branch_iot", "east_west",
                                 "low_power", "all"],
                        help="Deployment profile to benchmark")
    parser.add_argument("--quick", action="store_true",
                        help="Run reduced scenario set for quick validation")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory for results")
    args = parser.parse_args()

    config = load_config()

    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.join(os.path.dirname(__file__),
                                  "..", "..", "results", "security")
    os.makedirs(output_dir, exist_ok=True)

    profiles_to_run = []
    if args.profile == "all":
        profiles_to_run = list(config["deployment_profiles"].keys())
    else:
        profiles_to_run = [args.profile]

    scenarios = ALL_SCENARIOS
    if args.quick:
        # Quick mode: only benign, coordinated attack, single poison
        quick_names = {"A_benign", "B_coordinated", "C_single_poison"}
        scenarios = [(n, f) for n, f in ALL_SCENARIOS if n in quick_names]

    all_summaries = []

    print("=" * 72)
    print("GHOST MEADOW SECURITY EVALUATION BENCHMARK")
    print("=" * 72)
    print(f"Profiles: {profiles_to_run}")
    print(f"Scenarios: {len(scenarios)}")
    print(f"Approaches: {len(ALL_APPROACHES)}")
    print(f"Total runs: {len(profiles_to_run) * len(scenarios) * len(ALL_APPROACHES)}")
    print()

    start_time = time.time()

    for profile_name in profiles_to_run:
        profile = config["deployment_profiles"][profile_name]
        print(f"\n{'='*72}")
        print(f"PROFILE: {profile_name} — {profile['description']}")
        print(f"  nodes={profile['num_nodes']} topology={profile['topology']} "
              f"bloom_m={profile['bloom_m']} bloom_k={profile['bloom_k']}")
        print(f"{'='*72}")

        profile_config = {
            "num_nodes": profile["num_nodes"],
            "topology": profile["topology"],
            "contact_prob": profile["contact_prob"],
            "bloom_m": profile["bloom_m"],
            "bloom_k": profile["bloom_k"],
        }

        summaries = run_all(profile_config, ALL_APPROACHES, scenarios)
        # Tag with profile name
        for s in summaries:
            s["profile"] = profile_name
        all_summaries.extend(summaries)

    elapsed = time.time() - start_time

    # Output results
    print(f"\n{'='*72}")
    print("RESULTS SUMMARY")
    print(f"{'='*72}")
    print(format_summary_table(all_summaries))

    # Write outputs
    csv_path = os.path.join(output_dir, "security_bench_results.csv")
    jsonl_path = os.path.join(output_dir, "security_bench_results.jsonl")
    summary_path = os.path.join(output_dir, "security_bench_summary.txt")

    write_csv(all_summaries, csv_path)
    write_jsonl(all_summaries, jsonl_path)

    with open(summary_path, "w") as f:
        f.write("GHOST MEADOW SECURITY EVALUATION BENCHMARK RESULTS\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Runtime: {elapsed:.1f}s\n")
        f.write(f"Profiles: {profiles_to_run}\n")
        f.write(f"Scenarios: {len(scenarios)}\n")
        f.write(f"Approaches: {len(ALL_APPROACHES)}\n\n")
        f.write(format_summary_table(all_summaries))
        f.write("\n\nACCEPTANCE CRITERIA ASSESSMENT\n")
        f.write("=" * 72 + "\n")
        f.write(_assess_acceptance_criteria(all_summaries))

    print(f"\nResults written to:")
    print(f"  CSV:     {csv_path}")
    print(f"  JSONL:   {jsonl_path}")
    print(f"  Summary: {summary_path}")
    print(f"\nTotal runtime: {elapsed:.1f}s")

    # Print acceptance criteria assessment
    print(f"\n{'='*72}")
    print("ACCEPTANCE CRITERIA ASSESSMENT")
    print(f"{'='*72}")
    print(_assess_acceptance_criteria(all_summaries))

    return 0


def _assess_acceptance_criteria(summaries):
    """Evaluate the 8 acceptance criteria from the benchmark results."""
    lines = []

    # Group by scenario and approach
    by_scn = {}
    for s in summaries:
        scn = s["scenario"]
        if scn not in by_scn:
            by_scn[scn] = {}
        by_scn[scn][s["approach"]] = s

    # A. Does GM outperform local-only in any security-relevant condition?
    lines.append("\nA. Does Ghost Meadow outperform local-only detection?")
    gm_wins = 0
    gm_total = 0
    for scn, approaches in by_scn.items():
        gm = approaches.get("ghost_meadow")
        lo = approaches.get("local_only")
        if gm and lo:
            gm_total += 1
            gm_t = gm.get("time_to_first_local_suspicion")
            lo_t = lo.get("time_to_first_local_suspicion")
            if gm_t is not None and lo_t is not None and gm_t <= lo_t:
                gm_wins += 1
            elif gm_t is not None and lo_t is None:
                gm_wins += 1
    lines.append(f"   GM detects faster or equal in {gm_wins}/{gm_total} scenarios.")

    # B. Earlier coordinated-pressure awareness?
    lines.append("\nB. Earlier coordinated-pressure awareness vs local-only?")
    for scn in ["B_coordinated_attack", "G_partition_asymmetry", "H_transport_hostility"]:
        if scn in by_scn:
            gm = by_scn[scn].get("ghost_meadow", {})
            lo = by_scn[scn].get("local_only", {})
            gm_c = gm.get("time_to_first_regional_coord")
            lo_c = lo.get("time_to_first_regional_coord")
            gm_str = str(gm_c) if gm_c is not None else "never"
            lo_str = str(lo_c) if lo_c is not None else "never"
            lines.append(f"   {scn}: GM={gm_str}, local={lo_str}")

    # C. Bandwidth comparison
    lines.append("\nC. Bandwidth cost vs exact-sharing baselines?")
    for scn, approaches in by_scn.items():
        gm = approaches.get("ghost_meadow", {})
        eg = approaches.get("exact_gossip", {})
        if gm and eg:
            gm_b = gm.get("bytes_per_node", 0)
            eg_b = eg.get("bytes_per_node", 0)
            ratio = gm_b / eg_b if eg_b > 0 else float('inf')
            lines.append(f"   {scn}: GM={gm_b:.0f}B/node, exact={eg_b:.0f}B/node, "
                         f"ratio={ratio:.2f}x")
        break  # Just show one scenario for brevity

    # D. How badly does poisoning hurt?
    lines.append("\nD. Poisoning impact?")
    for scn in ["C_single_poison", "D_multi_collusion"]:
        if scn in by_scn:
            gm = by_scn[scn].get("ghost_meadow", {})
            lines.append(f"   {scn}: maxSat={gm.get('max_saturation_pct', 0):.1f}%, "
                         f"harmSteps={gm.get('steps_in_harmful_saturation', 0)}, "
                         f"falseEsc={gm.get('false_escalation_count', 0)}")

    # E. Do quorum and trust help?
    lines.append("\nE. Quorum and trust-weighted policies?")
    for scn in ["C_single_poison", "D_multi_collusion"]:
        if scn in by_scn:
            gm = by_scn[scn].get("ghost_meadow", {})
            lo = by_scn[scn].get("local_only", {})
            gm_fe = gm.get("false_escalation_count", 0)
            lo_fe = lo.get("false_escalation_count", 0)
            lines.append(f"   {scn}: GM false_esc={gm_fe}, local false_esc={lo_fe}")

    # F. When does saturation become useless?
    lines.append("\nF. Saturation collapse threshold?")
    for scn, approaches in by_scn.items():
        gm = approaches.get("ghost_meadow", {})
        ms = gm.get("max_saturation_pct", 0)
        hs = gm.get("steps_in_harmful_saturation", 0)
        if hs > 0:
            lines.append(f"   {scn}: maxSat={ms:.1f}%, harmfulSteps={hs}")

    # G. Which profiles are viable?
    lines.append("\nG. Profile viability?")
    by_profile = {}
    for s in summaries:
        p = s.get("profile", "unknown")
        if p not in by_profile:
            by_profile[p] = []
        by_profile[p].append(s)
    for p, runs in by_profile.items():
        gm_runs = [r for r in runs if r["approach"] == "ghost_meadow"]
        if gm_runs:
            avg_max_sat = sum(r["max_saturation_pct"] for r in gm_runs) / len(gm_runs)
            harm_total = sum(r["steps_in_harmful_saturation"] for r in gm_runs)
            lines.append(f"   {p}: avg_maxSat={avg_max_sat:.1f}%, total_harmSteps={harm_total}")

    # H. Which conditions make GM a bad fit?
    lines.append("\nH. Conditions where Ghost Meadow is a bad fit?")
    bad_fits = []
    for scn, approaches in by_scn.items():
        gm = approaches.get("ghost_meadow", {})
        if gm.get("steps_in_harmful_saturation", 0) > 100:
            bad_fits.append(f"   {scn}: excessive harmful saturation "
                           f"({gm['steps_in_harmful_saturation']} steps)")
        if (gm.get("false_escalation_count", 0) > 0 and
                "poison" in scn.lower() or "collusion" in scn.lower()):
            bad_fits.append(f"   {scn}: false escalation under poisoning "
                           f"({gm['false_escalation_count']} nodes)")
    if bad_fits:
        lines.extend(bad_fits)
    else:
        lines.append("   No clearly bad scenarios identified in this run.")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
