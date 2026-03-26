#!/usr/bin/env python3
"""
run_capacity_aware_eval.py
Comparative evaluation: fixed-threshold (composite) vs capacity-aware policy.

Runs all 9 scenarios (A-I) at m=4096 under both policies and compares:
  - False escalation count
  - Time to first detection
  - Detection accuracy (coordinated-pressure hit rate)
  - Max saturation

Also runs the baseline comparison scenarios A and B.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scenarios import ALL_SCENARIOS, _run_generic_scenario, _approach_to_class
from metrics import write_csv, write_jsonl
from harness import SecurityNode
from capacity_aware_node import CapacityAwareNode


def main():
    output_dir = os.path.join(os.path.dirname(__file__),
                              "..", "..", "results", "security", "capacity_aware")
    os.makedirs(output_dir, exist_ok=True)

    profile = {
        "num_nodes": 12, "topology": "regional_mesh",
        "contact_prob": 0.4, "bloom_m": 4096, "bloom_k": 2,
    }

    approaches = ["ghost_meadow", "capacity_aware"]

    print("=" * 72)
    print("CAPACITY-AWARE vs COMPOSITE POLICY COMPARISON")
    print(f"Profile: m={profile['bloom_m']}, k={profile['bloom_k']}, "
          f"nodes={profile['num_nodes']}")
    print("=" * 72)

    all_results = []
    start = time.time()

    for scn_name, scn_fn in ALL_SCENARIOS:
        for approach in approaches:
            collector = scn_fn(profile, approach)
            s = collector.summary_dict()
            s["approach"] = approach
            all_results.append(s)

            t1 = s.get("time_to_first_local_suspicion")
            fe = s["false_escalation_count"]
            sat = s["max_saturation_pct"]
            hits = s["true_coord_hits"]
            t1s = str(t1) if t1 is not None else "N/A"
            print(f"  {scn_name:>20s} / {approach:<16s}: "
                  f"t1={t1s:>4s} fe={fe:>2d} hits={hits:>2d} "
                  f"sat={sat:.1f}%")

    elapsed = time.time() - start

    # Write results
    write_csv(all_results, os.path.join(output_dir, "comparison.csv"))
    write_jsonl(all_results, os.path.join(output_dir, "comparison.jsonl"))

    # Print comparison table
    print(f"\n{'='*72}")
    print("SIDE-BY-SIDE COMPARISON")
    print(f"{'='*72}")
    print(f"  {'Scenario':<22s} | {'Composite':^28s} | {'Capacity-Aware':^28s}")
    print(f"  {'':22s} | {'t1':>4s} {'fe':>3s} {'hits':>4s} {'sat%':>6s} "
          f"| {'t1':>4s} {'fe':>3s} {'hits':>4s} {'sat%':>6s}")
    print(f"  {'-'*72}")

    by_scenario = {}
    for r in all_results:
        scn = r["scenario"]
        if scn not in by_scenario:
            by_scenario[scn] = {}
        by_scenario[scn][r["approach"]] = r

    for scn, approaches_data in by_scenario.items():
        comp = approaches_data.get("ghost_meadow", {})
        cap = approaches_data.get("capacity_aware", {})

        def _fmt(r):
            t1 = r.get("time_to_first_local_suspicion")
            t1s = f"{t1:>4d}" if t1 is not None else " N/A"
            fe = r.get("false_escalation_count", 0)
            hits = r.get("true_coord_hits", 0)
            sat = r.get("max_saturation_pct", 0)
            return f"{t1s} {fe:>3d} {hits:>4d} {sat:>5.1f}%"

        print(f"  {scn:<22s} | {_fmt(comp)} | {_fmt(cap)}")

    # Summary stats
    comp_results = [r for r in all_results if r["approach"] == "ghost_meadow"]
    cap_results = [r for r in all_results if r["approach"] == "capacity_aware"]

    def _sum_metric(results, key, default=0):
        return sum(r.get(key, default) for r in results)

    comp_fe = _sum_metric(comp_results, "false_escalation_count")
    cap_fe = _sum_metric(cap_results, "false_escalation_count")
    comp_hits = _sum_metric(comp_results, "true_coord_hits")
    cap_hits = _sum_metric(cap_results, "true_coord_hits")

    print(f"\n  Total false escalations:  composite={comp_fe}  capacity_aware={cap_fe}")
    print(f"  Total coord hits:         composite={comp_hits}  capacity_aware={cap_hits}")

    # Write summary
    summary_path = os.path.join(output_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write("CAPACITY-AWARE vs COMPOSITE POLICY COMPARISON\n")
        f.write(f"Runtime: {elapsed:.1f}s\n")
        f.write(f"Profile: m={profile['bloom_m']}, nodes={profile['num_nodes']}\n\n")
        f.write(f"Total false escalations:  composite={comp_fe}  "
                f"capacity_aware={cap_fe}\n")
        f.write(f"Total coord hits:         composite={comp_hits}  "
                f"capacity_aware={cap_hits}\n")

    print(f"\nResults: {output_dir}/")
    print(f"Runtime: {elapsed:.1f}s")

    return 0


if __name__ == "__main__":
    sys.exit(main())
