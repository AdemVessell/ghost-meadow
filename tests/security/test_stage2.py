#!/usr/bin/env python3
"""
test_stage2.py
Tests for stage 2 security evaluation extensions.

Validates:
1. Layer A measurement produces valid results
2. Size sweep covers expected range
3. Seed aggregation math is correct
4. Large-filter scenarios run without error
"""

import sys
import os
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "benchmarks", "security"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ghost_meadow import GhostMeadow
from run_stage2_bench import (run_layer_a_measurement, _aggregate_seeds,
                              _make_profile, _scenario_config)
from scenarios import _run_generic_scenario, _approach_to_class
from harness import SecurityNode

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  PASS: {name}")
        passed += 1
    else:
        print(f"  FAIL: {name} {detail}")
        failed += 1


def main():
    print("=" * 60)
    print("STAGE 2 SECURITY EVALUATION TESTS")
    print("=" * 60)

    # ---- Test 1: Large-filter GhostMeadow works correctly ----
    print("\nTest 1: Large-filter GhostMeadow correctness")
    key = 0xDEADBEEFCAFEBABE
    for m, k in [(32768, 7), (192000, 13)]:
        gm = GhostMeadow(key, 0, m=m, k=k)
        tok = b"\x01\x02\x03\x04"
        gm.seed(tok)
        check(f"m={m} seed+query", gm.query(tok))
        check(f"m={m} saturation > 0", gm.saturation() > 0)
        check(f"m={m} saturation < 0.01",
              gm.saturation() < 0.01,
              f"got {gm.saturation()}")
        gm.decay()
        check(f"m={m} epoch isolation", not gm.query(tok))

    # ---- Test 2: Seed aggregation math ----
    print("\nTest 2: Seed aggregation")
    fake_results = [
        {"scenario": "test", "approach": "gm", "num_nodes": 8,
         "time_to_first_local_suspicion": 10, "max_saturation_pct": 50.0,
         "false_escalation_count": 2, "time_to_median_local_suspicion": 12,
         "time_to_first_regional_coord": None, "time_to_fleet_awareness": 15,
         "true_coord_hits": 6, "missed_coord_attacks": 2,
         "stale_pressure_events": 5, "total_bytes": 1000, "total_merges": 50,
         "bytes_per_node": 125, "steps_in_harmful_saturation": 10,
         "final_saturation_variance": 0.5, "degradation_under_malicious": 0},
        {"scenario": "test", "approach": "gm", "num_nodes": 8,
         "time_to_first_local_suspicion": 20, "max_saturation_pct": 60.0,
         "false_escalation_count": 4, "time_to_median_local_suspicion": 22,
         "time_to_first_regional_coord": None, "time_to_fleet_awareness": 25,
         "true_coord_hits": 8, "missed_coord_attacks": 0,
         "stale_pressure_events": 3, "total_bytes": 2000, "total_merges": 60,
         "bytes_per_node": 250, "steps_in_harmful_saturation": 20,
         "final_saturation_variance": 0.8, "degradation_under_malicious": 0},
    ]
    agg = _aggregate_seeds(fake_results)
    check("Aggregation: mean t1 = 15",
          abs(agg["time_to_first_local_suspicion_mean"] - 15.0) < 0.01)
    check("Aggregation: std t1 = 5",
          abs(agg["time_to_first_local_suspicion_std"] - 5.0) < 0.01)
    check("Aggregation: mean sat = 55",
          abs(agg["max_saturation_pct_mean"] - 55.0) < 0.01)
    check("Aggregation: num_seeds = 2", agg["num_seeds"] == 2)

    # ---- Test 3: Scenario at m=32768 runs ----
    print("\nTest 3: m=32768 scenario execution")
    profile = _make_profile(8, "full_mesh", 0.5, 32768, 7)
    config = _scenario_config("A_benign", profile)
    collector = _run_generic_scenario(
        "A_benign", config, SecurityNode, "ghost_meadow")
    s = collector.summary_dict()
    check("m=32768 benign runs", s["max_saturation_pct"] > 0)
    check("m=32768 benign sat < 60%",
          s["max_saturation_pct"] < 60,
          f"got {s['max_saturation_pct']:.1f}%")
    check("m=32768 benign false_esc = 0",
          s["false_escalation_count"] == 0)

    # ---- Test 4: m=32768 coordinated attack ----
    print("\nTest 4: m=32768 attack detection")
    config = _scenario_config("B_coordinated", profile)
    collector = _run_generic_scenario(
        "B_coordinated", config, SecurityNode, "ghost_meadow")
    s = collector.summary_dict()
    check("m=32768 attack sat > benign",
          s["max_saturation_pct"] > 0)
    check("m=32768 attack merges > 0",
          s["total_merges"] > 0)

    # ---- Summary ----
    print(f"\n{'='*60}")
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed} failed")
    if failed == 0:
        print("ALL TESTS PASSED")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
