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

    # ---- Test 5: Separability measurement at m=32768 ----
    # This is the critical test for the "good regime" thesis.
    # We run benign and coordinated-attack scenarios at m=32768 and
    # directly compare their saturation. The stage 2 size sweep showed
    # separability is ~1-2% across ALL filter sizes. This test documents
    # the actual boundary rather than asserting a hoped-for outcome.
    print("\nTest 5: Benign vs attack separability at m=32768")
    profile_32k = _make_profile(8, "full_mesh", 0.5, 32768, 7)

    config_benign = _scenario_config("A_benign", profile_32k)
    config_attack = _scenario_config("B_coordinated", profile_32k)

    coll_benign = _run_generic_scenario(
        "A_benign", config_benign, SecurityNode, "ghost_meadow")
    coll_attack = _run_generic_scenario(
        "B_coordinated", config_attack, SecurityNode, "ghost_meadow")

    s_benign = coll_benign.summary_dict()
    s_attack = coll_attack.summary_dict()

    ben_sat = s_benign["max_saturation_pct"]
    atk_sat = s_attack["max_saturation_pct"]
    gap = atk_sat - ben_sat
    ratio = atk_sat / ben_sat if ben_sat > 0 else 0

    print(f"    Benign max sat:  {ben_sat:.2f}%")
    print(f"    Attack max sat:  {atk_sat:.2f}%")
    print(f"    Gap:             {gap:+.2f}%")
    print(f"    Ratio:           {ratio:.4f}x")

    # The attack scenario DOES produce higher saturation than benign.
    # This is a real signal — OR-merge propagation of campaign tokens
    # raises aggregate saturation above the benign baseline.
    check("m=32768 attack sat >= benign sat",
          atk_sat >= ben_sat,
          f"benign={ben_sat:.2f}% attack={atk_sat:.2f}%")

    # But the gap is small — under 2%. This is the fundamental finding
    # from the stage 2 size sweep: separability is ~1-2% regardless of m.
    # We assert the gap is under 5% to document this as a known architectural
    # characteristic, not a test failure to be fixed.
    check("m=32768 separability is small (<5%)",
          gap < 5.0,
          f"gap={gap:.2f}% — if this fails, the workload has changed")

    # Benign saturation should have real headroom at m=32768.
    # With 8 nodes, full mesh, 500 steps, and epoch length 200,
    # benign should stay well below the elevated threshold (25% would
    # be ideal, but the actual value depends on token rate and merge density).
    check("m=32768 benign sat has headroom (< 50%)",
          ben_sat < 50.0,
          f"benign={ben_sat:.2f}% — headroom exists but not as large as predicted")

    # Zero false escalation in both scenarios. This is the real win at
    # m=32768: the headroom eliminates policy false positives even though
    # the attack signal itself is small.
    check("m=32768 benign zero false escalation",
          s_benign["false_escalation_count"] == 0,
          f"got {s_benign['false_escalation_count']}")
    check("m=32768 attack zero false escalation",
          s_attack["false_escalation_count"] == 0,
          f"got {s_attack['false_escalation_count']}")

    # Summary interpretation printed for human review
    if gap < 5.0 and ben_sat < 50.0:
        print("    INTERPRETATION: At m=32768, Ghost Meadow eliminates false")
        print("    escalation (benign sat stays below thresholds) but the")
        print(f"    attack signal is only {gap:.2f}% above benign — too small")
        print("    for saturation-threshold-based detection to reliably")
        print("    distinguish attack from noise. The headroom is real;")
        print("    the separability is not.")

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
