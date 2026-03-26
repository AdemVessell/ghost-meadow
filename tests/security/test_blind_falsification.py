#!/usr/bin/env python3
"""
test_blind_falsification.py
Tests for the blind falsification framework itself — not the system under test.

Validates:
1. Freeze manifest integrity
2. Deterministic held-out generation from seed
3. Condition-to-config conversion
4. Verdict logic correctness
5. Separation of dev and held-out conditions
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "benchmarks", "security"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from blind_generator import (generate_conditions, condition_to_scenario_config,
                             HELD_OUT_MASTER_SEED, HELD_OUT_SEED_START,
                             HELD_OUT_VARIANT_BASE)
from run_blind_falsification import produce_verdict

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
    print("BLIND FALSIFICATION FRAMEWORK TESTS")
    print("=" * 60)

    # ---- Test 1: Freeze manifest integrity ----
    print("\nTest 1: Freeze manifest integrity")
    manifest_path = os.path.join(os.path.dirname(__file__), "..", "..",
                                 "docs", "blind_falsification_freeze_manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)

    check("Manifest has frozen_commit",
          "frozen_commit" in manifest and len(manifest["frozen_commit"]) == 40)
    check("Manifest has frozen_system",
          "frozen_system" in manifest)
    check("Manifest has profiles_under_test",
          "profiles_under_test" in manifest)
    check("Manifest has forbidden_after_freeze",
          len(manifest.get("forbidden_after_freeze", [])) >= 5)
    check("Policy thresholds frozen",
          manifest["frozen_system"]["policy_thresholds"]["sat_elevated"] == 25.0)

    # ---- Test 2: Deterministic held-out generation ----
    print("\nTest 2: Deterministic generation")
    conds1 = generate_conditions(num_seeds=3)
    conds2 = generate_conditions(num_seeds=3)
    check("Same seed produces same conditions",
          len(conds1) == len(conds2))
    if conds1 and conds2:
        check("First condition identical",
              conds1[0]["seed"] == conds2[0]["seed"] and
              conds1[0]["topology"] == conds2[0]["topology"])
        check("Last condition identical",
              conds1[-1]["seed"] == conds2[-1]["seed"])

    # ---- Test 3: Held-out seeds disjoint from dev ----
    print("\nTest 3: Dev/held-out separation")
    dev_seeds = set(range(20260326, 20260340))
    held_out_seeds = set(c["seed"] for c in conds1)
    check("No overlap between dev and held-out seeds",
          len(dev_seeds & held_out_seeds) == 0)
    check("Held-out variant base avoids dev range",
          HELD_OUT_VARIANT_BASE >= 10000)
    check("Held-out seeds start at expected range",
          all(s >= HELD_OUT_SEED_START for s in held_out_seeds))

    # ---- Test 4: Condition-to-config conversion ----
    print("\nTest 4: Config conversion")
    cond = conds1[0]
    config = condition_to_scenario_config(cond)
    check("Config has bloom_m", config["bloom_m"] == cond["m"])
    check("Config has bloom_k", config["bloom_k"] == cond["k"])
    check("Config has topology", config["topology"] == cond["topology"])
    check("Config has seed", config["seed"] == cond["seed"])
    check("Config has attack_type", "attack_type" in config)

    # ---- Test 5: Condition matrix coverage ----
    print("\nTest 5: Matrix coverage")
    conds_full = generate_conditions(num_seeds=10)
    profiles = set(c["profile_name"] for c in conds_full)
    traffics = set(c["traffic_regime"] for c in conds_full)
    topos = set(c["topology"] for c in conds_full)

    check("All 3 profiles present", len(profiles) == 3,
          f"got {profiles}")
    check("All 7 traffic regimes present", len(traffics) == 7,
          f"got {traffics}")
    check("Multiple topologies used", len(topos) >= 3,
          f"got {topos}")
    check("Expected condition count",
          len(conds_full) == 10 * 3 * 7,  # seeds * profiles * traffic
          f"got {len(conds_full)}")

    # ---- Test 6: Verdict logic ----
    print("\nTest 6: Verdict logic")
    # Synthetic results for testing verdict computation
    fake_manifest = {"frozen_commit": "a" * 40}
    fake_results = []

    # Create 10 paired GM + local_only results
    for i in range(10):
        fake_results.append({
            "condition_id": i, "approach": "ghost_meadow",
            "profile": "good_regime_32768", "m": 32768, "k": 7,
            "seed": 50000 + i, "topology": "ring",
            "contact_prob": 0.4, "epoch_length": 200,
            "traffic_regime": "benign_heavy" if i < 5 else "coordinated_bursty",
            "attack_type": "none" if i < 5 else "distributed_campaign",
            "has_real_attack": i >= 5,
            "time_to_first_local_suspicion": 30 + i,
            "time_to_fleet_awareness": 35 + i,
            "false_escalation_count": 0,
            "true_coord_hits": 8 if i >= 5 else 0,
            "missed_coord_attacks": 0,
            "max_saturation_pct": 40.0 + i,
            "bytes_per_node": 5000000,
            "total_merges": 1000, "num_nodes": 12,
            "layer_a_fp_rate": 0.001,
            "layer_a_campaign_recall": 1.0,
            "malicious_node_ids": [],
        })
        fake_results.append({
            "condition_id": i, "approach": "local_only",
            "profile": "good_regime_32768", "m": 32768,
            "time_to_first_local_suspicion": 60 + i,
            "max_saturation_pct": 70.0,
            "false_escalation_count": 5,
            "bytes_per_node": 0,
            "has_real_attack": i >= 5,
        })
        fake_results.append({
            "condition_id": i, "approach": "exact_gossip",
            "profile": "good_regime_32768", "m": 32768,
            "time_to_first_local_suspicion": 10 + i,
            "max_saturation_pct": 90.0,
            "false_escalation_count": 10,
            "bytes_per_node": 8000000,
            "has_real_attack": i >= 5,
        })

    verdict = produce_verdict(fake_results, fake_manifest)
    pv = verdict["profile_verdicts"].get("good_regime_32768", {})

    check("Verdict has profile",
          "good_regime_32768" in verdict["profile_verdicts"])
    check("Awareness verdict computed",
          "awareness_speedup_verdict" in pv)
    # GM (30-39) vs local (60-69): GM always faster -> 100% -> SUPPORT
    check("Awareness is SUPPORT (GM always faster)",
          pv.get("awareness_speedup_verdict") == "SUPPORT",
          f"got {pv.get('awareness_speedup_verdict')}")
    check("Bandwidth verdict computed",
          "bandwidth_verdict" in pv)
    check("False escalation verdict computed",
          "false_escalation_verdict" in pv)

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
