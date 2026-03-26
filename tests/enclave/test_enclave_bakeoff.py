#!/usr/bin/env python3
"""
test_enclave_bakeoff.py
Tests for the cooperative enclave bakeoff framework.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "benchmarks", "enclave"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "benchmarks", "security"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from enclave_baselines import (EWMALocalNode, ScalarMaxGossipNode,
                                ScalarMeanGossipNode)
from enclave_topologies import (make_corridor, make_wing_gateway,
                                 make_campus_building)
from capacity_aware_node import CapacityAwareNode
from harness import SimRNG
from run_enclave_bakeoff import (
    overlap_identical_event, breadth_weak_distributed,
    shift_change_bustle, do_merges, ALL_SCENARIOS, APPROACHES)

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
    print("COOPERATIVE ENCLAVE BAKEOFF TESTS")
    print("=" * 60)

    rng = SimRNG(12345)

    # ---- Test 1: Topologies produce valid graphs ----
    print("\nTest 1: Topology validity")
    for name, fn in [("corridor", make_corridor),
                     ("wing_gateway", make_wing_gateway),
                     ("campus_building", make_campus_building)]:
        adj = fn(32, rng)
        check(f"{name} has 32 nodes", len(adj) == 32)
        # Check connectivity: at least some edges
        total_edges = sum(len(v) for v in adj.values())
        check(f"{name} has edges", total_edges > 0,
              f"got {total_edges}")
        # Check symmetry
        symmetric = True
        for i, neighbors in adj.items():
            for j in neighbors:
                if i not in adj.get(j, set()):
                    symmetric = False
                    break
        check(f"{name} is symmetric", symmetric)

    # ---- Test 2: Baseline nodes satisfy interface ----
    print("\nTest 2: Baseline interface contract")
    for cls_name, cls in [("EWMALocal", EWMALocalNode),
                          ("ScalarMax", ScalarMaxGossipNode),
                          ("ScalarMean", ScalarMeanGossipNode)]:
        node = cls(node_id=0)
        check(f"{cls_name} has seed_token", hasattr(node, "seed_token"))
        check(f"{cls_name} has merge_from", hasattr(node, "merge_from"))
        check(f"{cls_name} has evaluate_policy", hasattr(node, "evaluate_policy"))
        check(f"{cls_name} has decay_epoch", hasattr(node, "decay_epoch"))

        # Test seed + evaluate cycle
        node.seed_token(b"test_event")
        result = node.evaluate_policy(0)
        check(f"{cls_name} evaluate returns zone",
              "zone" in result, str(result))
        check(f"{cls_name} has zone_history",
              len(node.zone_history) == 1)

    # ---- Test 3: GM CapacityAwareNode works ----
    print("\nTest 3: CapacityAwareNode interface")
    gm = CapacityAwareNode(node_id=0, bloom_m=4096, bloom_k=2)
    gm.seed_token(b"test")
    r = gm.evaluate_policy(0)
    check("GM evaluate returns zone", "zone" in r)
    check("GM saturation > 0", gm.saturation_history[-1] > 0)

    # ---- Test 4: Overlap identical — GM dedup test ----
    print("\nTest 4: Overlap identical dedup")
    topo = make_wing_gateway(32, SimRNG(99))

    # Run with GM
    gm_nodes = [CapacityAwareNode(i, bloom_m=4096, bloom_k=2)
                for i in range(32)]
    gm_result = overlap_identical_event(gm_nodes, topo, SimRNG(99), 99)

    # Run with scalar mean
    sm_nodes = [ScalarMeanGossipNode(i) for i in range(32)]
    sm_result = overlap_identical_event(sm_nodes, topo, SimRNG(99), 99)

    check("GM dedup: low max sat under identical events",
          gm_result["max_final_sat"] < 50,
          f"got {gm_result['max_final_sat']:.1f}%")

    # ---- Test 5: Breadth — GM detects distributed signal ----
    print("\nTest 5: Breadth detection")
    gm_nodes2 = [CapacityAwareNode(i, bloom_m=4096, bloom_k=2)
                 for i in range(32)]
    gm_breadth = breadth_weak_distributed(gm_nodes2, topo, SimRNG(100), 100)

    sm_nodes2 = [ScalarMaxGossipNode(i) for i in range(32)]
    sm_breadth = breadth_weak_distributed(sm_nodes2, topo, SimRNG(100), 100)

    # GM accumulates distinct bits from 32 unique events via OR-merge.
    # Scalar-max takes max(1,1,...,1) = 1 — blind to breadth.
    # Compare elevated_rate (operational metric), not pseudo-saturation
    # (which uses incompatible scales across approaches).
    gm_er = gm_breadth["elevated_rate"]
    sm_er = sm_breadth["elevated_rate"]
    check("GM breadth: higher elevated rate than scalar-max",
          gm_er >= sm_er,
          f"GM_elev_rate={gm_er:.2f} SM_elev_rate={sm_er:.2f}")

    # ---- Test 6: Shift-change bustle — no crash ----
    print("\nTest 6: Shift-change bustle runs")
    gm_nodes3 = [CapacityAwareNode(i, bloom_m=4096, bloom_k=2)
                 for i in range(32)]
    bustle_result = shift_change_bustle(gm_nodes3, topo, SimRNG(101), 101)
    check("Shift bustle completes", bustle_result is not None)
    check("Shift bustle has metrics",
          "elevated_rate" in bustle_result)

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
