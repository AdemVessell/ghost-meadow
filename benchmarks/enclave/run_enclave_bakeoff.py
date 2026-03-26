#!/usr/bin/env python3
"""
run_enclave_bakeoff.py
Cooperative-enclave bakeoff: tiny GM vs cheap scalar baselines.

Tests the two surviving structural claims:
  1. Idempotent dedup under redundant overlap
  2. Sensitivity to distributed breadth

20 seeds × 3 topologies per scenario per approach.
"""

import sys
import os
import time
import math
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "security"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ghost_meadow import GhostMeadow
from harness import SimRNG, Fleet
from capacity_aware_node import CapacityAwareNode
from enclave_baselines import (EWMALocalNode, ScalarMaxGossipNode,
                                ScalarMeanGossipNode)
from enclave_topologies import make_corridor, make_wing_gateway, make_campus_building
from metrics import write_csv, write_jsonl

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NUM_NODES = 32
CONTACT_PROB = 0.3
EPOCH_LENGTH = 300
STEPS = 300
BLOOM_M = 4096
BLOOM_K = 2
MISSION_KEY = 0xDEADBEEFCAFEBABE

TOPOLOGIES = {
    "corridor": make_corridor,
    "wing_gateway": make_wing_gateway,
    "campus_building": make_campus_building,
}

APPROACHES = {
    "gm_cap_aware": CapacityAwareNode,
    "ewma_local": EWMALocalNode,
    "scalar_max": ScalarMaxGossipNode,
    "scalar_mean": ScalarMeanGossipNode,
}


# ---------------------------------------------------------------------------
# Simulation engine (lightweight, purpose-built for enclave)
# ---------------------------------------------------------------------------
def run_enclave_scenario(scenario_fn, approach_name, node_class,
                         topo_name, topo_fn, seed):
    """Run one scenario with one approach on one topology at one seed."""
    rng = SimRNG(seed)
    topology = topo_fn(NUM_NODES, rng)

    # Build nodes
    nodes = []
    for i in range(NUM_NODES):
        if node_class == CapacityAwareNode:
            node = CapacityAwareNode(
                node_id=i, mission_key=MISSION_KEY,
                bloom_m=BLOOM_M, bloom_k=BLOOM_K)
        else:
            node = node_class(node_id=i)
        nodes.append(node)

    # Run scenario — returns metrics dict
    return scenario_fn(nodes, topology, rng, seed)


# ---------------------------------------------------------------------------
# Merge helper
# ---------------------------------------------------------------------------
def do_merges(nodes, topology, rng, contact_prob=CONTACT_PROB):
    """One round of stochastic merges."""
    for i in range(len(nodes)):
        for j in topology.get(i, set()):
            if i != j and rng.rand_bool(contact_prob):
                nodes[i].merge_from(nodes[j])


# ---------------------------------------------------------------------------
# SCENARIO: Redundant Overlap — Identical Event
# ---------------------------------------------------------------------------
def overlap_identical_event(nodes, topology, rng, seed):
    """All nodes observe the SAME event repeatedly.
    GM should dedup (sat stays flat). Scalars should amplify."""
    event = b"facility_alarm_zone_7_fire_sensor_42"

    # Phase 1: Every node observes the same event (ticks 0-49)
    for step in range(50):
        for node in nodes:
            node.seed_token(event)
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    # Phase 2: Continue observing + merging (ticks 50-149)
    for step in range(50, 150):
        # Half the nodes re-observe the same event each tick
        for i, node in enumerate(nodes):
            if rng.rand_bool(0.5):
                node.seed_token(event)
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "overlap_identical_event")


# ---------------------------------------------------------------------------
# SCENARIO: Redundant Overlap — Moving Cluster
# ---------------------------------------------------------------------------
def overlap_moving_cluster(nodes, topology, rng, seed):
    """A moving event cluster drifts through the topology.
    At each phase, a different subset of nodes observes overlapping events."""
    n = len(nodes)
    cluster_size = n // 4

    for phase in range(4):
        start = phase * cluster_size
        end = min(start + cluster_size + 4, n)  # overlap of 4
        event = f"cluster_event_phase_{phase}".encode()

        for step in range(phase * 40, (phase + 1) * 40):
            for i in range(start, end):
                if i < n:
                    nodes[i].seed_token(event)
            # Also some nodes re-observe previous phase events
            if phase > 0:
                old_event = f"cluster_event_phase_{phase-1}".encode()
                for i in range(max(0, start - 4), start):
                    if rng.rand_bool(0.3):
                        nodes[i].seed_token(old_event)
            do_merges(nodes, topology, rng)
            for node in nodes:
                node.evaluate_policy(step)

    # Tail phase: just merges
    for step in range(160, 200):
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "overlap_moving_cluster")


# ---------------------------------------------------------------------------
# SCENARIO: Redundant Overlap — Rebroadcast Storm
# ---------------------------------------------------------------------------
def overlap_rebroadcast_storm(nodes, topology, rng, seed):
    """One node's observation propagates via merge, then other nodes
    independently re-observe the same pattern locally."""
    event = b"pump_pressure_anomaly_building_3"

    # Phase 1: Node 0 observes, merges propagate
    nodes[0].seed_token(event)
    for step in range(50):
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    # Phase 2: Other nodes independently observe the same event
    for step in range(50, 150):
        for i, node in enumerate(nodes):
            if rng.rand_bool(0.3):
                node.seed_token(event)  # re-observation of same event
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "overlap_rebroadcast_storm")


# ---------------------------------------------------------------------------
# SCENARIO: Distributed Breadth — Weak Distributed
# ---------------------------------------------------------------------------
def breadth_weak_distributed(nodes, topology, rng, seed):
    """Each of N nodes observes ONE unique weak event.
    No single node has enough pressure alone. The fleet-wide merge
    should accumulate breadth that scalars cannot see."""
    n = len(nodes)

    # Phase 1: Each node seeds one unique observation
    for step in range(50):
        for i, node in enumerate(nodes):
            if step == 0:  # seed once at start
                event = f"weak_anomaly_node_{i}_unique".encode()
                node.seed_token(event)
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    # Phase 2: Continue merging only (propagate the breadth signal)
    for step in range(50, 200):
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "breadth_weak_distributed")


# ---------------------------------------------------------------------------
# SCENARIO: Distributed Breadth — Gradient
# ---------------------------------------------------------------------------
def breadth_gradient(nodes, topology, rng, seed):
    """Gradient: nodes near a source zone see more events, distant see fewer."""
    n = len(nodes)

    for step in range(200):
        for i, node in enumerate(nodes):
            # Gradient: node 0 sees 5 events/tick, node N-1 sees 0
            rate = max(0, 5 - (i * 5 // n))
            for _ in range(rate):
                event = f"gradient_event_{i}_{step}_{rng.rand_int(1000)}".encode()
                node.seed_token(event)
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "breadth_gradient")


# ---------------------------------------------------------------------------
# SCENARIO: Distributed Breadth vs Benign Bustle
# ---------------------------------------------------------------------------
def breadth_vs_benign_bustle(nodes, topology, rng, seed):
    """Broad weak anomaly mixed with high benign background noise."""
    n = len(nodes)

    for step in range(200):
        for i, node in enumerate(nodes):
            # High benign background (3 tokens/tick)
            for _ in range(3):
                node.seed_token(
                    f"benign_{step}_{i}_{rng.rand_int(10000)}".encode())

            # Distributed anomaly starting at step 80 (1 unique weak token)
            if step >= 80 and step <= 150:
                node.seed_token(
                    f"broad_anomaly_{i}_unique_{step//10}".encode())

        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "breadth_vs_benign_bustle")


# ---------------------------------------------------------------------------
# SCENARIO: Shift-Change Bustle (realism)
# ---------------------------------------------------------------------------
def shift_change_bustle(nodes, topology, rng, seed):
    """All nodes experience a burst of benign tokens then settle.
    Tests false escalation under transient noise."""
    for step in range(200):
        for node in nodes:
            if 40 <= step <= 70:
                # Shift change burst: 8 benign tokens per tick
                for _ in range(8):
                    node.seed_token(
                        f"shift_{step}_{rng.rand_int(50000)}".encode())
            else:
                # Normal: 1-2 benign tokens
                for _ in range(1 + rng.rand_int(2)):
                    node.seed_token(
                        f"normal_{step}_{rng.rand_int(50000)}".encode())
        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "shift_change_bustle")


# ---------------------------------------------------------------------------
# SCENARIO: Partition-Heal (realism)
# ---------------------------------------------------------------------------
def partition_heal(nodes, topology, rng, seed):
    """Wing-gateway topology with intermittent bridge failure."""
    n = len(nodes)
    half = n // 2

    # Find bridge edges (cross-half connections)
    bridge_edges = set()
    for i in range(half):
        for j in topology.get(i, set()):
            if j >= half:
                bridge_edges.add((i, j))
                bridge_edges.add((j, i))

    for step in range(200):
        for i, node in enumerate(nodes):
            node.seed_token(f"obs_{i}_{step}_{rng.rand_int(1000)}".encode())

        # Partition: disable bridge every 50 steps for 20 steps
        partitioned = (step % 50) >= 30

        for i in range(n):
            for j in topology.get(i, set()):
                if i != j and rng.rand_bool(CONTACT_PROB):
                    if partitioned and (i, j) in bridge_edges:
                        continue  # bridge down
                    nodes[i].merge_from(nodes[j])

        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "partition_heal")


# ---------------------------------------------------------------------------
# SCENARIO: Corridor Bottleneck (realism)
# ---------------------------------------------------------------------------
def corridor_bottleneck(nodes, topology, rng, seed):
    """Corridor topology: observations at one end must propagate
    through the chain to reach the other end."""
    n = len(nodes)

    for step in range(200):
        # Only first 4 nodes observe events
        for i in range(min(4, n)):
            nodes[i].seed_token(
                f"source_event_{i}_{step}".encode())

        do_merges(nodes, topology, rng)
        for node in nodes:
            node.evaluate_policy(step)

    return _collect_metrics(nodes, "corridor_bottleneck")


# ---------------------------------------------------------------------------
# Metrics collection
# ---------------------------------------------------------------------------
def _collect_metrics(nodes, scenario_name):
    """Collect enclave-specific metrics from node state."""
    n = len(nodes)
    honest = [nd for nd in nodes if not nd.is_malicious]

    max_zones = [max(nd.zone_history) if nd.zone_history else 0 for nd in honest]
    elevated_count = sum(1 for z in max_zones if z >= 1)
    coordinated_count = sum(1 for z in max_zones if z >= 3)

    first_elevated = [nd.first_elevated_step for nd in honest
                      if nd.first_elevated_step is not None]
    first_coord = [nd.first_coordinated_step for nd in honest
                   if nd.first_coordinated_step is not None]

    total_bytes = sum(nd.bytes_sent + nd.bytes_received for nd in honest)
    total_merges = sum(nd.merges_performed for nd in honest)

    # Saturation stats (for GM nodes; pseudo-sat for others)
    final_sats = [nd.saturation_history[-1] if nd.saturation_history else 0
                  for nd in honest]
    mean_sat = sum(final_sats) / len(final_sats) if final_sats else 0
    max_sat = max(final_sats) if final_sats else 0

    return {
        "scenario": scenario_name,
        "num_nodes": n,
        "elevated_count": elevated_count,
        "elevated_rate": elevated_count / len(honest) if honest else 0,
        "coordinated_count": coordinated_count,
        "time_to_first_elevated": min(first_elevated) if first_elevated else None,
        "time_to_majority_elevated": (
            sorted(first_elevated)[len(first_elevated) // 2]
            if len(first_elevated) > len(honest) // 2 else None),
        "time_to_first_coordinated": min(first_coord) if first_coord else None,
        "total_bytes": total_bytes,
        "bytes_per_node": total_bytes / len(honest) if honest else 0,
        "total_merges": total_merges,
        "merges_per_node": total_merges / len(honest) if honest else 0,
        "mean_final_sat": mean_sat,
        "max_final_sat": max_sat,
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def _aggregate(results_list):
    """Aggregate metrics across seeds/topologies."""
    if not results_list:
        return {}
    agg = {"scenario": results_list[0]["scenario"],
           "n_runs": len(results_list)}
    numeric_keys = [k for k in results_list[0] if k not in ("scenario",)]
    for key in numeric_keys:
        vals = [r[key] for r in results_list if r.get(key) is not None]
        if not vals:
            agg[f"{key}_mean"] = None
            agg[f"{key}_std"] = None
            continue
        if isinstance(vals[0], (int, float)):
            mean = sum(vals) / len(vals)
            std = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals)
                            ) if len(vals) > 1 else 0
            agg[f"{key}_mean"] = mean
            agg[f"{key}_std"] = std
    return agg


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
ALL_SCENARIOS = [
    ("overlap_identical", overlap_identical_event),
    ("overlap_moving", overlap_moving_cluster),
    ("overlap_rebroadcast", overlap_rebroadcast_storm),
    ("breadth_weak", breadth_weak_distributed),
    ("breadth_gradient", breadth_gradient),
    ("breadth_vs_bustle", breadth_vs_benign_bustle),
    ("shift_bustle", shift_change_bustle),
    ("partition_heal", partition_heal),
    ("corridor_bottleneck", corridor_bottleneck),
]


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Cooperative Enclave Bakeoff")
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.join(os.path.dirname(__file__),
                                  "..", "..", "results",
                                  "cooperative_enclave_bakeoff")
    os.makedirs(output_dir, exist_ok=True)

    num_seeds = args.seeds
    total_runs = (len(ALL_SCENARIOS) * len(APPROACHES) *
                  len(TOPOLOGIES) * num_seeds)

    print("=" * 72)
    print("COOPERATIVE ENCLAVE BAKEOFF")
    print("=" * 72)
    print(f"Nodes: {NUM_NODES}  m={BLOOM_M}  k={BLOOM_K}  "
          f"contact={CONTACT_PROB}")
    print(f"Scenarios: {len(ALL_SCENARIOS)}  Approaches: {len(APPROACHES)}  "
          f"Topologies: {len(TOPOLOGIES)}  Seeds: {num_seeds}")
    print(f"Total runs: {total_runs}")
    print()

    start = time.time()
    all_raw = []
    all_agg = []
    run_count = 0

    for scn_name, scn_fn in ALL_SCENARIOS:
        for approach_name, node_class in APPROACHES.items():
            seed_results = []
            for topo_name, topo_fn in TOPOLOGIES.items():
                for seed_idx in range(num_seeds):
                    seed = 70000 + seed_idx * 137
                    result = run_enclave_scenario(
                        scn_fn, approach_name, node_class,
                        topo_name, topo_fn, seed)
                    result["approach"] = approach_name
                    result["topology"] = topo_name
                    result["seed"] = seed
                    result["seed_idx"] = seed_idx
                    all_raw.append(result)
                    seed_results.append(result)
                    run_count += 1

            # Aggregate across seeds and topologies
            agg = _aggregate(seed_results)
            agg["approach"] = approach_name
            all_agg.append(agg)

            er = agg.get("elevated_rate_mean", 0)
            bw = agg.get("bytes_per_node_mean", 0)
            te = agg.get("time_to_first_elevated_mean")
            te_s = f"{te:.0f}" if te is not None else "N/A"
            print(f"  {scn_name:>22s}/{approach_name:<14s}: "
                  f"elev={er:.2f} bw={bw:.0f} t1={te_s}")

        if run_count % 100 == 0:
            print(f"    [{run_count}/{total_runs}] "
                  f"{time.time()-start:.0f}s elapsed")

    elapsed = time.time() - start

    # Write raw results
    write_csv(all_raw, os.path.join(output_dir, "raw_results.csv"))
    write_jsonl(all_raw, os.path.join(output_dir, "raw_results.jsonl"))
    write_csv(all_agg, os.path.join(output_dir, "aggregated_results.csv"))
    write_jsonl(all_agg, os.path.join(output_dir, "aggregated_results.jsonl"))

    # Print comparison tables
    _print_comparison(all_agg)

    # Write summary
    summary = _format_summary(all_agg, elapsed, num_seeds)
    summary_path = os.path.join(output_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write(summary)

    print(f"\nResults: {output_dir}/")
    print(f"Runtime: {elapsed:.1f}s")

    return 0


def _print_comparison(all_agg):
    """Print side-by-side comparison tables."""
    by_scenario = {}
    for a in all_agg:
        scn = a["scenario"]
        if scn not in by_scenario:
            by_scenario[scn] = {}
        by_scenario[scn][a["approach"]] = a

    print(f"\n{'='*90}")
    print("COMPARISON BY SCENARIO")
    print(f"{'='*90}")

    for scn, approaches in by_scenario.items():
        print(f"\n--- {scn} ---")
        print(f"  {'Approach':<16s} {'ElevRate':>9s} {'t1_elev':>8s} "
              f"{'CoordCnt':>9s} {'BW/node':>9s} {'MaxSat%':>8s}")
        for app_name in APPROACHES:
            a = approaches.get(app_name, {})
            er = a.get("elevated_rate_mean", 0)
            te = a.get("time_to_first_elevated_mean")
            cc = a.get("coordinated_count_mean", 0)
            bw = a.get("bytes_per_node_mean", 0)
            ms = a.get("max_final_sat_mean", 0)
            te_s = f"{te:>7.0f}" if te is not None else f"{'N/A':>7s}"
            print(f"  {app_name:<16s} {er:>8.2f} {te_s} "
                  f"{cc:>8.1f} {bw:>8.0f} {ms:>7.1f}%")


def _format_summary(all_agg, elapsed, num_seeds):
    """Format human-readable summary."""
    lines = [
        "COOPERATIVE ENCLAVE BAKEOFF SUMMARY",
        f"Runtime: {elapsed:.1f}s",
        f"Seeds: {num_seeds}, Topologies: {len(TOPOLOGIES)}",
        f"Nodes: {NUM_NODES}, m={BLOOM_M}, k={BLOOM_K}",
        "",
    ]

    by_scenario = {}
    for a in all_agg:
        scn = a["scenario"]
        if scn not in by_scenario:
            by_scenario[scn] = {}
        by_scenario[scn][a["approach"]] = a

    for scn, approaches in by_scenario.items():
        lines.append(f"\n=== {scn} ===")
        for app_name in APPROACHES:
            a = approaches.get(app_name, {})
            er = a.get("elevated_rate_mean", 0)
            bw = a.get("bytes_per_node_mean", 0)
            lines.append(f"  {app_name}: elev_rate={er:.3f} bw={bw:.0f}")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
