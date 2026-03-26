"""
blind_generator.py
Generates held-out evaluation conditions for blind falsification.

Conditions are deterministically generated from a master seed and are
not hand-authored. The generator produces structured randomized
combinations of:
  - seeds
  - topologies
  - token vocabulary shifts
  - traffic regimes
  - contact regimes

The held-out conditions must not overlap with development scenarios.
"""

import json
import os
import struct

# Use the harness PRNG for reproducibility
import sys
sys.path.insert(0, os.path.dirname(__file__))
from harness import SimRNG


# Master held-out seed (not used in any dev scenario)
HELD_OUT_MASTER_SEED = 77777777

# Token vocabulary shift to avoid overlap with dev range (0-1500)
HELD_OUT_VARIANT_BASE = 10000

# Held-out seed range (disjoint from dev range 20260326-20260340)
HELD_OUT_SEED_START = 50000

TOPOLOGIES = ["ring", "star_sparse", "regional_mesh",
              "partitioned_clusters", "full_mesh"]

CONTACT_PROBS = [0.15, 0.4, 0.7]

EPOCH_LENGTHS = [100, 200, 300]

TRAFFIC_REGIMES = [
    {"name": "benign_heavy", "attack_type": "none",
     "attack_params": {"background_token_rate": 5}},
    {"name": "coordinated_bursty", "attack_type": "distributed_campaign",
     "attack_params": {"campaign_start_step": 80, "campaign_token_rate": 12,
                       "campaign_affected_fraction": 0.7,
                       "background_token_rate": 3}},
    {"name": "low_and_slow", "attack_type": "distributed_campaign",
     "attack_params": {"campaign_start_step": 50, "campaign_token_rate": 2,
                       "campaign_affected_fraction": 0.4,
                       "background_token_rate": 3}},
    {"name": "poison_heavy", "attack_type": "poison_flood",
     "malicious_node_ids": [0],
     "attack_params": {"poison_token_rate": 80, "background_token_rate": 3}},
    {"name": "collusion_3", "attack_type": "coordinated_poison",
     "malicious_node_ids": [0, 1, 2],
     "attack_params": {"poison_token_rate": 30, "background_token_rate": 3}},
    {"name": "namespace_flood", "attack_type": "namespace_flood",
     "malicious_node_ids": [0],
     "attack_params": {"flood_diversity": 200, "background_token_rate": 3}},
    {"name": "stale_replay", "attack_type": "replay_stale",
     "malicious_node_ids": [0],
     "attack_params": {"background_token_rate": 3}},
]

FILTER_PROFILES = [
    {"name": "negative_control_4096", "m": 4096, "k": 2},
    {"name": "good_regime_32768", "m": 32768, "k": 7},
    {"name": "good_regime_192000", "m": 192000, "k": 13},
]


def generate_conditions(num_seeds=10, output_dir=None):
    """Generate the full held-out condition matrix.

    Returns list of condition dicts and optionally writes to disk.
    """
    rng = SimRNG(HELD_OUT_MASTER_SEED)
    conditions = []
    condition_id = 0

    for seed_idx in range(num_seeds):
        seed = HELD_OUT_SEED_START + seed_idx * 137  # deterministic, spaced

        for profile in FILTER_PROFILES:
            # Select a subset of traffic regimes per seed to keep matrix bounded
            # Each seed gets all traffic regimes
            for traffic in TRAFFIC_REGIMES:
                # Rotate topology and contact_prob deterministically
                topo_idx = (seed_idx + condition_id) % len(TOPOLOGIES)
                cp_idx = (seed_idx * 3 + condition_id) % len(CONTACT_PROBS)
                ep_idx = (seed_idx * 7 + condition_id) % len(EPOCH_LENGTHS)

                topology = TOPOLOGIES[topo_idx]
                contact_prob = CONTACT_PROBS[cp_idx]
                epoch_length = EPOCH_LENGTHS[ep_idx]

                has_real_attack = traffic["attack_type"] not in ("none",)

                condition = {
                    "condition_id": condition_id,
                    "seed": seed,
                    "seed_idx": seed_idx,
                    "profile_name": profile["name"],
                    "m": profile["m"],
                    "k": profile["k"],
                    "num_nodes": 12,
                    "topology": topology,
                    "contact_prob": contact_prob,
                    "epoch_length": epoch_length,
                    "steps": 500,
                    "traffic_regime": traffic["name"],
                    "attack_type": traffic["attack_type"],
                    "attack_params": traffic["attack_params"],
                    "malicious_node_ids": traffic.get("malicious_node_ids", []),
                    "has_real_attack": has_real_attack,
                    "variant_base": HELD_OUT_VARIANT_BASE,
                    "policy_variant": "composite",
                    "quorum_k": 3,
                    "trust_mode": "all_equal",
                }
                conditions.append(condition)
                condition_id += 1

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "held_out_conditions.json")
        with open(path, "w") as f:
            json.dump({"num_conditions": len(conditions),
                       "master_seed": HELD_OUT_MASTER_SEED,
                       "conditions": conditions}, f, indent=2)
        print(f"  Generated {len(conditions)} conditions -> {path}")

    return conditions


def condition_to_scenario_config(cond):
    """Convert a held-out condition to a scenario config dict
    compatible with _run_generic_scenario."""
    config = {
        "num_nodes": cond["num_nodes"],
        "topology": cond["topology"],
        "contact_prob": cond["contact_prob"],
        "bloom_m": cond["m"],
        "bloom_k": cond["k"],
        "steps": cond["steps"],
        "epoch_length": cond["epoch_length"],
        "seed": cond["seed"],
        "policy_variant": cond["policy_variant"],
        "quorum_k": cond["quorum_k"],
        "trust_mode": cond["trust_mode"],
        "attack_type": cond["attack_type"],
        "attack_params": cond["attack_params"],
        "malicious_node_ids": cond.get("malicious_node_ids", []),
    }
    return config


if __name__ == "__main__":
    conditions = generate_conditions(
        num_seeds=10,
        output_dir=os.path.join(os.path.dirname(__file__),
                                "..", "..", "results", "security", "blind",
                                "generated_conditions"))
    # Summary
    profiles = {}
    traffic = {}
    for c in conditions:
        profiles[c["profile_name"]] = profiles.get(c["profile_name"], 0) + 1
        traffic[c["traffic_regime"]] = traffic.get(c["traffic_regime"], 0) + 1
    print(f"\n  Total conditions: {len(conditions)}")
    print(f"  By profile: {profiles}")
    print(f"  By traffic: {traffic}")
