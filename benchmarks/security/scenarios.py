"""
scenarios.py
Security threat scenarios for Ghost Meadow benchmarks.

Each scenario function takes a fleet and runs the full simulation,
returning a MetricsCollector with results.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from harness import (Fleet, SecurityNode, LocalOnlyNode, ExactGossipNode,
                     CounterAggNode, SimRNG)
from security_tokens import TokenGenerator
from security_policy import ZONE_COORDINATED
from metrics import MetricsCollector


def _run_generic_scenario(scenario_name, config, node_class, approach_name,
                          seed_offset=0):
    """Generic scenario runner that works for any node class.

    Config keys:
      num_nodes, topology, contact_prob, bloom_m, bloom_k, steps, epoch_length,
      mission_key, policy_variant, quorum_k, trust_mode,
      malicious_node_ids, attack_type, attack_params
    """
    num_nodes = config.get("num_nodes", 8)
    steps = config.get("steps", 500)
    epoch_length = config.get("epoch_length", 200)
    bloom_m = config.get("bloom_m", 4096)
    bloom_k = config.get("bloom_k", 2)
    mission_key = config.get("mission_key", 0xDEADBEEFCAFEBABE)
    topology = config.get("topology", "regional_mesh")
    contact_prob = config.get("contact_prob", 0.4)
    policy_variant = config.get("policy_variant", "composite")
    quorum_k = config.get("quorum_k", 3)
    trust_mode = config.get("trust_mode", "all_equal")
    base_seed = config.get("seed", 20260326) + seed_offset
    corruption_rate = config.get("corruption_rate", 0.0)
    drop_rate = config.get("drop_rate", 0.0)

    malicious_ids = set(config.get("malicious_node_ids", []))
    attack_type = config.get("attack_type", "none")
    attack_params = config.get("attack_params", {})

    fleet = Fleet(
        num_nodes=num_nodes,
        topology_type=topology,
        contact_prob=contact_prob,
        bloom_m=bloom_m,
        bloom_k=bloom_k,
        mission_key=mission_key,
        policy_variant=policy_variant,
        quorum_k=quorum_k,
        trust_mode=trust_mode,
        seed=base_seed,
        node_class=node_class,
        corruption_rate=corruption_rate,
        drop_rate=drop_rate,
    )

    # Mark malicious nodes
    for mid in malicious_ids:
        if mid < len(fleet.nodes):
            fleet.nodes[mid].is_malicious = True

    token_gen = TokenGenerator(base_seed + 1000)
    sim_rng = SimRNG(base_seed + 2000)

    campaign_start = attack_params.get("campaign_start_step", 100)
    campaign_rate = attack_params.get("campaign_token_rate", 8)
    campaign_fraction = attack_params.get("campaign_affected_fraction", 0.6)
    bg_rate = attack_params.get("background_token_rate", 3)
    poison_rate = attack_params.get("poison_token_rate", 50)
    flood_diversity = attack_params.get("flood_diversity", 200)
    sybil_ids = attack_params.get("sybil_identities", 4)

    had_real_attack = attack_type in (
        "distributed_campaign", "replay_stale", "sybil_flood")

    collector = MetricsCollector(scenario_name, approach_name, num_nodes)

    # Determine campaign-affected nodes (honest nodes that see the campaign)
    honest_ids = [i for i in range(num_nodes) if i not in malicious_ids]
    n_affected = max(1, int(len(honest_ids) * campaign_fraction))
    affected_ids = set(honest_ids[:n_affected])

    for step in range(steps):
        fleet.advance_step()

        # Epoch boundary
        if epoch_length > 0 and step > 0 and step % epoch_length == 0:
            fleet.run_decay()

        # --- Seeding phase ---
        for node in fleet.nodes:
            nid = node.node_id

            # Background benign traffic for all honest nodes
            if nid not in malicious_ids:
                for _ in range(bg_rate):
                    if sim_rng.rand_bool(0.6):
                        node.seed_token(token_gen.random_benign_token())
                # Occasional false positive
                if sim_rng.rand_bool(0.05):
                    node.seed_token(token_gen.random_false_positive())

            # Attack-specific seeding
            if attack_type == "distributed_campaign":
                if (step >= campaign_start and nid in affected_ids and
                        nid not in malicious_ids):
                    for _ in range(campaign_rate):
                        tok = token_gen.campaign_token_correlated(
                            campaign_id=1, node_id=nid, step=step)
                        node.seed_token(tok)

            elif attack_type == "poison_flood":
                if nid in malicious_ids:
                    for _ in range(poison_rate):
                        tok = token_gen.poison_token(nid, step)
                        node.seed_token(tok)

            elif attack_type == "coordinated_poison":
                if nid in malicious_ids:
                    for _ in range(poison_rate):
                        tok = token_gen.poison_token(nid, step)
                        node.seed_token(tok)

            elif attack_type == "namespace_flood":
                if nid in malicious_ids:
                    for idx in range(flood_diversity):
                        tok = token_gen.namespace_flood_token(nid, step * flood_diversity + idx)
                        node.seed_token(tok)

            elif attack_type == "replay_stale":
                if nid in malicious_ids:
                    # Replay tokens from earlier in the epoch
                    for s in range(max(0, step - 50), step):
                        tok = token_gen.stale_replay_token(s, step)
                        node.seed_token(tok)

            elif attack_type == "sybil_flood":
                if nid in malicious_ids:
                    # Seed under multiple apparent identities
                    for sid in range(sybil_ids):
                        for _ in range(poison_rate // sybil_ids):
                            tok = token_gen.poison_token(
                                nid * 100 + sid, step)
                            node.seed_token(tok)

        # --- Merge phase ---
        fleet.run_merge_phase()

        # --- Policy phase ---
        fleet.run_policy_phase()

        # --- Record metrics ---
        is_attack_active = (attack_type != "none" and step >= campaign_start)
        collector.record_step(step, fleet.nodes, is_attack_active)

    collector.finalize(
        fleet.nodes,
        had_real_attack=had_real_attack,
        attack_start_step=campaign_start if had_real_attack else None)

    return collector


# ---- Scenario A: Benign Baseline ----
def scenario_A_benign(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260326,
        "attack_type": "none",
        "attack_params": {"background_token_rate": 3},
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("A_benign_baseline", config, node_class, approach)


# ---- Scenario B: Distributed Coordinated Attack ----
def scenario_B_coordinated(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260327,
        "attack_type": "distributed_campaign",
        "attack_params": {
            "campaign_start_step": 100,
            "campaign_token_rate": 8,
            "campaign_affected_fraction": 0.6,
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("B_coordinated_attack", config, node_class, approach)


# ---- Scenario C: Single Malicious Poison Node ----
def scenario_C_single_poison(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260328,
        "malicious_node_ids": [0],
        "attack_type": "poison_flood",
        "attack_params": {
            "poison_token_rate": 50,
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("C_single_poison", config, node_class, approach)


# ---- Scenario D: Multi-Node Collusion ----
def scenario_D_multi_collusion(profile_config, approach="ghost_meadow"):
    num = profile_config.get("num_nodes", 8)
    n_malicious = min(3, num // 3)
    config = {
        "num_nodes": num,
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260329,
        "malicious_node_ids": list(range(n_malicious)),
        "attack_type": "coordinated_poison",
        "attack_params": {
            "poison_token_rate": 30,
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("D_multi_collusion", config, node_class, approach)


# ---- Scenario E: Namespace / Token-Space Flooding ----
def scenario_E_namespace_flood(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260330,
        "malicious_node_ids": [0],
        "attack_type": "namespace_flood",
        "attack_params": {
            "flood_diversity": 200,
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("E_namespace_flood", config, node_class, approach)


# ---- Scenario F: Replay / Stale-Pressure Abuse ----
def scenario_F_replay_stale(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 600,
        "epoch_length": 150,
        "seed": 20260331,
        "malicious_node_ids": [0],
        "attack_type": "replay_stale",
        "attack_params": {
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("F_replay_stale", config, node_class, approach)


# ---- Scenario G: Contact Asymmetry / Partition Abuse ----
def scenario_G_partition(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": "partitioned_clusters",
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260332,
        "attack_type": "distributed_campaign",
        "attack_params": {
            "campaign_start_step": 50,
            "campaign_affected_fraction": 0.3,
            "campaign_token_rate": 8,
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("G_partition_asymmetry", config, node_class, approach)


# ---- Scenario H: Transport Hostility ----
def scenario_H_transport(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260333,
        "corruption_rate": 0.15,
        "drop_rate": 0.30,
        "attack_type": "distributed_campaign",
        "attack_params": {
            "campaign_start_step": 100,
            "campaign_token_rate": 8,
            "campaign_affected_fraction": 0.6,
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("H_transport_hostility", config, node_class, approach)


# ---- Scenario I: Sybil-Like Behavior ----
def scenario_I_sybil(profile_config, approach="ghost_meadow"):
    config = {
        "num_nodes": profile_config.get("num_nodes", 8),
        "topology": profile_config.get("topology", "regional_mesh"),
        "contact_prob": profile_config.get("contact_prob", 0.4),
        "bloom_m": profile_config.get("bloom_m", 4096),
        "bloom_k": profile_config.get("bloom_k", 2),
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260334,
        "malicious_node_ids": [0],
        "attack_type": "sybil_flood",
        "attack_params": {
            "sybil_identities": 4,
            "poison_token_rate": 20,
            "background_token_rate": 3,
        },
    }
    node_class = _approach_to_class(approach)
    return _run_generic_scenario("I_sybil_behavior", config, node_class, approach)


# ---- Helper: map approach name to node class ----
def _approach_to_class(approach):
    return {
        "ghost_meadow": SecurityNode,
        "local_only": LocalOnlyNode,
        "exact_gossip": ExactGossipNode,
        "counter_agg": CounterAggNode,
    }.get(approach, SecurityNode)


# ---- Run all scenarios for all approaches ----
ALL_SCENARIOS = [
    ("A_benign", scenario_A_benign),
    ("B_coordinated", scenario_B_coordinated),
    ("C_single_poison", scenario_C_single_poison),
    ("D_multi_collusion", scenario_D_multi_collusion),
    ("E_namespace_flood", scenario_E_namespace_flood),
    ("F_replay_stale", scenario_F_replay_stale),
    ("G_partition", scenario_G_partition),
    ("H_transport", scenario_H_transport),
    ("I_sybil", scenario_I_sybil),
]

ALL_APPROACHES = ["ghost_meadow", "local_only", "exact_gossip", "counter_agg"]


def run_all(profile_config, approaches=None, scenarios=None):
    """Run all requested scenarios across all requested approaches.

    Returns list of MetricsCollector summary dicts.
    """
    if approaches is None:
        approaches = ALL_APPROACHES
    if scenarios is None:
        scenarios = ALL_SCENARIOS

    summaries = []
    for scn_name, scn_fn in scenarios:
        for approach in approaches:
            print(f"  Running {scn_name} / {approach}...", end=" ", flush=True)
            collector = scn_fn(profile_config, approach)
            summary = collector.summary_dict()
            summaries.append(summary)
            sat = summary["max_saturation_pct"]
            t1 = summary.get("time_to_first_local_suspicion")
            t1_str = str(t1) if t1 is not None else "N/A"
            print(f"maxSat={sat:.1f}% firstLocal={t1_str}")
    return summaries
