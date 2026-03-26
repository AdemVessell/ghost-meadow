#!/usr/bin/env python3
"""
run_stage2_bench.py
Stage 2 security evaluation — proving or falsifying the good regime.

Extends the stage 1 suite with:
  1. Standard (m=32768) and Full (m=192000) profile benchmarks
  2. Multi-seed sensitivity analysis
  3. Direct Layer A FP/FN measurement
  4. Filter-size sweep / viability frontier
  5. Policy ablation in good regimes
  6. Trust model validation across regimes
  7. Strengthened baselines

Usage:
  python3 benchmarks/security/run_stage2_bench.py [--phase PHASE] [--seeds N]

Phases: all, good_regime, seed_sweep, layer_a, size_sweep, policy, trust
"""

import sys
import os
import json
import time
import argparse
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ghost_meadow import GhostMeadow
from harness import (Fleet, SecurityNode, LocalOnlyNode, ExactGossipNode,
                     CounterAggNode, SimRNG)
from security_tokens import TokenGenerator, ALL_CATEGORIES, SUBCATEGORIES
from security_policy import (SecurityPolicy, TrustModel, TRUST_FULL,
                             TRUST_SEMI, TRUST_UNTRUSTED,
                             ZONE_NOMINAL, ZONE_ELEVATED, ZONE_COORDINATED,
                             ZONE_CONTAINMENT, ZONE_NAMES)
from scenarios import (_run_generic_scenario, scenario_A_benign,
                       scenario_B_coordinated, scenario_C_single_poison,
                       scenario_E_namespace_flood,
                       ALL_SCENARIOS, ALL_APPROACHES,
                       _approach_to_class)
from metrics import MetricsCollector, write_csv, write_jsonl


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def _make_profile(num_nodes, topology, contact_prob, bloom_m, bloom_k):
    return {"num_nodes": num_nodes, "topology": topology,
            "contact_prob": contact_prob, "bloom_m": bloom_m,
            "bloom_k": bloom_k}


def _optimal_k(m, n_target):
    """Optimal k for Bloom filter: k = (m/n) * ln(2)."""
    if n_target <= 0:
        return 2
    k = max(1, int(round((m / n_target) * 0.6931)))
    return min(k, 20)  # cap at 20


# ---------------------------------------------------------------------------
# PHASE 2: Good-regime benchmarks (m=32768 and m=192000)
# ---------------------------------------------------------------------------
def run_good_regime(output_dir, num_seeds=1):
    """Run core scenarios at standard and full profiles."""
    print("\n" + "=" * 72)
    print("PHASE 2: GOOD REGIME BENCHMARKS")
    print("=" * 72)

    profiles = {
        "micro_4096": _make_profile(12, "regional_mesh", 0.4, 4096, 2),
        "standard_32768": _make_profile(12, "regional_mesh", 0.4, 32768, 7),
        "full_192000": _make_profile(12, "regional_mesh", 0.4, 192000, 13),
    }

    # Focus on the scenarios that matter most for the thesis
    key_scenarios = [
        ("A_benign", scenario_A_benign),
        ("B_coordinated", scenario_B_coordinated),
        ("C_single_poison", scenario_C_single_poison),
        ("E_namespace_flood", scenario_E_namespace_flood),
    ]

    approaches = ["ghost_meadow", "local_only", "exact_gossip"]
    all_summaries = []

    for pname, pcfg in profiles.items():
        print(f"\n--- Profile: {pname} (m={pcfg['bloom_m']}, k={pcfg['bloom_k']}) ---")
        for scn_name, scn_fn in key_scenarios:
            for approach in approaches:
                results_across_seeds = []
                for seed_idx in range(num_seeds):
                    # Use seed_offset to vary across seeds
                    collector = scn_fn(pcfg, approach)
                    if num_seeds > 1:
                        # Re-run with offset seed via generic runner
                        config = _scenario_config(scn_name, pcfg, seed_idx)
                        node_class = _approach_to_class(approach)
                        collector = _run_generic_scenario(
                            scn_name, config, node_class, approach,
                            seed_offset=seed_idx * 1000)
                    s = collector.summary_dict()
                    s["profile"] = pname
                    s["seed_idx"] = seed_idx
                    results_across_seeds.append(s)

                if num_seeds == 1:
                    all_summaries.append(results_across_seeds[0])
                    sat = results_across_seeds[0]["max_saturation_pct"]
                    t1 = results_across_seeds[0].get("time_to_first_local_suspicion")
                    print(f"  {scn_name}/{approach}: maxSat={sat:.1f}% "
                          f"t1={t1 if t1 else 'N/A'}")
                else:
                    agg = _aggregate_seeds(results_across_seeds)
                    agg["profile"] = pname
                    all_summaries.append(agg)
                    print(f"  {scn_name}/{approach}: "
                          f"maxSat={agg['max_saturation_pct_mean']:.1f}±"
                          f"{agg['max_saturation_pct_std']:.1f}%")

    _write_results(all_summaries, output_dir, "good_regime")
    return all_summaries


def _scenario_config(scn_name, profile_config, seed_idx=0):
    """Build config dict for a named scenario + profile."""
    base = {
        "num_nodes": profile_config["num_nodes"],
        "topology": profile_config["topology"],
        "contact_prob": profile_config["contact_prob"],
        "bloom_m": profile_config["bloom_m"],
        "bloom_k": profile_config["bloom_k"],
        "steps": 500,
        "epoch_length": 200,
        "seed": 20260326 + seed_idx * 1000,
    }
    scenario_specifics = {
        "A_benign": {"attack_type": "none",
                     "attack_params": {"background_token_rate": 3}},
        "B_coordinated": {
            "attack_type": "distributed_campaign",
            "seed": 20260327 + seed_idx * 1000,
            "attack_params": {
                "campaign_start_step": 100, "campaign_token_rate": 8,
                "campaign_affected_fraction": 0.6, "background_token_rate": 3}},
        "C_single_poison": {
            "seed": 20260328 + seed_idx * 1000,
            "malicious_node_ids": [0],
            "attack_type": "poison_flood",
            "attack_params": {"poison_token_rate": 50, "background_token_rate": 3}},
        "E_namespace_flood": {
            "seed": 20260330 + seed_idx * 1000,
            "malicious_node_ids": [0],
            "attack_type": "namespace_flood",
            "attack_params": {"flood_diversity": 200, "background_token_rate": 3}},
    }
    base.update(scenario_specifics.get(scn_name, {}))
    return base


# ---------------------------------------------------------------------------
# PHASE 3: Multi-seed sensitivity analysis
# ---------------------------------------------------------------------------
def run_seed_sweep(output_dir, num_seeds=10):
    """Run key scenarios across multiple seeds to test stability."""
    print("\n" + "=" * 72)
    print(f"PHASE 3: MULTI-SEED SENSITIVITY ({num_seeds} seeds)")
    print("=" * 72)

    profiles = {
        "micro_4096": _make_profile(12, "regional_mesh", 0.4, 4096, 2),
        "standard_32768": _make_profile(12, "regional_mesh", 0.4, 32768, 7),
    }

    key_scenarios = [
        ("A_benign", scenario_A_benign),
        ("B_coordinated", scenario_B_coordinated),
        ("C_single_poison", scenario_C_single_poison),
    ]

    all_agg = []

    for pname, pcfg in profiles.items():
        print(f"\n--- Profile: {pname} ---")
        for scn_name, scn_fn in key_scenarios:
            for approach in ["ghost_meadow", "local_only"]:
                seed_results = []
                for seed_idx in range(num_seeds):
                    config = _scenario_config(scn_name, pcfg, seed_idx)
                    node_class = _approach_to_class(approach)
                    collector = _run_generic_scenario(
                        scn_name, config, node_class, approach,
                        seed_offset=seed_idx * 1000)
                    s = collector.summary_dict()
                    s["profile"] = pname
                    s["seed_idx"] = seed_idx
                    seed_results.append(s)

                agg = _aggregate_seeds(seed_results)
                agg["profile"] = pname
                all_agg.append(agg)

                t1_m = agg.get("time_to_first_local_suspicion_mean")
                t1_s = agg.get("time_to_first_local_suspicion_std", 0)
                sat_m = agg["max_saturation_pct_mean"]
                sat_s = agg["max_saturation_pct_std"]
                print(f"  {scn_name}/{approach}: "
                      f"t1={t1_m:.1f}±{t1_s:.1f} "
                      f"sat={sat_m:.1f}±{sat_s:.1f}%")

    _write_results(all_agg, output_dir, "seed_sweep")
    return all_agg


def _aggregate_seeds(results):
    """Aggregate summary dicts across seeds into mean/std/min/max."""
    if not results:
        return {}
    agg = {"scenario": results[0]["scenario"],
           "approach": results[0]["approach"],
           "num_nodes": results[0]["num_nodes"],
           "num_seeds": len(results)}

    numeric_keys = [
        "time_to_first_local_suspicion", "time_to_median_local_suspicion",
        "time_to_first_regional_coord", "time_to_fleet_awareness",
        "false_escalation_count", "true_coord_hits", "missed_coord_attacks",
        "stale_pressure_events", "total_bytes", "total_merges",
        "bytes_per_node", "max_saturation_pct", "steps_in_harmful_saturation",
        "final_saturation_variance", "degradation_under_malicious",
    ]
    for key in numeric_keys:
        vals = [r[key] for r in results if r.get(key) is not None]
        if vals:
            mean_v = sum(vals) / len(vals)
            std_v = math.sqrt(sum((v - mean_v) ** 2 for v in vals) / len(vals)
                              ) if len(vals) > 1 else 0.0
            agg[f"{key}_mean"] = mean_v
            agg[f"{key}_std"] = std_v
            agg[f"{key}_min"] = min(vals)
            agg[f"{key}_max"] = max(vals)
        else:
            agg[f"{key}_mean"] = None
            agg[f"{key}_std"] = None
            agg[f"{key}_min"] = None
            agg[f"{key}_max"] = None
    return agg


# ---------------------------------------------------------------------------
# PHASE 4: Direct Layer A FP/FN measurement
# ---------------------------------------------------------------------------
def run_layer_a_measurement(output_dir):
    """Measure raw Bloom filter FP/FN rates under security-token workloads."""
    print("\n" + "=" * 72)
    print("PHASE 4: DIRECT LAYER A FP/FN MEASUREMENT")
    print("=" * 72)

    filter_sizes = [
        (512, 2), (1024, 2), (4096, 2), (8192, 3),
        (32768, 7), (65536, 9), (192000, 13),
    ]

    results = []
    mission_key = 0xDEADBEEFCAFEBABE
    rng = SimRNG(20260326)
    tgen = TokenGenerator(20260326)

    for m, k in filter_sizes:
        print(f"\n  --- m={m}, k={k} ---")

        # Create a single node and seed security tokens
        meadow = GhostMeadow(mission_key, 0, m=m, k=k)

        # Ground truth: track which tokens were actually seeded
        seeded_tokens = set()
        never_seeded = []

        # Phase A: Seed a realistic workload (200 steps of background)
        for step in range(200):
            for _ in range(3):  # background rate
                tok = tgen.random_benign_token()
                meadow.seed(tok)
                seeded_tokens.add(tok)

        sat_after_benign = meadow.saturation_pct()

        # Generate never-seeded tokens for FP testing
        tgen_fp = TokenGenerator(99999)
        for _ in range(2000):
            tok = tgen_fp.random_benign_token()
            if tok not in seeded_tokens:
                never_seeded.append(tok)
            if len(never_seeded) >= 1000:
                break

        # Measure FP rate (benign-only)
        fp_count_benign = sum(1 for t in never_seeded if meadow.query(t))
        fp_rate_benign = fp_count_benign / len(never_seeded)

        # Measure FN rate (should be 0 within epoch)
        fn_count = 0
        seeded_list = list(seeded_tokens)[:500]
        for t in seeded_list:
            if not meadow.query(t):
                fn_count += 1
        fn_rate = fn_count / len(seeded_list) if seeded_list else 0

        print(f"    After 200 benign steps: sat={sat_after_benign:.2f}% "
              f"FP={fp_rate_benign:.4f} FN={fn_rate:.4f}")

        # Phase B: Add attack tokens (campaign)
        campaign_tokens = set()
        for step in range(200, 300):
            for _ in range(8):
                tok = tgen.campaign_token_correlated(1, 0, step)
                meadow.seed(tok)
                campaign_tokens.add(tok)

        sat_after_attack = meadow.saturation_pct()

        # FP rate after attack
        fp_count_attack = sum(1 for t in never_seeded if meadow.query(t))
        fp_rate_attack = fp_count_attack / len(never_seeded)

        # Can we still distinguish campaign tokens?
        campaign_list = list(campaign_tokens)[:200]
        campaign_hit = sum(1 for t in campaign_list if meadow.query(t))
        campaign_recall = campaign_hit / len(campaign_list) if campaign_list else 0

        print(f"    After attack phase: sat={sat_after_attack:.2f}% "
              f"FP={fp_rate_attack:.4f} campaign_recall={campaign_recall:.4f}")

        # Phase C: Merge from another node (simulates fleet)
        other = GhostMeadow(mission_key, 1, m=m, k=k)
        for step in range(200):
            for _ in range(3):
                other.seed(tgen.random_benign_token())
        meadow.merge_raw(other.raw_bits(), 1)

        sat_after_merge = meadow.saturation_pct()
        fp_count_merged = sum(1 for t in never_seeded if meadow.query(t))
        fp_rate_merged = fp_count_merged / len(never_seeded)

        # Campaign recall after merge
        campaign_hit_merged = sum(
            1 for t in campaign_list if meadow.query(t))
        campaign_recall_merged = (campaign_hit_merged / len(campaign_list)
                                  if campaign_list else 0)

        print(f"    After merge: sat={sat_after_merge:.2f}% "
              f"FP={fp_rate_merged:.4f} "
              f"campaign_recall={campaign_recall_merged:.4f}")

        # Phase D: Epoch boundary
        meadow.decay()
        sat_after_decay = meadow.saturation_pct()

        # After decay, all tokens should be false negatives (epoch isolation)
        fn_after_decay = sum(1 for t in seeded_list if meadow.query(t))
        fn_rate_decay = fn_after_decay / len(seeded_list) if seeded_list else 0

        print(f"    After decay: sat={sat_after_decay:.2f}% "
              f"epoch_isolation_violation={fn_rate_decay:.4f}")

        # Theoretical FP rate for comparison
        n_seeded_approx = len(seeded_tokens)
        theo_fp = (1.0 - math.exp(-k * n_seeded_approx / m)) ** k

        results.append({
            "m": m, "k": k,
            "sat_benign_pct": sat_after_benign,
            "sat_attack_pct": sat_after_attack,
            "sat_merged_pct": sat_after_merge,
            "sat_decay_pct": sat_after_decay,
            "fp_rate_benign": fp_rate_benign,
            "fp_rate_attack": fp_rate_attack,
            "fp_rate_merged": fp_rate_merged,
            "fn_rate_within_epoch": fn_rate,
            "fn_rate_after_decay": fn_rate_decay,
            "campaign_recall_local": campaign_recall,
            "campaign_recall_merged": campaign_recall_merged,
            "theoretical_fp": theo_fp,
            "tokens_seeded": len(seeded_tokens),
            "separability": sat_after_attack - sat_after_benign,
        })

    _write_results(results, output_dir, "layer_a_measurement")
    _print_layer_a_table(results)
    return results


def _print_layer_a_table(results):
    """Pretty-print Layer A measurement results."""
    print(f"\n{'='*90}")
    print("LAYER A ERROR RATES BY FILTER SIZE")
    print(f"{'='*90}")
    print(f"  {'m':>8s} {'k':>3s} {'sat_ben%':>9s} {'sat_atk%':>9s} "
          f"{'sat_mrg%':>9s} {'FP_ben':>8s} {'FP_mrg':>8s} "
          f"{'recall':>7s} {'separ':>6s}")
    for r in results:
        print(f"  {r['m']:>8d} {r['k']:>3d} "
              f"{r['sat_benign_pct']:>8.2f}% "
              f"{r['sat_attack_pct']:>8.2f}% "
              f"{r['sat_merged_pct']:>8.2f}% "
              f"{r['fp_rate_benign']:>8.4f} "
              f"{r['fp_rate_merged']:>8.4f} "
              f"{r['campaign_recall_merged']:>6.3f} "
              f"{r['separability']:>5.1f}%")


# ---------------------------------------------------------------------------
# PHASE 5: Filter-size sweep / viability frontier
# ---------------------------------------------------------------------------
def run_size_sweep(output_dir):
    """Sweep filter sizes from 512 to 192000 on key scenarios."""
    print("\n" + "=" * 72)
    print("PHASE 5: FILTER-SIZE SWEEP / VIABILITY FRONTIER")
    print("=" * 72)

    sweep_sizes = [
        (512, 2), (1024, 2), (2048, 2), (4096, 2),
        (8192, 3), (16384, 5), (32768, 7), (65536, 9),
        (192000, 13),
    ]

    # Run benign + coordinated attack for each size, GM vs local-only
    scenarios_to_run = [
        ("A_benign", scenario_A_benign),
        ("B_coordinated", scenario_B_coordinated),
        ("C_single_poison", scenario_C_single_poison),
    ]

    all_results = []

    for m, k in sweep_sizes:
        profile = _make_profile(12, "regional_mesh", 0.4, m, k)
        print(f"\n  --- m={m}, k={k} ---")

        for scn_name, scn_fn in scenarios_to_run:
            for approach in ["ghost_meadow", "local_only"]:
                config = _scenario_config(scn_name, profile)
                node_class = _approach_to_class(approach)
                collector = _run_generic_scenario(
                    scn_name, config, node_class, approach)
                s = collector.summary_dict()
                s["m"] = m
                s["k"] = k
                all_results.append(s)

                sat = s["max_saturation_pct"]
                t1 = s.get("time_to_first_local_suspicion")
                t1s = str(t1) if t1 else "N/A"
                fe = s.get("false_escalation_count", 0)
                print(f"    {scn_name}/{approach}: "
                      f"sat={sat:.1f}% t1={t1s} fe={fe}")

    _write_results(all_results, output_dir, "size_sweep")
    _print_viability_frontier(all_results)
    return all_results


def _print_viability_frontier(results):
    """Print the viability frontier table."""
    print(f"\n{'='*90}")
    print("VIABILITY FRONTIER: GM vs Local-Only by Filter Size")
    print(f"{'='*90}")

    # Group by m and scenario
    by_m = {}
    for r in results:
        m = r.get("m", 0)
        if m not in by_m:
            by_m[m] = {}
        key = (r["scenario"], r["approach"])
        by_m[m][key] = r

    print(f"  {'m':>8s} | {'Benign sat%':>12s} | "
          f"{'Attack sat%':>12s} | {'Separability':>12s} | "
          f"{'GM t1':>6s} {'Lo t1':>6s} | "
          f"{'GM fe':>5s} {'Lo fe':>5s} | {'BW/node':>8s}")
    print(f"  {'-'*88}")

    for m in sorted(by_m.keys()):
        data = by_m[m]
        gm_ben = data.get(("A_benign", "ghost_meadow"), {})
        gm_atk = data.get(("B_coordinated", "ghost_meadow"), {})
        lo_atk = data.get(("B_coordinated", "local_only"), {})

        ben_sat = gm_ben.get("max_saturation_pct", 0)
        atk_sat = gm_atk.get("max_saturation_pct", 0)
        sep = atk_sat - ben_sat
        gm_t1 = gm_atk.get("time_to_first_local_suspicion")
        lo_t1 = lo_atk.get("time_to_first_local_suspicion")
        gm_fe = gm_atk.get("false_escalation_count", 0)
        lo_fe = lo_atk.get("false_escalation_count", 0)
        bw = gm_atk.get("bytes_per_node", 0)

        gm_t1s = f"{gm_t1:>6d}" if gm_t1 is not None else f"{'N/A':>6s}"
        lo_t1s = f"{lo_t1:>6d}" if lo_t1 is not None else f"{'N/A':>6s}"

        print(f"  {m:>8d} | {ben_sat:>11.1f}% | {atk_sat:>11.1f}% | "
              f"{sep:>+11.1f}% | "
              f"{gm_t1s} {lo_t1s} | {gm_fe:>5d} {lo_fe:>5d} | {bw:>8.0f}")


# ---------------------------------------------------------------------------
# PHASE 6: Policy ablation in good regime
# ---------------------------------------------------------------------------
def run_policy_ablation_regimes(output_dir):
    """Run policy variants across bad/promising/strong regimes."""
    print("\n" + "=" * 72)
    print("PHASE 6: POLICY ABLATION ACROSS REGIMES")
    print("=" * 72)

    regimes = {
        "bad_4096": _make_profile(12, "regional_mesh", 0.4, 4096, 2),
        "promising_32768": _make_profile(12, "regional_mesh", 0.4, 32768, 7),
        "strong_192000": _make_profile(12, "regional_mesh", 0.4, 192000, 13),
    }

    variants = ["basic", "quorum_gated", "trust_weighted",
                "delta_sensitive", "anti_stale", "composite"]

    # Test on coordinated attack and single poison
    test_scenarios = [
        ("B_coordinated", "distributed_campaign",
         {"campaign_start_step": 100, "campaign_token_rate": 8,
          "campaign_affected_fraction": 0.6, "background_token_rate": 3}),
        ("C_single_poison", "poison_flood",
         {"poison_token_rate": 50, "background_token_rate": 3}),
    ]

    all_results = []

    for regime_name, pcfg in regimes.items():
        print(f"\n--- Regime: {regime_name} (m={pcfg['bloom_m']}) ---")

        for scn_name, atk_type, atk_params in test_scenarios:
            for variant in variants:
                config = {
                    "num_nodes": pcfg["num_nodes"],
                    "topology": pcfg["topology"],
                    "contact_prob": pcfg["contact_prob"],
                    "bloom_m": pcfg["bloom_m"],
                    "bloom_k": pcfg["bloom_k"],
                    "steps": 500, "epoch_length": 200,
                    "seed": 20260327 if "coord" in scn_name else 20260328,
                    "policy_variant": variant,
                    "attack_type": atk_type,
                    "attack_params": atk_params,
                }
                if "poison" in scn_name:
                    config["malicious_node_ids"] = [0]

                approach_name = f"gm_{variant}"
                collector = _run_generic_scenario(
                    scn_name, config, SecurityNode, approach_name)
                s = collector.summary_dict()
                s["regime"] = regime_name
                s["m"] = pcfg["bloom_m"]
                s["policy_variant"] = variant
                all_results.append(s)

                t1 = s.get("time_to_first_local_suspicion")
                fe = s["false_escalation_count"]
                sat = s["max_saturation_pct"]
                print(f"  {scn_name}/{variant}: t1={t1} fe={fe} sat={sat:.1f}%")

    _write_results(all_results, output_dir, "policy_ablation_regimes")
    return all_results


# ---------------------------------------------------------------------------
# PHASE 7: Trust model validation
# ---------------------------------------------------------------------------
def run_trust_validation(output_dir):
    """Run trust-mode comparisons under multiple scenarios and regimes."""
    print("\n" + "=" * 72)
    print("PHASE 7: TRUST MODEL VALIDATION")
    print("=" * 72)

    regimes = {
        "micro_4096": _make_profile(12, "regional_mesh", 0.4, 4096, 2),
        "standard_32768": _make_profile(12, "regional_mesh", 0.4, 32768, 7),
    }

    trust_modes = ["all_equal", "tiered", "single_untrusted"]

    test_scenarios = [
        ("A_benign", "none", {}, []),
        ("C_single_poison", "poison_flood",
         {"poison_token_rate": 50, "background_token_rate": 3}, [0]),
        ("D_multi_collusion", "coordinated_poison",
         {"poison_token_rate": 30, "background_token_rate": 3}, [0, 1, 2]),
        ("E_namespace_flood", "namespace_flood",
         {"flood_diversity": 200, "background_token_rate": 3}, [0]),
    ]

    all_results = []

    for regime_name, pcfg in regimes.items():
        print(f"\n--- Regime: {regime_name} ---")

        for scn_name, atk_type, atk_params, mal_ids in test_scenarios:
            for tmode in trust_modes:
                config = {
                    "num_nodes": pcfg["num_nodes"],
                    "topology": pcfg["topology"],
                    "contact_prob": pcfg["contact_prob"],
                    "bloom_m": pcfg["bloom_m"],
                    "bloom_k": pcfg["bloom_k"],
                    "steps": 500, "epoch_length": 200,
                    "seed": 20260328,
                    "trust_mode": tmode,
                    "policy_variant": "composite",
                    "attack_type": atk_type,
                    "attack_params": atk_params,
                    "malicious_node_ids": mal_ids,
                }
                approach_name = f"trust_{tmode}"
                collector = _run_generic_scenario(
                    scn_name, config, SecurityNode, approach_name)
                s = collector.summary_dict()
                s["regime"] = regime_name
                s["m"] = pcfg["bloom_m"]
                s["trust_mode"] = tmode
                all_results.append(s)

                t1 = s.get("time_to_first_local_suspicion")
                fe = s["false_escalation_count"]
                sat = s["max_saturation_pct"]
                print(f"  {scn_name}/{tmode}: t1={t1} fe={fe} sat={sat:.1f}%")

    _write_results(all_results, output_dir, "trust_validation")
    return all_results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def _write_results(results, output_dir, prefix):
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, f"{prefix}.csv")
    jsonl_path = os.path.join(output_dir, f"{prefix}.jsonl")
    write_csv(results, csv_path)
    write_jsonl(results, jsonl_path)
    print(f"\n  Written: {csv_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Ghost Meadow Stage 2 Security Evaluation")
    parser.add_argument("--phase", default="all",
                        choices=["all", "good_regime", "seed_sweep",
                                 "layer_a", "size_sweep", "policy", "trust"],
                        help="Which phase to run")
    parser.add_argument("--seeds", type=int, default=5,
                        help="Number of seeds for sweep (default 5)")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory")
    args = parser.parse_args()

    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.join(os.path.dirname(__file__),
                                  "..", "..", "results", "security", "stage2")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 72)
    print("GHOST MEADOW STAGE 2 SECURITY EVALUATION")
    print("=" * 72)

    start = time.time()
    all_outputs = {}

    phases = {
        "good_regime": lambda: run_good_regime(output_dir),
        "seed_sweep": lambda: run_seed_sweep(output_dir, args.seeds),
        "layer_a": lambda: run_layer_a_measurement(output_dir),
        "size_sweep": lambda: run_size_sweep(output_dir),
        "policy": lambda: run_policy_ablation_regimes(output_dir),
        "trust": lambda: run_trust_validation(output_dir),
    }

    if args.phase == "all":
        for name, fn in phases.items():
            all_outputs[name] = fn()
    else:
        all_outputs[args.phase] = phases[args.phase]()

    elapsed = time.time() - start
    print(f"\n{'='*72}")
    print(f"Stage 2 complete. Runtime: {elapsed:.1f}s")
    print(f"Results in: {output_dir}")
    print(f"{'='*72}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
