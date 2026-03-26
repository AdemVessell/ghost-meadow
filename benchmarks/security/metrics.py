"""
metrics.py
Metrics collection and reporting for Ghost Meadow security benchmarks.

Collects detection timing, quality, efficiency, robustness, and saturation
metrics across scenario runs. Outputs CSV and human-readable summaries.
"""

import csv
import io
import json

from security_policy import ZONE_NAMES, ZONE_COORDINATED, ZONE_CONTAINMENT, ZONE_ELEVATED


class MetricsCollector:
    """Collects metrics from a single scenario run."""

    def __init__(self, scenario_name, approach_name, num_nodes):
        self.scenario_name = scenario_name
        self.approach_name = approach_name
        self.num_nodes = num_nodes

        # Detection timing
        self.first_local_suspicion_steps = []  # per honest node
        self.first_regional_coord_steps = []
        self.first_fleet_awareness_step = None

        # Quality
        self.false_escalation_count = 0
        self.true_coord_hits = 0
        self.missed_coord_attacks = 0
        self.stale_pressure_events = 0
        self.poison_amplification_samples = []

        # Efficiency
        self.total_bytes = 0
        self.total_merges = 0
        self.node_bytes = []  # per-node bytes

        # Robustness
        self.degradation_under_malicious = 0.0

        # Saturation
        self.saturation_timeseries = []  # list of (step, mean_sat, var_sat)
        self.max_saturation_seen = 0.0
        self.steps_in_harmful_saturation = 0  # sat > 80%

        # Zone distribution over time
        self.zone_timeseries = []  # list of (step, zone_dist_dict)

        # Raw node data for detailed analysis
        self.node_metrics = []

    def record_step(self, step, nodes, is_attack_active=False,
                    campaign_tokens=None):
        """Record metrics for one simulation step."""
        honest_sats = []
        zones = {z: 0 for z in range(5)}

        for node in nodes:
            if node.is_malicious:
                continue
            if node.saturation_history:
                sat = node.saturation_history[-1]
                honest_sats.append(sat)
            if node.zone_history:
                z = node.zone_history[-1]
                zones[z] = zones.get(z, 0) + 1

        if honest_sats:
            mean_sat = sum(honest_sats) / len(honest_sats)
            var_sat = (sum((s - mean_sat) ** 2 for s in honest_sats)
                       / len(honest_sats))
            self.saturation_timeseries.append((step, mean_sat, var_sat))
            self.max_saturation_seen = max(self.max_saturation_seen, mean_sat)
            if mean_sat > 80.0:
                self.steps_in_harmful_saturation += 1

        self.zone_timeseries.append((step, dict(zones)))

    def finalize(self, nodes, had_real_attack=False,
                 attack_start_step=None):
        """Compute final metrics from node data."""
        honest_nodes = [n for n in nodes if not n.is_malicious]

        for node in honest_nodes:
            self.total_bytes += node.bytes_sent + node.bytes_received
            self.total_merges += node.merges_performed
            self.node_bytes.append(node.bytes_sent + node.bytes_received)

            # Detection timing
            if node.first_elevated_step is not None:
                self.first_local_suspicion_steps.append(
                    node.first_elevated_step)
            if node.first_coordinated_step is not None:
                self.first_regional_coord_steps.append(
                    node.first_coordinated_step)

        # Fleet-wide awareness: when did majority of honest nodes reach elevated?
        if self.first_local_suspicion_steps:
            sorted_steps = sorted(self.first_local_suspicion_steps)
            majority_idx = len(sorted_steps) // 2
            if majority_idx < len(sorted_steps):
                self.first_fleet_awareness_step = sorted_steps[majority_idx]

        # Quality metrics
        if had_real_attack:
            nodes_that_detected = len(self.first_regional_coord_steps)
            self.true_coord_hits = nodes_that_detected
            self.missed_coord_attacks = len(honest_nodes) - nodes_that_detected
        else:
            # No attack — any escalation to coordinated+ is false
            for node in honest_nodes:
                if node.zone_history:
                    max_zone = max(node.zone_history)
                    if max_zone >= ZONE_COORDINATED:
                        self.false_escalation_count += 1

        # Per-node summary
        for node in honest_nodes:
            avg_sat = (sum(node.saturation_history) / len(node.saturation_history)
                       if node.saturation_history else 0)
            max_zone = max(node.zone_history) if node.zone_history else 0
            self.node_metrics.append({
                "node_id": node.node_id,
                "tokens_seeded": node.tokens_seeded,
                "merges": node.merges_performed,
                "bytes_total": node.bytes_sent + node.bytes_received,
                "avg_saturation": avg_sat,
                "max_zone": max_zone,
                "first_elevated": node.first_elevated_step,
                "first_coordinated": node.first_coordinated_step,
            })

    def summary_dict(self):
        """Return a flat dict of key metrics for comparison."""
        d = {
            "scenario": self.scenario_name,
            "approach": self.approach_name,
            "num_nodes": self.num_nodes,
        }

        # Detection timing
        if self.first_local_suspicion_steps:
            d["time_to_first_local_suspicion"] = min(
                self.first_local_suspicion_steps)
            d["time_to_median_local_suspicion"] = sorted(
                self.first_local_suspicion_steps)[
                    len(self.first_local_suspicion_steps) // 2]
        else:
            d["time_to_first_local_suspicion"] = None
            d["time_to_median_local_suspicion"] = None

        if self.first_regional_coord_steps:
            d["time_to_first_regional_coord"] = min(
                self.first_regional_coord_steps)
            d["time_to_median_regional_coord"] = sorted(
                self.first_regional_coord_steps)[
                    len(self.first_regional_coord_steps) // 2]
        else:
            d["time_to_first_regional_coord"] = None
            d["time_to_median_regional_coord"] = None

        d["time_to_fleet_awareness"] = self.first_fleet_awareness_step

        # Quality
        d["false_escalation_count"] = self.false_escalation_count
        d["true_coord_hits"] = self.true_coord_hits
        d["missed_coord_attacks"] = self.missed_coord_attacks
        d["stale_pressure_events"] = self.stale_pressure_events

        # Efficiency
        d["total_bytes"] = self.total_bytes
        d["total_merges"] = self.total_merges
        d["bytes_per_node"] = (self.total_bytes / self.num_nodes
                               if self.num_nodes > 0 else 0)
        d["mean_packet_size"] = (self.total_bytes / max(1, self.total_merges))

        # Saturation
        d["max_saturation_pct"] = self.max_saturation_seen
        d["steps_in_harmful_saturation"] = self.steps_in_harmful_saturation

        # Saturation variance at end
        if self.saturation_timeseries:
            _, _, final_var = self.saturation_timeseries[-1]
            d["final_saturation_variance"] = final_var
        else:
            d["final_saturation_variance"] = 0.0

        return d


def format_summary_table(summaries):
    """Format a list of summary dicts as a human-readable table."""
    lines = []
    if not summaries:
        return "No results.\n"

    # Group by scenario
    scenarios = {}
    for s in summaries:
        scn = s["scenario"]
        if scn not in scenarios:
            scenarios[scn] = []
        scenarios[scn].append(s)

    for scn_name, runs in scenarios.items():
        lines.append(f"\n{'='*72}")
        lines.append(f"SCENARIO: {scn_name}")
        lines.append(f"{'='*72}")

        header = (f"  {'Approach':<20s} {'1st Local':>10s} {'Med Local':>10s} "
                  f"{'1st Coord':>10s} {'Fleet':>8s} "
                  f"{'FalseEsc':>9s} {'Hits':>5s} {'Miss':>5s} "
                  f"{'Bytes/N':>10s} {'MaxSat%':>8s} {'HarmSteps':>10s}")
        lines.append(header)
        lines.append(f"  {'-'*len(header)}")

        for r in runs:
            def fmt(v):
                return f"{v:>10d}" if v is not None else f"{'N/A':>10s}"
            line = (f"  {r['approach']:<20s} "
                    f"{fmt(r['time_to_first_local_suspicion'])} "
                    f"{fmt(r['time_to_median_local_suspicion'])} "
                    f"{fmt(r['time_to_first_regional_coord'])} "
                    f"{fmt(r['time_to_fleet_awareness'])[2:]} "
                    f"{r['false_escalation_count']:>9d} "
                    f"{r['true_coord_hits']:>5d} "
                    f"{r['missed_coord_attacks']:>5d} "
                    f"{r['bytes_per_node']:>10.0f} "
                    f"{r['max_saturation_pct']:>7.1f}% "
                    f"{r['steps_in_harmful_saturation']:>10d}")
            lines.append(line)

    return "\n".join(lines) + "\n"


def write_csv(summaries, filepath):
    """Write summary metrics to CSV."""
    if not summaries:
        return
    keys = summaries[0].keys()
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for s in summaries:
            writer.writerow(s)


def write_jsonl(summaries, filepath):
    """Write summary metrics as JSONL."""
    with open(filepath, "w") as f:
        for s in summaries:
            f.write(json.dumps(s, default=str) + "\n")
