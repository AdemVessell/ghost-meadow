"""
enclave_baselines.py
Cheap scalar baselines for cooperative-enclave bakeoff.

Each baseline implements the same node interface contract as SecurityNode
so it plugs into Fleet and _run_generic_scenario without modification.

These are not strawmen. Each represents a plausible lightweight alternative
that a real deployment might choose instead of Ghost Meadow.
"""

import sys
import os
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "security"))


class EWMALocalNode:
    """Baseline: Local EWMA pressure tracker, no cross-node sharing.

    Each node keeps its own exponentially-weighted moving average of
    local observation rate. No merges, no gossip, zero bandwidth.
    This is the "do nothing distributed" baseline.

    Pressure: p = alpha * new_event_count_this_tick + (1-alpha) * p_prev
    Escalation: p > threshold (tuned to match GM sensitivity)
    """

    def __init__(self, node_id, alpha=0.1, threshold_elevated=3.0,
                 threshold_coordinated=8.0, **kwargs):
        self.node_id = node_id
        self.is_malicious = False
        self.alpha = alpha
        self.threshold_elevated = threshold_elevated
        self.threshold_coordinated = threshold_coordinated

        self.pressure = 0.0
        self._tick_tokens = 0
        self.local_tokens = set()

        # Metrics (interface contract)
        self.tokens_seeded = 0
        self.merges_performed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.zone_history = []
        self.saturation_history = []
        self.merge_delta_history = []
        self.first_elevated_step = None
        self.first_coordinated_step = None

    def seed_token(self, token_bytes):
        self.local_tokens.add(token_bytes)
        self.tokens_seeded += 1
        self._tick_tokens += 1

    def merge_from(self, other):
        pass  # No merging — local only

    def evaluate_policy(self, step):
        self.pressure = (self.alpha * self._tick_tokens +
                         (1 - self.alpha) * self.pressure)
        self._tick_tokens = 0

        zone = 0
        if self.pressure >= self.threshold_coordinated:
            zone = 3
        elif self.pressure >= self.threshold_elevated:
            zone = 1

        self.zone_history.append(zone)
        # Map pressure to pseudo-saturation for metrics compatibility
        pseudo_sat = min(100.0, self.pressure * 10.0)
        self.saturation_history.append(pseudo_sat)

        if zone >= 1 and self.first_elevated_step is None:
            self.first_elevated_step = step
        if zone >= 3 and self.first_coordinated_step is None:
            self.first_coordinated_step = step

        return {"zone": zone, "zone_name": f"zone_{zone}",
                "zone_changed": len(self.zone_history) < 2 or
                                zone != self.zone_history[-2],
                "saturation_pct": pseudo_sat, "merge_sources": 0,
                "quorum_met": False, "eval_count": step}

    def decay_epoch(self):
        self.pressure = 0.0
        self._tick_tokens = 0
        self.local_tokens.clear()

    def can_query_token(self, token_bytes):
        return token_bytes in self.local_tokens


class ScalarMaxGossipNode:
    """Baseline: Nodes gossip a single scalar max-pressure value.

    On merge, take max of own pressure and peer's pressure.
    Bandwidth: 4 bytes per merge (one float32).
    This is the cheapest possible gossip baseline.

    Structurally blind to:
    - distributed breadth (max of many 1s is still 1)
    - idempotent dedup (has no concept of bit-identity)
    """

    def __init__(self, node_id, threshold_elevated=3.0,
                 threshold_coordinated=8.0, **kwargs):
        self.node_id = node_id
        self.is_malicious = False
        self.threshold_elevated = threshold_elevated
        self.threshold_coordinated = threshold_coordinated

        self.local_pressure = 0.0
        self.merged_pressure = 0.0
        self._tick_tokens = 0
        self.local_tokens = set()
        self.merge_sources = set()

        # Metrics
        self.tokens_seeded = 0
        self.merges_performed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.zone_history = []
        self.saturation_history = []
        self.merge_delta_history = []
        self.first_elevated_step = None
        self.first_coordinated_step = None

    def seed_token(self, token_bytes):
        self.local_tokens.add(token_bytes)
        self.tokens_seeded += 1
        self._tick_tokens += 1

    def merge_from(self, other):
        old = self.merged_pressure
        self.merged_pressure = max(self.merged_pressure, other.merged_pressure,
                                   other.local_pressure)
        self.merge_sources.add(other.node_id)
        self.merges_performed += 1
        delta = self.merged_pressure - old
        self.merge_delta_history.append(delta)
        # 4 bytes (one float) per merge
        self.bytes_received += 4
        other.bytes_sent += 4
        return delta

    def evaluate_policy(self, step):
        self.local_pressure = self._tick_tokens
        self._tick_tokens = 0
        effective = max(self.local_pressure, self.merged_pressure)

        zone = 0
        if effective >= self.threshold_coordinated:
            zone = 3
        elif effective >= self.threshold_elevated:
            zone = 1

        self.zone_history.append(zone)
        pseudo_sat = min(100.0, effective * 10.0)
        self.saturation_history.append(pseudo_sat)

        if zone >= 1 and self.first_elevated_step is None:
            self.first_elevated_step = step
        if zone >= 3 and self.first_coordinated_step is None:
            self.first_coordinated_step = step

        return {"zone": zone, "zone_name": f"zone_{zone}",
                "zone_changed": len(self.zone_history) < 2 or
                                zone != self.zone_history[-2],
                "saturation_pct": pseudo_sat,
                "merge_sources": len(self.merge_sources),
                "quorum_met": False, "eval_count": step}

    def decay_epoch(self):
        self.local_pressure = 0.0
        self.merged_pressure = 0.0
        self._tick_tokens = 0
        self.local_tokens.clear()
        self.merge_sources.clear()
        self.merge_delta_history.clear()

    def can_query_token(self, token_bytes):
        return token_bytes in self.local_tokens


class ScalarMeanGossipNode:
    """Baseline: Nodes gossip running mean pressure + observation count.

    On merge, weighted-combine means. This can potentially capture
    distributed breadth via count accumulation — the fairest scalar test.
    Bandwidth: 8 bytes per merge (float mean + uint32 count).
    """

    def __init__(self, node_id, threshold_elevated=2.0,
                 threshold_coordinated=5.0, **kwargs):
        self.node_id = node_id
        self.is_malicious = False
        self.threshold_elevated = threshold_elevated
        self.threshold_coordinated = threshold_coordinated

        self.local_count = 0
        self.total_count = 0  # local + merged
        self.total_pressure_sum = 0.0
        self._tick_tokens = 0
        self.local_tokens = set()
        self.merge_sources = set()

        # Metrics
        self.tokens_seeded = 0
        self.merges_performed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.zone_history = []
        self.saturation_history = []
        self.merge_delta_history = []
        self.first_elevated_step = None
        self.first_coordinated_step = None

    def seed_token(self, token_bytes):
        self.local_tokens.add(token_bytes)
        self.tokens_seeded += 1
        self._tick_tokens += 1
        self.local_count += 1

    def merge_from(self, other):
        old_count = self.total_count
        # Absorb other's total count and pressure sum
        self.total_count += other.total_count
        self.total_pressure_sum += other.total_pressure_sum
        self.merge_sources.add(other.node_id)
        self.merges_performed += 1
        delta = self.total_count - old_count
        self.merge_delta_history.append(delta)
        # 8 bytes (float mean + uint32 count)
        self.bytes_received += 8
        other.bytes_sent += 8
        return delta

    def evaluate_policy(self, step):
        # Update local pressure
        self.total_count = max(self.total_count, self.local_count)
        self.total_pressure_sum = max(self.total_pressure_sum,
                                      float(self.local_count))
        self._tick_tokens = 0

        # Effective pressure: mean events across fleet
        effective = (self.total_pressure_sum / max(1, len(self.merge_sources) + 1))

        zone = 0
        if effective >= self.threshold_coordinated:
            zone = 3
        elif effective >= self.threshold_elevated:
            zone = 1

        self.zone_history.append(zone)
        pseudo_sat = min(100.0, effective * 5.0)
        self.saturation_history.append(pseudo_sat)

        if zone >= 1 and self.first_elevated_step is None:
            self.first_elevated_step = step
        if zone >= 3 and self.first_coordinated_step is None:
            self.first_coordinated_step = step

        return {"zone": zone, "zone_name": f"zone_{zone}",
                "zone_changed": len(self.zone_history) < 2 or
                                zone != self.zone_history[-2],
                "saturation_pct": pseudo_sat,
                "merge_sources": len(self.merge_sources),
                "quorum_met": False, "eval_count": step}

    def decay_epoch(self):
        self.local_count = 0
        self.total_count = 0
        self.total_pressure_sum = 0.0
        self._tick_tokens = 0
        self.local_tokens.clear()
        self.merge_sources.clear()
        self.merge_delta_history.clear()

    def can_query_token(self, token_bytes):
        return token_bytes in self.local_tokens
