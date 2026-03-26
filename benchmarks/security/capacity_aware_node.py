"""
capacity_aware_node.py
CapacityAwareNode — wraps GhostMeadow with the capacity-aware policy.

Drop-in replacement for SecurityNode in the Fleet/scenario runner.
Same interface contract: seed_token, merge_from, evaluate_policy,
decay_epoch, can_query_token.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ghost_meadow import GhostMeadow
from capacity_aware_policy import CapacityAwarePolicy, CapZone

# Zone mapping: CapZone values → MetricsCollector-compatible values.
# MetricsCollector checks first_elevated_step at zone >= 1 (ZONE_ELEVATED)
# and first_coordinated_step at zone >= 3 (ZONE_COORDINATED).
# CapZone: NOMINAL=0, ELEVATED=1, COORDINATED=2, CRITICAL=3
# Map COORDINATED(2) → 3 and CRITICAL(3) → 4 for metric compatibility.
_CAPZONE_TO_METRIC = {
    CapZone.NOMINAL: 0,
    CapZone.ELEVATED: 1,
    CapZone.COORDINATED: 3,  # maps to ZONE_COORDINATED threshold
    CapZone.CRITICAL: 4,     # maps to ZONE_CONTAINMENT threshold
}


def _patch_meadow(meadow):
    """Add set_zone/inc_ghost_trigger methods to Python GhostMeadow.
    These exist in the C++ header but not in the Python port."""
    meadow.set_zone = lambda z: setattr(meadow, '_zone', z)
    meadow.inc_ghost_trigger = lambda: setattr(
        meadow, '_ghost_trigger_count',
        getattr(meadow, '_ghost_trigger_count', 0) + 1)
    return meadow


class CapacityAwareNode:
    """Node using capacity-aware policy instead of fixed thresholds.

    Satisfies the same interface contract as SecurityNode for use
    with Fleet and _run_generic_scenario.
    """

    def __init__(self, node_id, mission_key=0xDEADBEEFCAFEBABE,
                 bloom_m=4096, bloom_k=2, **kwargs):
        self.node_id = node_id
        self.meadow = _patch_meadow(
            GhostMeadow(mission_key, node_id, m=bloom_m, k=bloom_k))
        self.bloom_m = bloom_m
        self.bloom_k = bloom_k
        self.is_malicious = False

        self.policy = CapacityAwarePolicy(
            m=bloom_m, k=bloom_k,
            lambda_est=0.5,
            delta_critical=0.08,
            velocity_window=5,
            velocity_sigma=3.0,
            calibration_ticks=20,
        )

        # Metrics accumulators (same as SecurityNode)
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
        self.meadow.seed(token_bytes)
        self.tokens_seeded += 1

    def merge_from(self, other_node):
        """OR-merge from another node's meadow."""
        delta = self.meadow.merge_raw(
            other_node.meadow.raw_bits(), other_node.node_id)
        self.merges_performed += 1
        payload_bytes = len(other_node.meadow.raw_bits())
        self.bytes_received += payload_bytes + 8
        other_node.bytes_sent += payload_bytes + 8
        self.merge_delta_history.append(delta)
        return delta

    def evaluate_policy(self, step):
        """Run capacity-aware policy and record metrics."""
        result = self.policy.evaluate(self.meadow)

        # Map CapZone to metric-compatible zone value
        metric_zone = _CAPZONE_TO_METRIC.get(result.zone, int(result.zone))
        self.zone_history.append(metric_zone)
        self.saturation_history.append(self.meadow.saturation_pct())

        if metric_zone >= 1 and self.first_elevated_step is None:
            self.first_elevated_step = step

        if metric_zone >= 3 and self.first_coordinated_step is None:
            self.first_coordinated_step = step

        return {
            "zone": metric_zone,
            "zone_name": result.zone.name,
            "zone_changed": len(self.zone_history) < 2 or
                            self.zone_history[-1] != self.zone_history[-2],
            "saturation_pct": self.meadow.saturation_pct(),
            "merge_sources": self.meadow.state()["merge_source_count"],
            "quorum_met": False,
            "eval_count": result.tick,
        }

    def decay_epoch(self):
        self.meadow.decay()
        # Policy detects epoch change via meadow.epoch() — no explicit reset

    def can_query_token(self, token_bytes):
        return self.meadow.query(token_bytes)
