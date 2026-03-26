"""
security_policy.py
Security-oriented Layer B policy for Ghost Meadow benchmarks.

Extends the existing policy philosophy (saturation-based escalation with
quorum guard) to support security-specific evaluation semantics.

Policy output states:
  0 = nominal
  1 = elevated
  2 = suspicious
  3 = coordinated_pressure
  4 = containment_recommended

These are advisory states, not proof. They represent the policy's best
estimate of the security posture given the approximate Bloom filter data.
"""

ZONE_NOMINAL = 0
ZONE_ELEVATED = 1
ZONE_SUSPICIOUS = 2
ZONE_COORDINATED = 3
ZONE_CONTAINMENT = 4

ZONE_NAMES = {
    0: "nominal",
    1: "elevated",
    2: "suspicious",
    3: "coordinated_pressure",
    4: "containment_recommended",
}

# Peer trust classes
TRUST_FULL = 2
TRUST_SEMI = 1
TRUST_UNTRUSTED = 0


class SecurityPolicy:
    """Security-oriented Layer B policy.

    Implements multiple policy evaluation strategies that can be selected
    per-node or per-benchmark run. All strategies read only the public
    state from the GhostMeadow instance (saturation, merge_source_count,
    merge_delta_last) — they never touch Layer A internals.

    Policy variants:
      basic          - saturation thresholds only (existing behavior)
      quorum_gated   - require N trusted merge sources for escalation
      trust_weighted - weight peer contributions by trust class
      delta_sensitive - escalate on rapid saturation changes
      anti_stale     - penalize pressure that appears stale/static
      composite      - all of the above combined
    """

    def __init__(self, variant="composite", quorum_k=3,
                 sat_elevated=25.0, sat_suspicious=45.0,
                 sat_coordinated=65.0, sat_containment=80.0,
                 trust_class=TRUST_FULL):
        self.variant = variant
        self.quorum_k = quorum_k
        self.sat_elevated = sat_elevated
        self.sat_suspicious = sat_suspicious
        self.sat_coordinated = sat_coordinated
        self.sat_containment = sat_containment
        self.trust_class = trust_class

        # State tracking for delta-sensitive and anti-stale
        self._prev_saturation = 0.0
        self._saturation_deltas = []
        self._stale_counter = 0
        self._eval_count = 0
        self._zone = ZONE_NOMINAL
        self._zone_history = []

    def evaluate(self, meadow_state):
        """Evaluate policy given a meadow state dict.

        Args:
            meadow_state: dict with keys matching GhostMeadow.state() output
                         (saturation_pct, merge_source_count, merge_delta_last, etc.)

        Returns:
            dict with zone, details, and advisory info
        """
        sat = meadow_state["saturation_pct"]
        sources = meadow_state["merge_source_count"]
        delta = meadow_state["merge_delta_last"]

        if self.variant == "basic":
            zone = self._eval_basic(sat)
        elif self.variant == "quorum_gated":
            zone = self._eval_quorum_gated(sat, sources)
        elif self.variant == "trust_weighted":
            zone = self._eval_trust_weighted(sat, sources, meadow_state)
        elif self.variant == "delta_sensitive":
            zone = self._eval_delta_sensitive(sat, delta)
        elif self.variant == "anti_stale":
            zone = self._eval_anti_stale(sat, delta)
        elif self.variant == "composite":
            zone = self._eval_composite(sat, sources, delta, meadow_state)
        else:
            zone = self._eval_basic(sat)

        prev_zone = self._zone
        self._zone = zone
        self._prev_saturation = sat
        self._eval_count += 1
        self._zone_history.append(zone)

        return {
            "zone": zone,
            "zone_name": ZONE_NAMES.get(zone, "unknown"),
            "zone_changed": zone != prev_zone,
            "saturation_pct": sat,
            "merge_sources": sources,
            "quorum_met": sources >= self.quorum_k,
            "eval_count": self._eval_count,
        }

    def reset_epoch(self):
        """Call at epoch boundary to reset tracking state."""
        self._prev_saturation = 0.0
        self._saturation_deltas = []
        self._stale_counter = 0
        self._zone = ZONE_NOMINAL

    def _eval_basic(self, sat):
        """Pure saturation threshold policy."""
        if sat >= self.sat_containment:
            return ZONE_CONTAINMENT
        elif sat >= self.sat_coordinated:
            return ZONE_COORDINATED
        elif sat >= self.sat_suspicious:
            return ZONE_SUSPICIOUS
        elif sat >= self.sat_elevated:
            return ZONE_ELEVATED
        return ZONE_NOMINAL

    def _eval_quorum_gated(self, sat, sources):
        """Saturation + quorum guard for high escalation levels."""
        base = self._eval_basic(sat)
        if base >= ZONE_CONTAINMENT and sources < self.quorum_k:
            return ZONE_COORDINATED  # cap at coordinated without quorum
        if base >= ZONE_COORDINATED and sources < max(1, self.quorum_k - 1):
            return ZONE_SUSPICIOUS  # need at least some corroboration
        return base

    def _eval_trust_weighted(self, sat, sources, state):
        """Apply trust weighting to effective saturation.

        Trusted peers' merge contributions count fully.
        Semi-trusted count at 50%. Untrusted at 25%.
        This is applied at Layer B interpretation, not at Layer A merge.
        """
        trust_factor = {TRUST_FULL: 1.0, TRUST_SEMI: 0.75,
                        TRUST_UNTRUSTED: 0.5}.get(self.trust_class, 1.0)
        effective_sat = sat * trust_factor
        base = self._eval_basic(effective_sat)
        if base >= ZONE_CONTAINMENT and sources < self.quorum_k:
            return ZONE_COORDINATED
        return base

    def _eval_delta_sensitive(self, sat, delta):
        """Escalate faster when saturation is changing rapidly."""
        self._saturation_deltas.append(sat - self._prev_saturation)
        if len(self._saturation_deltas) > 10:
            self._saturation_deltas.pop(0)

        avg_delta = (sum(self._saturation_deltas) / len(self._saturation_deltas)
                     if self._saturation_deltas else 0)

        # Rapid increase lowers thresholds
        urgency_shift = min(10.0, max(0.0, avg_delta * 2.0))
        effective_sat = sat + urgency_shift

        return self._eval_basic(effective_sat)

    def _eval_anti_stale(self, sat, delta):
        """Penalize static pressure that hasn't changed recently.
        If saturation is high but delta is near-zero for many evals,
        reduce effective escalation — the signal may be stale."""
        if sat > 5.0 and abs(delta) < 2:
            self._stale_counter += 1
        else:
            self._stale_counter = max(0, self._stale_counter - 2)

        # Stale penalty: reduce effective saturation
        stale_penalty = min(15.0, self._stale_counter * 1.5)
        effective_sat = max(0.0, sat - stale_penalty)

        return self._eval_basic(effective_sat)

    def _eval_composite(self, sat, sources, delta, state):
        """Combine all policy signals.

        Order of evaluation:
        1. Trust-weighted effective saturation
        2. Delta sensitivity adjustment
        3. Anti-stale penalty
        4. Quorum guard for high escalation
        """
        # Trust weighting
        trust_factor = {TRUST_FULL: 1.0, TRUST_SEMI: 0.75,
                        TRUST_UNTRUSTED: 0.5}.get(self.trust_class, 1.0)
        effective_sat = sat * trust_factor

        # Delta sensitivity
        self._saturation_deltas.append(sat - self._prev_saturation)
        if len(self._saturation_deltas) > 10:
            self._saturation_deltas.pop(0)
        avg_delta = (sum(self._saturation_deltas) / len(self._saturation_deltas)
                     if self._saturation_deltas else 0)
        urgency_shift = min(8.0, max(0.0, avg_delta * 1.5))
        effective_sat += urgency_shift

        # Anti-stale
        if sat > 5.0 and abs(delta) < 2:
            self._stale_counter += 1
        else:
            self._stale_counter = max(0, self._stale_counter - 2)
        stale_penalty = min(10.0, self._stale_counter * 1.0)
        effective_sat = max(0.0, effective_sat - stale_penalty)

        # Base zone from adjusted saturation
        base = self._eval_basic(effective_sat)

        # Quorum guard
        if base >= ZONE_CONTAINMENT and sources < self.quorum_k:
            base = ZONE_COORDINATED
        if base >= ZONE_COORDINATED and sources < max(1, self.quorum_k - 1):
            base = ZONE_SUSPICIOUS

        return base


class TrustModel:
    """Manages peer trust assignments for a fleet of nodes."""

    def __init__(self, num_nodes, mode="all_equal"):
        """
        Modes:
          all_equal     - every peer is fully trusted
          tiered        - first 1/3 full, middle 1/3 semi, last 1/3 untrusted
          single_untrusted - one specific node is untrusted, rest full
          custom        - use set_trust() to assign individually
        """
        self.num_nodes = num_nodes
        self.mode = mode
        self._trust = {}
        self._init_trust(mode)

    def _init_trust(self, mode):
        if mode == "all_equal":
            for i in range(self.num_nodes):
                self._trust[i] = TRUST_FULL
        elif mode == "tiered":
            third = self.num_nodes // 3
            for i in range(self.num_nodes):
                if i < third:
                    self._trust[i] = TRUST_FULL
                elif i < 2 * third:
                    self._trust[i] = TRUST_SEMI
                else:
                    self._trust[i] = TRUST_UNTRUSTED
        elif mode == "single_untrusted":
            for i in range(self.num_nodes):
                self._trust[i] = TRUST_FULL
            self._trust[0] = TRUST_UNTRUSTED
        else:
            for i in range(self.num_nodes):
                self._trust[i] = TRUST_FULL

    def get_trust(self, node_id):
        return self._trust.get(node_id, TRUST_FULL)

    def set_trust(self, node_id, trust_class):
        self._trust[node_id] = trust_class

    def get_merge_weight(self, src_node_id):
        """Weight for merge contribution from src_node_id.
        Applied at Layer B interpretation, not at Layer A merge."""
        t = self.get_trust(src_node_id)
        return {TRUST_FULL: 1.0, TRUST_SEMI: 0.5, TRUST_UNTRUSTED: 0.25}[t]
