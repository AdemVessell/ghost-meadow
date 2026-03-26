#!/usr/bin/env python3
"""
capacity_aware_policy.py
Ghost Meadow — Capacity-Aware Layer B Policy Engine

Replaces fixed-threshold policy with dynamic baseline tracking.
Instead of "fire if saturation > 60%", this policy asks:
"fire if saturation is anomalously higher than expected background noise
at this point in the epoch."

Math basis:
  S_base(t) = 1 - exp(-k * lambda * t / m)

  where:
    m = filter bits (4096 for 512B profile)
    k = hash functions (2 or 4)
    lambda = empirical background event rate (events/tick)
    t = ticks since last epoch reset

Two trigger modes:
  A) Magnitude: S_actual > S_base(t) + delta_critical
  B) Velocity: dS/dt > v_max_noise

Design constraints preserved:
  - O(1) computation per tick (no allocations, no lookups)
  - No modifications to Layer A
  - Reads only state() telemetry — saturation_pct and epoch
  - Deterministic given same inputs
"""

import math
from enum import IntEnum


class CapZone(IntEnum):
    """Zone escalation levels."""
    NOMINAL = 0
    ELEVATED = 1      # Magnitude anomaly detected
    COORDINATED = 2   # Sustained magnitude or velocity anomaly
    CRITICAL = 3      # Both triggers firing simultaneously


class CapacityAwarePolicy:
    """
    Dynamic capacity-aware policy engine for Ghost Meadow Layer B.

    Instead of fixed saturation thresholds, this policy tracks the
    expected background saturation curve S_base(t) and triggers only
    when actual saturation deviates significantly from expectation.

    Parameters:
        m: Filter size in bits (default 4096 for 512B profile)
        k: Number of hash functions (default 2)
        lambda_est: Initial estimate of background event rate (events/tick).
                    Will be refined during calibration phase if enabled.
        delta_critical: Magnitude threshold — fraction above baseline to trigger.
                        E.g., 0.10 means fire if actual is 10% above expected.
        velocity_window: Number of ticks for velocity calculation sliding window.
        velocity_sigma: Number of standard deviations above expected velocity
                        to trigger velocity anomaly.
        calibration_ticks: Number of ticks at epoch start used for lambda
                          estimation. During calibration, only velocity triggers
                          fire (magnitude is suppressed to avoid false alarm
                          during baseline learning).
    """

    def __init__(
        self,
        m=4096,
        k=2,
        lambda_est=0.5,
        delta_critical=0.08,
        velocity_window=5,
        velocity_sigma=3.0,
        calibration_ticks=20,
    ):
        self.m = m
        self.k = k
        self.lambda_est = lambda_est
        self.delta_critical = delta_critical
        self.velocity_window = velocity_window
        self.velocity_sigma = velocity_sigma
        self.calibration_ticks = calibration_ticks

        # Internal state — reset each epoch
        self._tick = 0
        self._epoch = 0
        self._zone = CapZone.NOMINAL
        self._saturation_history = []
        self._ghost_trigger_count = 0
        self._magnitude_firing = False
        self._velocity_firing = False

        # Calibration state
        self._calibrating = True
        self._calibration_samples = []

        # Consecutive anomaly counter for escalation
        self._consecutive_anomaly_ticks = 0

    def expected_saturation(self, t):
        """
        Theoretical baseline saturation at tick t given background rate lambda.

        S_base(t) = 1 - exp(-k * lambda * t / m)

        Returns fraction [0.0, 1.0].
        """
        if t <= 0:
            return 0.0
        exponent = -self.k * self.lambda_est * t / self.m
        exponent = max(exponent, -50.0)
        return 1.0 - math.exp(exponent)

    def expected_velocity(self, t):
        """
        Derivative of expected saturation at tick t.

        dS/dt = (k * lambda / m) * exp(-k * lambda * t / m)

        Returns fraction/tick.
        """
        if t <= 0:
            return self.k * self.lambda_est / self.m
        exponent = -self.k * self.lambda_est * t / self.m
        exponent = max(exponent, -50.0)
        return (self.k * self.lambda_est / self.m) * math.exp(exponent)

    def _update_calibration(self, actual_sat):
        """
        During early epoch ticks, refine lambda estimate from observed data.

        Uses the inverse of the saturation formula:
          lambda_obs = -m * ln(1 - S_actual) / (k * t)
        """
        self._calibration_samples.append(actual_sat)

        if len(self._calibration_samples) >= self.calibration_ticks:
            self._calibrating = False

            s_final = self._calibration_samples[-1]
            t_final = len(self._calibration_samples)

            if s_final > 0.0 and s_final < 1.0 and t_final > 0:
                lambda_obs = -self.m * math.log(1.0 - s_final) / (self.k * t_final)
                self.lambda_est = 0.3 * self.lambda_est + 0.7 * lambda_obs

    def evaluate(self, meadow):
        """
        Core evaluation — called once per tick per node.

        Reads meadow.saturation() and meadow.epoch(). Returns CapacityAwareResult.
        Writes zone back via meadow.set_zone() if available.
        """
        actual_sat = meadow.saturation()
        current_epoch = meadow.epoch() if hasattr(meadow, 'epoch') else 0

        # Detect epoch boundary — reset internal state
        if current_epoch != self._epoch:
            self._reset_epoch(current_epoch)

        self._tick += 1
        self._saturation_history.append(actual_sat)

        # Phase 1: Calibration
        if self._calibrating:
            self._update_calibration(actual_sat)
            result = self._check_velocity_only(actual_sat)
            if hasattr(meadow, 'set_zone'):
                meadow.set_zone(self._zone)
            return result

        # Phase 2: Active monitoring
        s_base = self.expected_saturation(self._tick)

        # Trigger A: Magnitude anomaly
        magnitude_delta = actual_sat - s_base
        self._magnitude_firing = magnitude_delta > self.delta_critical

        # Trigger B: Velocity anomaly
        self._velocity_firing = False
        if len(self._saturation_history) >= self.velocity_window + 1:
            idx = len(self._saturation_history) - 1
            s_now = self._saturation_history[idx]
            s_prev = self._saturation_history[idx - self.velocity_window]
            v_actual = (s_now - s_prev) / self.velocity_window

            v_expected = self.expected_velocity(self._tick)
            v_noise_std = math.sqrt(v_expected / self.m) if v_expected > 0 else 0.001
            v_threshold = v_expected + self.velocity_sigma * v_noise_std

            self._velocity_firing = v_actual > v_threshold

        # Zone escalation logic
        if self._magnitude_firing or self._velocity_firing:
            self._consecutive_anomaly_ticks += 1
        else:
            self._consecutive_anomaly_ticks = max(
                0, self._consecutive_anomaly_ticks - 1)

        old_zone = self._zone

        if self._magnitude_firing and self._velocity_firing:
            self._zone = CapZone.CRITICAL
        elif self._consecutive_anomaly_ticks >= 3:
            self._zone = CapZone.COORDINATED
        elif self._magnitude_firing or self._velocity_firing:
            self._zone = CapZone.ELEVATED
        elif self._consecutive_anomaly_ticks == 0:
            self._zone = CapZone.NOMINAL

        # Ghost trigger on escalation to CRITICAL
        if self._zone == CapZone.CRITICAL and old_zone != CapZone.CRITICAL:
            self._ghost_trigger_count += 1
            if hasattr(meadow, 'inc_ghost_trigger'):
                meadow.inc_ghost_trigger()

        if hasattr(meadow, 'set_zone'):
            meadow.set_zone(self._zone)

        return CapacityAwareResult(
            zone=self._zone,
            tick=self._tick,
            actual_sat=actual_sat,
            expected_sat=s_base,
            magnitude_delta=magnitude_delta,
            magnitude_firing=self._magnitude_firing,
            velocity_firing=self._velocity_firing,
            lambda_est=self.lambda_est,
            calibrating=False,
            consecutive_anomaly=self._consecutive_anomaly_ticks,
        )

    def _check_velocity_only(self, actual_sat):
        """Velocity-only check during calibration phase."""
        self._velocity_firing = False

        if len(self._saturation_history) >= self.velocity_window + 1:
            idx = len(self._saturation_history) - 1
            s_now = self._saturation_history[idx]
            s_prev = self._saturation_history[idx - self.velocity_window]
            v_actual = (s_now - s_prev) / self.velocity_window

            conservative_v_max = 0.02  # 2% per tick is suspicious
            self._velocity_firing = v_actual > conservative_v_max

        if self._velocity_firing:
            self._zone = CapZone.ELEVATED
            self._consecutive_anomaly_ticks += 1
        else:
            self._zone = CapZone.NOMINAL
            self._consecutive_anomaly_ticks = max(
                0, self._consecutive_anomaly_ticks - 1)

        return CapacityAwareResult(
            zone=self._zone,
            tick=self._tick,
            actual_sat=actual_sat,
            expected_sat=0.0,
            magnitude_delta=0.0,
            magnitude_firing=False,
            velocity_firing=self._velocity_firing,
            lambda_est=self.lambda_est,
            calibrating=True,
            consecutive_anomaly=self._consecutive_anomaly_ticks,
        )

    def _reset_epoch(self, new_epoch):
        """Reset internal state on epoch boundary."""
        self._epoch = new_epoch
        self._tick = 0
        self._saturation_history = []
        self._calibrating = True
        self._calibration_samples = []
        self._consecutive_anomaly_ticks = 0
        self._magnitude_firing = False
        self._velocity_firing = False
        self._zone = CapZone.NOMINAL
        # lambda_est carries across epochs — learned, not reset

    @property
    def zone(self):
        return self._zone

    @property
    def ghost_trigger_count(self):
        return self._ghost_trigger_count


class CapacityAwareResult:
    """Result from a single policy evaluation tick."""

    __slots__ = (
        'zone', 'tick', 'actual_sat', 'expected_sat', 'magnitude_delta',
        'magnitude_firing', 'velocity_firing', 'lambda_est', 'calibrating',
        'consecutive_anomaly',
    )

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        status = []
        if self.calibrating:
            status.append("CALIBRATING")
        if self.magnitude_firing:
            status.append("MAG")
        if self.velocity_firing:
            status.append("VEL")
        flags = "+".join(status) if status else "QUIET"
        return (
            f"<CapResult zone={self.zone.name} tick={self.tick} "
            f"actual={self.actual_sat:.4f} expected={self.expected_sat:.4f} "
            f"delta={self.magnitude_delta:+.4f} lambda={self.lambda_est:.4f} "
            f"flags={flags}>"
        )


# ---------------------------------------------------------------------------
# Inline test harness — 7 tests
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from ghost_meadow import GhostMeadow

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

    print("=" * 60)
    print("CAPACITY-AWARE POLICY INLINE TESTS")
    print("=" * 60)

    KEY = 0xDEADBEEFCAFEBABE

    # Patch GhostMeadow with the methods the policy expects
    def _patch_meadow(m):
        m.set_zone = lambda z: setattr(m, '_zone', z)
        m.inc_ghost_trigger = lambda: setattr(
            m, '_ghost_trigger_count',
            getattr(m, '_ghost_trigger_count', 0) + 1)
        return m

    # TEST 1: Expected saturation is monotonically increasing
    print("\nTest 1: S_base monotonicity")
    p = CapacityAwarePolicy(m=4096, k=2, lambda_est=1.0)
    prev = 0.0
    monotonic = True
    for t in range(1, 500):
        s = p.expected_saturation(t)
        if s < prev:
            monotonic = False
            break
        prev = s
    check("S_base(t) is monotonically increasing", monotonic)

    # TEST 2: S_base(0) == 0
    print("\nTest 2: S_base(0) == 0")
    check("S_base(0) == 0", p.expected_saturation(0) == 0.0)

    # TEST 3: S_base(large t) approaches 1.0
    print("\nTest 3: S_base(large t) → 1.0")
    s_large = p.expected_saturation(100000)
    check("S_base(100000) > 0.99", s_large > 0.99, f"got {s_large}")

    # TEST 4: Benign traffic stays NOMINAL (no false alarm)
    print("\nTest 4: Benign traffic — no false alarm")
    meadow = _patch_meadow(GhostMeadow(KEY, 0, m=4096, k=2))
    policy = CapacityAwarePolicy(m=4096, k=2, lambda_est=0.5,
                                  calibration_ticks=20)
    max_zone = CapZone.NOMINAL
    for tick in range(100):
        # Benign: ~2 tokens per tick
        for _ in range(2):
            meadow.seed(f"benign_{tick}_{_}".encode())
        result = policy.evaluate(meadow)
        if result.zone > max_zone:
            max_zone = result.zone
    check("Benign stays NOMINAL", max_zone == CapZone.NOMINAL,
          f"reached {CapZone(max_zone).name}")

    # TEST 5: Coordinated spike triggers escalation
    print("\nTest 5: Coordinated spike — triggers escalation")
    meadow2 = _patch_meadow(GhostMeadow(KEY, 1, m=4096, k=2))
    policy2 = CapacityAwarePolicy(m=4096, k=2, lambda_est=0.5,
                                   delta_critical=0.05, calibration_ticks=15)
    # Calibration phase: benign
    for tick in range(20):
        meadow2.seed(f"cal_{tick}".encode())
        policy2.evaluate(meadow2)
    # Attack phase: massive spike
    spike_zone = CapZone.NOMINAL
    for tick in range(20, 50):
        for i in range(30):  # 30 tokens/tick — way above baseline
            meadow2.seed(f"attack_{tick}_{i}".encode())
        result = policy2.evaluate(meadow2)
        if result.zone > spike_zone:
            spike_zone = result.zone
    check("Spike triggers ELEVATED or higher",
          spike_zone >= CapZone.ELEVATED,
          f"max zone was {CapZone(spike_zone).name}")

    # TEST 6: Epoch reset clears state and re-enters calibration
    print("\nTest 6: Epoch reset")
    meadow3 = _patch_meadow(GhostMeadow(KEY, 2, m=4096, k=2))
    policy3 = CapacityAwarePolicy(m=4096, k=2, lambda_est=0.5,
                                   calibration_ticks=10)
    for tick in range(20):
        meadow3.seed(f"pre_{tick}".encode())
        policy3.evaluate(meadow3)
    check("Pre-decay: not calibrating", not policy3._calibrating)
    # Trigger epoch
    meadow3.decay()
    result = policy3.evaluate(meadow3)
    check("Post-decay: re-enters calibration", result.calibrating)

    # TEST 7: Lambda estimate preserved across epoch boundary
    print("\nTest 7: Lambda preservation")
    lambda_before = policy3.lambda_est
    # The evaluate above already started new epoch calibration
    # Lambda should be the learned value, not reset to default
    check("Lambda preserved across epoch",
          lambda_before != 0.5,  # should have been refined from calibration
          f"lambda={lambda_before}")

    print(f"\n{'='*60}")
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed} failed")
    if failed == 0:
        print("ALL TESTS PASSED")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
