# Capacity-Aware Policy Evaluation Results

**Date:** 2026-03-26
**Source:** `benchmarks/security/run_capacity_aware_eval.py`
**Profile:** m=4096, k=2, 12 nodes, regional mesh
**Status:** 9 scenarios × 2 approaches = 18 runs

---

## Purpose

Tests whether a capacity-aware Layer B policy — which tracks expected background saturation dynamically instead of using fixed thresholds — improves detection speed, reduces false escalation, and maintains detection accuracy compared to the existing composite fixed-threshold policy.

The capacity-aware policy was motivated by the blind falsification verdict (docs/blind_falsification_verdict.md) which showed fixed thresholds are inert at m≥32768 (saturation never reaches them) and indistinguishable from noise at m=4096 (benign saturates to ~73%).

## Policy Comparison

| Policy | Mechanism |
|--------|-----------|
| **composite** (existing) | Fixed saturation thresholds: elevated=25%, suspicious=45%, coordinated=65%, containment=80%. Combines quorum guard, trust weighting, delta sensitivity, and anti-stale decay. |
| **capacity_aware** (new) | Dynamic baseline tracking: S_base(t) = 1 - exp(-k·λ·t/m). Online lambda calibration during first 20 ticks. Dual triggers: magnitude anomaly (actual > expected + δ) and velocity anomaly (dS/dt exceeds noise floor). |

---

## Results: Side-by-Side

| Scenario | Composite t1 | Cap-Aware t1 | Composite fe | Cap-Aware fe | Composite hits | Cap-Aware hits | Composite sat% | Cap-Aware sat% |
|----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| A benign | 27 | **22** | 12 | **10** | 0 | 0 | 73.2 | 73.2 |
| B coordinated | 29 | **21** | 0 | 0 | 12 | 12 | 74.3 | 74.3 |
| C poison | 28 | **27** | 11 | **9** | 0 | 0 | 73.2 | **60.3** |
| D collusion | 33 | **21** | 9 | 9 | 0 | 0 | 75.1 | **63.9** |
| E namespace | **2** | 6 | 11 | 11 | 0 | 0 | 100.0 | 100.0 |
| F replay | 31 | **21** | 0 | 0 | 11 | 10 | 67.7 | **53.7** |
| G partition | 27 | **21** | 0 | 0 | 9 | **10** | 73.7 | 73.7 |
| H transport | 29 | **16** | 0 | 0 | 12 | 12 | 73.7 | 73.7 |
| I sybil | 25 | **21** | 0 | 0 | 11 | 11 | 80.9 | **70.8** |

Bold = better result.

## Aggregate Comparison

| Metric | Composite | Capacity-Aware | Δ |
|--------|:---------:|:--------------:|:---:|
| Total false escalations | 43 | **39** | -9.3% |
| Total coordinated hits | 55 | 55 | 0% |
| Faster detection (of 9) | 1 | **7** | — |
| Lower max saturation (of 9) | 0 | **4** | — |

---

## Key Findings

### 1. Detection speed: capacity-aware is faster in 7/9 scenarios

The capacity-aware velocity trigger detects saturation-rate anomalies before absolute thresholds are crossed. Average improvement: 5-13 steps earlier detection (B: 21 vs 29, H: 16 vs 29).

**Exception:** Namespace flooding (E) — the fixed-threshold policy detects at step 2 vs capacity-aware at step 6, because the flood overwhelms the Bloom filter so fast that even a conservative velocity-only calibration trigger catches it slightly later than a threshold already at 25%.

### 2. False escalation: 9% reduction

Capacity-aware produces 39 total false escalations vs 43 for composite. The improvement comes from benign (10 vs 12) and poison (9 vs 11) scenarios where the learned baseline absorbs normal saturation accumulation that fixed thresholds treat as anomalous.

### 3. Detection accuracy: identical coordinated-pressure hits

Both policies detect 55 coordinated-pressure events across all scenarios. The capacity-aware policy does not sacrifice detection accuracy for its speed advantage.

### 4. Lower max saturation under adversarial conditions

Under poison (60.3% vs 73.2%), collusion (63.9% vs 75.1%), replay (53.7% vs 67.7%), and sybil (70.8% vs 80.9%), the capacity-aware nodes show lower max saturation. This is because the velocity trigger fires earlier, giving operators more time to respond before the filter becomes heavily saturated.

---

## Structural Advantage Tests (Baseline Comparison)

Two additional tests demonstrate properties unique to Bloom-filter-based sharing that no scalar gossip system can replicate:

### Scenario A: Idempotent Deduplication (10/10 tests passing)

8 nodes all observe the exact same event. After full gossip merge:
- Ghost Meadow: saturation unchanged (0.000488 before and after). OR of identical bits = same bits.
- Scalar-sum baseline: would report 8 events (8× overcounting).
- Scalar-max baseline: correctly reports 1 event but loses distributed participation info.
- Capacity-aware policy: stays NOMINAL — no false alarm from redundant flood.

### Scenario B: Distributed Creep (10/10 tests passing)

8 nodes each observe a unique event. After full gossip merge:
- Ghost Meadow: saturation increases to 8.00× single-node level. Each event sets k=2 distinct bits; 8 events set ~16 bits total.
- Scalar-max baseline: collapses all 8 distinct events to pressure=1 (structurally blind to distributed breadth).
- All 8 events are queryable on every node after merge.
- Capacity-aware velocity trigger fires on rapid multi-source merge.

---

## Limitations

- Evaluated at m=4096 only. The capacity-aware policy is expected to perform proportionally better at m≥32768 where it can learn a more accurate baseline, but this has not been tested here.
- Lambda calibration uses a 20-tick warmup. Attacks during the first 20 ticks of an epoch may be detected only by the conservative velocity trigger, not the magnitude trigger.
- The 9% false-escalation reduction is modest. The fundamental issue — that benign saturation at m=4096 is ~73% — is not solved by the policy; it's a Layer A capacity limitation.

---

## Reproducibility

```bash
# Inline policy tests (8/8)
python3 benchmarks/security/capacity_aware_policy.py

# Baseline comparison tests (10/10)
python3 tests/security/test_baseline_comparison.py

# Full comparative evaluation (18 runs, ~24s)
python3 benchmarks/security/run_capacity_aware_eval.py
```
