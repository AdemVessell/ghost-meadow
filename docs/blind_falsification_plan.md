# Pre-Registered Blind Falsification Plan

**Frozen commit:** f453416f21650c365bdab2ff62eef8e6553c398c
**Date:** 2026-03-26
**Purpose:** Test whether Ghost Meadow's security-telemetry thesis survives under held-out conditions with no post-hoc tuning.

---

## Candidate System (Frozen)

Ghost Meadow composite policy with fixed thresholds:
- elevated=25%, suspicious=45%, coordinated=65%, containment=80%
- quorum_k=3, trust=all_equal
- Bloom filter with FNV-1a hash, OR-merge, epoch decay

No modifications allowed after this document is finalized.

---

## Pre-Registered Acceptance Criteria

Evaluated on held-out conditions only. Thresholds set before results are examined.

### SUPPORT (thesis survives)

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Awareness speedup vs local-only | GM detects first in ≥60% of held-out conditions | Must hold across topologies and seeds |
| Bandwidth vs exact gossip | GM uses ≤80% of exact gossip bandwidth in ≥80% of conditions | Fixed-payload advantage should be robust |
| False escalation (benign) | ≤2 nodes false-escalate per run at m≥32768 | Headroom should prevent false positives |
| Coordinated-pressure hit rate | GM detects in ≥50% of honest nodes under attack at m≥32768 | Must propagate awareness to majority |
| Seed stability | Std of awareness timing ≤10% of mean across 10 seeds | Results should not be fragile |
| Benign saturation headroom | Benign sat < 50% at m=32768, < 25% at m=192000 | Headroom must be real |

### WEAK SUPPORT (partial survival)

| Metric | Threshold |
|--------|-----------|
| Awareness speedup | GM detects first in 40-59% of held-out conditions |
| False escalation | 3-5 nodes false-escalate at m≥32768 |
| Coord hit rate | GM detects in 30-49% of honest nodes |
| Seed stability | Std of awareness timing 10-20% of mean |

### FAILURE (thesis damaged)

| Metric | Threshold |
|--------|-----------|
| Awareness speedup | GM detects first in <40% of held-out conditions |
| False escalation | >5 nodes false-escalate at m≥32768 |
| Benign saturation | Benign sat ≥50% at m=32768 |
| Seed stability | Std >20% of mean |
| Poisoning | GM degrades >20% more than local-only under poison |

### CATASTROPHIC FAILURE

| Metric | Threshold |
|--------|-----------|
| GM slower than local-only in >70% of held-out conditions | Architecture provides no useful value |
| Benign saturation ≥80% at m=32768 | Filter is non-functional |
| Namespace flood saturates m=192000 to >90% in <200 steps | No flood resilience even at max sizing |
| All baselines outperform GM on every metric | No defensible thesis remains |

---

## Pre-Registered Failure Conditions (Explicit)

The following outcomes, if observed, falsify specific claims:

1. **"Larger filters improve separability"** — FALSIFIED if attack-benign gap at m=32768 is <2% across held-out conditions (consistent with stage 2 finding of ~1%)
2. **"Policy mechanisms provide useful defense"** — FALSIFIED if no policy variant produces >5% improvement on any metric vs basic
3. **"Trust weighting helps under poisoning"** — FALSIFIED if tiered trust produces <10% reduction in false escalation vs all_equal at m≥32768
4. **"Awareness speedup is robust"** — FALSIFIED if speedup disappears under sparse or partitioned topologies
5. **"Bandwidth advantage is real"** — FALSIFIED if GM transmits more bytes/node than exact gossip in >20% of conditions

---

## Held-Out Generation Protocol

1. Seeds drawn from range [50000, 59999], 10 seeds per condition
2. Topologies rotated: ring, star_sparse, regional_mesh, partitioned_clusters, full_mesh
3. Token vocabularies shifted: variant_base=10000 (no overlap with dev range 0-1500)
4. Contact probabilities varied: 0.15, 0.4, 0.7
5. Epoch lengths varied: 100, 200, 300
6. Traffic regimes: benign, coordinated, poison, namespace_flood

All generated deterministically from a master held-out seed.
No conditions dropped after generation unless technically invalid (logged if so).

---

## Baseline Assumptions

Documented in docs/blind_baseline_assumptions.md.

---

## Verdict Protocol

1. Run all held-out conditions with frozen system
2. Aggregate results per metric
3. Compare against pre-registered thresholds
4. Produce verdict: SUPPORT / WEAK SUPPORT / FAILURE / CATASTROPHIC FAILURE per claim
5. No threshold modification after results are visible
