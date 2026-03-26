# Cooperative Enclave Bakeoff Plan

**Date:** 2026-03-26
**Status:** Executed — see verdict document.

## What Was Falsified Previously

The broad security-telemetry thesis for Ghost Meadow failed under blind falsification:
- Fixed-threshold policies are inert at m≥32768 (saturation never reaches thresholds)
- At m=4096, benign saturation sits at ~73%, making attack signals indistinguishable from noise
- Bandwidth advantage inverts at m≥32768 (Bloom filter payload larger than exact gossip)
- Policy mechanisms provide near-zero measurable benefit once headroom exists

## What Survived

Two structural properties survived all testing:
1. **Idempotent deduplication** — OR-merge of identical observations produces zero amplification
2. **Distributed breadth sensitivity** — N unique observations merge to N×k distinct bits; scalar-max collapses to 1

## The Narrow Claim Being Tested

> Can tiny-profile Ghost Meadow (512B, m=4096) act as a useful advisory distributed-pressure substrate inside a trusted cooperative enclave, and beat cheap scalar baselines on the properties those baselines structurally lose?

## Deployment Shape

Industrial campus / facility wing advisory mesh:
- 32 trusted nodes
- Building-wing topologies (corridor, wing_gateway, campus_building)
- Contact probability 0.3
- 300-step epochs
- Advisory output only (not authoritative control)

## Pre-Registered Acceptance Criteria

### SUPPORT (narrow win justified)
1. GM dedup_amplification ≤ scalar baselines in ≥80% of seeds
2. GM breadth_detection_rate ≥ 50% while scalar_max ≤ 20% in ≥80% of seeds
3. GM benign_bustle_false_alarm ≤ scalar baselines
4. Stability: std ≤ 20% of mean for key metrics
5. Bandwidth: GM ≤ 2× cheapest scalar

### FAILURE
- GM does not beat scalars on either structural claim
- GM wins but with unacceptable false escalation
- Gains < 5% (operationally trivial)

## Execution

- 9 scenarios (3 overlap + 3 breadth + 3 realism)
- 4 approaches (gm_cap_aware, ewma_local, scalar_max, scalar_mean)
- 3 topologies × 20 seeds = 60 runs per scenario per approach
- Total: 2160 runs

## Result

See [cooperative_enclave_bakeoff_verdict.md](cooperative_enclave_bakeoff_verdict.md).
