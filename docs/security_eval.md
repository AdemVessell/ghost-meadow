# Ghost Meadow Security Evaluation

**Date:** 2026-03-26
**Evaluator:** Automated security benchmark suite v1.0
**Scope:** Does Ghost Meadow, as currently designed, provide useful value as a distributed security-telemetry / shared-suspicion sidecar?

---

## Framing

Ghost Meadow is evaluated here as a **bounded, mergeable, probabilistic shared-suspicion substrate** — not as a SIEM, IDS, or exact reputation system. The evaluation asks whether OR-merging Bloom filters between nodes provides faster or cheaper coordinated-pressure awareness than simpler alternatives, and where the architecture breaks.

## What Was Tested

### Scenarios (9 total)

| ID | Scenario | Purpose |
|----|----------|---------|
| A | Benign baseline | Normal detector chatter, no attack — measures false escalation |
| B | Distributed coordinated attack | Honest nodes independently detect same campaign — measures propagation speed |
| C | Single malicious poison node | One node floods tokens — measures containment |
| D | Multi-node collusion | Multiple poisoners — measures degradation |
| E | Namespace/token-space flooding | Attacker maximizes Bloom saturation via diverse tokens |
| F | Replay/stale-pressure abuse | Old patterns rebroadcast across epoch boundaries |
| G | Contact asymmetry / partition | Two clusters with weak bridge — measures uneven pressure |
| H | Transport hostility | 15% corruption + 30% packet loss |
| I | Sybil-like behavior | One adversary with 4 apparent identities |

### Approaches Compared (4 total)

| Approach | Description |
|----------|-------------|
| **ghost_meadow** | Full Ghost Meadow: Bloom filter Layer A + composite security policy Layer B |
| **local_only** | Each node uses only its own detector stream, no sharing |
| **exact_gossip** | Nodes share exact token sets, capped at 200 tokens per merge |
| **counter_agg** | Nodes share per-category counters |

### Deployment Profile Tested

- **edge_pop**: 12 nodes, regional mesh topology, m=4096 bits, k=2 hashes, 40% contact probability

### Policy Configuration

- Composite policy: trust-weighted + delta-sensitive + anti-stale + quorum-gated
- Thresholds: elevated=25%, suspicious=45%, coordinated=65%, containment=80%
- Quorum: 3 merge sources for high escalation

---

## Key Findings

### 1. Ghost Meadow Consistently Detects Faster Than Local-Only

Across all 9 scenarios, Ghost Meadow reached first local suspicion (elevated zone) faster than local-only detection:

| Scenario | GM First Local | Local-Only First | Speedup |
|----------|---------------|-----------------|---------|
| A (benign) | step 27 | step 64 | 2.4x |
| B (coordinated) | step 29 | step 61 | 2.1x |
| C (poison) | step 28 | step 60 | 2.1x |
| D (collusion) | step 33 | step 67 | 2.0x |
| E (namespace) | step 2 | step 64 | 32x |
| F (replay) | step 31 | step 64 | 2.1x |
| G (partition) | step 27 | step 62 | 2.3x |
| H (transport) | step 29 | step 62 | 2.1x |
| I (sybil) | step 25 | step 63 | 2.5x |

**Interpretation:** This is real and meaningful. OR-merge propagation gives every node visibility into the fleet's aggregate observation state much faster than local accumulation alone. The ~2x speedup is consistent and architecture-inherent.

**Caveat:** This speedup also applies to benign traffic. GM reaches elevated zone at step 27 even with no attack, because merged background traffic accumulates saturation faster. The speedup is in saturation awareness, not in attack-specific detection.

### 2. The Signal-to-Noise Problem Is Severe at m=4096

This is the most important finding.

| Scenario | GM Max Saturation | Benign Max Saturation | Difference |
|----------|------------------|-----------------------|------------|
| A (benign) | 73.2% | 73.2% (self) | baseline |
| B (coordinated) | 74.3% | 73.2% | +1.1% |
| C (poison) | 73.2% | 73.2% | +0.0% |
| D (collusion) | 75.1% | 73.2% | +1.9% |
| E (namespace) | 100.0% | 73.2% | +26.8% |

**At m=4096 with 12 nodes and 200-step epochs:**
- Background traffic alone saturates to ~73%
- A coordinated attack adds only ~1% more saturation
- The Bloom filter cannot distinguish "benign background with merges" from "benign + real attack" in most scenarios
- Only extreme attacks (namespace flooding, E) produce distinguishable saturation

**This means:** For the MICRO profile (m=4096, k=2), Ghost Meadow's saturation signal is mostly noise from benign-traffic accumulation via merges. The useful signal window — the gap between benign and attack saturation — is too narrow for reliable detection.

### 3. Namespace Flooding Is Devastating

Scenario E (one node spraying 200 diverse tokens per step) drove Ghost Meadow to 100% saturation with 453 steps in harmful saturation regime. This is a near-total denial of service for the Bloom filter's utility. Once saturated, every query returns true, making the filter useless.

**This is a fundamental vulnerability of Bloom-filter-based approaches.** It is not unique to Ghost Meadow, but Ghost Meadow's OR-merge propagation makes it worse: one flooding node's saturation propagates to all connected nodes.

### 4. Poisoning Propagation Is Contained by Topology, Not by Policy

In scenarios C and D (single and multi-node poisoning), Ghost Meadow's saturation stayed below 75% — similar to benign. This is not because the policy contained the poison. It is because:
- The poison node's tokens merge into neighbors' already-saturated filters
- At high saturation, new tokens contribute fewer new bits (OR of already-set bits)
- The Bloom filter's natural saturation curve provides passive containment

**The quorum guard and trust-weighted policy did not measurably help** in these scenarios because the policy operates on saturation percentage, and malicious saturation is hard to distinguish from benign saturation at m=4096. Both GM and local-only showed the same false escalation counts (11 and 9 respectively), because escalation is driven by cumulative saturation, not by attack-specific signal.

### 5. Bandwidth Advantage Over Exact Gossip

| Scenario | GM Bytes/Node | Exact Gossip Bytes/Node | Ratio |
|----------|--------------|------------------------|-------|
| A (benign) | 726,960 | 1,074,775 | 0.68x |
| B (coordinated) | 722,887 | 1,070,053 | 0.68x |
| H (transport) | 431,340 | 756,140 | 0.57x |

Ghost Meadow transfers 32-43% less data per node than exact gossip. This is the fixed-size Bloom filter advantage: regardless of how many tokens are observed, the merge payload is always m/8 bytes (512 bytes for m=4096).

Counter aggregation is much cheaper (35-65KB/node), but loses per-token query capability.

### 6. Epoch Decay Provides Real Stale-Pressure Containment

Scenario F (replay/stale) showed that Ghost Meadow detected the replay campaign (first local at step 31) while local-only never reached coordinated zone. The epoch decay mechanism (every 150 steps) effectively limits cross-epoch contamination. Old tokens do not carry across decay boundaries by design — this is the 0dB0 constraint working as intended.

### 7. Transport Hostility Is Well-Tolerated

Under 15% corruption + 30% packet loss (scenario H), Ghost Meadow's detection timing degraded minimally (step 29 vs 29 in clean conditions). The CRC-16 transport integrity prevents corrupted data from entering the filter. Packet loss reduces merge throughput but the redundancy of the mesh topology compensates.

### 8. Partition Topology Creates Detection Gaps

In scenario G (partitioned clusters with single bridge), Ghost Meadow missed 3/12 honest nodes for coordinated detection. Nodes in the far partition received insufficient merge data through the bridge. Local-only actually performed better here (12/12 detections) because it doesn't depend on merge connectivity.

**This is a real limitation:** Ghost Meadow's value is proportional to merge connectivity. In sparse or partitioned topologies, it can perform worse than local-only for some nodes.

---

## Acceptance Criteria Assessment

### A. Does Ghost Meadow outperform local-only in any security-relevant condition?
**Yes.** GM consistently reaches suspicion ~2x faster than local-only due to merge-accelerated saturation accumulation. This is a real structural advantage.

### B. Does it provide useful earlier coordinated-pressure awareness?
**Partially.** GM reaches coordinated-zone detection 15-25% faster than local-only in scenarios B, G, and H. However, at m=4096, the coordinated-pressure signal is very close to benign-traffic saturation, making it unreliable as a discriminator.

### C. How much bandwidth does it save vs exact-sharing baselines?
**32-43% less than exact gossip.** This is the fixed-payload advantage. Counter aggregation is much cheaper but loses query capability.

### D. How badly does poisoning hurt?
**Not catastrophically, but not because of countermeasures.** Poisoning impact is passively bounded by the Bloom filter's saturation curve, not by policy mechanisms. The quorum guard and trust weighting don't provide measurable protection because they operate on the same saturated signal.

### E. How much do quorum and trust-weighted policies help?
**Minimally at m=4096.** The policies operate on saturation percentage. When benign and malicious traffic produce similar saturation levels, the policies cannot distinguish them. Trust weighting needs larger filters where malicious saturation is distinguishable from benign.

### F. When does saturation become operationally useless?
**At m=4096 with 12 merging nodes: consistently above 70% by step 200.** Namespace flooding drives it to 100%. The useful signal window (where attack saturation is distinguishable from benign) is approximately steps 10-50 of each epoch — roughly 25% of the epoch.

### G. Which deployment profile sizes are still viable?
**m=4096 is marginal for 12-node fleets with sustained traffic.** The average max saturation of 77% leaves little headroom. Larger filters (m=32768 or m=192000) would have much better signal-to-noise. The low_power profile (m=512) would be nearly useless for security telemetry.

### H. Which threat conditions make Ghost Meadow a bad fit?
1. **Namespace flooding** — devastating, drives to 100% saturation
2. **Partitioned topologies** — merge-dependent detection fails for isolated nodes
3. **High sustained background traffic** — saturates the filter, drowning attack signal
4. **Any scenario requiring attack-vs-benign discrimination** at small filter sizes

---

## What Ghost Meadow Does Well (for security telemetry)

1. **Faster aggregate awareness.** Merge propagation genuinely accelerates fleet-wide saturation awareness by ~2x vs local-only.
2. **Fixed bandwidth.** Payload is always m/8 bytes regardless of token count. This is a real advantage over exact sharing.
3. **Epoch isolation.** The decay mechanism effectively limits stale data contamination.
4. **Transport resilience.** CRC-16 integrity + OR-merge idempotency make it robust under hostile transport conditions.
5. **Passive poisoning containment.** The saturation curve naturally limits how much damage one node can do.

## What Ghost Meadow Does Poorly (for security telemetry)

1. **Cannot distinguish attack from noise at small filter sizes.** This is the critical weakness. At m=4096, the signal-to-noise ratio for attack detection is near zero.
2. **OR-merge amplifies flooding attacks.** One saturated node can poison connected nodes' entire filter.
3. **No per-token provenance.** The Bloom filter cannot attribute which tokens came from which source. Policy must operate on aggregate saturation only.
4. **Quorum and trust mechanisms are largely ineffective** when the underlying signal is indistinguishable from noise.
5. **Partition-sensitive.** Value degrades sharply with poor merge connectivity.

---

## Recommendations

### If continuing the "security telemetry sidecar" thesis:

1. **Use larger filters.** m=32768 (STANDARD profile, 4KB) or m=192000 (FULL profile, 24KB) would dramatically improve signal-to-noise ratio by keeping benign-traffic saturation below 20%, leaving headroom for attack signal.

2. **Shorten epochs.** Shorter epochs (50-100 steps instead of 200) reduce accumulated benign saturation per epoch, improving the useful signal window.

3. **Add saturation-rate monitoring.** The delta-sensitive policy is a good idea but needs tuning. The rate of saturation change is potentially more informative than absolute saturation for security applications.

4. **Consider per-category sub-filters.** Instead of one large Bloom filter, partition into category-specific sub-filters. This would prevent namespace flooding from affecting all categories and allow more targeted detection.

5. **Add merge-source-weighted saturation.** Track how much saturation came from merges vs local observations. High merge-contributed saturation with low local saturation could indicate remote-origin pressure.

### What claims should be softened in the README:

- The README does not currently claim security-telemetry fitness, so no claims need softening.
- If the "distributed security telemetry sidecar" thesis is pursued, any claims should explicitly state the minimum viable filter size (m >= 32768) and acknowledge that m=4096 is insufficient for attack/benign discrimination.

### What claims are now better supported:

- **OR-merge convergence under hostile conditions** — confirmed in security-specific scenarios
- **CRC-16 transport integrity** — confirmed under 15% corruption + 30% loss
- **Epoch isolation** — confirmed effective for anti-stale in security context
- **Fixed-bandwidth advantage** — confirmed at 32-43% savings vs exact sharing
- **Passive poisoning containment** — confirmed via saturation curve behavior

---

## Conclusion

Ghost Meadow has a **defensible but narrow** role in distributed security telemetry:

**Where it works:** Fleet-wide awareness acceleration when (a) filter size is adequate (m >= 32768), (b) merge connectivity is good, and (c) background traffic rate is calibrated to epoch length. Under these conditions, it provides real 2x speedup in aggregate awareness with meaningful bandwidth savings over exact sharing.

**Where it fails:** At small filter sizes (m=4096), against namespace flooding, in partitioned topologies, and in any scenario requiring reliable discrimination between benign and malicious saturation. The policy mechanisms (quorum, trust) cannot compensate for inadequate signal-to-noise at the Bloom filter layer.

**Bottom line:** The architecture is sound for what it claims to be — a probabilistic, approximate, bounded substrate for shared suspicion. But the security-telemetry use case has stricter signal-to-noise requirements than the general swarm-convergence use case, and these requirements are not met at the smaller profile sizes. The thesis is supportable for STANDARD and FULL profiles, not for MICRO or TINY.

---

## Reproducibility

All results can be reproduced with:
```bash
# Full benchmark
python3 benchmarks/security/run_security_bench.py --profile edge_pop

# Test suite
python3 tests/security/test_security_scenarios.py

# Quick validation (3 scenarios only)
python3 benchmarks/security/run_security_bench.py --quick
```

Seed: 20260326 (deterministic via xorshift64 PRNG)
