# Cooperative Enclave Baselines

## Purpose

These baselines represent cheap, plausible alternatives that a real cooperative-enclave deployment might choose instead of Ghost Meadow. They are not strawmen — each is a defensible engineering choice.

## Baseline 1: EWMA Local (No Sharing)

**What it does:** Each node tracks its own local pressure via exponentially-weighted moving average: `p = α·new + (1-α)·old`. No cross-node communication. Zero bandwidth.

**Why it's fair:** This is the "do nothing distributed" baseline. Any distributed system should outperform total isolation on distributed-signal detection. If GM cannot beat this, it has no cooperative value.

**Parameters:** α=0.1, elevated threshold=3.0, coordinated threshold=8.0. Thresholds tuned to the node's own pressure metric (events/tick), not to GM's saturation scale.

**Structural blindness:** Cannot detect anything that requires combining observations from multiple nodes. Sees only its own local stream.

## Baseline 2: Scalar Max Gossip

**What it does:** Nodes gossip a single scalar: their current max local pressure. On merge, take max. Bandwidth: 4 bytes per merge.

**Why it's fair:** This is the cheapest possible gossip system. If GM's 512-byte Bloom filter doesn't beat a 4-byte scalar, the compression overhead is not justified.

**Parameters:** Elevated threshold=3.0, coordinated threshold=8.0.

**Structural blindness:** `max(1, 1, ..., 1) = 1`. If each of N nodes has pressure=1, the max is still 1. Structurally blind to distributed breadth where many nodes each see a little.

**Structural strength:** Correctly handles dedup: if all nodes see the same thing and report pressure=1, max=1. No amplification.

## Baseline 3: Scalar Mean Gossip

**What it does:** Nodes gossip running mean pressure + observation count. On merge, accumulate totals. Bandwidth: 8 bytes per merge.

**Why it's fair:** This is the simplest aggregation that can theoretically capture breadth via count accumulation. It's the fairest scalar test against GM's breadth claim.

**Parameters:** Elevated threshold=2.0, coordinated threshold=5.0.

**Structural weakness:** Amplifies duplicates. If all nodes see the same event and gossip counts, total count = N × local count. This causes systematic false escalation under redundant overlap.

**Structural strength:** Can detect distributed breadth through count accumulation. Unlike max, sum(1,1,...,1) = N, which reflects the number of contributors.

## Fairness Guarantees

All baselines get:
- Same topology, same contact probability, same number of merges
- Thresholds tuned to their own metric scale (not GM's saturation)
- The cheapest possible bandwidth footprint
- Full credit for any detection they achieve

GM gets no advantage except its structural properties (OR-merge idempotency, bit-level accumulation, transitive state propagation).
