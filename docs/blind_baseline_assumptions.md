# Baseline Assumptions for Blind Falsification

## Local-Only (Baseline 1)

**What it does:** Each node accumulates tokens in an exact set. No inter-node communication. Policy evaluates based on local token count mapped to pseudo-saturation.

**What it does not do:** Share any information between nodes. It has zero bandwidth cost but also zero collaborative awareness.

**Why it's fair:** This is the minimum-viable comparison. Any distributed system should outperform isolation. If GM cannot beat this, it has no value.

**Where it's simplified:** The pseudo-saturation mapping (token_count / 500 * 100%) is not calibrated to match Bloom filter saturation curves exactly. This means policy-zone timing is approximate. However, this favors local-only slightly because its "saturation" can only grow from local tokens, making it a conservative baseline.

## Exact Gossip (Baseline 2)

**What it does:** Nodes share exact token sets capped at 500 tokens per merge. Uses quorum-gated policy with k=3 merge sources. Tracks merge sources. Deterministic sharing (sorted tokens for reproducibility).

**What it does not do:** Compress data. Every shared token costs 4 bytes. No probabilistic compression, no Bloom filter approximation.

**Why it's fair:** This represents "what if you just shared the actual tokens?" — the naive approach that GM's Bloom filter is supposed to improve upon via bandwidth efficiency. The 500-token cap is realistic for a lightweight gossip system.

**Where it's simplified:** Real gossip systems have more sophisticated deduplication, priority queues, and freshness tracking. The 500-cap is generous but not production-faithful. Pseudo-saturation mapping is approximate.

## Counter Aggregation (Baseline 3)

**What it does:** Nodes share per-(category, subcategory) counters. Uses max-aggregation across peers. Quorum-gated policy with k=3. Per-subcategory granularity (83 possible counters).

**What it does not do:** Share individual tokens. Cannot answer per-token membership queries. Loses all variant-level information.

**Why it's fair:** This represents the minimum-bandwidth alternative — sharing only aggregate counts. If GM cannot provide better awareness than simple counters, its complexity is not justified.

**Where it's simplified:** Real counter systems might use exponential decay, sliding windows, or hierarchical aggregation. This implementation uses simple max-merge per counter, which is analogous to GM's OR-merge monotonicity.
