# Cooperative Enclave Bakeoff — Verdict

**Date:** 2026-03-26
**Runs:** 2160 (9 scenarios × 4 approaches × 3 topologies × 20 seeds)
**Runtime:** 1305s
**Profile:** m=4096, k=2, 32 nodes, contact_prob=0.3

---

## Results Table

| Scenario | GM elev | EWMA elev | Max elev | Mean elev | GM bw | Max bw | Mean bw |
|----------|:-------:|:---------:|:--------:|:---------:|------:|-------:|--------:|
| **OVERLAP** | | | | | | | |
| overlap_identical | **0.00** | 0.00 | 0.00 | 1.00 | 387K | 3K | 6K |
| overlap_moving | **0.00** | 0.00 | 0.00 | 1.00 | 516K | 4K | 8K |
| overlap_rebroadcast | **0.00** | 0.00 | 0.00 | 1.00 | 387K | 3K | 6K |
| **BREADTH** | | | | | | | |
| breadth_weak | **0.10** | 0.00 | 0.00 | 1.00 | 517K | 4K | 8K |
| breadth_gradient | 1.00 | 0.41 | 1.00 | 1.00 | 516K | 4K | 8K |
| breadth_vs_bustle | 1.00 | 1.00 | 1.00 | 1.00 | 516K | 4K | 8K |
| **REALISM** | | | | | | | |
| shift_bustle | 1.00 | 1.00 | 1.00 | 1.00 | 516K | 4K | 8K |
| partition_heal | **1.00** | 0.00 | 0.00 | 1.00 | 514K | 4K | 8K |
| corridor_bottleneck | **0.76** | 0.00 | 0.00 | 1.00 | 517K | 4K | 8K |

Bold = best result among approaches.

---

## Structural Claim 1: Redundant Overlap Deduplication

**Verdict: TIE with scalar-max, WIN over scalar-mean.**

| Approach | overlap_identical | overlap_moving | overlap_rebroadcast |
|----------|:-:|:-:|:-:|
| GM cap-aware | 0.00 (silent) | 0.00 (silent) | 0.00 (silent) |
| EWMA local | 0.00 (silent) | 0.00 (silent) | 0.00 (silent) |
| Scalar-max | 0.00 (silent) | 0.00 (silent) | 0.00 (silent) |
| Scalar-mean | **1.00 (false alarm)** | **1.00 (false alarm)** | **1.00 (false alarm)** |

GM correctly deduplicates redundant observations — but **so does scalar-max and EWMA-local**. The only baseline that fails at dedup is scalar-mean/sum, which amplifies counts.

**Assessment:** GM's idempotent OR-merge is structurally correct for dedup, but it does not beat scalar-max gossip, which achieves the same result at 130× less bandwidth (3K vs 387K bytes/node). The dedup advantage is real against sum-based baselines but **not against max-based baselines**.

---

## Structural Claim 2: Distributed Breadth Sensitivity

**Verdict: NARROW WIN on breadth_weak. TIE on others.**

| Scenario | GM | EWMA | Scalar-max | Scalar-mean |
|----------|:--:|:----:|:----------:|:-----------:|
| breadth_weak | **0.10** | 0.00 | 0.00 | 1.00 (false) |
| breadth_gradient | 1.00 | 0.41 | 1.00 | 1.00 |
| breadth_vs_bustle | 1.00 | 1.00 | 1.00 | 1.00 |

**breadth_weak_distributed** is the key test: 32 nodes each observe one unique weak event. Only GM detects anything (10% of nodes reach elevated). Scalar-max sees max(1,1,...,1)=1 — structurally blind. EWMA sees nothing (each node has only 1 local token). Scalar-mean detects at 100% but is simultaneously false-alarming on everything else.

**This is a real structural win**, but it is narrow:
- Only 10% of GM nodes detect (3.2 of 32 nodes reach elevated)
- The signal is weak enough that 90% of GM nodes also miss it
- The win is detectable only at the fleet level, not per-node

For stronger signals (breadth_gradient, breadth_vs_bustle), all approaches detect — GM offers no advantage.

---

## Realism Scenarios

**Partition-heal and corridor-bottleneck show a genuine GM advantage.**

| Scenario | GM | EWMA | Scalar-max | Scalar-mean |
|----------|:--:|:----:|:----------:|:-----------:|
| partition_heal | **1.00** | 0.00 | 0.00 | 1.00 |
| corridor_bottleneck | **0.76** | 0.00 | 0.00 | 1.00 |

Under partition/heal and corridor bottleneck topologies, GM propagates pressure through the topology via OR-merge. EWMA (local-only) and scalar-max cannot propagate — they only see local observations. Scalar-mean propagates but over-amplifies.

**This is GM's strongest showing.** In topologies with restricted connectivity, OR-merge transitivity allows observations from one wing to reach the other wing via intermediate merges. Scalar-max gossips only a single number, which doesn't accumulate the way bit-level OR does.

**However:** Scalar-mean also detects in these scenarios (at the cost of 100% false escalation elsewhere).

---

## Shift-Change Bustle (False Alarm Test)

| Approach | Elevated rate | Time to first |
|----------|:---:|:---:|
| GM | 1.00 | step 8 |
| EWMA | 1.00 | step 42 |
| Scalar-max | 1.00 | step 40 |
| Scalar-mean | 1.00 | step 0 |

**All approaches false-escalate under shift-change bustle.** GM fires earliest (step 8) — its velocity trigger catches the burst before calibration absorbs it. This is not a win; it's a problem. The capacity-aware policy's lambda calibration is too short (20 ticks) to absorb a bustle burst that starts at tick 40.

---

## Bandwidth

| Approach | Bytes/node (typical) | Ratio to cheapest |
|----------|-----:|:---:|
| EWMA local | 0 | — |
| Scalar-max | ~4K | 1.0x |
| Scalar-mean | ~8K | 2.0x |
| **GM cap-aware** | **~516K** | **130x** |

GM's 512-byte filter payload is sent every merge. With ~1000 merges per node per scenario, this accumulates to ~516K — **130× more than scalar-max**. This fails the pre-registered criterion of ≤2× cheapest scalar.

---

## Pre-Registered Acceptance Criteria

| Criterion | Threshold | Result | Verdict |
|-----------|-----------|--------|---------|
| Dedup amplification | GM ≤ scalars 80% of seeds | TIE with max, WIN vs mean | **PARTIAL** |
| Breadth detection | GM ≥50% vs max ≤20% | GM=10% vs max=0% | **FAIL** (GM below 50%) |
| Benign bustle | GM ≤ scalars | GM fires earliest | **FAIL** |
| Stability | std ≤20% of mean | Stable across seeds | **SUPPORT** |
| Bandwidth | ≤2× cheapest | 130× cheapest | **FAIL** |

**Overall: WEAK SUPPORT at best, closer to FAILURE.**

---

## Answers to the Seven Verdict Questions

### 1. Did tiny GM beat cheap baselines on redundant overlap?
**Tie.** GM correctly deduplicates, but scalar-max gossip does too, at 130× less bandwidth. GM beats only scalar-mean/sum.

### 2. Did tiny GM beat cheap baselines on distributed breadth?
**Marginal.** GM is the only non-false-alarm approach to detect breadth_weak (10% detection rate), but the detection rate is operationally weak. On stronger signals, all approaches detect.

### 3. Were the wins operationally meaningful or only cosmetic?
**Mixed.** The partition-heal and corridor-bottleneck results are operationally meaningful — GM propagates pressure through restricted topologies where scalar-max cannot. But 10% breadth detection on the flagship weak-signal scenario is not operationally useful.

### 4. Did benign bustle remain a problem?
**Yes.** GM fires earliest (step 8) under shift-change bustle. The capacity-aware policy's velocity trigger is too sensitive to transient bursts.

### 5. Does this justify a narrow "cooperative enclave advisory pressure substrate" identity?
**Only with topology restrictions.** GM has a genuine advantage in partitioned or bottlenecked topologies where scalar gossip cannot propagate accumulated state. In well-connected topologies, scalar-max is cheaper and equally effective at dedup. The narrative narrows from "cooperative enclave" to "topologically constrained cooperative enclave with restricted gateways."

### 6. What exact claim is now defensible?
**"In cooperative enclaves with gateway-bottleneck or partition-prone topologies, tiny Ghost Meadow (512B) provides transitive pressure propagation through OR-merge that scalar-max gossip structurally cannot match. This comes at 130× bandwidth cost and with higher bustle sensitivity."**

### 7. What exact claim is still not defensible?
- "GM beats cheap baselines on dedup" — Scalar-max ties.
- "GM beats cheap baselines on distributed breadth at operationally useful rates" — 10% detection is not useful.
- "GM is bandwidth-efficient vs scalar baselines" — 130× is not.
- "GM handles benign bustle well" — It fires earliest under bustle.
- "GM is the right choice for well-connected enclaves" — Scalar-max is cheaper and equivalent.

---

## What GM's Remaining Value Actually Is

Ghost Meadow's only surviving unique advantage is **transitive accumulation through topology bottlenecks**. In the partition_heal scenario, observations from Wing A pass through the gateway to Wing B via OR-merge. Each merge carries the full accumulated bit state, so information propagates transitively even through a single gateway node. Scalar-max gossips only the maximum pressure value, which loses the structure of which observations contributed.

This is a narrow but real property. It is most valuable when:
1. The topology has restricted gateways or bottlenecks
2. The signal is distributed across many sources
3. You need eventual fleet-wide awareness, not just local detection
4. You can tolerate 130× bandwidth overhead for 512B merges

It is not valuable when:
1. The topology is well-connected (scalar-max is equivalent and cheaper)
2. The signal is strong enough for any single node to detect locally
3. Bandwidth is constrained
4. You need to distinguish signal from transient bustle
