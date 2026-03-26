# Ghost Meadow

**Topology-sensitive propagation primitive for partitioned cooperative enclaves.**

| | |
|---|---|
| **Status** | Narrowed research prototype. Simulation-only. No hardware validation. |
| **Surviving claim** | Transitive pressure propagation through topology bottlenecks via OR-merge, where scalar gossip structurally fails. Demonstrated in cooperative enclave bakeoff (2160 runs, 20 seeds, 3 topologies). |
| **Falsified claims** | General security telemetry sidecar. Distributed saturation barometer. Bandwidth-efficient alternative to exact gossip at large filter sizes. These were tested under blind falsification (315 runs) and pre-registered cooperative bakeoff and did not survive. |

Ghost Meadow is a bounded Bloom-filter CRDT that accumulates local observations and merges with nearby nodes via bitwise OR. Its remaining demonstrated advantage is narrow: in partition-prone or gateway-constrained topologies, OR-merge carries accumulated multi-source state transitively through bottleneck nodes, propagating distributed pressure that scalar gossip structurally cannot represent. In well-connected topologies, scalar-max gossip matches or exceeds Ghost Meadow at 130x less bandwidth.

---

## Executive Verdict

Ghost Meadow was originally proposed as a general probabilistic memory substrate for embedded swarms. Systematic evaluation — including blind falsification (315 held-out conditions across 3 filter-size profiles), a pre-registered cooperative enclave bakeoff (2160 runs across 9 scenarios, 4 approaches, 3 topologies, 20 seeds), and direct Layer A measurement across 7 filter sizes — narrowed the project substantially.

**What survived:** One structural advantage. In topologies with gateway bottlenecks or intermittent partitions, Ghost Meadow's OR-merge propagates accumulated state transitively through relay nodes. Scalar-max gossip, which carries only a single pressure value, cannot accumulate multi-source observations across relays. This was demonstrated in partition-heal (GM elevated_rate=1.00, scalar-max=0.00) and corridor-bottleneck (GM=0.76, scalar-max=0.00) scenarios.

**What failed:** The broad security-telemetry thesis. Fixed-threshold policies are inert at m>=32768 (saturation never reaches thresholds). At m=4096, benign saturation sits at ~73%, making attack signals indistinguishable from noise. The bandwidth advantage inverts at large filter sizes. Deduplication ties scalar-max. Distributed breadth detection is operationally weak (10% node detection rate). The project is not a general distributed pressure substrate.

**Why it narrowed:** Testing against cheap scalar baselines showed that most of Ghost Meadow's hypothesized advantages either did not materialize or were matched by simpler alternatives. The topology-bottleneck propagation property is the one result that scalar baselines structurally cannot replicate.

---

## The Surviving Claim

In cooperative enclaves with gateway-bottleneck or partition-prone topologies, tiny Ghost Meadow (512 bytes, m=4096, k=2) provides transitive pressure propagation through OR-merge that scalar-max gossip structurally cannot match.

**How it works:** When Node A observes events and merges with gateway Node G, and later Node G merges with Node B on the other side of a partition, Node B receives the accumulated bit-state from Node A — not just a scalar summary, but a set of bit positions that OR-merge preserves transitively. If multiple source nodes contribute distinct observations before they reach the gateway, the merged filter at the gateway carries all of them. Scalar-max gossip collapses this to a single number: `max(1, 1, ..., 1) = 1`.

**Evidence from cooperative enclave bakeoff:**

| Scenario | Ghost Meadow | EWMA Local | Scalar-Max | Scalar-Mean |
|----------|:---:|:---:|:---:|:---:|
| partition_heal | **1.00** | 0.00 | 0.00 | 1.00 (false alarm) |
| corridor_bottleneck | **0.76** | 0.00 | 0.00 | 1.00 (false alarm) |
| overlap_identical | 0.00 | 0.00 | 0.00 | 1.00 (false alarm) |
| breadth_weak | 0.10 | 0.00 | 0.00 | 1.00 (false alarm) |

Values are elevated_rate: fraction of honest nodes that detected pressure. 2160 runs, 20 seeds, 3 topologies.

**What this table shows:**
- **partition_heal and corridor_bottleneck:** GM propagates pressure where scalar-max and EWMA cannot. This is the surviving structural advantage.
- **overlap_identical:** GM ties scalar-max on deduplication. Both stay silent. Not a win for GM.
- **breadth_weak:** GM detects at 10% — operationally too weak to carry the project. Not a reliable win.
- **Scalar-mean:** Detects everything but also false-alarms on everything. Not a useful baseline win.

---

## Engineering Tradeoffs and Constraints

These are known architectural limitations, not caveats to be minimized.

### Bandwidth: ~130x scalar-max

In the cooperative enclave bakeoff, Ghost Meadow transmitted ~516K bytes per node vs ~4K for scalar-max gossip. The 512-byte Bloom filter payload is sent on every merge contact. With ~1000 merges per node per epoch, this accumulates to ~130x the cost of a 4-byte scalar. This is the primary cost of the surviving advantage.

### Bustle sensitivity

Ghost Meadow fires earliest (step 8) under shift-change bustle — before EWMA (step 42) and scalar-max (step 40). The capacity-aware policy's velocity trigger is too sensitive to transient bursts during the lambda-calibration warmup period. In cooperative enclaves with periodic high-activity transitions (shift changes, maintenance windows), this produces advisory false alarms.

### Weak breadth detection

Ghost Meadow detected distributed weak signals in only 10% of nodes (breadth_weak scenario). This is structurally better than scalar-max (0%) but operationally too weak to be a reliable detection mechanism. Distributed breadth sensitivity is a theoretical advantage that does not translate to useful detection rates at m=4096.

### Poor fit for well-connected topologies

In well-connected meshes, scalar-max gossip achieves equivalent deduplication at 130x less bandwidth. Ghost Meadow's transitive propagation advantage only manifests when topology restricts direct contact and forces state to pass through bottleneck relays.

### Large-profile security thesis falsified

The prediction that larger Bloom filters (m=32768 and m=192000) would make Ghost Meadow viable for security telemetry was falsified under blind evaluation. At m>=32768, Ghost Meadow detects slower than local-only detection (mean -1.8 steps), the bandwidth advantage inverts (filter payload larger than exact gossip), and policy thresholds are never reached. All three profiles (m=4096, m=32768, m=192000) failed pre-registered acceptance criteria.

### No hardware validation

Zero bytes have been transmitted over a real radio. No ESP32 or STM32 flash. No power profiling. No multi-device over-the-air merge. No field test. The surviving claim is demonstrated only in simulation.

---

## Target Deployment Shape

Ghost Meadow is a candidate only in a narrow deployment environment:

- **Cooperative enclave**: trusted or semi-trusted nodes, no public internet threat model
- **Partition-prone or gateway-constrained topology**: the topology itself is the main obstacle to information propagation
- **Advisory output only**: "regional pressure rising" or "broad observation accumulating" — not authoritative control, exact counts, or provenance
- **Internal-only propagation**: enclave-local, not internet-facing

**Ghost Meadow is only worth considering if:**
- [ ] Scalar summaries lose meaningful structure when relayed through topology bottlenecks
- [ ] 130x bandwidth cost over scalar-max is acceptable for the deployment
- [ ] Exact observation counts and provenance are not required
- [ ] The topology has restricted gateways, intermittent partitions, or relay-dependent paths
- [ ] The output is advisory, not authoritative

If any of these do not hold, scalar-max gossip is cheaper and equivalent.

---

## Illustrative Deployment Classes

These are topology-driven examples where the surviving property may matter. They are not deployment recommendations or target-customer promises.

### Data mules in subterranean or RF-denied networks

Underground facilities, mines, or tunnel systems where relay nodes (data mules) are the only path between isolated sensor clusters. Each mule carries an OR-merged filter that accumulates observations from its contact zone. When two mules meet at a junction, their merge carries the full accumulated state from both zones — not just the maximum pressure scalar. Scalar-max collapses multi-zone observations to a single number at each relay hop.

### Partitioned tactical or field swarms

Mobile nodes in contested RF environments where network partitions are frequent and unpredictable. When two partition fragments reconnect, a single OR-merge of their respective filters propagates all accumulated observations from both fragments. Scalar-max carries only the highest-pressure value from each fragment, losing the structure of which observations contributed.

### Delay-tolerant orbital or CubeSat relay systems

Satellite constellations with intermittent contact windows where ground observations accumulate during a pass and must be relayed through one or two orbital hops. Each hop carries the full merged filter. Scalar gossip loses multi-ground-station observation diversity at the first relay.

---

## Anti-Use-Cases

Ghost Meadow is not suitable for:

- **Well-connected meshes** where scalar gossip propagates effectively (scalar-max is cheaper and equivalent)
- **General security telemetry sidecars** (this thesis was tested and falsified)
- **General anomaly barometers** (benign saturation is indistinguishable from anomaly at m=4096)
- **Exact coordination or consensus systems** (Ghost Meadow is approximate and advisory)
- **Exact counts, provenance, or audit** (Bloom filters lose per-observation identity)
- **Public, open, or hostile networks** (no adversarial guarantees survived testing)
- **Bandwidth-sensitive deployments** where 130x overhead over scalar-max is unacceptable
- **Distributed breadth detection** as a primary objective (10% node detection rate is not operationally useful)

---

## Evidence Summary

The repository preserves both positive and negative evaluation results. Major claims were tested and most were narrowed or falsified.

| Evaluation | Scope | Key Result |
|------------|-------|------------|
| Chaos suite | 7 adversarial scenarios (C++) | 7/7 passed. 0 integrity leaks across 7255 packets. |
| Cross-language validation | 8 hash/CRDT property tests | 8/8 passed. Bit-identical C++ and Python. |
| TLA+ formal verification | CRDT properties, quorum guard | All invariants hold across reachable states. |
| Blind falsification | 315 runs, 3 profiles, 7 traffic regimes | All 3 profiles FAIL overall. Large-filter thesis falsified. |
| Capacity-aware policy | 18 runs, 9 scenarios, composite vs cap-aware | 7/9 faster detection, 9% fewer false escalations. |
| Network friction | DPI drop (30%), MTU fragmentation, jitter | 3/3 passed. Full convergence at 30% drop rate. |
| Cooperative enclave bakeoff | 2160 runs, 9 scenarios, 4 approaches, 3 topologies, 20 seeds | Topology bottleneck propagation: GM=1.00 vs scalar-max=0.00. Dedup: tie. Breadth: weak. Bandwidth: 130x. |

---

## Architecture

```
Layer B: ghost_policy.h / capacity_aware_policy.py
  Fixed-threshold or capacity-aware dynamic baseline
  Reads saturation + epoch from Layer A
        │
        ▼
Layer A: ghost_meadow.h / ghost_meadow.py
  seed()    — add observation
  merge()   — OR bit arrays (the surviving primitive)
  query()   — test membership
  decay()   — epoch boundary reset
  state()   — telemetry export

Transport: ghost_transport.h (CRC-16)
  pack_burst()      — full bit array serialization
  unpack_burst()    — validate + merge
```

**Layer A** is a bounded Bloom filter with OR-merge (CRDT: commutative, associative, idempotent). It accumulates, merges, queries, decays, and reports. It has no policy and makes no decisions. The surviving value — transitive propagation through bottlenecks — is a property of Layer A's OR-merge, not of any policy logic.

**Layer B** is a policy/interpretation layer. The capacity-aware variant uses dynamic baseline tracking (`S_base(t) = 1 - exp(-k*lambda*t/m)`) instead of fixed thresholds. It is better than the original fixed-threshold policy (7/9 faster detection, 9% fewer false escalations) but cannot overcome Layer A's saturation limitations at m=4096.

**Profiles:** Tiny (64B), Micro (512B), Standard (4KB), Full (24KB). Only the Micro profile (m=4096, k=2, 512 bytes) retains demonstrated value. Larger profiles were tested and the security thesis for them was falsified.

---

## Why Scalar Baselines Are Not Enough in the Surviving Niche

The obvious question: why not just use scalar-max gossip?

In the partition-heal and corridor-bottleneck scenarios, scalar-max gossip carries a single number: the maximum observed pressure. When Node A sees events and relays through gateway G to Node B, scalar-max sends `max(pressure_A) = 1`. When Node C also relays through G, scalar-max sends `max(max(A), max(C)) = 1`. Node B cannot distinguish "one source saw something" from "many sources each saw something."

Ghost Meadow's OR-merge carries the full bit-state. If Nodes A and C each seeded different observations, their merged filter at G contains the union of both sets of bits. Node B receives a filter with higher saturation than either source alone — it sees the accumulated breadth. This is the transitive accumulation property.

This matters only when topology forces state through bottleneck relays. In well-connected topologies where every node can contact every other node directly, scalar-max is sufficient and 130x cheaper.

---

## Repository Contents

| Path | Description |
|------|-------------|
| `ghost_meadow.h` | Layer A core — Bloom filter with OR-merge, epoch decay (C++11, no STL) |
| `ghost_meadow.py` | Layer A MicroPython port — 512-byte Micro profile |
| `ghost_policy.h` | Layer B fixed-threshold policy (C++) |
| `ghost_transport.h` | CRC-16 wire protocol (C++) |
| `ghost_profiles.h` | Tiny/Micro/Standard/Full profile definitions |
| `ghost_persist.h` | Persistence layer — snapshot save/restore with CRC-16 |
| `ghost_actuator.h` | Actuation interface — zone-transition callbacks |
| `GhostMeadow.tla` | TLA+ formal specification — CRDT properties |
| `sim_main.cpp` | Convergence simulation (8 nodes, 500 steps) |
| `ghost_chaos.cpp` | 7 adversarial chaos scenarios |
| `benchmarks/security/` | Security evaluation suite — stages 1 and 2 |
| `benchmarks/security/capacity_aware_policy.py` | Capacity-aware dynamic-baseline policy |
| `benchmarks/enclave/` | Cooperative enclave bakeoff framework |
| `tests/security/` | Security and stage 2 test suites |
| `tests/enclave/` | Enclave bakeoff tests |
| `docs/blind_falsification_verdict.md` | Blind falsification results — thesis falsified |
| `docs/cooperative_enclave_bakeoff_verdict.md` | Enclave bakeoff verdict — surviving claim |
| `results/` | Raw CSV/JSONL outputs from all evaluation runs |

## Quick Start

```bash
# Core simulation (8 nodes, 500 steps)
g++ -std=c++11 -O2 -o sim_main sim_main.cpp && ./sim_main

# Chaos suite (7 adversarial scenarios)
g++ -std=c++11 -O2 -o ghost_chaos ghost_chaos.cpp && ./ghost_chaos

# Cross-language validation
python3 test_fp_and_crossval.py

# Capacity-aware policy tests (8/8)
python3 benchmarks/security/capacity_aware_policy.py

# Cooperative enclave bakeoff (~22 min, 2160 runs)
python3 benchmarks/enclave/run_enclave_bakeoff.py --seeds 20

# Enclave framework tests (33 tests)
python3 tests/enclave/test_enclave_bakeoff.py
```

---

## Status

Ghost Meadow is a narrowed research prototype. Its broad security-telemetry and general distributed-barometer interpretations were tested under blind falsification and pre-registered bakeoff evaluation, and did not survive. Its remaining demonstrated value is topology-sensitive transitive propagation in partitioned cooperative enclaves, at 130x bandwidth cost over scalar-max gossip. No hardware validation exists.

---

## Future Work

Consistent with the surviving claim only:

1. **Hardware bring-up of Micro profile** — ESP32 flash of the 512-byte filter, real radio merge over LoRa or BLE
2. **DTN/bottleneck topology evaluation** — systematic testing on delay-tolerant and relay-dependent network models
3. **Bandwidth reduction** — delta encoding, sparse payload compression, or sub-filter partitioning while preserving transitive accumulation
4. **Topology-aware policy** — policy variants that exploit knowledge of gateway position and partition state

---

## Research Note

This repository preserves both positive and negative results. The project began with broad claims about probabilistic swarm convergence as a general distributed primitive. Systematic adversarial testing, blind falsification, and comparative bakeoff evaluation narrowed those claims to a single surviving structural advantage. The negative results are documented alongside the positive ones because both are useful for understanding where OR-merge CRDT primitives do and do not provide value over simpler alternatives.

---

## License

MIT License

Copyright (c) 2025-2026 Adem Vessell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
