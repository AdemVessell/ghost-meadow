# Cooperative Enclave Bakeoff Results

**Date:** 2026-03-26
**Runs:** 2160 (9 scenarios × 4 approaches × 3 topologies × 20 seeds)
**Runtime:** 1305s
**Profile:** m=4096, k=2, 32 nodes, contact_prob=0.3

---

## Question

Can tiny Ghost Meadow (512B, m=4096) act as a useful advisory distributed-pressure substrate inside a trusted cooperative enclave, and beat cheap scalar baselines on the properties those baselines structurally lose?

## Approaches Compared

| Approach | Description | Bandwidth/merge |
|----------|-------------|:---:|
| **gm_cap_aware** | Ghost Meadow m=4096 + capacity-aware policy | 512 bytes |
| **ewma_local** | Local EWMA pressure, no sharing | 0 bytes |
| **scalar_max** | Gossip max-pressure scalar | 4 bytes |
| **scalar_mean** | Gossip mean+count | 8 bytes |

## Topologies

| Topology | Structure |
|----------|-----------|
| corridor | Linear chain with skip-links |
| wing_gateway | Two dense clusters + 1-2 gateway bridges |
| campus_building | 4 clusters on a backbone ring |

## Results

### Overlap Scenarios (Dedup Test)

| Scenario | GM | EWMA | Max | Mean |
|----------|:--:|:----:|:---:|:----:|
| overlap_identical | 0.00 | 0.00 | 0.00 | **1.00** |
| overlap_moving | 0.00 | 0.00 | 0.00 | **1.00** |
| overlap_rebroadcast | 0.00 | 0.00 | 0.00 | **1.00** |

GM correctly deduplicates. But scalar-max also correctly deduplicates at 130× less bandwidth. Only scalar-mean over-amplifies.

### Breadth Scenarios (Distributed Signal Test)

| Scenario | GM | EWMA | Max | Mean |
|----------|:--:|:----:|:---:|:----:|
| breadth_weak | **0.10** | 0.00 | 0.00 | 1.00 (false) |
| breadth_gradient | 1.00 | 0.41 | 1.00 | 1.00 |
| breadth_vs_bustle | 1.00 | 1.00 | 1.00 | 1.00 |

GM is the only non-false-alarm approach to detect the weak distributed signal (breadth_weak: 10% node detection). But 10% is operationally weak.

### Realism Scenarios

| Scenario | GM | EWMA | Max | Mean |
|----------|:--:|:----:|:---:|:----:|
| shift_bustle | 1.00 | 1.00 | 1.00 | 1.00 |
| partition_heal | **1.00** | 0.00 | 0.00 | 1.00 (false) |
| corridor_bottleneck | **0.76** | 0.00 | 0.00 | 1.00 (false) |

**GM's strongest result:** In partitioned/bottlenecked topologies, OR-merge carries accumulated state through gateway nodes. Scalar-max (which gossips only one number) cannot propagate accumulated multi-source observations transitively.

### Bandwidth

| Approach | Bytes/node (typical) |
|----------|----:|
| EWMA local | 0 |
| Scalar-max | ~4K |
| Scalar-mean | ~8K |
| GM cap-aware | **~516K** |

GM costs 130× more than scalar-max per node.

## Verdict

**WEAK SUPPORT.** GM has one genuine unique advantage — transitive pressure propagation through topology bottlenecks — that scalar-max structurally cannot match. This advantage is real, stable across 20 seeds and 3 topologies, and operationally meaningful for gateway/partition scenarios.

However:
- GM ties scalar-max on dedup (both stay silent)
- GM's breadth detection is operationally weak (10%)
- GM costs 130× more bandwidth
- GM fires first under benign bustle (false alarm)

**Defensible claim:** "In topology-constrained cooperative enclaves, tiny Ghost Meadow provides transitive pressure propagation through OR-merge that scalar-max gossip structurally cannot match."

**Not defensible:** "GM beats cheap baselines on dedup or breadth at acceptable bandwidth cost."

## Reproducibility

```bash
# Full bakeoff (2160 runs, ~22 min)
python3 benchmarks/enclave/run_enclave_bakeoff.py --seeds 20

# Framework tests (33 tests)
python3 tests/enclave/test_enclave_bakeoff.py
```

Seeds: deterministic, starting at 70000 with spacing 137.

## Full Verdict

See [docs/cooperative_enclave_bakeoff_verdict.md](../../docs/cooperative_enclave_bakeoff_verdict.md).
