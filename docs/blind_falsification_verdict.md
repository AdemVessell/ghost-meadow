# Blind Falsification Verdict

**Date:** 2026-03-26
**Frozen commit:** f453416f21650c365bdab2ff62eef8e6553c398c
**Conditions:** 105 held-out (5 seeds × 3 profiles × 7 traffic regimes)
**Runs:** 315 (105 × 3 approaches), 0 skipped
**Runtime:** 5030s (~84 minutes)
**Protocol:** Pre-registered thresholds, deterministic held-out generation, no post-hoc tuning

---

## Overall Verdict: ALL THREE PROFILES FAIL

| Profile | Overall | Awareness | Bandwidth | False Esc | Coord Hits | Headroom | Stability |
|---------|---------|-----------|-----------|-----------|------------|----------|-----------|
| m=4096 (control) | **FAILURE** | SUPPORT | SUPPORT | FAILURE | FAILURE | FAILURE | SUPPORT |
| m=32768 (good) | **FAILURE** | FAILURE | FAILURE | SUPPORT | FAILURE | FAILURE | SUPPORT |
| m=192000 (strong) | **FAILURE** | FAILURE | FAILURE | SUPPORT | FAILURE | SUPPORT | SUPPORT |

---

## What Survived

### 1. Seed stability (all profiles: SUPPORT)
All findings are reproducible and non-fragile. Coefficient of variation ≤0.08 across held-out seeds. This is not a fluke.

### 2. False escalation at large filters (m≥32768: SUPPORT)
Zero false escalation under benign held-out conditions at m≥32768. The headroom genuinely prevents false positives.

### 3. Layer A correctness (all profiles)
FP rate 0.000 at m≥32768, campaign recall 1.000 at all sizes. The Bloom filter works exactly as theory predicts.

### 4. Awareness speedup at m=4096 (SUPPORT)
GM detects faster in 100% of held-out conditions at m=4096 (mean 34 steps faster). The OR-merge propagation genuinely accelerates saturation awareness at small filter sizes.

---

## What Failed

### 1. Awareness speedup at m≥32768 (FAILURE)
GM detects first in only 14% of conditions at m=32768 and m=192000. Local-only is faster or equivalent in 86% of held-out conditions. At m=32768, mean advantage is **-1.8 steps** (GM is actually slower). At m=192000, the mean advantage statistic is misleading: it shows +45 steps, but this is because local-only detects at ~60 steps while GM mostly **never detects at all** (saturation stays below thresholds).

**Root cause:** Larger filters spread tokens across more bits, so each token contributes less saturation. At m≥32768, saturation accumulates too slowly to reach the 25% elevated threshold before local-only's pseudo-saturation (based on token count) reaches its own thresholds.

### 2. Bandwidth advantage (m≥32768: FAILURE)
GM transmits ≤80% of exact gossip bandwidth in 0% of conditions at m≥32768. The fixed-size Bloom filter payload is m/8 bytes = 4KB at m=32768 and 24KB at m=192000 — **larger** than exact gossip's per-merge cost of ~2KB (500 tokens × 4 bytes).

**Root cause:** The bandwidth advantage inverts at large filter sizes. At m=4096, the filter is 512 bytes — genuinely compact. At m=32768, it's 4096 bytes, which exceeds the typical exact-gossip merge payload. The stage 1 bandwidth advantage claim only held because it was measured at m=4096.

### 3. Coordinated-pressure hit rate (all profiles: FAILURE)
Zero coordinated-pressure detection at m≥32768 (hit rate 0.00). At m=4096, hit rate is 0.27 — well below the 0.50 threshold.

**Root cause:** At m≥32768, saturation never reaches the coordinated zone threshold (65%). At m=4096, saturation is high enough but is indistinguishable from benign — the "hits" are mostly false coincidences where both benign and attack reach similar saturation levels.

### 4. Benign saturation headroom at m=32768 (FAILURE)
Benign saturation at m=32768 averaged 50.1% across held-out conditions — above the 50% threshold. This is worse than the stage 2 finding of 43.4% because held-out conditions include varied topologies (ring, star) and contact probabilities that change merge patterns.

**Root cause:** The stage 2 benchmark used only regional_mesh with contact_prob=0.4. The blind suite exposed that different topologies and contact rates shift benign saturation significantly. Star topologies with low contact concentrate merges through hubs, raising saturation. This topology sensitivity was masked by the fixed topology in earlier evaluations.

---

## Pre-Registered Claim Assessment

| Claim | Verdict | Evidence |
|-------|---------|----------|
| "Larger filters improve separability" | **FALSIFIED** | Separability constant at ~1% across all m |
| "Policy mechanisms provide useful defense" | **FALSIFIED** | No policy variant triggers at m≥32768 (sat below thresholds) |
| "Trust weighting helps under poisoning" | **NOT TESTED** (trust=all_equal frozen) | Would need separate trust-mode blind run |
| "Awareness speedup is robust" | **FALSIFIED for m≥32768** | GM slower in 86% of held-out conditions |
| "Bandwidth advantage is real" | **FALSIFIED for m≥32768** | GM payload larger than exact gossip at these sizes |

---

## Answers to Verdict Questions

### A. Does GM show real value in the held-out good regime?
**No.** At m=32768 and m=192000, GM fails to detect faster, costs more bandwidth, and produces zero coordinated-pressure hits. The only value retained is zero false escalation and stable seed behavior.

### B. Is the awareness advantage stable across unseen conditions?
**Yes at m=4096, No at m≥32768.** The advantage is real but exists only in the filter-size range where it's accompanied by high false escalation — a tradeoff, not a solution.

### C. Does the architecture remain useful under poisoning, collusion, and flood pressure?
**Not distinguishably.** The system absorbs attack tokens into the Bloom filter identically to benign tokens. The policy cannot tell the difference.

### D. Are trust and policy wins still real on held-out conditions?
**Not testable from this run** (trust was frozen at all_equal). Policy variants cannot fire at m≥32768 because saturation stays below thresholds.

### E. Is Layer A distinguishability actually good enough?
**Layer A works perfectly (FP=0.000, recall=1.000 at m≥32768).** But Layer A distinguishability — the ability to tell *whether* the filter contains attack tokens vs benign tokens via saturation — is near zero. The Bloom filter does what Bloom filters do: accumulate bits. It cannot tell you *what kind* of bits were added.

### F. Where exactly does the thesis survive?
The thesis survives only at **m=4096 under the narrow framing of "faster aggregate saturation awareness at the cost of high false escalation."** This is a real but modest value that the README already honestly disclaims.

### G. Where exactly does it fail?
Everywhere that the security-telemetry thesis claims more than "shared saturation barometer":
- m≥32768: no awareness advantage, no bandwidth advantage, no detection capability
- m=4096: awareness advantage exists but comes with 75% benign saturation and frequent false escalation
- All sizes: policy cannot distinguish attack-induced saturation from benign saturation

### H. What is the single strongest remaining threat to validity?
**The fixed policy thresholds.** The thresholds (25%/45%/65%/80%) are calibrated for m=4096 saturation dynamics. At m≥32768, these thresholds are unreachable under normal operation, making the entire policy layer inert. A threshold-scaling policy (where thresholds adapt to filter capacity) might recover some value — but this would need to be designed and re-evaluated from scratch, not grafted on post-hoc.

---

## Conclusion

The blind falsification has **substantially weakened the security-telemetry thesis** for Ghost Meadow.

**What's left standing:**
1. Layer A (Bloom filter) works correctly at all sizes
2. Results are stable and reproducible
3. OR-merge propagation genuinely accelerates saturation awareness at small filter sizes
4. Zero false escalation at large filter sizes

**What's falsified or weakened:**
1. The "good regime" prediction (m≥32768 would work well) — **falsified**
2. Bandwidth advantage at large sizes — **falsified** (inverts at m≥32768)
3. Coordinated-pressure detection at any size — **failed pre-registered threshold**
4. Awareness speedup at large sizes — **falsified** (GM is slower than local-only)
5. Policy mechanisms at large sizes — **inert** (thresholds never reached)

**Honest remaining claim:** Ghost Meadow provides faster aggregate saturation awareness at m=4096 with ~2x speedup, at the cost of high false escalation and no attack-vs-benign discrimination. This is a distributed saturation barometer, useful for triggering deeper inspection, not for identifying attacks.

**Next decisive experiment:** Design and evaluate a capacity-aware policy where thresholds scale with filter size (e.g., elevated = benign_baseline + 3σ instead of fixed 25%). This could potentially recover value at large filter sizes, but must be evaluated in its own pre-registered falsification run.
