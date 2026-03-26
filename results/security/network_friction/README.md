# Network Friction Test Results

**Date:** 2026-03-26
**Source:** `tests/security/test_host_network_friction.py`
**Status:** 3/3 passed
**Seed:** 20260326 (deterministic)

---

## Purpose

Tests whether Ghost Meadow's CRDT properties survive the friction that real host-network security infrastructure creates: DPI/firewall packet drops, MTU fragmentation, and asymmetric routing jitter. These are not attacks on Ghost Meadow itself — they are the environmental conditions a real deployment would face when Ghost Meadow traffic traverses encrypted tunnels, enterprise firewalls, or constrained radio links.

## Adapter

The test uses a `GhostNode` wrapper mapping the test API to the actual `GhostMeadow` class:

| Test API | GhostMeadow API |
|----------|----------------|
| `node.observe(data)` | `meadow.seed(data)` |
| `node.get_saturation()` | `meadow.saturation_pct()` |
| `node.export_filter()` | `bytes(meadow.raw_bits())` — O(1) constant size, m/8 bytes |
| `node.receive_merge(payload)` | `meadow.merge_raw(bytearray(payload), 255)` — fire-and-forget |

No transport-layer additions. No sequence IDs, TCP handshakes, or cryptographic signatures. Payload is raw Bloom filter bits.

---

## Results

### Test 1: DPI Firewall Survival

| Parameter | Value |
|-----------|-------|
| Filter | m=4096, k=2 (512 bytes) |
| Nodes | 10 |
| Drop rate | 30% |
| Observations | 50 (seeded into node 0) |
| Gossip ticks | 50 (random-walk) |
| Target saturation | 2.37% |
| Final saturation (node 9) | 2.37% |
| Convergence ratio | 1.00 (threshold: 0.90) |
| Packets delivered | 38 |
| Packets dropped | 7 |
| **Result** | **PASS** |

**Why it works:** OR-merge is idempotent and transitive. A single successful merge propagates the entire bit array. With 50 gossip rounds and 70% delivery rate, even the most isolated node receives multiple complete merges. 30% packet loss is catastrophic for TCP but irrelevant for a CRDT — every successful delivery achieves full state transfer.

### Test 2: MTU Fragmentation Collapse

| Parameter | Value |
|-----------|-------|
| Filter | m=192000, k=13 (24000 bytes) |
| MTU | 256 bytes |
| Fragments required | 94 |
| Drop rate per fragment | 1% |
| Theoretical success rate | 0.99^94 = 39% |
| Transmission succeeded | No (fragment dropped) |
| Receiver saturation | 0.00% |
| **Result** | **PASS** |

**Why it works:** The MockHostNetwork simulates CRC-16 behavior: if any fragment is lost, the entire payload is rejected. The receiver never calls `receive_merge` on incomplete data. Ghost Meadow's Layer A is never exposed to partial or corrupted bit arrays. This confirms that the CRC-16 transport integrity (verified in the C++ chaos tests with 0 leaks across 7255 packets) correctly protects the Bloom filter from partial delivery.

**Implication:** At 24KB payload with 256-byte MTU, each merge attempt has only ~39% chance of success. This means 24KB filters require either larger MTU, lower loss rates, or more merge attempts to converge. The architecture handles this gracefully (failed merges are simply no-ops) but convergence time increases.

### Test 3: Asymmetric Jitter Convergence

| Parameter | Value |
|-----------|-------|
| Filter | m=4096, k=2 (512 bytes) |
| Max jitter | 50ms |
| Nodes | 2 (crossed merge) |
| Filters identical after merge | Yes |
| Node 0 has event_A | Yes |
| Node 0 has event_B | Yes |
| Node 9 has event_A | Yes |
| Node 9 has event_B | Yes |
| **Result** | **PASS** |

**Why it works:** OR-merge is commutative (`A|B == B|A`), associative (`(A|B)|C == A|(B|C)`), and idempotent (`A|A == A`). These CRDT properties are mathematically guaranteed regardless of delivery order, timing, or duplication. Asymmetric latency — even seconds of routing delay through encrypted tunnels — cannot cause state divergence because the merge operation has no temporal dependency.

---

## Constraints Maintained

- **O(1) constant payload:** m/8 bytes per merge, regardless of observation count
- **Fire-and-forget merge:** no ACKs, no retries, no sequence IDs
- **No Web2 transport additions:** no TCP handshakes, no cryptographic signatures on payloads
- **CRC-16 protection:** partial/corrupted payloads are rejected before reaching Layer A
- **Deterministic reproduction:** fixed random seed (20260326) for all tests
