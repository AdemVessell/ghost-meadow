# Ghost Meadow

**Swarms don't need to share facts — they need to share priors.**

| | |
|---|---|
| **Status** | Simulation-only — all layers implemented, all tests passing, cross-language interop verified |
| **Strongest evidence** | 7/7 adversarial chaos scenarios passed; CRDT properties formally verified in TLA+; CRC-16 transport with zero integrity leaks across all test runs |
| **Not yet shown** | No hardware validation — zero bytes have gone over a real radio. No ESP32 flash, no power profiling, no multi-device over-the-air merge, no field test |
| **Fair criticism** | This is a thoroughly tested *simulation* of an embedded system, not a tested embedded system. The jump from sim to hardware is where most projects fail. Until someone flashes this onto real nodes and runs a real merge over a real radio, the core claim — that OR-merge convergence works under real-world constraints — is unverified. |

Ghost Meadow is a probabilistic memory substrate for embedded swarm systems. Each node maintains a Bloom filter that accumulates local observations and merges with nearby nodes via OR during brief contact windows. Nodes never exchange raw data — they exchange compressed belief states. Over time, the swarm converges on a shared probabilistic picture of the environment without any node knowing what any other node actually saw.

> **Looking for hardware testers.** If you have an ESP32 or STM32 and want to run the first real flash test, see [HARDWARE_WANTED.md](HARDWARE_WANTED.md) or open an issue.

---


## What problem does this solve?

Swarm nodes operating under bandwidth, power, and contact-time constraints can't share full state. Traditional approaches require structured messages, consensus protocols, or shared clocks. Ghost Meadow requires none of these. A single OR of two bit arrays — achievable in microseconds over any physical layer — propagates information transitively through the swarm.

## Why is this novel?

Three ideas that don't appear together in prior work:

1. **False positives as a feature.** In a standard Bloom filter, false positives are a cost you tolerate. Here, shared false positives between nodes *are* shared priors — they represent implicit agreement about the environment's state, even when that agreement is probabilistically wrong. The swarm acts on saturation level, not on individual query results.

2. **The 0dB0 constraint.** Zero-knowledge baseline: every node starts every epoch with an empty bit array. No pre-loaded models, no training data, no assumptions. All information is acquired through observation and merge. This makes the system auditable — you can always answer "where did this belief come from?" by tracing merge sources.

3. **Two-layer architecture with structural decoupling.** Layer A (the Bloom filter) has no policy, no decisions, no thresholds. It only accumulates, merges, queries, decays, and reports. Layer B (the policy engine) reads Layer A's telemetry and makes all decisions — zone escalation, quorum guards, ghost triggers. The layers communicate through a narrow interface (`state()` read, `set_zone()` write). This means you can swap policy without touching the memory substrate, or vice versa.

## Architecture

```
Layer B: ghost_policy.h          Layer B: ghost_actuator.h
  evaluate() → zone 0-3           on_nominal / on_yellow
  quorum guard                     on_orange  / on_red
  ghost trigger                    (ESP32 stub / silent stub)
        │ reads state()                   ▲ fires on zone change
        │ writes set_zone()               │
        ▼                                 │
Layer A: ghost_meadow.h ──────────────────┘
  seed()    — add observation
  merge()   — OR bit arrays
  query()   — test membership
  decay()   — epoch boundary reset
  state()   — telemetry export

Transport: ghost_transport.h (v1.1 — CRC-16)
  pack_burst()      — full bit array serialization
  unpack_burst()    — validate + merge
  xor_delta_pack()  — bandwidth-efficient delta
  Physical layer: function pointer typedef (LoRa/BLE/serial/laser)
```

## File map

| File | Description |
|------|-------------|
| `ghost_meadow.h` | Layer A — Bloom filter core. Seed, merge, query, decay. Default: n=10000, p=0.0001 (192000 bits, 13 hashes). |
| `ghost_policy.h` | Layer B — 4-zone escalation (nominal/yellow/orange/red), quorum guard, ghost trigger, autonomy parameter. |
| `ghost_actuator.h` | Actuation interface — function pointer dispatch on zone transitions. ESP32 and silent stubs included. |
| `ghost_transport.h` | Wire protocol v1.1 — burst + delta packing with CRC-16 integrity. Pluggable physical layer. |
| `ghost_meadow.py` | MicroPython port of Layer A. 512-byte footprint (m=4096, k=2). Hash-interop verified against C++. |
| `sim_main.cpp` | Convergence simulation — 8 nodes, 500 steps, epoch decay + re-convergence. |
| `ghost_chaos.cpp` | 7 adversarial chaos scenarios — blackout, node death, poison, asymmetric topology, epoch storm, packet corruption, late joiner. |
| `test_hash_crossval.cpp` | C++ side of cross-language hash + FP rate validation. |
| `test_fp_and_crossval.py` | Python side — FP rate empirical vs. theoretical, CRDT property proofs. |
| `ghost_profiles.h` | Configurable node profiles — Tiny/Micro/Standard/Full sizing with heterogeneous merge support. |
| `ghost_persist.h` | Persistence layer — snapshot save/restore to flat buffer with CRC-16 integrity. |
| `swarm_visualizer.py` | Network topology visualizer — terminal (ANSI) and matplotlib replay of merge propagation. |
| `index.html` | Interactive browser demo — JS port of core algorithm with real-time swarm visualization. |
| `GhostMeadow.tla` | Formal TLA+ specification — CRDT properties, quorum guard, convergence proofs. |
| `GhostMeadow.cfg` | TLC model checker configuration for small-model verification. |
| `test_profiles_persist.cpp` | Tests for configurable profiles and persistence layer. |
| `swarm_state.schema.json` | JSON Schema v1.1 for telemetry export format. |

## Quick start

```bash
# Convergence simulation (8 nodes, 500 steps)
g++ -std=c++11 -O2 -o sim_main sim_main.cpp && ./sim_main

# Chaos test suite (7 adversarial scenarios)
g++ -std=c++11 -O2 -o ghost_chaos ghost_chaos.cpp && ./ghost_chaos

# Cross-language hash validation
g++ -std=c++11 -O2 -o test_hash_crossval test_hash_crossval.cpp && ./test_hash_crossval

# Python cross-validation (FP rate + CRDT properties)
python3 test_fp_and_crossval.py

# MicroPython invariant tests
python3 ghost_meadow.py

# Profile & persistence tests
g++ -std=c++11 -O2 -o test_profiles_persist test_profiles_persist.cpp && ./test_profiles_persist

# Swarm topology visualizer (terminal)
python3 swarm_visualizer.py --nodes 8 --steps 200

# Swarm topology visualizer (matplotlib)
python3 swarm_visualizer.py --plot --nodes 16 --topology ring

# Interactive browser demo — open in any browser
open ghost_meadow_wasm.html
```

## Test results

All tests passing as of the current release. Here's what's been verified:

### Convergence simulation
8 nodes, contact range ±3, 500 steps with epoch decay at step 250.
- Pre-decay convergence: step 1 (variance < 0.001)
- Post-decay re-convergence: step 251
- Saturation spread at step 500: 14.75%–14.93% across all 8 nodes (variance 0.0026)

### Chaos suite — 7/7 passed

| Scenario | Result |
|----------|--------|
| Blackout gauntlet (32 nodes, 80% drop, 1000 steps) | variance=0.010 < 0.05 |
| Node death (kill nodes mid-run) | survivor variance=0.000025, snapshots intact |
| Poison node (adversarial saturation) | ghost trigger fired, others stayed below red |
| Asymmetric topology (chain vs mesh) | chain 2.1x slower than mesh, both converge |
| Epoch storm (rapid consecutive decays) | reconverge in 1 step each, snapshots intact |
| Packet corruption (CRC-16 validation) | 7255 packets, 1128 corrupted, **0 leaked** (0.00%) |
| Late joiner (node enters mid-epoch) | caught up in 23 steps, 33 merges |

### Cross-language validation — 8/8 passed

| Test | Result |
|------|--------|
| Hash interop C++ ↔ Python | Bit-identical across all test vectors |
| FP rate vs. theory (C++) | Within 1.09x of theoretical at all saturation levels |
| FP rate vs. theory (Python) | Within 1.03x of theoretical at all saturation levels |
| Zero false negatives | 0 missed across 1000 seeded observations |
| Merge commutativity (A∣B == B∣A) | Verified |
| Merge associativity ((A∣B)∣C == A∣(B∣C)) | Verified |
| Merge idempotency (A∣A == A) | Verified |
| MicroPython invariants (7 tests) | All passed |

### Transport integrity (CRC-16)
- Exhaustive single-bit flip test: every corrupted packet rejected
- 0 integrity leaks across all chaos and cross-validation runs

## What's proven

- OR-merge convergence under hostile conditions (blackout, node death, poison, asymmetric topology)
- Epoch decay and re-convergence work correctly
- CRC-16 wire integrity catches all tested corruption patterns with zero leaks
- False positive rates match Bloom filter theory within 10%
- CRDT properties hold: commutativity, associativity, idempotency
- C++ and MicroPython implementations produce bit-identical hashes
- Policy engine correctly escalates zones and fires ghost triggers on adversarial saturation

- Heterogeneous merge between different-sized nodes preserves OR-monotonicity
- Persistence save/restore preserves query results and saturation across reboot
- CRC-16 integrity on persist buffers catches corruption
- TLA+ model verifies CRDT properties (commutativity, associativity, idempotency, OR-monotonicity)
- TLA+ quorum guard invariant holds across all reachable states

## What's NOT proven (yet)

- No ESP32 or STM32 flash/run — code is designed for embedded but untested on metal
- No real radio transport — LoRa, BLE, or any physical layer
- No power/memory profiling on actual hardware
- No multi-device over-the-air merge
- No formal security audit
- No long-duration soak test (hours/days of continuous operation)

## Hardware targets

- **ESP32** — primary target. C++ headers compile under ESP-IDF. MicroPython port for rapid prototyping.
- **STM32** — any Cortex-M with 32KB+ RAM. No STL, no dynamic allocation, no threads.
- **Any C++11 embedded target** — headers are self-contained with only `<stdint.h>`, `<stddef.h>`, `<string.h>`.

Memory per node (default sizing):
- Bit array: 24,000 bytes (192,000 bits)
- Epoch snapshots (4): 96,000 bytes
- Total: ~120 KB per node

MicroPython port: ~512 bytes per node (m=4096, k=2).

## Safety invariants

These hold at all times and are verified by the test suites:

1. **OR-monotonicity**: `merge_delta >= 0`. Merging never clears bits.
2. **Zero false negatives** within a single epoch. If you seeded it, `query()` returns true.
3. **Saturation is non-decreasing** within an epoch.
4. **Epoch isolation**: `decay()` clears all bits. False negatives across epoch boundary by design.
5. **Quorum guard**: Red zone requires N distinct merge sources. Without quorum, capped at orange.
6. **CRC-16 integrity**: Corrupted packets are rejected before merge. Zero leaks verified.

## What's next

1. **ESP32 bring-up** — flash onto real hardware, measure RAM/flash/cycle counts
2. **Real radio transport** — LoRa or BLE, first over-the-air merge
3. **Multi-device field test** — 3+ nodes, real observations, real convergence
4. **Long-duration soak test** — hours of continuous operation, measure drift
5. **TLC model checking** — run TLA+ spec through TLC with larger state spaces
6. **WASM compilation** — compile C++ core to WASM via Emscripten for native-speed browser demo

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

