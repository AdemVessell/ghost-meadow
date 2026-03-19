# Ghost Meadow

**Swarms don't need to share facts — they need to share priors.**

Ghost Meadow is a probabilistic memory substrate for embedded swarm systems. Each node maintains a Bloom filter that accumulates local observations and merges with nearby nodes via OR during brief contact windows. Nodes never exchange raw data — they exchange compressed belief states. Over time, the swarm converges on a shared probabilistic picture of the environment without any node knowing what any other node actually saw.

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

Transport: ghost_transport.h
  pack_burst()      — full bit array serialization
  unpack_burst()    — validate + merge
  xor_delta_pack()  — bandwidth-efficient delta
  Physical layer: function pointer typedef (LoRa/BLE/serial/laser)
```

## File map

| File | Description |
|------|-------------|
| `ghost_meadow.h` | Layer A — Bloom filter core. Seed, merge, query, decay. Sized for n=10000, p=0.0001 (192000 bits, 13 hashes). |
| `ghost_policy.h` | Layer B — Zone escalation (nominal/yellow/orange/red), quorum guard, ghost trigger, autonomy parameter. |
| `ghost_actuator.h` | Actuation interface — function pointer dispatch on zone transitions. ESP32 and silent stubs included. |
| `ghost_transport.h` | Burst-window serialization with magic/checksum header. XOR delta for extended contact. Pluggable physical layer. |
| `ghost_meadow.py` | MicroPython port of Layer A for ESP32. 512-byte memory footprint (m=4096, k=2). |
| `sim_main.cpp` | Convergence simulation — 8 nodes, 500 steps, proves OR-merge convergence with variance tracking. |
| `swarm_state.schema.json` | JSON Schema v1.1 for telemetry export format. |

## Quick start

```bash
g++ -std=c++11 -O2 -o sim_main sim_main.cpp
./sim_main
```

MicroPython port:
```bash
python3 ghost_meadow.py    # runs 7 invariant tests
```

## Simulation output

The simulation instantiates 8 nodes with contact range ±3 and runs 500 steps. Epoch decay at step 250 resets all nodes, then re-convergence occurs.

```
=== Transport Tests ===
  Transport tests: ALL PASSED (3/3)

=== Actuation Test ===
[ACT] node=42 zone=RED     sat=89.9% sources=1 epoch=0
  Actuation test: PASSED (zone transition fired)

=== Ghost Meadow Convergence Simulation ===
Nodes: 8 | Steps: 500 | Contact range: +/-3 | Decay at step 250

--- Step 100 ---
  Node 0: sat=  6.40%  zone=nominal  merges=135  sources=3
  Node 3: sat=  6.43%  zone=nominal  merges=243  sources=6
  Node 7: sat=  6.47%  zone=nominal  merges=121  sources=3
  Variance: 0.000463

--- Step 200 ---
  Node 0: sat= 11.95%  zone=nominal  merges=263  sources=3
  Node 3: sat= 11.96%  zone=nominal  merges=505  sources=6
  Node 7: sat= 11.93%  zone=nominal  merges=232  sources=3
  Variance: 0.000306

--- Step 400 ---
  Node 0: sat=  9.28%  zone=nominal  merges=479  sources=3
  Node 3: sat=  9.26%  zone=nominal  merges=960  sources=6
  Node 7: sat=  9.24%  zone=nominal  merges=463  sources=3
  Variance: 0.000381
```

Saturation variance stays below 0.009 across all 500 steps. Nodes converge despite asymmetric seeding and local-only contact. Central nodes (3-4) accumulate more merges due to topology; edge nodes (0, 7) have fewer sources but maintain the same saturation within 0.2%.

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

These hold at all times and are verified by the embedded test suites:

1. **OR-monotonicity**: `merge_delta >= 0`. Merging never clears bits.
2. **Zero false negatives** within a single epoch. If you seeded it, `query()` returns true.
3. **Saturation is non-decreasing** within an epoch.
4. **Epoch isolation**: `decay()` clears all bits. False negatives across epoch boundary by design.
5. **Quorum guard**: Red zone requires N distinct merge sources. Without quorum, capped at orange.

## License

Unlicensed. Do what you want with it.
