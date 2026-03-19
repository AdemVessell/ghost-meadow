/**
 * ghost_actuator.h
 * Ghost Meadow — Actuation Interface (Zone Consequences)
 * Version 1.0 | Single-header, no-STL, embedded-friendly
 *
 * Gives zone escalation real consequences via function pointer dispatch.
 * Two built-in stubs:
 *   GM_ACTUATOR_ESP32  — printf to serial (for hardware targets)
 *   GM_ACTUATOR_SILENT — no-ops (for testing and simulation)
 *
 * Thread safety: none. Single-threaded embedded use assumed.
 */
#pragma once
#include "ghost_policy.h"  // brings in GhostActuator struct definition
#include <cstdio>

// ---------------------------------------------------------------------------
// gm_actuate() — dispatch to the correct function pointer by zone
// ---------------------------------------------------------------------------
static inline void gm_actuate(const GhostActuator* act, gm_u8 zone,
                               gm_u8 node_id, gm_f32 sat_pct,
                               gm_u32 sources, gm_u8 epoch)
{
    if (!act) return;
    switch (zone) {
        case 0: if (act->on_nominal) act->on_nominal(node_id, sat_pct, sources, epoch); break;
        case 1: if (act->on_yellow)  act->on_yellow(node_id, sat_pct, sources, epoch);  break;
        case 2: if (act->on_orange)  act->on_orange(node_id, sat_pct, sources, epoch);  break;
        case 3: if (act->on_red)     act->on_red(node_id, sat_pct, sources, epoch);     break;
        default: break;
    }
}

// ---------------------------------------------------------------------------
// ESP32 stub — printf to serial for hardware targets
// ---------------------------------------------------------------------------
static void _gm_esp32_nominal(gm_u8 nid, gm_f32 sat, gm_u32 src, gm_u8 ep) {
    printf("[ACT] node=%u zone=NOMINAL sat=%.1f%% sources=%u epoch=%u\n", nid, sat, src, ep);
}
static void _gm_esp32_yellow(gm_u8 nid, gm_f32 sat, gm_u32 src, gm_u8 ep) {
    printf("[ACT] node=%u zone=YELLOW  sat=%.1f%% sources=%u epoch=%u\n", nid, sat, src, ep);
}
static void _gm_esp32_orange(gm_u8 nid, gm_f32 sat, gm_u32 src, gm_u8 ep) {
    printf("[ACT] node=%u zone=ORANGE  sat=%.1f%% sources=%u epoch=%u\n", nid, sat, src, ep);
}
static void _gm_esp32_red(gm_u8 nid, gm_f32 sat, gm_u32 src, gm_u8 ep) {
    printf("[ACT] node=%u zone=RED     sat=%.1f%% sources=%u epoch=%u\n", nid, sat, src, ep);
}

static const GhostActuator GM_ACTUATOR_ESP32 = {
    _gm_esp32_nominal,
    _gm_esp32_yellow,
    _gm_esp32_orange,
    _gm_esp32_red
};

// ---------------------------------------------------------------------------
// Silent stub — no-ops for testing and simulation
// ---------------------------------------------------------------------------
static const GhostActuator GM_ACTUATOR_SILENT = {
    nullptr, nullptr, nullptr, nullptr
};
