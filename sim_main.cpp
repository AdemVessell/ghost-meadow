/**
 * sim_main.cpp
 * Ghost Meadow — Convergence Simulation Harness
 *
 * Instantiates 8 GhostMeadowDefault nodes, runs 500 steps with random
 * observations and OR-merges between nodes in simulated contact range.
 * Prints saturation every 50 steps, tracks convergence variance, and
 * reports when variance drops below 0.001.
 *
 * Compile: g++ -std=c++11 -O2 -o sim_main sim_main.cpp
 */
#include "ghost_meadow.h"
#include "ghost_policy.h"
#include "ghost_actuator.h"
#include "ghost_transport.h"
#include <cstdio>
#include <cmath>

// ---------------------------------------------------------------------------
// Simulation parameters
// ---------------------------------------------------------------------------
static const int NUM_NODES            = 8;
static const int NUM_STEPS            = 500;
static const int PRINT_INTERVAL       = 50;
static const float CONVERGE_THRESHOLD = 0.001f;
static const int CONTACT_RANGE        = 3;    // nodes within +/-3 can merge
static const int DECAY_STEP           = 250;  // epoch boundary at midpoint
static const gm_u64 MISSION_KEY      = 0xDEADBEEFCAFEBABEULL;

// ---------------------------------------------------------------------------
// xorshift64 — deterministic PRNG, no STL needed
// ---------------------------------------------------------------------------
static gm_u64 rng_state = 0x12345678ABCDEF01ULL;

static gm_u64 xorshift64() {
    gm_u64 x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static gm_u32 rng_u32() { return (gm_u32)(xorshift64() & 0xFFFFFFFFu); }
static float   rng_f32() { return (float)(rng_u32() % 10000) / 10000.0f; }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const char* zone_name(gm_u8 z) {
    switch (z) {
        case 0: return "nominal";
        case 1: return "yellow ";
        case 2: return "orange ";
        case 3: return "red    ";
        default: return "???    ";
    }
}

static float compute_variance(float* vals, int n) {
    float mean = 0.0f;
    for (int i = 0; i < n; i++) mean += vals[i];
    mean /= (float)n;
    float var = 0.0f;
    for (int i = 0; i < n; i++) {
        float d = vals[i] - mean;
        var += d * d;
    }
    return var / (float)n;
}

// ---------------------------------------------------------------------------
// Nodes — heap-allocated to avoid stack overflow (~120KB each)
// ---------------------------------------------------------------------------
static GhostMeadowDefault* nodes[NUM_NODES];
static GhostPolicyDefault  policy(0.5f, 3, &GM_ACTUATOR_SILENT);

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    // --- Transport tests ---
    printf("=== Transport Tests ===\n");
    int transport_failures = gm_run_transport_tests();
    if (transport_failures == 0)
        printf("  Transport tests: ALL PASSED (3/3)\n\n");
    else {
        printf("  Transport tests: FAILED (%d errors)\n", transport_failures);
        return 1;
    }

    // --- Actuation test ---
    printf("=== Actuation Test ===\n");
    {
        // Use ESP32 actuator on a small meadow to verify zone transition fires
        GhostMeadow<1024, 3> act_m(MISSION_KEY, 42);
        GhostPolicy<1024, 3> act_p(0.0f, 1, &GM_ACTUATOR_ESP32);

        // Fill to high saturation to trigger escalation through zones
        for (gm_u32 i = 0; i < 800; i++) {
            gm_u8 buf[4] = { (gm_u8)(i & 0xFF), (gm_u8)((i >> 8) & 0xFF), 0xAC, 0xDC };
            act_m.seed(buf, 4);
        }
        // Need a merge source for quorum
        GhostMeadow<1024, 3> act_other(MISSION_KEY, 43);
        gm_u8 obs[] = {0xFF};
        act_other.seed(obs, 1);
        act_m.merge(act_other);

        GhostPolicyResult r = act_p.evaluate(act_m);
        // Zone should have escalated from nominal (0) — actuator printf above confirms
        if (r.zone_after == GP_ZONE_NOMINAL) {
            printf("  Actuation test: FAILED (stayed nominal at high saturation)\n");
            return 1;
        }
        printf("  Actuation test: PASSED (zone transition fired)\n\n");
    }

    printf("=== Ghost Meadow Convergence Simulation ===\n");
    printf("Nodes: %d | Steps: %d | Contact range: +/-%d | Decay at step %d\n\n",
           NUM_NODES, NUM_STEPS, CONTACT_RANGE, DECAY_STEP);

    // Allocate nodes
    for (int i = 0; i < NUM_NODES; i++)
        nodes[i] = new GhostMeadowDefault(MISSION_KEY, (gm_u8)i);

    bool converged_pre_decay  = false;
    bool converged_post_decay = false;
    int  converge_step_pre    = -1;
    int  converge_step_post   = -1;

    for (int step = 1; step <= NUM_STEPS; step++) {

        // --- Epoch decay at midpoint ---
        if (step == DECAY_STEP) {
            printf("\n>>> EPOCH DECAY at step %d — clearing all nodes <<<\n\n", step);
            for (int i = 0; i < NUM_NODES; i++)
                nodes[i]->decay();
            policy.rearm_ghost();
            converged_pre_decay = converged_pre_decay; // preserve
        }

        // --- Seed phase: each node has ~60% chance to seed 1-3 observations ---
        for (int i = 0; i < NUM_NODES; i++) {
            if (rng_f32() < 0.6f) {
                int num_obs = 1 + (int)(rng_u32() % 3);
                for (int o = 0; o < num_obs; o++) {
                    gm_u32 val = rng_u32();
                    gm_u8 buf[4] = {
                        (gm_u8)(val & 0xFF),
                        (gm_u8)((val >> 8) & 0xFF),
                        (gm_u8)((val >> 16) & 0xFF),
                        (gm_u8)((val >> 24) & 0xFF)
                    };
                    nodes[i]->seed(buf, 4);
                }
            }
        }

        // --- Merge phase: pairs within contact range merge with ~40% chance ---
        for (int i = 0; i < NUM_NODES; i++) {
            for (int j = 0; j < NUM_NODES; j++) {
                if (i == j) continue;
                int dist = (i - j);
                if (dist < 0) dist = -dist;
                if (dist <= CONTACT_RANGE && rng_f32() < 0.4f) {
                    nodes[i]->merge(*nodes[j]);
                }
            }
        }

        // --- Policy phase ---
        for (int i = 0; i < NUM_NODES; i++)
            policy.evaluate(*nodes[i]);

        // --- Saturation & variance ---
        float sats[NUM_NODES];
        for (int i = 0; i < NUM_NODES; i++)
            sats[i] = nodes[i]->saturation_pct();

        float var = compute_variance(sats, NUM_NODES);

        // --- Print every PRINT_INTERVAL steps ---
        if (step % PRINT_INTERVAL == 0 || step == 1) {
            printf("--- Step %3d ---\n", step);
            for (int i = 0; i < NUM_NODES; i++) {
                GhostSwarmState st = nodes[i]->state();
                printf("  Node %d: sat=%6.2f%%  zone=%s  merges=%u  sources=%u\n",
                       i, sats[i], zone_name(st.layer_b_zone),
                       st.total_merges_lifetime, st.merge_source_count);
            }
            printf("  Variance: %.6f\n", var);
        }

        // --- Convergence detection ---
        if (step < DECAY_STEP && !converged_pre_decay && var < CONVERGE_THRESHOLD) {
            converged_pre_decay = true;
            converge_step_pre = step;
            printf("  >>> CONVERGED (pre-decay) at step %d — variance=%.6f < %.3f\n",
                   step, var, CONVERGE_THRESHOLD);
        }
        if (step > DECAY_STEP && !converged_post_decay && var < CONVERGE_THRESHOLD) {
            converged_post_decay = true;
            converge_step_post = step;
            printf("  >>> CONVERGED (post-decay) at step %d — variance=%.6f < %.3f\n",
                   step, var, CONVERGE_THRESHOLD);
        }
    }

    // --- Final summary ---
    printf("\n=== Final State (step %d) ===\n", NUM_STEPS);
    float final_sats[NUM_NODES];
    for (int i = 0; i < NUM_NODES; i++) {
        final_sats[i] = nodes[i]->saturation_pct();
        GhostSwarmState st = nodes[i]->state();
        printf("  Node %d: sat=%6.2f%%  zone=%s  epoch=%u  total_merges=%u\n",
               i, final_sats[i], zone_name(st.layer_b_zone),
               st.epoch_id, st.total_merges_lifetime);
    }
    float final_var = compute_variance(final_sats, NUM_NODES);
    printf("\nFinal variance: %.6f\n", final_var);

    if (converged_pre_decay)
        printf("Pre-decay convergence:  step %d\n", converge_step_pre);
    else
        printf("Pre-decay convergence:  NOT ACHIEVED\n");

    if (converged_post_decay)
        printf("Post-decay convergence: step %d\n", converge_step_post);
    else
        printf("Post-decay convergence: NOT ACHIEVED\n");

    printf("\n=== Simulation complete ===\n");

    // Cleanup
    for (int i = 0; i < NUM_NODES; i++)
        delete nodes[i];

    return 0;
}
