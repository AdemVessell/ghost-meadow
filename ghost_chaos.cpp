/**
 * ghost_chaos.cpp
 * Ghost Meadow — Hostile Environment Stress Tests
 *
 * 7 adversarial scenarios that break every polite assumption in sim_main.
 * Compile: g++ -std=c++11 -O2 -o ghost_chaos ghost_chaos.cpp
 */
#include "ghost_meadow.h"
#include "ghost_policy.h"
#include "ghost_actuator.h"
#include "ghost_transport.h"
#include <cstdio>
#include <cmath>
#include <cstring>

// ---------------------------------------------------------------------------
// PRNG — xorshift64, resettable per scenario for isolation
// ---------------------------------------------------------------------------
static gm_u64 rng_state;
static void   rng_reset(gm_u64 seed) { rng_state = seed; }
static gm_u64 xorshift64() {
    gm_u64 x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x; return x;
}
static gm_u32 rng_u32() { return (gm_u32)(xorshift64() & 0xFFFFFFFFu); }
static float  rng_f32() { return (float)(rng_u32() % 10000) / 10000.0f; }

static const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static float compute_variance(float* v, int n) {
    float mean = 0; for (int i = 0; i < n; i++) mean += v[i]; mean /= n;
    float var = 0; for (int i = 0; i < n; i++) { float d = v[i]-mean; var += d*d; }
    return var / n;
}
static void seed_random(GhostMeadowDefault* node) {
    gm_u32 val = rng_u32();
    gm_u8 buf[4] = { (gm_u8)(val), (gm_u8)(val>>8), (gm_u8)(val>>16), (gm_u8)(val>>24) };
    node->seed(buf, 4);
}

// ===================================================================
// SCENARIO 1: BLACKOUT GAUNTLET
// 32 nodes, 80% contact drop, 1000 steps, variance < 0.05
// ===================================================================
static bool scenario_blackout() {
    const int N = 32, STEPS = 1000, RANGE = 3;
    rng_reset(0xB1AC007CAFEBAB0ULL);

    GhostMeadowDefault* nodes[N];
    for (int i = 0; i < N; i++) nodes[i] = new GhostMeadowDefault(KEY, (gm_u8)i);

    for (int step = 0; step < STEPS; step++) {
        // Seed
        for (int i = 0; i < N; i++)
            if (rng_f32() < 0.6f) { int c = 1+(rng_u32()%3); for (int j=0;j<c;j++) seed_random(nodes[i]); }
        // Merge with 80% drop → only 20% of contacts succeed
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                if (i == j) continue;
                int d = i-j; if (d<0) d=-d;
                if (d <= RANGE && rng_f32() < 0.08f)  // 40% base * 20% survival = 8%
                    nodes[i]->merge(*nodes[j]);
            }
    }

    float sats[N];
    for (int i = 0; i < N; i++) sats[i] = nodes[i]->saturation_pct();
    float var = compute_variance(sats, N);
    for (int i = 0; i < N; i++) delete nodes[i];

    bool pass = var < 0.05f;
    printf("[%s] BLACKOUT GAUNTLET — 32 nodes, 80%% drop, 1000 steps — variance=%.6f (threshold <0.05)\n",
           pass ? "PASS" : "FAIL", var);
    return pass;
}

// ===================================================================
// SCENARIO 2: NODE DEATH
// 8 nodes, 3 die at step 100, survivors converge, forensic snapshots intact
// ===================================================================
static bool scenario_node_death() {
    const int N = 8, STEPS = 300, RANGE = 3;
    const int DEATH_STEP = 100;
    const int DEAD_START = 5; // nodes 5,6,7 die
    rng_reset(0xDEAD0DE000000001ULL);

    GhostMeadowDefault* nodes[N];
    for (int i = 0; i < N; i++) nodes[i] = new GhostMeadowDefault(KEY, (gm_u8)i);

    for (int step = 0; step < STEPS; step++) {
        // At death step, trigger decay on dying nodes so they have a forensic snapshot
        if (step == DEATH_STEP) {
            for (int i = DEAD_START; i < N; i++)
                nodes[i]->decay();
        }

        for (int i = 0; i < N; i++) {
            if (step >= DEATH_STEP && i >= DEAD_START) continue; // dead
            if (rng_f32() < 0.6f) { int c = 1+(rng_u32()%3); for (int j=0;j<c;j++) seed_random(nodes[i]); }
        }
        for (int i = 0; i < N; i++) {
            if (step >= DEATH_STEP && i >= DEAD_START) continue;
            for (int j = 0; j < N; j++) {
                if (i == j) continue;
                if (step >= DEATH_STEP && j >= DEAD_START) continue;
                int d = i-j; if (d<0) d=-d;
                if (d <= RANGE && rng_f32() < 0.4f)
                    nodes[i]->merge(*nodes[j]);
            }
        }
    }

    // Check survivor convergence
    float surv_sats[5];
    for (int i = 0; i < 5; i++) surv_sats[i] = nodes[i]->saturation_pct();
    float surv_var = compute_variance(surv_sats, 5);

    // Check dead nodes' forensic snapshots are intact (nonzero from pre-death epoch)
    bool snapshots_ok = true;
    for (int i = DEAD_START; i < N; i++) {
        const gm_u8* snap = nodes[i]->epoch_snapshot(0); // most recent snapshot
        gm_u32 nonzero = 0;
        for (gm_u32 b = 0; b < nodes[i]->raw_bytes(); b++)
            if (snap[b]) nonzero++;
        if (nonzero == 0) snapshots_ok = false;
    }

    for (int i = 0; i < N; i++) delete nodes[i];

    bool pass = surv_var < 0.01f && snapshots_ok;
    printf("[%s] NODE DEATH — survivors variance=%.6f (<0.01), snapshots=%s\n",
           pass ? "PASS" : "FAIL", surv_var, snapshots_ok ? "intact" : "EMPTY");
    return pass;
}

// ===================================================================
// SCENARIO 3: POISON NODE
// Node 0 seeds 10x, assert ghost triggers fire, others below red 200 steps
// ===================================================================
static bool scenario_poison() {
    const int N = 8, STEPS = 500, RANGE = 2;
    rng_reset(0x501500DE0CAFEULL);

    GhostMeadowDefault* nodes[N];
    for (int i = 0; i < N; i++) nodes[i] = new GhostMeadowDefault(KEY, (gm_u8)i);

    // Per-node policies with autonomy=0 (lowest thresholds for sensitivity)
    GhostPolicy<192000, 13> policies[N] = {
        {0.0f, 1}, {0.0f, 1}, {0.0f, 1}, {0.0f, 1},
        {0.0f, 1}, {0.0f, 1}, {0.0f, 1}, {0.0f, 1}
    };

    bool others_below_red = true;

    for (int step = 0; step < STEPS; step++) {
        // Node 0: poison — 10x seeding
        for (int s = 0; s < 30; s++) seed_random(nodes[0]);

        // Others: normal 1-3
        for (int i = 1; i < N; i++)
            if (rng_f32() < 0.6f) { int c = 1+(rng_u32()%3); for (int j=0;j<c;j++) seed_random(nodes[i]); }

        // Merge
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                if (i == j) continue;
                int d = i-j; if (d<0) d=-d;
                if (d <= RANGE && rng_f32() < 0.4f)
                    nodes[i]->merge(*nodes[j]);
            }

        // Policy
        for (int i = 0; i < N; i++) {
            GhostPolicyResult r = policies[i].evaluate(*nodes[i]);
            // Check others below red for first 200 steps
            if (step < 200 && i > 0 && r.zone_after == GP_ZONE_RED)
                others_below_red = false;
        }
    }

    GhostSwarmState s0 = nodes[0]->state();
    bool ghost_fired = s0.ghost_trigger_count > 0;

    for (int i = 0; i < N; i++) delete nodes[i];

    bool pass = ghost_fired && others_below_red;
    printf("[%s] POISON NODE — ghost_triggers=%u on node 0, others_below_red_200=%s\n",
           pass ? "PASS" : "FAIL", s0.ghost_trigger_count,
           others_below_red ? "yes" : "NO");
    return pass;
}

// ===================================================================
// SCENARIO 4: ASYMMETRIC TOPOLOGY
// 16-node chain vs full mesh, report convergence step ratio
// ===================================================================
static int run_topology(int n, bool chain_only, gm_u64 seed) {
    rng_reset(seed);
    GhostMeadowDefault** nodes = new GhostMeadowDefault*[n];
    for (int i = 0; i < n; i++) nodes[i] = new GhostMeadowDefault(KEY, (gm_u8)i);

    const int MAX_STEPS = 5000;
    int converge_step = MAX_STEPS;
    // Aggressive seeding — each node gets 50 observations/step so saturation
    // actually diverges across topology before merges equalize it.
    // Only odd-indexed nodes seed (asymmetric load) to create real imbalance.

    for (int step = 0; step < MAX_STEPS; step++) {
        for (int i = 0; i < n; i++) {
            int rate = (i % 2 == 0) ? 5 : 50; // even nodes seed little, odd seed lots
            for (int s = 0; s < rate; s++) seed_random(nodes[i]);
        }

        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++) {
                if (i == j) continue;
                int d = i-j; if (d<0) d=-d;
                bool in_range = chain_only ? (d <= 1) : true;
                if (in_range && rng_f32() < 0.4f)
                    nodes[i]->merge(*nodes[j]);
            }

        float sats[16];
        for (int i = 0; i < n; i++) sats[i] = nodes[i]->saturation_pct();
        float var = compute_variance(sats, n);
        if (var < 0.001f && step > 10) { converge_step = step; break; }
    }

    for (int i = 0; i < n; i++) delete nodes[i];
    delete[] nodes;
    return converge_step;
}

static bool scenario_asymmetric() {
    const int N = 16;
    const gm_u64 SEED = 0xA500E7E1CCAFE0ULL;

    int chain_steps = run_topology(N, true, SEED);
    int mesh_steps  = run_topology(N, false, SEED);

    float ratio = (mesh_steps > 0) ? (float)chain_steps / (float)mesh_steps : 999.0f;
    bool chain_converged = chain_steps < 5000;
    bool mesh_converged  = mesh_steps < 5000;
    bool pass = chain_converged && mesh_converged;

    printf("[%s] ASYMMETRIC TOPOLOGY — chain=%d steps, mesh=%d steps, ratio=%.1fx\n",
           pass ? "PASS" : "FAIL", chain_steps, mesh_steps, ratio);
    return pass;
}

// ===================================================================
// SCENARIO 5: EPOCH STORM
// Decay every 50 steps, 5 epochs, re-converge within 30 steps each time
// ===================================================================
static bool scenario_epoch_storm() {
    const int N = 8, RANGE = 3;
    const int DECAY_INTERVAL = 50, NUM_EPOCHS = 5;
    const int TOTAL_STEPS = DECAY_INTERVAL * NUM_EPOCHS;
    rng_reset(0xE00C570FACE0ULL);

    GhostMeadowDefault* nodes[N];
    for (int i = 0; i < N; i++) nodes[i] = new GhostMeadowDefault(KEY, (gm_u8)i);
    GhostPolicyDefault policy(0.5f, 3);

    bool all_reconverge = true;
    int reconverge_steps[NUM_EPOCHS];
    for (int i = 0; i < NUM_EPOCHS; i++) reconverge_steps[i] = -1;

    int current_epoch = 0;
    bool epoch_converged = false;

    for (int step = 1; step <= TOTAL_STEPS; step++) {
        // Decay at epoch boundaries
        if (step > 1 && ((step - 1) % DECAY_INTERVAL == 0)) {
            for (int i = 0; i < N; i++) nodes[i]->decay();
            policy.rearm_ghost();
            current_epoch++;
            epoch_converged = false;
        }

        // Asymmetric seeding — node 0 seeds 20x, others seed 2-3x
        // Creates real variance that must be resolved by merges each epoch
        for (int i = 0; i < N; i++) {
            if (i == 0) {
                for (int s = 0; s < 20; s++) seed_random(nodes[i]);
            } else if (rng_f32() < 0.6f) {
                int c = 1+(rng_u32()%3);
                for (int j = 0; j < c; j++) seed_random(nodes[i]);
            }
        }

        // Merge — contact range ±3, 40% probability
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                if (i == j) continue;
                int d = i-j; if (d<0) d=-d;
                if (d <= RANGE && rng_f32() < 0.4f)
                    nodes[i]->merge(*nodes[j]);
            }

        // Policy
        for (int i = 0; i < N; i++) policy.evaluate(*nodes[i]);

        // Convergence within epoch
        float sats[N];
        for (int i = 0; i < N; i++) sats[i] = nodes[i]->saturation_pct();
        float var = compute_variance(sats, N);

        if (!epoch_converged && var < 0.005f) {
            int steps_since_decay = ((step - 1) % DECAY_INTERVAL) + 1;
            reconverge_steps[current_epoch] = steps_since_decay;
            epoch_converged = true;
            if (steps_since_decay > 30) all_reconverge = false;
        }
    }

    // Check forensic snapshots — last epoch snapshot should have nonzero bits
    bool snapshots_ok = true;
    for (int i = 0; i < N; i++) {
        const gm_u8* snap = nodes[i]->epoch_snapshot(0);
        gm_u32 nonzero = 0;
        for (gm_u32 b = 0; b < nodes[i]->raw_bytes(); b++)
            if (snap[b]) nonzero++;
        if (nonzero == 0) snapshots_ok = false;
    }

    for (int i = 0; i < N; i++) delete nodes[i];

    // Any epoch that never converged (-1) is a failure
    for (int i = 0; i < NUM_EPOCHS; i++)
        if (reconverge_steps[i] < 0) all_reconverge = false;

    bool pass = all_reconverge && snapshots_ok;
    printf("[%s] EPOCH STORM — reconverge steps: [", pass ? "PASS" : "FAIL");
    for (int i = 0; i < NUM_EPOCHS; i++)
        printf("%d%s", reconverge_steps[i], i < NUM_EPOCHS-1 ? "," : "");
    printf("] (max 30), snapshots=%s\n", snapshots_ok ? "intact" : "EMPTY");
    return pass;
}

// ===================================================================
// SCENARIO 6: PACKET CORRUPTION
// 15% of burst packets corrupted, assert rejected, no bad merges
// ===================================================================
static bool scenario_packet_corruption() {
    const int N = 8, STEPS = 500, RANGE = 3;
    rng_reset(0xC0000E7EDCAFEULL);

    GhostMeadowDefault* nodes[N];
    for (int i = 0; i < N; i++) nodes[i] = new GhostMeadowDefault(KEY, (gm_u8)i);

    const gm_u32 BUF_SIZE = GhostMeadowDefault::BYTES + GM_TRANSPORT_OVERHEAD;
    gm_u8* wire = new gm_u8[BUF_SIZE];

    gm_u32 total_packets = 0;
    gm_u32 corrupted_packets = 0;
    gm_u32 rejected_packets = 0;
    gm_u32 successful_merges = 0;
    gm_u32 corrupted_merges = 0; // must stay 0

    for (int step = 0; step < STEPS; step++) {
        // Seed
        for (int i = 0; i < N; i++)
            if (rng_f32() < 0.6f) { int c = 1+(rng_u32()%3); for (int j=0;j<c;j++) seed_random(nodes[i]); }

        // Merge via transport layer with corruption
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                if (i == j) continue;
                int d = i-j; if (d<0) d=-d;
                if (d <= RANGE && rng_f32() < 0.4f) {
                    gm_u32 packed = gm_pack_burst(*nodes[j], wire, BUF_SIZE);
                    if (packed == 0) continue;
                    total_packets++;

                    bool is_corrupt = rng_f32() < 0.15f;
                    if (is_corrupt) {
                        // Flip a random byte in the packet
                        gm_u32 flip_pos = rng_u32() % packed;
                        wire[flip_pos] ^= (gm_u8)(1 + (rng_u32() % 255));
                        corrupted_packets++;
                    }

                    GhostMergeResult r = gm_unpack_burst(*nodes[i], wire, packed);
                    if (is_corrupt) {
                        if (!r.canary_ok)
                            rejected_packets++;
                        else
                            corrupted_merges++; // BAD — corruption wasn't caught
                    } else {
                        if (r.canary_ok) successful_merges++;
                    }
                }
            }
    }

    float sats[N];
    for (int i = 0; i < N; i++) sats[i] = nodes[i]->saturation_pct();
    float var = compute_variance(sats, N);

    delete[] wire;
    for (int i = 0; i < N; i++) delete nodes[i];

    // CRC-16 catches all single-bit, double-bit, and odd-count errors,
    // plus all burst errors up to 16 bits. Random byte-flip corruption
    // has ~1/65536 chance of going undetected. We allow up to 0.5%.
    float false_accept_rate = corrupted_packets > 0
        ? (float)corrupted_merges / (float)corrupted_packets : 0.0f;
    bool checksum_ok = false_accept_rate < 0.005f;
    bool convergence_ok = var < 0.02f;
    bool pass = checksum_ok && convergence_ok;

    printf("[%s] PACKET CORRUPTION — %u packets, %u corrupted, %u rejected, "
           "%u leaked (%.2f%%), variance=%.6f\n",
           pass ? "PASS" : "FAIL", total_packets, corrupted_packets,
           rejected_packets, corrupted_merges, false_accept_rate * 100.0f, var);
    return pass;
}

// ===================================================================
// SCENARIO 7: LATE JOINER
// 8 nodes run 300 steps, node 9 joins cold, measure catch-up
// ===================================================================
static bool scenario_late_joiner() {
    const int N = 9, RANGE = 3, TOTAL_STEPS = 800, JOIN_STEP = 300;
    rng_reset(0x1A7E001ECAFE0ULL);

    GhostMeadowDefault* nodes[N];
    for (int i = 0; i < N; i++) nodes[i] = new GhostMeadowDefault(KEY, (gm_u8)i);

    gm_u32 joiner_merges_at_catchup = 0;
    bool caught_up = false;
    int catchup_step = -1;

    for (int step = 0; step < TOTAL_STEPS; step++) {
        int active = (step < JOIN_STEP) ? 8 : N;

        // Aggressive seeding — 30 obs/step/node so swarm has real saturation
        for (int i = 0; i < active; i++) {
            // Node 8 (joiner) seeds normally after joining; others seed heavily
            int rate = (step >= JOIN_STEP && i == 8) ? 5 : 30;
            for (int s = 0; s < rate; s++) seed_random(nodes[i]);
        }

        // Merge — established nodes merge freely; joiner has limited bandwidth
        // (10% of bit array per merge via merge_raw to simulate burst-window constraint)
        for (int i = 0; i < active; i++)
            for (int j = 0; j < active; j++) {
                if (i == j) continue;
                int d = i-j; if (d<0) d=-d;
                if (d <= RANGE && rng_f32() < 0.4f) {
                    if (i == 8 || j == 8) {
                        // Bandwidth-limited merge for joiner: only 10% of bytes
                        gm_u32 chunk = nodes[j]->raw_bytes() / 10;
                        gm_u32 offset = (rng_u32() % 10) * chunk;
                        // Build partial buffer
                        gm_u8 partial[24000];
                        memset(partial, 0, sizeof(partial));
                        memcpy(partial + offset, nodes[j]->raw_bits() + offset, chunk);
                        nodes[i]->merge_raw(partial, nodes[j]->raw_bytes(), nodes[j]->node_id());
                    } else {
                        nodes[i]->merge(*nodes[j]);
                    }
                }
            }

        // Check catch-up after join
        if (step >= JOIN_STEP && !caught_up) {
            float avg = 0;
            for (int i = 0; i < 8; i++) avg += nodes[i]->saturation_pct();
            avg /= 8.0f;

            float joiner_sat = nodes[8]->saturation_pct();
            float gap = avg - joiner_sat;
            if (gap < 0) gap = -gap;

            if (avg > 1.0f && (gap / avg) < 0.05f) { // require avg > 1% to avoid trivial
                caught_up = true;
                catchup_step = step - JOIN_STEP;
                joiner_merges_at_catchup = nodes[8]->total_merges();
            }
        }
    }

    for (int i = 0; i < N; i++) delete nodes[i];

    bool pass = caught_up;
    printf("[%s] LATE JOINER — caught up in %d steps, %u merges after joining\n",
           pass ? "PASS" : "FAIL", catchup_step, joiner_merges_at_catchup);
    return pass;
}

// ===================================================================
// MAIN
// ===================================================================
int main() {
    printf("=== GHOST MEADOW CHAOS SIMULATION ===\n\n");

    int passed = 0, total = 7;
    if (scenario_blackout())          passed++;
    if (scenario_node_death())        passed++;
    if (scenario_poison())            passed++;
    if (scenario_asymmetric())        passed++;
    if (scenario_epoch_storm())       passed++;
    if (scenario_packet_corruption()) passed++;
    if (scenario_late_joiner())       passed++;

    printf("\n=== RESULT: %d/%d PASSED ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
