/**
 * ghost_policy.h
 * Ghost Meadow — Layer B Policy Module
 * Version 1.1 | Single-header, no-STL, embedded-friendly
 *
 * Layer B contract:
 *   - All decisions, escalation, and ghost triggers live here.
 *   - Reads Layer A via state() only.
 *   - Writes Layer A via set_zone() and inc_ghost_trigger() only.
 *   - Structurally decoupled: no direct access to Layer A internals.
 *
 * Escalation ladder:
 *   Zone 0 (nominal) — no action required
 *   Zone 1 (yellow)  — advisory, logged but no autonomy restriction
 *   Zone 2 (orange)  — autonomy reduced, operator notified
 *   Zone 3 (red)     — quorum guard enforced, autonomy suspended
 *
 * Quorum guard:
 *   Red-zone actions require merge_source_count >= quorum_k.
 *   Without quorum, red-zone transitions are blocked (stays orange).
 *
 * Autonomy parameter:
 *   Configurable via constructor (0.0 = full human control, 1.0 = full autonomy).
 *   Affects escalation thresholds — higher autonomy tolerates more saturation
 *   before escalating. Not hardcoded to human-in-loop.
 *
 * Thread safety: none. Single-threaded embedded use assumed.
 */
#pragma once
#include "ghost_meadow.h"

// ---------------------------------------------------------------------------
// Compile-time policy defaults (overridable)
// ---------------------------------------------------------------------------
#ifndef GP_SAT_YELLOW_DEFAULT
#define GP_SAT_YELLOW_DEFAULT 40.0f   // saturation % to enter yellow
#endif
#ifndef GP_SAT_ORANGE_DEFAULT
#define GP_SAT_ORANGE_DEFAULT 65.0f   // saturation % to enter orange
#endif
#ifndef GP_SAT_RED_DEFAULT
#define GP_SAT_RED_DEFAULT    85.0f   // saturation % to enter red
#endif
#ifndef GP_QUORUM_K_DEFAULT
#define GP_QUORUM_K_DEFAULT   3       // min merge sources for red-zone action
#endif
#ifndef GP_GHOST_TRIGGER_SAT
#define GP_GHOST_TRIGGER_SAT  50.0f   // saturation % at which ghost trigger fires
#endif

// ---------------------------------------------------------------------------
// Policy zone constants
// ---------------------------------------------------------------------------
enum GhostZone : gm_u8 {
    GP_ZONE_NOMINAL = 0,
    GP_ZONE_YELLOW  = 1,
    GP_ZONE_ORANGE  = 2,
    GP_ZONE_RED     = 3
};

// ---------------------------------------------------------------------------
// PolicyResult — returned by evaluate(), describes the action taken
// ---------------------------------------------------------------------------
struct GhostPolicyResult {
    gm_u8  zone_before;
    gm_u8  zone_after;
    gm_bool ghost_triggered;       // true if ghost trigger fired this cycle
    gm_bool quorum_met;            // true if merge_source_count >= quorum_k
    gm_bool red_blocked;           // true if red was warranted but quorum blocked it
    gm_f32  effective_sat_yellow;  // threshold used (after autonomy adjustment)
    gm_f32  effective_sat_orange;
    gm_f32  effective_sat_red;
};

// ---------------------------------------------------------------------------
// GhostPolicy — Layer B policy engine
//   Templated on the same M, K as GhostMeadow for type safety
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
class GhostPolicy {
public:
    // -----------------------------------------------------------------------
    // Constructor
    //   autonomy: 0.0 (full human control) to 1.0 (full autonomy)
    //   quorum_k: minimum merge sources required for red-zone action
    // -----------------------------------------------------------------------
    GhostPolicy(gm_f32 autonomy = 0.5f, gm_u32 quorum_k = GP_QUORUM_K_DEFAULT)
        : _autonomy(autonomy < 0.0f ? 0.0f : (autonomy > 1.0f ? 1.0f : autonomy))
        , _quorum_k(quorum_k)
        , _sat_yellow(GP_SAT_YELLOW_DEFAULT)
        , _sat_orange(GP_SAT_ORANGE_DEFAULT)
        , _sat_red(GP_SAT_RED_DEFAULT)
        , _ghost_trigger_sat(GP_GHOST_TRIGGER_SAT)
        , _ghost_armed(true)
        , _eval_count(0)
    {}

    // -----------------------------------------------------------------------
    // evaluate() — run policy against current meadow state
    // Reads meadow via state(), writes via set_zone() / inc_ghost_trigger()
    // Call once per tick / merge cycle
    // -----------------------------------------------------------------------
    GhostPolicyResult evaluate(GhostMeadow<M, K>& meadow) {
        GhostSwarmState st = meadow.state();
        GhostPolicyResult r;
        r.zone_before     = st.layer_b_zone;
        r.ghost_triggered = false;
        r.quorum_met      = (st.merge_source_count >= _quorum_k);
        r.red_blocked     = false;

        // Compute effective thresholds — higher autonomy raises thresholds
        // (tolerates more saturation before escalating)
        gm_f32 autonomy_shift = _autonomy * 15.0f; // up to +15% shift
        r.effective_sat_yellow = _sat_yellow + autonomy_shift;
        r.effective_sat_orange = _sat_orange + autonomy_shift;
        r.effective_sat_red    = _sat_red    + autonomy_shift;

        // Clamp effective thresholds to [0, 100]
        if (r.effective_sat_yellow > 100.0f) r.effective_sat_yellow = 100.0f;
        if (r.effective_sat_orange > 100.0f) r.effective_sat_orange = 100.0f;
        if (r.effective_sat_red    > 100.0f) r.effective_sat_red    = 100.0f;

        // Determine target zone from saturation
        gm_f32 sat = st.saturation_pct;
        gm_u8 target_zone = GP_ZONE_NOMINAL;
        if (sat >= r.effective_sat_red)         target_zone = GP_ZONE_RED;
        else if (sat >= r.effective_sat_orange) target_zone = GP_ZONE_ORANGE;
        else if (sat >= r.effective_sat_yellow) target_zone = GP_ZONE_YELLOW;

        // Quorum guard: block red if quorum not met
        if (target_zone == GP_ZONE_RED && !r.quorum_met) {
            target_zone = GP_ZONE_ORANGE;
            r.red_blocked = true;
        }

        r.zone_after = target_zone;
        meadow.set_zone(target_zone);

        // Ghost trigger — fires once when saturation crosses threshold
        gm_f32 ghost_threshold = _ghost_trigger_sat + (_autonomy * 10.0f);
        if (ghost_threshold > 100.0f) ghost_threshold = 100.0f;

        if (_ghost_armed && sat >= ghost_threshold) {
            meadow.inc_ghost_trigger();
            r.ghost_triggered = true;
            _ghost_armed = false; // one-shot per arm cycle
        }

        _eval_count++;
        return r;
    }

    // -----------------------------------------------------------------------
    // rearm_ghost() — re-enable ghost trigger (call after epoch boundary)
    // -----------------------------------------------------------------------
    void rearm_ghost() { _ghost_armed = true; }

    // -----------------------------------------------------------------------
    // Accessors / setters
    // -----------------------------------------------------------------------
    gm_f32 autonomy() const          { return _autonomy; }
    void set_autonomy(gm_f32 a)      { _autonomy = a < 0.0f ? 0.0f : (a > 1.0f ? 1.0f : a); }
    gm_u32 quorum_k() const          { return _quorum_k; }
    void set_quorum_k(gm_u32 k)      { _quorum_k = k; }
    gm_u32 eval_count() const        { return _eval_count; }

    void set_thresholds(gm_f32 yellow, gm_f32 orange, gm_f32 red) {
        _sat_yellow = yellow;
        _sat_orange = orange;
        _sat_red    = red;
    }

    void set_ghost_trigger_sat(gm_f32 sat) { _ghost_trigger_sat = sat; }

private:
    gm_f32 _autonomy;           // 0.0 = human control, 1.0 = full autonomy
    gm_u32 _quorum_k;           // min merge sources for red-zone
    gm_f32 _sat_yellow;         // base saturation threshold for yellow
    gm_f32 _sat_orange;         // base saturation threshold for orange
    gm_f32 _sat_red;            // base saturation threshold for red
    gm_f32 _ghost_trigger_sat;  // base saturation for ghost trigger
    gm_bool _ghost_armed;       // one-shot guard
    gm_u32 _eval_count;         // total evaluations
};

// ---------------------------------------------------------------------------
// Convenience typedef matching GhostMeadowDefault
// ---------------------------------------------------------------------------
typedef GhostPolicy<192000, 13> GhostPolicyDefault;

// ---------------------------------------------------------------------------
// Minimal Layer B test harness
// Returns 0 on pass, error count on failure
// ---------------------------------------------------------------------------
inline int gp_run_policy_tests() {
    int failures = 0;
    const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;

    // --- TEST 1: nominal zone at zero saturation ---
    {
        GhostMeadow<1024, 3> m(KEY, 0);
        GhostPolicy<1024, 3> p(0.5f, 2);
        GhostPolicyResult r = p.evaluate(m);
        if (r.zone_after != GP_ZONE_NOMINAL) failures++;
        if (r.ghost_triggered) failures++;
    }

    // --- TEST 2: escalation ladder (autonomy=0 for lowest thresholds) ---
    {
        GhostMeadow<1024, 3> m(KEY, 0);
        GhostPolicy<1024, 3> p(0.0f, 1);

        // Fill meadow to ~90% saturation
        for (gm_u32 i = 0; i < 800; i++) {
            gm_u8 buf[4];
            buf[0] = (gm_u8)(i & 0xFF);
            buf[1] = (gm_u8)((i >> 8) & 0xFF);
            buf[2] = 0xDE;
            buf[3] = 0xAD;
            m.seed(buf, 4);
        }

        // Need quorum for red — merge from another node
        GhostMeadow<1024, 3> other(KEY, 1);
        gm_u8 obs[] = {0xFF, 0xFE};
        other.seed(obs, 2);
        m.merge(other);

        GhostPolicyResult r = p.evaluate(m);
        // At ~90% sat with autonomy=0, thresholds are at defaults (40/65/85)
        // Should be red zone since sat > 85% and quorum met (1 source >= quorum_k=1)
        if (r.zone_after != GP_ZONE_RED) failures++;
        if (!r.quorum_met) failures++;
    }

    // --- TEST 3: quorum guard blocks red ---
    {
        GhostMeadow<1024, 3> m(KEY, 0);
        GhostPolicy<1024, 3> p(0.0f, 5); // quorum_k=5, impossible to meet

        // Fill to high saturation
        for (gm_u32 i = 0; i < 800; i++) {
            gm_u8 buf[4];
            buf[0] = (gm_u8)(i & 0xFF);
            buf[1] = (gm_u8)((i >> 8) & 0xFF);
            buf[2] = 0xAB;
            buf[3] = 0xCD;
            m.seed(buf, 4);
        }

        GhostPolicyResult r = p.evaluate(m);
        // Saturation high, but merge_source_count=0 < quorum_k=5
        if (r.quorum_met) failures++;
        if (!r.red_blocked) failures++;
        if (r.zone_after == GP_ZONE_RED) failures++; // must NOT be red
        if (r.zone_after != GP_ZONE_ORANGE) failures++; // should fall back to orange
    }

    // --- TEST 4: ghost trigger fires once ---
    {
        GhostMeadow<1024, 3> m(KEY, 0);
        GhostPolicy<1024, 3> p(0.0f, 1);
        p.set_ghost_trigger_sat(5.0f); // low threshold for test

        // Seed enough to cross 5% saturation
        for (gm_u32 i = 0; i < 100; i++) {
            gm_u8 buf[2] = { (gm_u8)(i & 0xFF), (gm_u8)((i >> 8) & 0xFF) };
            m.seed(buf, 2);
        }

        GhostPolicyResult r1 = p.evaluate(m);
        if (!r1.ghost_triggered) failures++;

        // Second eval — ghost should NOT trigger again (one-shot)
        GhostPolicyResult r2 = p.evaluate(m);
        if (r2.ghost_triggered) failures++;

        // Rearm and eval again — should trigger
        p.rearm_ghost();
        GhostPolicyResult r3 = p.evaluate(m);
        if (!r3.ghost_triggered) failures++;
    }

    // --- TEST 5: autonomy shifts thresholds ---
    {
        GhostMeadow<1024, 3> m(KEY, 0);
        GhostPolicy<1024, 3> p_low(0.0f, 1);
        GhostPolicy<1024, 3> p_high(1.0f, 1);

        // Fill to ~46% saturation (between low-autonomy yellow=40 and high-autonomy yellow=55)
        for (gm_u32 i = 0; i < 220; i++) {
            gm_u8 buf[4];
            buf[0] = (gm_u8)(i & 0xFF);
            buf[1] = (gm_u8)((i >> 8) & 0xFF);
            buf[2] = 0x11;
            buf[3] = 0x22;
            m.seed(buf, 4);
        }

        GhostPolicyResult r_low  = p_low.evaluate(m);
        GhostPolicyResult r_high = p_high.evaluate(m);

        // Low autonomy: yellow threshold=40, sat should be > 40 → at least yellow
        // High autonomy: yellow threshold=55, sat should be < 55 → nominal
        if (r_low.zone_after == GP_ZONE_NOMINAL) failures++;  // should be escalated
        if (r_high.zone_after != GP_ZONE_NOMINAL) failures++; // should be nominal
    }

    // --- TEST 6: eval_count increments ---
    {
        GhostMeadow<1024, 3> m(KEY, 0);
        GhostPolicy<1024, 3> p(0.5f, 1);
        p.evaluate(m);
        p.evaluate(m);
        p.evaluate(m);
        if (p.eval_count() != 3) failures++;
    }

    return failures;
}

// ---------------------------------------------------------------------------
// END ghost_policy.h
// ---------------------------------------------------------------------------
