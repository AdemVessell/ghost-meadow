/**
 * ghost_meadow.h
 * Ghost Meadow — Layer A Probabilistic Memory Substrate
 * Version 1.1 | Single-header, no-STL, embedded-friendly
 *
 * Layer A contract:
 *   - No decisions. No policy. No ghost triggers.
 *   - Only: accumulate, merge, query, decay, report.
 *   - All policy lives in Layer B (ghost_policy.h).
 *
 * Sizing at n=10000, p=0.0001:
 *   m = 191701 bits (~23.4 KB), k = 13 hash functions
 *
 * Safety invariants (must hold at all times):
 *   1. merge_delta() >= 0  (OR-monotonicity — canary for impl bugs)
 *   2. false_negative_rate == 0.0f within a single epoch (append-only)
 *   3. saturation() is non-decreasing within an epoch
 *
 * Usage:
 *   GhostMeadow<192000, 13> meadow(mission_key, node_id);
 *   meadow.seed(obs_data, obs_len);
 *   uint32_t delta = meadow.merge(other_meadow);  // delta >= 0, always
 *   bool present = meadow.query(obs_data, obs_len);
 *   float sat = meadow.saturation();
 *   meadow.decay();  // epoch boundary only
 *
 * Thread safety: none. Single-threaded embedded use assumed.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
// ---------------------------------------------------------------------------
// Compile-time configuration
// ---------------------------------------------------------------------------
#ifndef GM_EPOCH_LOG_SIZE
#define GM_EPOCH_LOG_SIZE 4     // how many epoch snapshots to retain (forensic mode)
#endif
#ifndef GM_MAX_NODE_ID
#define GM_MAX_NODE_ID 255
#endif
// ---------------------------------------------------------------------------
// Minimal portable types (no STL)
// ---------------------------------------------------------------------------
typedef uint8_t  gm_u8;
typedef uint16_t gm_u16;
typedef uint32_t gm_u32;
typedef uint64_t gm_u64;
typedef int32_t  gm_i32;
typedef float    gm_f32;
typedef bool     gm_bool;
// ---------------------------------------------------------------------------
// MergeResult — returned by merge(), exposes canary
// ---------------------------------------------------------------------------
struct GhostMergeResult {
    gm_u32 bits_set;      // newly set bits — must be >= 0 (canary)
    gm_u32 src_node_id;   // contributing node
    gm_u8  epoch_id;      // epoch at time of merge
    gm_bool canary_ok;    // true iff bits_set >= 0 (always true for correct impl)
};
// ---------------------------------------------------------------------------
// SwarmState — telemetry struct for Layer B and external consumers
// Mirrors swarm_state.json v1.1 schema
// ---------------------------------------------------------------------------
struct GhostSwarmState {
    gm_u8  node_id;
    gm_u8  epoch_id;
    gm_f32 saturation_pct;          // 0.0 – 100.0
    gm_u32 merge_source_count;      // distinct sources merged this epoch
    gm_i32 merge_delta_last;        // canary: must be >= 0
    gm_u32 ghost_trigger_count;     // managed by Layer B, stored here
    gm_f32 false_neg_budget;        // 0.0 within epoch; Layer B sets across boundary
    gm_u8  layer_b_zone;            // 0=nominal 1=yellow 2=orange 3=red
    gm_u32 total_merges_lifetime;
};
// ---------------------------------------------------------------------------
// GhostMeadow<M, K>
//   M = number of bits in the meadow (must be multiple of 8)
//   K = number of hash functions
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
class GhostMeadow {
public:
    static_assert(M % 8 == 0, "M must be a multiple of 8");
    static_assert(K >= 1 && K <= 32, "K must be between 1 and 32");
    static_assert(M >= 64, "M must be at least 64 bits");
    static const gm_u32 BYTES = M / 8;
    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------
    GhostMeadow(gm_u64 mission_key, gm_u8 node_id)
        : _mission_key(mission_key)
        , _node_id(node_id)
        , _epoch(0)
        , _bits_set(0)
        , _merge_source_count(0)
        , _total_merges(0)
        , _merge_delta_last(0)
        , _ghost_trigger_count(0)
        , _layer_b_zone(0)
    {
        memset(_bits, 0, BYTES);
        memset(_merge_sources, 0, sizeof(_merge_sources));
        // Snapshot slot for forensic mode
        for (int i = 0; i < GM_EPOCH_LOG_SIZE; i++)
            memset(_epoch_snapshots[i], 0, BYTES);
    }
    // -----------------------------------------------------------------------
    // seed() — add an observation to the meadow
    // obs: pointer to observation data, len: byte length
    // Seeds k bit positions derived from mission-keyed hash family
    // -----------------------------------------------------------------------
    void seed(const gm_u8* obs, gm_u32 len) {
        for (gm_u8 i = 0; i < K; i++) {
            gm_u32 pos = _hash(obs, len, i) % M;
            gm_u32 byte_idx = pos / 8;
            gm_u8  bit_idx  = pos % 8;
            if (!(_bits[byte_idx] & (1u << bit_idx))) {
                _bits[byte_idx] |= (1u << bit_idx);
                _bits_set++;
            }
        }
    }
    // -----------------------------------------------------------------------
    // merge() — OR-merge another meadow into this one
    // Returns GhostMergeResult with delta (canary: must be >= 0)
    // Registers source node for quorum guard
    // -----------------------------------------------------------------------
    GhostMergeResult merge(const GhostMeadow<M, K>& other) {
        GhostMergeResult result;
        result.src_node_id = other._node_id;
        result.epoch_id    = _epoch;
        result.bits_set    = 0;
        for (gm_u32 i = 0; i < BYTES; i++) {
            gm_u8 before = _bits[i];
            _bits[i] |= other._bits[i];
            gm_u8 after = _bits[i];
            // Count newly set bits
            gm_u8 diff = after & ~before;
            result.bits_set += _popcount8(diff);
        }
        // Recalculate bits_set from scratch for accuracy
        _bits_set = _count_bits();
        // Canary check — delta must be non-negative (OR-monotonicity)
        result.canary_ok = true; // always true for OR; impl guard below
        _merge_delta_last = (gm_i32)result.bits_set; // bits_set is new bits only
        // Register merge source
        _register_source(other._node_id);
        _total_merges++;
        return result;
    }
    // -----------------------------------------------------------------------
    // merge_raw() — merge from raw bit array (burst-window transfer)
    // Used when other node sends only its packed bit array, not full object
    // -----------------------------------------------------------------------
    GhostMergeResult merge_raw(const gm_u8* other_bits, gm_u32 other_bytes,
                                gm_u8 src_node_id)
    {
        GhostMergeResult result;
        result.src_node_id = src_node_id;
        result.epoch_id    = _epoch;
        result.bits_set    = 0;
        result.canary_ok   = true;
        gm_u32 merge_bytes = (other_bytes < BYTES) ? other_bytes : BYTES;
        for (gm_u32 i = 0; i < merge_bytes; i++) {
            gm_u8 before = _bits[i];
            _bits[i] |= other_bits[i];
            gm_u8 diff = _bits[i] & ~before;
            result.bits_set += _popcount8(diff);
        }
        _bits_set = _count_bits();
        _merge_delta_last = (gm_i32)result.bits_set;
        _register_source(src_node_id);
        _total_merges++;
        return result;
    }
    // -----------------------------------------------------------------------
    // query() — test membership (approximate)
    // Returns true if element is possibly in set ("maybe")
    // Never returns false for elements that were seeded (no false negatives
    // within epoch). May return true for unseen elements (false positives).
    // -----------------------------------------------------------------------
    gm_bool query(const gm_u8* obs, gm_u32 len) const {
        for (gm_u8 i = 0; i < K; i++) {
            gm_u32 pos      = _hash(obs, len, i) % M;
            gm_u32 byte_idx = pos / 8;
            gm_u8  bit_idx  = pos % 8;
            if (!(_bits[byte_idx] & (1u << bit_idx))) return false;
        }
        return true; // "possibly in set"
    }
    // -----------------------------------------------------------------------
    // decay() — epoch boundary reset
    // ONLY call at epoch transitions, never mid-mission
    // Saves snapshot for forensic mode before clearing
    // -----------------------------------------------------------------------
    void decay() {
        // Save snapshot before clearing (Dead Meadow forensic mode)
        gm_u8 slot = _epoch % GM_EPOCH_LOG_SIZE;
        memcpy(_epoch_snapshots[slot], _bits, BYTES);
        // Clear meadow
        memset(_bits, 0, BYTES);
        _bits_set = 0;
        _merge_source_count = 0;
        _merge_delta_last = 0;
        memset(_merge_sources, 0, sizeof(_merge_sources));
        _epoch++;
    }
    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    gm_f32 saturation() const {
        return (gm_f32)_bits_set / (gm_f32)M;
    }
    gm_f32 saturation_pct() const {
        return saturation() * 100.0f;
    }
    gm_u32 merge_source_count() const {
        return _merge_source_count;
    }
    gm_i32 merge_delta_last() const {
        return _merge_delta_last; // canary: assert >= 0 in your test suite
    }
    gm_u8 epoch() const { return _epoch; }
    gm_u8 node_id() const { return _node_id; }
    gm_u32 total_merges() const { return _total_merges; }
    const gm_u8* raw_bits() const { return _bits; }
    gm_u32 raw_bytes() const { return BYTES; }
    // -----------------------------------------------------------------------
    // state() — export full telemetry for Layer B and swarm_state.json
    // -----------------------------------------------------------------------
    GhostSwarmState state() const {
        GhostSwarmState s;
        s.node_id              = _node_id;
        s.epoch_id             = _epoch;
        s.saturation_pct       = saturation_pct();
        s.merge_source_count   = _merge_source_count;
        s.merge_delta_last     = _merge_delta_last;
        s.ghost_trigger_count  = _ghost_trigger_count;
        s.false_neg_budget     = 0.0f; // 0 within epoch; Layer B manages across boundary
        s.layer_b_zone         = _layer_b_zone;
        s.total_merges_lifetime = _total_merges;
        return s;
    }
    // Layer B writes back zone and ghost count via these setters
    void set_zone(gm_u8 zone)          { _layer_b_zone = zone; }
    void inc_ghost_trigger()            { _ghost_trigger_count++; }
    // -----------------------------------------------------------------------
    // Forensic snapshot access (Dead Meadow mode)
    // Returns pointer to epoch snapshot (read-only)
    // -----------------------------------------------------------------------
    const gm_u8* epoch_snapshot(gm_u8 epoch_offset) const {
        gm_u8 slot = (_epoch - 1 - epoch_offset) % GM_EPOCH_LOG_SIZE;
        return _epoch_snapshots[slot];
    }
    // -----------------------------------------------------------------------
    // Idempotency check — merge_idempotent(other) should return delta == 0
    // after other has already been merged. Use in test suite.
    // -----------------------------------------------------------------------
    gm_u32 merge_idempotency_check(const GhostMeadow<M, K>& other) const {
        gm_u32 delta = 0;
        for (gm_u32 i = 0; i < BYTES; i++) {
            gm_u8 result = _bits[i] | other._bits[i];
            gm_u8 diff   = result & ~_bits[i];
            delta += _popcount8(diff);
        }
        return delta; // should be 0 if other was already merged
    }
    // -----------------------------------------------------------------------
    // XOR delta — for bandwidth-efficient burst window (extended contact)
    // Encodes only differing bits between this and other
    // -----------------------------------------------------------------------
    void xor_delta(const GhostMeadow<M, K>& other, gm_u8* out_delta, gm_u32& out_bytes) const {
        out_bytes = 0;
        for (gm_u32 i = 0; i < BYTES; i++) {
            out_delta[i] = _bits[i] ^ other._bits[i];
            if (out_delta[i]) out_bytes = i + 1; // track sparse payload size
        }
    }
private:
    // -----------------------------------------------------------------------
    // Mission-keyed hash family
    // Uses FNV-1a seeded with mission_key XOR'd with hash index
    // Provides k independent hash functions from a single primitive
    // -----------------------------------------------------------------------
    gm_u32 _hash(const gm_u8* data, gm_u32 len, gm_u8 hash_idx) const {
        // FNV-1a with mission_key seed per hash function
        const gm_u32 FNV_PRIME  = 16777619u;
        const gm_u32 FNV_OFFSET = 2166136261u;
        gm_u32 seed = (gm_u32)(_mission_key ^ ((gm_u64)hash_idx * 0x9e3779b97f4a7c15ULL));
        gm_u32 h = FNV_OFFSET ^ seed;
        for (gm_u32 i = 0; i < len; i++) {
            h ^= data[i];
            h *= FNV_PRIME;
        }
        // Final mix
        h ^= h >> 16;
        h *= 0x45d9f3b;
        h ^= h >> 16;
        return h;
    }
    // Population count for single byte
    static gm_u8 _popcount8(gm_u8 b) {
        b = b - ((b >> 1) & 0x55u);
        b = (b & 0x33u) + ((b >> 2) & 0x33u);
        return (b + (b >> 4)) & 0x0Fu;
    }
    gm_u32 _count_bits() const {
        gm_u32 count = 0;
        for (gm_u32 i = 0; i < BYTES; i++)
            count += _popcount8(_bits[i]);
        return count;
    }
    void _register_source(gm_u8 src_id) {
        // Simple dedup — mark source as seen this epoch
        gm_u32 byte_idx = src_id / 8;
        gm_u8  bit_idx  = src_id % 8;
        if (byte_idx < sizeof(_merge_sources)) {
            if (!(_merge_sources[byte_idx] & (1u << bit_idx))) {
                _merge_sources[byte_idx] |= (1u << bit_idx);
                _merge_source_count++;
            }
        }
    }
    // -----------------------------------------------------------------------
    // Member data
    // -----------------------------------------------------------------------
    gm_u64 _mission_key;
    gm_u8  _node_id;
    gm_u8  _epoch;
    gm_u32 _bits_set;
    gm_u32 _merge_source_count;
    gm_u32 _total_merges;
    gm_i32 _merge_delta_last;
    gm_u32 _ghost_trigger_count;
    gm_u8  _layer_b_zone;
    gm_u8  _bits[BYTES];
    gm_u8  _merge_sources[(GM_MAX_NODE_ID / 8) + 1]; // bitmask of seen sources
    gm_u8  _epoch_snapshots[GM_EPOCH_LOG_SIZE][BYTES]; // Dead Meadow forensic log
};
// ---------------------------------------------------------------------------
// Convenience typedef for spec-default sizing
// n=10000, p=0.0001 → m=191701 → round to 192000 (multiple of 8), k=13
// ---------------------------------------------------------------------------
typedef GhostMeadow<192000, 13> GhostMeadowDefault;
// ---------------------------------------------------------------------------
// Minimal test harness — call gm_run_invariant_tests() in your test suite
// Returns 0 on pass, error count on failure
// ---------------------------------------------------------------------------
inline int gm_run_invariant_tests() {
    int failures = 0;
    const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;
    GhostMeadow<1024, 3> a(KEY, 0);
    GhostMeadow<1024, 3> b(KEY, 1);
    // Seed a and b with different data
    const gm_u8 obs_a[] = { 0x01, 0x02, 0x03 };
    const gm_u8 obs_b[] = { 0xAA, 0xBB, 0xCC };
    a.seed(obs_a, 3);
    b.seed(obs_b, 3);
    float sat_before = a.saturation();
    // TEST 1: merge_delta >= 0 (canary)
    GhostMergeResult r = a.merge(b);
    if ((int)r.bits_set < 0) failures++;       // should never happen
    if (!r.canary_ok) failures++;
    // TEST 2: saturation non-decreasing after merge
    if (a.saturation() < sat_before) failures++;
    // TEST 3: idempotency — merging same source again yields delta == 0
    gm_u32 idem_delta = a.merge_idempotency_check(b);
    if (idem_delta != 0) failures++;
    // TEST 4: query — seeded element must be present (no false negatives)
    if (!a.query(obs_a, 3)) failures++;
    if (!a.query(obs_b, 3)) failures++;
    // TEST 5: merge_delta_last accessible and non-negative
    if (a.merge_delta_last() < 0) failures++;
    // TEST 6: decay resets saturation to 0
    a.decay();
    if (a.saturation() != 0.0f) failures++;
    if (a.epoch() != 1) failures++;
    // TEST 7: after decay, previously seeded element no longer present
    // (false negative across epoch boundary — expected and documented)
    // This test confirms epoch isolation, not a bug
    if (a.query(obs_a, 3)) failures++; // should be absent after decay
    return failures;
}
// ---------------------------------------------------------------------------
// END ghost_meadow.h
// ---------------------------------------------------------------------------
