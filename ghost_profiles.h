/**
 * ghost_profiles.h
 * Ghost Meadow — Configurable Node Profiles
 * Version 1.0 | Single-header, no-STL, embedded-friendly
 *
 * Defines hardware profiles for heterogeneous swarms where nodes have
 * different memory budgets. Each profile specifies Bloom filter sizing
 * (m bits, k hashes) appropriate for the target platform.
 *
 * Heterogeneous merge rules:
 *   - Nodes with different m values can still merge via merge_raw()
 *   - The smaller array is OR'd into the prefix of the larger array
 *   - Bits beyond the smaller node's range are unaffected
 *   - This is safe because OR-monotonicity still holds
 *   - FP rates will differ across nodes (smaller nodes have higher FP)
 *
 * Thread safety: none. Single-threaded embedded use assumed.
 */
#pragma once
#include "ghost_meadow.h"
#include "ghost_policy.h"

// ---------------------------------------------------------------------------
// Profile definitions — compile-time constants for each platform
// ---------------------------------------------------------------------------

/**
 * Profile: TINY — ATtiny / low-RAM MCU
 *   m=512 bits (64 bytes), k=2
 *   Capacity: ~35 observations before 50% saturation
 *   RAM: 64 bytes per node (+ snapshots)
 */
#define GM_PROFILE_TINY_M    512
#define GM_PROFILE_TINY_K    2

/**
 * Profile: MICRO — MicroPython / ESP8266 / small ESP32
 *   m=4096 bits (512 bytes), k=2
 *   Matches ghost_meadow.py default
 *   Capacity: ~1400 observations before 50% saturation
 *   RAM: 512 bytes per node
 */
#define GM_PROFILE_MICRO_M   4096
#define GM_PROFILE_MICRO_K   2

/**
 * Profile: STANDARD — ESP32 with comfortable RAM
 *   m=32768 bits (4 KB), k=7
 *   Capacity: ~3200 observations at p=0.01
 *   RAM: 4 KB per node
 */
#define GM_PROFILE_STANDARD_M  32768
#define GM_PROFILE_STANDARD_K  7

/**
 * Profile: FULL — Desktop / simulation / high-RAM embedded
 *   m=192000 bits (~24 KB), k=13
 *   Matches GhostMeadowDefault (n=10000, p=0.0001)
 *   RAM: ~24 KB per node
 */
#define GM_PROFILE_FULL_M    192000
#define GM_PROFILE_FULL_K    13

// ---------------------------------------------------------------------------
// Typedefs for each profile
// ---------------------------------------------------------------------------
typedef GhostMeadow<GM_PROFILE_TINY_M, GM_PROFILE_TINY_K>         GhostMeadowTiny;
typedef GhostMeadow<GM_PROFILE_MICRO_M, GM_PROFILE_MICRO_K>       GhostMeadowMicro;
typedef GhostMeadow<GM_PROFILE_STANDARD_M, GM_PROFILE_STANDARD_K> GhostMeadowStandard;
typedef GhostMeadow<GM_PROFILE_FULL_M, GM_PROFILE_FULL_K>         GhostMeadowFull;

// Matching policy typedefs
typedef GhostPolicy<GM_PROFILE_TINY_M, GM_PROFILE_TINY_K>         GhostPolicyTiny;
typedef GhostPolicy<GM_PROFILE_MICRO_M, GM_PROFILE_MICRO_K>       GhostPolicyMicro;
typedef GhostPolicy<GM_PROFILE_STANDARD_M, GM_PROFILE_STANDARD_K> GhostPolicyStandard;
typedef GhostPolicy<GM_PROFILE_FULL_M, GM_PROFILE_FULL_K>         GhostPolicyFull;

// ---------------------------------------------------------------------------
// Profile info struct — runtime metadata for logging and telemetry
// ---------------------------------------------------------------------------
struct GhostProfile {
    const char* name;
    gm_u32 m_bits;
    gm_u8  k_hashes;
    gm_u32 ram_bytes;       // m_bits / 8
    gm_u32 capacity_50pct;  // approx n for 50% saturation: -(m/k)*ln(0.5)
    float  fp_at_capacity;  // theoretical FP at capacity
};

static inline GhostProfile gm_profile_info(const char* profile_name) {
    GhostProfile p;
    p.name = profile_name;

    // Lookup by name
    if (profile_name[0] == 't' || profile_name[0] == 'T') {
        p.m_bits = GM_PROFILE_TINY_M;
        p.k_hashes = GM_PROFILE_TINY_K;
    } else if (profile_name[0] == 'm' || profile_name[0] == 'M') {
        p.m_bits = GM_PROFILE_MICRO_M;
        p.k_hashes = GM_PROFILE_MICRO_K;
    } else if (profile_name[0] == 's' || profile_name[0] == 'S') {
        p.m_bits = GM_PROFILE_STANDARD_M;
        p.k_hashes = GM_PROFILE_STANDARD_K;
    } else {
        p.m_bits = GM_PROFILE_FULL_M;
        p.k_hashes = GM_PROFILE_FULL_K;
    }

    p.ram_bytes = p.m_bits / 8;
    // capacity at 50% sat: n = -(m/k) * ln(1 - 0.5) = (m/k) * ln(2)
    p.capacity_50pct = (gm_u32)((float)p.m_bits / (float)p.k_hashes * 0.6931f);
    // FP at capacity: (1 - e^(-k*n/m))^k = (0.5)^k
    float half_pow = 1.0f;
    for (int i = 0; i < p.k_hashes; i++) half_pow *= 0.5f;
    p.fp_at_capacity = half_pow;

    return p;
}

// ---------------------------------------------------------------------------
// Heterogeneous merge helper — merge smaller node into larger via raw bits
//
// When two nodes have different m values, only the overlapping prefix is
// merged. The larger node's extra bits are unaffected. This is safe because
// the smaller node's hash positions are always within [0, m_small), which
// is a subset of the larger node's range.
//
// Usage:
//   GhostMeadowFull big_node(KEY, 0);
//   GhostMeadowTiny tiny_node(KEY, 1);
//   gm_hetero_merge(big_node, tiny_node);
// ---------------------------------------------------------------------------
template<gm_u32 M_DST, gm_u8 K_DST, gm_u32 M_SRC, gm_u8 K_SRC>
GhostMergeResult gm_hetero_merge(GhostMeadow<M_DST, K_DST>& dst,
                                  const GhostMeadow<M_SRC, K_SRC>& src)
{
    return dst.merge_raw(src.raw_bits(), src.raw_bytes(), src.node_id());
}

// ---------------------------------------------------------------------------
// Heterogeneous swarm simulation test
// Returns 0 on pass, error count on failure
// ---------------------------------------------------------------------------
inline int gm_run_profile_tests() {
    int failures = 0;
    const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;

    // TEST 1: Tiny node can merge into Full node
    {
        GhostMeadowFull big(KEY, 0);
        GhostMeadowTiny tiny(KEY, 1);

        gm_u8 obs[] = {0x42, 0x43};
        tiny.seed(obs, 2);
        float big_sat_before = big.saturation();

        GhostMergeResult r = gm_hetero_merge(big, tiny);
        if (!r.canary_ok) failures++;
        if (big.saturation() < big_sat_before) failures++;  // must not decrease
        if ((gm_i32)r.bits_set < 0) failures++;
    }

    // TEST 2: Full node can merge into Tiny node (prefix only)
    {
        GhostMeadowFull big(KEY, 0);
        GhostMeadowTiny tiny(KEY, 1);

        gm_u8 obs[] = {0xDE, 0xAD};
        big.seed(obs, 2);
        float tiny_sat_before = tiny.saturation();

        GhostMergeResult r = gm_hetero_merge(tiny, big);
        if (!r.canary_ok) failures++;
        if (tiny.saturation() < tiny_sat_before) failures++;
    }

    // TEST 3: Standard ↔ Micro merge preserves OR-monotonicity
    {
        GhostMeadowStandard std_node(KEY, 0);
        GhostMeadowMicro micro_node(KEY, 1);

        for (int i = 0; i < 100; i++) {
            gm_u8 buf[2] = {(gm_u8)(i & 0xFF), (gm_u8)((i >> 8) & 0xFF)};
            std_node.seed(buf, 2);
            micro_node.seed(buf, 2);
        }

        gm_u32 std_bits_before = 0;
        for (gm_u32 i = 0; i < std_node.raw_bytes(); i++) {
            gm_u8 b = std_node.raw_bits()[i];
            b = b - ((b >> 1) & 0x55u);
            b = (b & 0x33u) + ((b >> 2) & 0x33u);
            std_bits_before += (b + (b >> 4)) & 0x0Fu;
        }

        GhostMergeResult r = gm_hetero_merge(std_node, micro_node);
        if ((gm_i32)r.bits_set < 0) failures++;

        gm_u32 std_bits_after = 0;
        for (gm_u32 i = 0; i < std_node.raw_bytes(); i++) {
            gm_u8 b = std_node.raw_bits()[i];
            b = b - ((b >> 1) & 0x55u);
            b = (b & 0x33u) + ((b >> 2) & 0x33u);
            std_bits_after += (b + (b >> 4)) & 0x0Fu;
        }

        if (std_bits_after < std_bits_before) failures++;  // OR-monotonicity
    }

    // TEST 4: Profile info calculation
    {
        GhostProfile tiny_info = gm_profile_info("tiny");
        if (tiny_info.m_bits != 512) failures++;
        if (tiny_info.k_hashes != 2) failures++;
        if (tiny_info.ram_bytes != 64) failures++;

        GhostProfile full_info = gm_profile_info("full");
        if (full_info.m_bits != 192000) failures++;
        if (full_info.k_hashes != 13) failures++;
    }

    return failures;
}
