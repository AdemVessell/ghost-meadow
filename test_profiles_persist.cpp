/**
 * test_profiles_persist.cpp
 * Ghost Meadow — Tests for configurable profiles and persistence layer
 *
 * Compile: g++ -std=c++11 -O2 -o test_profiles_persist test_profiles_persist.cpp
 */
#include "ghost_profiles.h"
#include "ghost_persist.h"
#include <cstdio>

int main() {
    printf("=== Ghost Meadow Profile & Persistence Tests ===\n\n");

    int total_failures = 0;

    // Profile tests
    printf("--- Profile Tests ---\n");
    int profile_failures = gm_run_profile_tests();
    if (profile_failures == 0)
        printf("  Profile tests: ALL PASSED (4/4)\n");
    else
        printf("  Profile tests: FAILED (%d errors)\n", profile_failures);
    total_failures += profile_failures;

    // Profile info display
    printf("\n--- Profile Info ---\n");
    const char* names[] = {"tiny", "micro", "standard", "full"};
    for (int i = 0; i < 4; i++) {
        GhostProfile p = gm_profile_info(names[i]);
        printf("  %-10s m=%6u  k=%2u  RAM=%6u bytes  cap@50%%=%5u  FP@cap=%.6f\n",
               p.name, p.m_bits, p.k_hashes, p.ram_bytes,
               p.capacity_50pct, p.fp_at_capacity);
    }

    // Persistence tests
    printf("\n--- Persistence Tests ---\n");
    int persist_failures = gm_run_persist_tests();
    if (persist_failures == 0)
        printf("  Persistence tests: ALL PASSED (5/5)\n");
    else
        printf("  Persistence tests: FAILED (%d errors)\n", persist_failures);
    total_failures += persist_failures;

    // Heterogeneous swarm demo
    printf("\n--- Heterogeneous Swarm Demo ---\n");
    {
        const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;
        GhostMeadowFull   big(KEY, 0);
        GhostMeadowStandard std(KEY, 1);
        GhostMeadowMicro  micro(KEY, 2);
        GhostMeadowTiny   tiny(KEY, 3);

        // All nodes observe the same data
        for (int i = 0; i < 200; i++) {
            gm_u8 buf[4] = {(gm_u8)(i & 0xFF), (gm_u8)((i >> 8) & 0xFF), 0xAA, 0xBB};
            big.seed(buf, 4);
            std.seed(buf, 4);
            micro.seed(buf, 4);
            tiny.seed(buf, 4);
        }

        printf("  After 200 identical observations:\n");
        printf("    Full:     sat=%.2f%%\n", big.saturation_pct());
        printf("    Standard: sat=%.2f%%\n", std.saturation_pct());
        printf("    Micro:    sat=%.2f%%\n", micro.saturation_pct());
        printf("    Tiny:     sat=%.2f%%\n", tiny.saturation_pct());

        // Cross-merge: tiny → full
        float full_sat_before = big.saturation();
        GhostMergeResult r = gm_hetero_merge(big, tiny);
        printf("  Tiny→Full merge: delta=%u bits, full sat %.2f%% → %.2f%%\n",
               r.bits_set, full_sat_before * 100, big.saturation_pct());

        // Cross-merge: full → tiny
        float tiny_sat_before = tiny.saturation();
        r = gm_hetero_merge(tiny, big);
        printf("  Full→Tiny merge: delta=%u bits, tiny sat %.2f%% → %.2f%%\n",
               r.bits_set, tiny_sat_before * 100, tiny.saturation_pct());
    }

    // Persist size report
    printf("\n--- Persist Buffer Sizes ---\n");
    printf("  Tiny:     %u bytes\n", gm_persist_size<GM_PROFILE_TINY_M, GM_PROFILE_TINY_K>());
    printf("  Micro:    %u bytes\n", gm_persist_size<GM_PROFILE_MICRO_M, GM_PROFILE_MICRO_K>());
    printf("  Standard: %u bytes\n", gm_persist_size<GM_PROFILE_STANDARD_M, GM_PROFILE_STANDARD_K>());
    printf("  Full:     %u bytes\n", gm_persist_size<GM_PROFILE_FULL_M, GM_PROFILE_FULL_K>());

    printf("\n=== RESULT: %s (%d failures) ===\n",
           total_failures == 0 ? "ALL PASSED" : "FAILURES", total_failures);
    return total_failures == 0 ? 0 : 1;
}
