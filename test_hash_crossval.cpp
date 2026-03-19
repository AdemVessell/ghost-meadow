/**
 * test_hash_crossval.cpp
 * Cross-validation: emit hash outputs for known inputs so Python can compare.
 *
 * Compile: g++ -std=c++11 -O2 -o test_hash_crossval test_hash_crossval.cpp
 * Output:  one line per test vector: "hash_idx observation_hex bit_position"
 *
 * These are the ground-truth values. If ghost_meadow.py produces different
 * bit positions for the same inputs, the MicroPython port is broken for interop.
 */
#include "ghost_meadow.h"
#include <cstdio>
#include <cmath>

// Expose the private _hash via a thin wrapper that replicates the logic.
// We test bit positions (hash % M), which is what seed() actually uses.
static gm_u32 cpp_hash(gm_u64 mission_key, const gm_u8* data, gm_u32 len,
                        gm_u8 hash_idx, gm_u32 m) {
    const gm_u32 FNV_PRIME  = 16777619u;
    const gm_u32 FNV_OFFSET = 2166136261u;
    gm_u32 seed = (gm_u32)(mission_key ^ ((gm_u64)hash_idx * 0x9e3779b97f4a7c15ULL));
    gm_u32 h = FNV_OFFSET ^ seed;
    for (gm_u32 i = 0; i < len; i++) {
        h ^= data[i];
        h *= FNV_PRIME;
    }
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;
    return h % m;
}

int main() {
    const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;

    // Test vectors: varying lengths, hash indices, and data patterns
    struct TestVec {
        const char* label;
        gm_u8 data[16];
        gm_u32 len;
    };

    TestVec vectors[] = {
        {"3byte_A",   {0x01, 0x02, 0x03},                          3},
        {"3byte_B",   {0xAA, 0xBB, 0xCC},                          3},
        {"1byte",     {0xFF},                                       1},
        {"4byte",     {0xDE, 0xAD, 0xBE, 0xEF},                    4},
        {"8byte",     {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}, 8},
        {"zeros",     {0x00, 0x00, 0x00, 0x00},                    4},
        {"ones",      {0xFF, 0xFF, 0xFF, 0xFF},                    4},
        {"single_0",  {0x00},                                       1},
    };
    int n_vectors = sizeof(vectors) / sizeof(vectors[0]);

    // Test at two sizes: m=1024 (small, shared test size) and m=4096 (Python default)
    gm_u32 sizes[] = {1024, 4096};
    gm_u8 max_k = 5; // test hash indices 0..4

    printf("# Ghost Meadow Hash Cross-Validation — C++ Ground Truth\n");
    printf("# mission_key=0xDEADBEEFCAFEBABE\n");
    printf("# FORMAT: m hash_idx label raw_hash bit_position\n");

    for (int si = 0; si < 2; si++) {
        gm_u32 m = sizes[si];
        for (int vi = 0; vi < n_vectors; vi++) {
            for (gm_u8 ki = 0; ki < max_k; ki++) {
                gm_u32 raw = cpp_hash(KEY, vectors[vi].data, vectors[vi].len, ki, m);
                // Also emit raw 32-bit hash (before mod) for deeper debugging
                // Recompute without mod
                const gm_u32 FNV_PRIME  = 16777619u;
                const gm_u32 FNV_OFFSET = 2166136261u;
                gm_u32 seed = (gm_u32)(KEY ^ ((gm_u64)ki * 0x9e3779b97f4a7c15ULL));
                gm_u32 h = FNV_OFFSET ^ seed;
                for (gm_u32 i = 0; i < vectors[vi].len; i++) {
                    h ^= vectors[vi].data[i];
                    h *= FNV_PRIME;
                }
                h ^= h >> 16;
                h *= 0x45d9f3b;
                h ^= h >> 16;

                printf("%u %u %s %u %u\n", m, ki, vectors[vi].label, h, raw);
            }
        }
    }

    // ---- Bit-level verification: seed the same observations into C++ and export raw bits ----
    printf("\n# BIT ARRAY VERIFICATION (m=1024, k=3)\n");
    printf("# Seed obs_a=[01,02,03] then obs_b=[AA,BB,CC], export hex of bit array\n");

    GhostMeadow<1024, 3> meadow(KEY, 0);
    const gm_u8 obs_a[] = {0x01, 0x02, 0x03};
    const gm_u8 obs_b[] = {0xAA, 0xBB, 0xCC};
    meadow.seed(obs_a, 3);
    meadow.seed(obs_b, 3);

    printf("BITS ");
    for (gm_u32 i = 0; i < meadow.raw_bytes(); i++)
        printf("%02x", meadow.raw_bits()[i]);
    printf("\n");
    printf("SATURATION %.10f\n", meadow.saturation());
    printf("BITS_SET %u\n", (unsigned)meadow.raw_bytes()); // total bytes for reference

    // Count set bits
    gm_u32 set_count = 0;
    for (gm_u32 i = 0; i < meadow.raw_bytes(); i++) {
        gm_u8 b = meadow.raw_bits()[i];
        b = b - ((b >> 1) & 0x55u);
        b = (b & 0x33u) + ((b >> 2) & 0x33u);
        set_count += (b + (b >> 4)) & 0x0Fu;
    }
    printf("SET_BITS %u\n", set_count);

    // ---- Empirical FP rate at various saturations ----
    printf("\n# EMPIRICAL FALSE POSITIVE RATE (m=1024, k=3)\n");
    printf("# Seed n observations, query 10000 random never-seeded, measure FP rate\n");
    printf("# FORMAT: n_seeded saturation_pct empirical_fp_rate theoretical_fp_rate\n");

    int test_counts[] = {10, 50, 100, 200, 300};
    for (int tc = 0; tc < 5; tc++) {
        int n_seed = test_counts[tc];
        GhostMeadow<1024, 3> fp_test(KEY, 0);

        // Seed n observations with deterministic data
        for (int i = 0; i < n_seed; i++) {
            gm_u8 obs[4] = {
                (gm_u8)(i & 0xFF),
                (gm_u8)((i >> 8) & 0xFF),
                (gm_u8)0xAA,  // marker so query set doesn't overlap
                (gm_u8)0xAA
            };
            fp_test.seed(obs, 4);
        }

        float sat = fp_test.saturation();

        // Query 10000 never-seeded observations
        int fp_count = 0;
        int n_queries = 10000;
        for (int i = 0; i < n_queries; i++) {
            gm_u8 qobs[4] = {
                (gm_u8)(i & 0xFF),
                (gm_u8)((i >> 8) & 0xFF),
                (gm_u8)0xBB,  // different marker — never seeded
                (gm_u8)0xBB
            };
            if (fp_test.query(qobs, 4)) fp_count++;
        }

        float empirical_fp = (float)fp_count / (float)n_queries;
        // Theoretical: (1 - e^(-kn/m))^k
        float theoretical_fp = powf(1.0f - expf(-(float)(3 * n_seed) / 1024.0f), 3.0f);

        printf("%d %.4f %.6f %.6f\n", n_seed, sat * 100.0f, empirical_fp, theoretical_fp);
    }

    return 0;
}
