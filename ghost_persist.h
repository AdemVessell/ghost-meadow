/**
 * ghost_persist.h
 * Ghost Meadow — Persistence Layer (Snapshot Save/Restore)
 * Version 1.0 | Single-header, no-STL, embedded-friendly
 *
 * Serializes a GhostMeadow node's complete state to a flat byte buffer
 * suitable for writing to flash, SD card, EEPROM, or filesystem.
 * On reboot, restore from the buffer to resume mid-epoch.
 *
 * Wire format (little-endian):
 *   [0x47][0x4D][0x50][0x31]   — 4-byte magic "GMP1"
 *   [version]                   — 1 byte (currently 1)
 *   [node_id]                   — 1 byte
 *   [epoch_id]                  — 1 byte
 *   [m_bits_lo][m_bits_hi]      — 4 bytes (M as uint32 LE)
 *   [m_bits_b2][m_bits_b3]
 *   [k_hashes]                  — 1 byte
 *   [bits_set 4 bytes LE]       — 4 bytes
 *   [merge_source_count 4B LE]  — 4 bytes
 *   [total_merges 4B LE]        — 4 bytes
 *   [merge_delta_last 4B LE]    — 4 bytes (signed, stored as uint32)
 *   [ghost_trigger_count 4B LE] — 4 bytes
 *   [layer_b_zone]              — 1 byte
 *   [reserved 4 bytes]          — future use, zeroed
 *   [bit_array...]              — M/8 bytes
 *   [epoch_snapshots...]        — GM_EPOCH_LOG_SIZE * M/8 bytes
 *   [merge_sources...]          — (GM_MAX_NODE_ID/8)+1 bytes
 *   [crc16_hi][crc16_lo]        — 2-byte CRC-16 of everything above
 *
 * Thread safety: none. Single-threaded embedded use assumed.
 */
#pragma once
#include "ghost_meadow.h"
#include "ghost_transport.h"  // for _gm_crc16

// Magic bytes
#define GM_PERSIST_MAGIC_0 0x47  // 'G'
#define GM_PERSIST_MAGIC_1 0x4D  // 'M'
#define GM_PERSIST_MAGIC_2 0x50  // 'P'
#define GM_PERSIST_MAGIC_3 0x31  // '1'
#define GM_PERSIST_VERSION 1

// Header size before variable-length data
#define GM_PERSIST_HDR_SIZE 33  // 4+1+1+1+4+1+4+4+4+4+4+1+4 = 37... let's compute:
// magic(4) + version(1) + node_id(1) + epoch(1) + m_bits(4) + k(1) +
// bits_set(4) + merge_src_count(4) + total_merges(4) + merge_delta(4) +
// ghost_triggers(4) + zone(1) + reserved(4) = 37
#undef GM_PERSIST_HDR_SIZE
#define GM_PERSIST_HDR_SIZE 37

// ---------------------------------------------------------------------------
// LE encode/decode helpers
// ---------------------------------------------------------------------------
static inline void _gm_put_u32_le(gm_u8* buf, gm_u32 val) {
    buf[0] = (gm_u8)(val & 0xFF);
    buf[1] = (gm_u8)((val >> 8) & 0xFF);
    buf[2] = (gm_u8)((val >> 16) & 0xFF);
    buf[3] = (gm_u8)((val >> 24) & 0xFF);
}

static inline gm_u32 _gm_get_u32_le(const gm_u8* buf) {
    return (gm_u32)buf[0]
         | ((gm_u32)buf[1] << 8)
         | ((gm_u32)buf[2] << 16)
         | ((gm_u32)buf[3] << 24);
}

// ---------------------------------------------------------------------------
// Compute total persist buffer size for a given meadow type
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
gm_u32 gm_persist_size() {
    const gm_u32 BYTES = M / 8;
    const gm_u32 sources_bytes = (GM_MAX_NODE_ID / 8) + 1;
    return GM_PERSIST_HDR_SIZE
         + BYTES                              // bit array
         + (GM_EPOCH_LOG_SIZE * BYTES)        // epoch snapshots
         + sources_bytes                      // merge sources
         + 2;                                 // CRC-16
}

// ---------------------------------------------------------------------------
// gm_persist_save() — serialize meadow state to buffer
// Returns bytes written, or 0 if buffer too small.
//
// NOTE: This function accesses private members by reading them through
// the public API (state(), raw_bits(), epoch_snapshot()) and reconstructing
// internal state. The merge_sources bitmask is not directly accessible,
// so we store the count but not the bitmask on save. On restore, the
// bitmask is zeroed (merge_source_count is preserved as metadata only).
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
gm_u32 gm_persist_save(const GhostMeadow<M, K>& meadow, gm_u8* buf, gm_u32 buf_size) {
    const gm_u32 total = gm_persist_size<M, K>();
    if (buf_size < total) return 0;

    const gm_u32 BYTES = M / 8;
    const gm_u32 sources_bytes = (GM_MAX_NODE_ID / 8) + 1;
    gm_u32 pos = 0;

    // Magic
    buf[pos++] = GM_PERSIST_MAGIC_0;
    buf[pos++] = GM_PERSIST_MAGIC_1;
    buf[pos++] = GM_PERSIST_MAGIC_2;
    buf[pos++] = GM_PERSIST_MAGIC_3;

    // Version
    buf[pos++] = GM_PERSIST_VERSION;

    // Node metadata
    GhostSwarmState st = meadow.state();
    buf[pos++] = st.node_id;
    buf[pos++] = st.epoch_id;

    // M and K
    _gm_put_u32_le(buf + pos, M); pos += 4;
    buf[pos++] = K;

    // Counters
    gm_u32 bits_set_count = 0;
    for (gm_u32 i = 0; i < BYTES; i++) {
        gm_u8 b = meadow.raw_bits()[i];
        b = b - ((b >> 1) & 0x55u);
        b = (b & 0x33u) + ((b >> 2) & 0x33u);
        bits_set_count += (b + (b >> 4)) & 0x0Fu;
    }
    _gm_put_u32_le(buf + pos, bits_set_count); pos += 4;
    _gm_put_u32_le(buf + pos, st.merge_source_count); pos += 4;
    _gm_put_u32_le(buf + pos, st.total_merges_lifetime); pos += 4;
    _gm_put_u32_le(buf + pos, (gm_u32)st.merge_delta_last); pos += 4;
    _gm_put_u32_le(buf + pos, st.ghost_trigger_count); pos += 4;
    buf[pos++] = st.layer_b_zone;

    // Reserved
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;

    // Bit array
    memcpy(buf + pos, meadow.raw_bits(), BYTES);
    pos += BYTES;

    // Epoch snapshots
    for (int s = 0; s < GM_EPOCH_LOG_SIZE; s++) {
        if (st.epoch_id > 0 && s == 0) {
            memcpy(buf + pos, meadow.epoch_snapshot(0), BYTES);
        } else {
            // For safety, write zeros for snapshots we can't reliably access
            // (epoch_snapshot with offset > 0 when epoch_id is low)
            if (st.epoch_id > (gm_u8)s) {
                memcpy(buf + pos, meadow.epoch_snapshot((gm_u8)s), BYTES);
            } else {
                memset(buf + pos, 0, BYTES);
            }
        }
        pos += BYTES;
    }

    // Merge sources — not directly accessible, write zeros
    memset(buf + pos, 0, sources_bytes);
    pos += sources_bytes;

    // CRC-16 over everything before CRC
    gm_u16 crc = _gm_crc16(buf, pos);
    buf[pos++] = (gm_u8)(crc >> 8);
    buf[pos++] = (gm_u8)(crc & 0xFF);

    return pos;
}

// ---------------------------------------------------------------------------
// Persist validation result
// ---------------------------------------------------------------------------
struct GhostPersistInfo {
    gm_bool valid;
    gm_u8   node_id;
    gm_u8   epoch_id;
    gm_u32  m_bits;
    gm_u8   k_hashes;
    gm_u32  bits_set;
    gm_u32  total_merges;
};

// ---------------------------------------------------------------------------
// gm_persist_validate() — check buffer integrity without restoring
// ---------------------------------------------------------------------------
static inline GhostPersistInfo gm_persist_validate(const gm_u8* buf, gm_u32 buf_len) {
    GhostPersistInfo info;
    memset(&info, 0, sizeof(info));
    info.valid = false;

    if (buf_len < GM_PERSIST_HDR_SIZE + 2) return info;

    // Magic
    if (buf[0] != GM_PERSIST_MAGIC_0 || buf[1] != GM_PERSIST_MAGIC_1 ||
        buf[2] != GM_PERSIST_MAGIC_2 || buf[3] != GM_PERSIST_MAGIC_3)
        return info;

    // Version
    if (buf[4] != GM_PERSIST_VERSION) return info;

    info.node_id = buf[5];
    info.epoch_id = buf[6];
    info.m_bits = _gm_get_u32_le(buf + 7);
    info.k_hashes = buf[11];
    info.bits_set = _gm_get_u32_le(buf + 12);
    info.total_merges = _gm_get_u32_le(buf + 20);

    // Compute expected size
    gm_u32 bytes = info.m_bits / 8;
    gm_u32 sources_bytes = (GM_MAX_NODE_ID / 8) + 1;
    gm_u32 expected = GM_PERSIST_HDR_SIZE + bytes
                    + (GM_EPOCH_LOG_SIZE * bytes)
                    + sources_bytes + 2;

    if (buf_len < expected) return info;

    // CRC
    gm_u16 expected_crc = _gm_crc16(buf, expected - 2);
    gm_u16 actual_crc = ((gm_u16)buf[expected - 2] << 8) | (gm_u16)buf[expected - 1];
    if (expected_crc != actual_crc) return info;

    info.valid = true;
    return info;
}

// ---------------------------------------------------------------------------
// gm_persist_restore() — restore meadow state from buffer
//
// Creates a new GhostMeadow from saved state by:
//   1. Constructing a fresh node with the saved mission_key and node_id
//   2. Merging the saved bit array via merge_raw()
//   3. Setting zone via set_zone()
//
// Limitations:
//   - mission_key must be provided externally (not stored in persist format
//     for security — you don't want keys on flash if the device is captured)
//   - merge_sources bitmask is reset (source count is metadata only)
//   - epoch snapshots are restored into the bit array only (not into snapshot slots)
//   - Epoch counter is advanced to match saved epoch via decay() calls
//
// Returns true on success, false on validation failure.
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
gm_bool gm_persist_restore(GhostMeadow<M, K>& meadow, const gm_u8* buf, gm_u32 buf_len,
                             gm_u64 mission_key)
{
    GhostPersistInfo info = gm_persist_validate(buf, buf_len);
    if (!info.valid) return false;

    // Verify M and K match
    if (info.m_bits != M || info.k_hashes != K) return false;

    // Reconstruct meadow
    const gm_u32 BYTES = M / 8;

    // Re-initialize by constructing in-place
    // (we can't call constructor directly, so we use decay to reset, then merge)
    // First, advance epoch to match
    // Start fresh
    GhostMeadow<M, K> fresh(mission_key, info.node_id);

    // Advance epoch to match saved state
    for (gm_u8 e = 0; e < info.epoch_id; e++)
        fresh.decay();

    // Merge saved bit array
    const gm_u8* saved_bits = buf + GM_PERSIST_HDR_SIZE;
    fresh.merge_raw(saved_bits, BYTES, info.node_id);

    // Restore zone
    fresh.set_zone(buf[32]);  // layer_b_zone position

    // Restore ghost trigger count
    gm_u32 ghost_triggers = _gm_get_u32_le(buf + 28);
    for (gm_u32 g = 0; g < ghost_triggers; g++)
        fresh.inc_ghost_trigger();

    // Copy into output
    memcpy(&meadow, &fresh, sizeof(GhostMeadow<M, K>));
    return true;
}

// ---------------------------------------------------------------------------
// Test harness
// Returns 0 on pass, error count on failure
// ---------------------------------------------------------------------------
inline int gm_run_persist_tests() {
    int failures = 0;
    const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;

    // TEST 1: Save and validate round-trip
    {
        GhostMeadow<1024, 3> m(KEY, 5);
        gm_u8 obs[] = {0x01, 0x02, 0x03};
        m.seed(obs, 3);
        gm_u8 obs2[] = {0xAA, 0xBB};
        m.seed(obs2, 2);

        const gm_u32 sz = gm_persist_size<1024, 3>();
        gm_u8* buf = new gm_u8[sz];

        gm_u32 written = gm_persist_save(m, buf, sz);
        if (written != sz) failures++;

        GhostPersistInfo info = gm_persist_validate(buf, written);
        if (!info.valid) failures++;
        if (info.node_id != 5) failures++;
        if (info.m_bits != 1024) failures++;
        if (info.k_hashes != 3) failures++;

        delete[] buf;
    }

    // TEST 2: Save-restore preserves query results
    {
        GhostMeadow<1024, 3> original(KEY, 7);
        gm_u8 obs1[] = {0xDE, 0xAD};
        gm_u8 obs2[] = {0xBE, 0xEF};
        gm_u8 obs3[] = {0xCA, 0xFE};
        original.seed(obs1, 2);
        original.seed(obs2, 2);
        original.seed(obs3, 2);

        const gm_u32 sz = gm_persist_size<1024, 3>();
        gm_u8* buf = new gm_u8[sz];
        gm_persist_save(original, buf, sz);

        GhostMeadow<1024, 3> restored(KEY, 0);  // dummy, will be overwritten
        gm_bool ok = gm_persist_restore(restored, buf, sz, KEY);
        if (!ok) failures++;

        // All seeded observations must be queryable
        if (!restored.query(obs1, 2)) failures++;
        if (!restored.query(obs2, 2)) failures++;
        if (!restored.query(obs3, 2)) failures++;

        // Node ID preserved
        if (restored.node_id() != 7) failures++;

        delete[] buf;
    }

    // TEST 3: Corrupted buffer rejected
    {
        GhostMeadow<1024, 3> m(KEY, 3);
        gm_u8 obs[] = {0x42};
        m.seed(obs, 1);

        const gm_u32 sz = gm_persist_size<1024, 3>();
        gm_u8* buf = new gm_u8[sz];
        gm_persist_save(m, buf, sz);

        // Corrupt a byte
        buf[20] ^= 0xFF;

        GhostPersistInfo info = gm_persist_validate(buf, sz);
        if (info.valid) failures++;  // should be invalid

        GhostMeadow<1024, 3> restored(KEY, 0);
        gm_bool ok = gm_persist_restore(restored, buf, sz, KEY);
        if (ok) failures++;  // should fail

        delete[] buf;
    }

    // TEST 4: Wrong M/K rejected
    {
        GhostMeadow<1024, 3> m(KEY, 0);
        gm_u8 obs[] = {0x01};
        m.seed(obs, 1);

        const gm_u32 sz = gm_persist_size<1024, 3>();
        gm_u8* buf = new gm_u8[sz];
        gm_persist_save(m, buf, sz);

        // Try to restore into different sized meadow
        GhostMeadow<4096, 2> wrong_size(KEY, 0);
        gm_bool ok = gm_persist_restore(wrong_size, buf, sz, KEY);
        if (ok) failures++;  // M mismatch should fail

        delete[] buf;
    }

    // TEST 5: Saturation preserved
    {
        GhostMeadow<1024, 3> original(KEY, 2);
        for (int i = 0; i < 50; i++) {
            gm_u8 buf[2] = {(gm_u8)(i & 0xFF), (gm_u8)((i >> 8) & 0xFF)};
            original.seed(buf, 2);
        }

        float original_sat = original.saturation();

        const gm_u32 sz = gm_persist_size<1024, 3>();
        gm_u8* pbuf = new gm_u8[sz];
        gm_persist_save(original, pbuf, sz);

        GhostMeadow<1024, 3> restored(KEY, 0);
        gm_persist_restore(restored, pbuf, sz, KEY);

        // Saturation should be at least as high (merge_raw may set additional bits
        // due to self-merge, but in practice should be identical)
        if (restored.saturation() < original_sat * 0.99f) failures++;

        delete[] pbuf;
    }

    return failures;
}
