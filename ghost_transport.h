/**
 * ghost_transport.h
 * Ghost Meadow — Transport Layer (Burst-Window Serialization)
 * Version 1.1 | Single-header, no-STL, embedded-friendly
 *
 * Wire format:
 *   [0xBE][0xEF]              — 2-byte magic
 *   [node_id]                 — 1 byte source node
 *   [epoch_id]                — 1 byte epoch at time of pack
 *   [len_hi][len_lo]          — 2 bytes payload length
 *   [payload... ]             — raw bit array or XOR delta
 *   [crc_hi][crc_lo]          — 2-byte CRC-16/CCITT of all preceding bytes
 *
 * Total overhead: 8 bytes per burst.
 *
 * CRC-16/CCITT (poly 0x1021, init 0xFFFF) replaces the v1.0 XOR checksum.
 * Detects all single-bit, double-bit, and odd-bit-count errors.
 * Detects all burst errors up to 16 bits. Minimal code and zero-table
 * implementation suitable for bare-metal embedded.
 *
 * Physical layer is abstracted via function pointer typedefs —
 * plug in LoRa, BLE, serial, laser, whatever.
 *
 * Thread safety: none. Single-threaded embedded use assumed.
 */
#pragma once
#include "ghost_meadow.h"

// ---------------------------------------------------------------------------
// Header constants
// ---------------------------------------------------------------------------
#define GM_TRANSPORT_MAGIC_0  0xBE
#define GM_TRANSPORT_MAGIC_1  0xEF
#define GM_TRANSPORT_HDR_SIZE 6   // magic(2) + node_id(1) + epoch(1) + len(2)
#define GM_TRANSPORT_OVERHEAD 8   // header(6) + CRC-16(2)

// ---------------------------------------------------------------------------
// Physical layer abstraction — function pointer typedefs
// Any transport (LoRa, BLE, serial, laser) implements these.
// ---------------------------------------------------------------------------
typedef gm_bool (*gm_phy_send_fn)(const gm_u8* buf, gm_u32 len, void* ctx);
typedef gm_u32  (*gm_phy_recv_fn)(gm_u8* buf, gm_u32 max_len, void* ctx);

// ---------------------------------------------------------------------------
// CRC-16/CCITT — poly 0x1021, init 0xFFFF, no table (20 lines, 0 RAM)
// Replaces XOR checksum: catches all 1-bit, 2-bit, odd-count, and
// burst errors up to 16 bits. XOR only caught odd-count single-byte errors.
// ---------------------------------------------------------------------------
static inline gm_u16 _gm_crc16(const gm_u8* buf, gm_u32 len) {
    gm_u16 crc = 0xFFFF;
    for (gm_u32 i = 0; i < len; i++) {
        crc ^= (gm_u16)buf[i] << 8;
        for (gm_u8 bit = 0; bit < 8; bit++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc = crc << 1;
        }
    }
    return crc;
}

// ---------------------------------------------------------------------------
// pack_burst() — serialize full bit array into wire format
// Returns total bytes written, or 0 if buffer too small.
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
gm_u32 gm_pack_burst(const GhostMeadow<M, K>& src, gm_u8* buf, gm_u32 buf_size) {
    const gm_u32 BYTES = GhostMeadow<M, K>::BYTES;
    gm_u32 total = GM_TRANSPORT_OVERHEAD + BYTES;
    if (buf_size < total) return 0;

    // Header
    buf[0] = GM_TRANSPORT_MAGIC_0;
    buf[1] = GM_TRANSPORT_MAGIC_1;
    buf[2] = src.node_id();
    buf[3] = src.epoch();
    buf[4] = (gm_u8)((BYTES >> 8) & 0xFF);
    buf[5] = (gm_u8)(BYTES & 0xFF);

    // Payload
    memcpy(buf + GM_TRANSPORT_HDR_SIZE, src.raw_bits(), BYTES);

    // CRC-16
    gm_u16 crc = _gm_crc16(buf, GM_TRANSPORT_HDR_SIZE + BYTES);
    buf[GM_TRANSPORT_HDR_SIZE + BYTES]     = (gm_u8)(crc >> 8);
    buf[GM_TRANSPORT_HDR_SIZE + BYTES + 1] = (gm_u8)(crc & 0xFF);

    return total;
}

// ---------------------------------------------------------------------------
// unpack_burst() — validate header+CRC, merge into destination node
// On validation failure: returns result with canary_ok=false.
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
GhostMergeResult gm_unpack_burst(GhostMeadow<M, K>& dst, const gm_u8* buf, gm_u32 buf_len) {
    GhostMergeResult fail;
    fail.bits_set    = 0;
    fail.src_node_id = 0;
    fail.epoch_id    = 0;
    fail.canary_ok   = false;

    // Minimum size check
    if (buf_len < GM_TRANSPORT_OVERHEAD) return fail;

    // Magic check
    if (buf[0] != GM_TRANSPORT_MAGIC_0 || buf[1] != GM_TRANSPORT_MAGIC_1) return fail;

    // Extract header
    gm_u8  src_node = buf[2];
    gm_u8  src_epoch = buf[3];
    gm_u32 payload_len = ((gm_u32)buf[4] << 8) | (gm_u32)buf[5];

    // Length sanity
    if (buf_len < GM_TRANSPORT_HDR_SIZE + payload_len + 2) return fail;

    // CRC-16
    gm_u16 expected_crc = _gm_crc16(buf, GM_TRANSPORT_HDR_SIZE + payload_len);
    gm_u16 actual_crc   = ((gm_u16)buf[GM_TRANSPORT_HDR_SIZE + payload_len] << 8)
                         | (gm_u16)buf[GM_TRANSPORT_HDR_SIZE + payload_len + 1];
    if (expected_crc != actual_crc) return fail;

    // Merge
    GhostMergeResult result = dst.merge_raw(buf + GM_TRANSPORT_HDR_SIZE, payload_len, src_node);
    result.epoch_id = src_epoch;
    return result;
}

// ---------------------------------------------------------------------------
// xor_delta_pack() — pack only differing bits (extended contact window)
// Returns total bytes written, or 0 if buffer too small.
// Payload is the XOR of local and remote bit arrays, trimmed to last nonzero byte.
// ---------------------------------------------------------------------------
template<gm_u32 M, gm_u8 K>
gm_u32 gm_xor_delta_pack(const GhostMeadow<M, K>& local,
                          const GhostMeadow<M, K>& remote,
                          gm_u8* buf, gm_u32 buf_size)
{
    const gm_u32 BYTES = GhostMeadow<M, K>::BYTES;

    // Compute XOR delta and find sparse length
    gm_u8 delta[BYTES];
    gm_u32 sparse_len = 0;
    local.xor_delta(remote, delta, sparse_len);
    if (sparse_len == 0) sparse_len = 1; // at least 1 byte for identical arrays

    gm_u32 total = GM_TRANSPORT_OVERHEAD + sparse_len;
    if (buf_size < total) return 0;

    // Header — uses local node's identity
    buf[0] = GM_TRANSPORT_MAGIC_0;
    buf[1] = GM_TRANSPORT_MAGIC_1;
    buf[2] = local.node_id();
    buf[3] = local.epoch();
    buf[4] = (gm_u8)((sparse_len >> 8) & 0xFF);
    buf[5] = (gm_u8)(sparse_len & 0xFF);

    // Payload — sparse delta
    memcpy(buf + GM_TRANSPORT_HDR_SIZE, delta, sparse_len);

    // CRC-16
    gm_u16 crc = _gm_crc16(buf, GM_TRANSPORT_HDR_SIZE + sparse_len);
    buf[GM_TRANSPORT_HDR_SIZE + sparse_len]     = (gm_u8)(crc >> 8);
    buf[GM_TRANSPORT_HDR_SIZE + sparse_len + 1] = (gm_u8)(crc & 0xFF);

    return total;
}

// ---------------------------------------------------------------------------
// Transport test harness
// Returns 0 on pass, error count on failure
// ---------------------------------------------------------------------------
inline int gm_run_transport_tests() {
    int failures = 0;
    const gm_u64 KEY = 0xDEADBEEFCAFEBABEULL;

    // --- TEST 1: Round-trip full burst ---
    {
        GhostMeadow<1024, 3> src(KEY, 5);
        GhostMeadow<1024, 3> dst(KEY, 9);

        const gm_u8 obs1[] = { 0x01, 0x02, 0x03 };
        const gm_u8 obs2[] = { 0xAA, 0xBB, 0xCC };
        src.seed(obs1, 3);
        src.seed(obs2, 3);

        const gm_u32 BUF_SIZE = 1024 / 8 + GM_TRANSPORT_OVERHEAD;
        gm_u8 wire[BUF_SIZE];
        gm_u32 packed = gm_pack_burst(src, wire, BUF_SIZE);

        if (packed != BUF_SIZE) failures++;

        GhostMergeResult r = gm_unpack_burst(dst, wire, packed);
        if (!r.canary_ok) failures++;
        if (r.src_node_id != 5) failures++;
        if (!dst.query(obs1, 3)) failures++;
        if (!dst.query(obs2, 3)) failures++;
    }

    // --- TEST 2: CRC corruption detected ---
    {
        GhostMeadow<1024, 3> src(KEY, 2);
        GhostMeadow<1024, 3> dst(KEY, 7);

        const gm_u8 obs[] = { 0xDE, 0xAD };
        src.seed(obs, 2);

        const gm_u32 BUF_SIZE = 1024 / 8 + GM_TRANSPORT_OVERHEAD;
        gm_u8 wire[BUF_SIZE];
        gm_u32 packed = gm_pack_burst(src, wire, BUF_SIZE);

        // Corrupt a payload byte
        wire[GM_TRANSPORT_HDR_SIZE + 10] ^= 0xFF;

        GhostMergeResult r = gm_unpack_burst(dst, wire, packed);
        if (r.canary_ok) failures++; // should have failed
    }

    // --- TEST 3: Single-bit flip detected (CRC-16 guarantee) ---
    {
        GhostMeadow<1024, 3> src(KEY, 3);
        GhostMeadow<1024, 3> dst(KEY, 8);

        const gm_u8 obs[] = { 0x42, 0x43, 0x44 };
        src.seed(obs, 3);

        const gm_u32 BUF_SIZE = 1024 / 8 + GM_TRANSPORT_OVERHEAD;
        gm_u8 wire[BUF_SIZE];
        gm_u32 packed = gm_pack_burst(src, wire, BUF_SIZE);

        // Flip every single bit position — CRC-16 must catch ALL of them
        int single_bit_misses = 0;
        for (gm_u32 byte_pos = 0; byte_pos < packed - 2; byte_pos++) {
            for (gm_u8 bit = 0; bit < 8; bit++) {
                gm_u8 saved = wire[byte_pos];
                wire[byte_pos] ^= (1u << bit);

                GhostMeadow<1024, 3> tmp(KEY, 8);
                GhostMergeResult r = gm_unpack_burst(tmp, wire, packed);
                if (r.canary_ok) single_bit_misses++;

                wire[byte_pos] = saved;
            }
        }
        if (single_bit_misses != 0) failures++;
    }

    // --- TEST 4: XOR delta is smaller than full burst ---
    {
        GhostMeadow<1024, 3> a(KEY, 0);
        GhostMeadow<1024, 3> b(KEY, 1);

        const gm_u8 obs_a[] = { 0x01 };
        const gm_u8 obs_b[] = { 0x02 };
        a.seed(obs_a, 1);
        b.seed(obs_b, 1);

        const gm_u32 FULL_SIZE = 1024 / 8 + GM_TRANSPORT_OVERHEAD;
        gm_u8 full_buf[FULL_SIZE];
        gm_u8 delta_buf[FULL_SIZE];

        gm_u32 full_len  = gm_pack_burst(a, full_buf, FULL_SIZE);
        gm_u32 delta_len = gm_xor_delta_pack(a, b, delta_buf, FULL_SIZE);

        if (delta_len >= full_len) failures++; // delta should be smaller
    }

    return failures;
}
