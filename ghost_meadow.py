"""
ghost_meadow.py
Ghost Meadow — Layer A MicroPython Port
Version 1.0 | ESP32-friendly, no external dependencies

Implements the same Bloom filter semantics as ghost_meadow.h:
  seed(), merge_raw(), query(), decay(), saturation(), state()

Sized for MicroPython memory budget:
  Default m=4096 bits (512 bytes), k=2 hash functions

Runs on MicroPython 1.22+ with no imports beyond builtins.
"""


class GhostMeadow:
    def __init__(self, mission_key, node_id, m=4096, k=2):
        self._mission_key = mission_key & 0xFFFFFFFFFFFFFFFF
        self._node_id = node_id & 0xFF
        self._m = m
        self._k = k
        self._bytes = m // 8
        self._bits = bytearray(self._bytes)
        self._bits_set = 0
        self._epoch = 0
        self._merge_source_count = 0
        self._total_merges = 0
        self._merge_delta_last = 0
        self._merge_sources = set()
        self._zone = 0
        self._ghost_trigger_count = 0

    def _hash(self, data, hash_idx):
        """FNV-1a seeded with mission_key XOR hash_idx."""
        FNV_PRIME = 16777619
        FNV_OFFSET = 2166136261
        seed = (self._mission_key ^ (hash_idx * 0x9E3779B97F4A7C15)) & 0xFFFFFFFF
        h = (FNV_OFFSET ^ seed) & 0xFFFFFFFF
        for b in data:
            h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
        # Final mix
        h = ((h ^ (h >> 16)) * 0x45D9F3B) & 0xFFFFFFFF
        h = h ^ (h >> 16)
        return h % self._m

    def seed(self, obs):
        """Add observation bytes to the meadow."""
        for i in range(self._k):
            pos = self._hash(obs, i)
            byte_idx = pos >> 3
            bit_idx = pos & 7
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                self._bits[byte_idx] |= (1 << bit_idx)
                self._bits_set += 1

    def query(self, obs):
        """Test membership. No false negatives within epoch."""
        for i in range(self._k):
            pos = self._hash(obs, i)
            byte_idx = pos >> 3
            bit_idx = pos & 7
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def merge_raw(self, other_bits, src_id):
        """OR-merge raw bit array from another node. Returns delta."""
        merge_len = min(len(other_bits), self._bytes)
        delta = 0
        for i in range(merge_len):
            before = self._bits[i]
            self._bits[i] |= other_bits[i]
            diff = self._bits[i] & ~before
            # popcount for byte
            d = diff
            d = d - ((d >> 1) & 0x55)
            d = (d & 0x33) + ((d >> 2) & 0x33)
            delta += (d + (d >> 4)) & 0x0F
        self._bits_set = self._count_bits()
        self._merge_delta_last = delta
        if src_id not in self._merge_sources:
            self._merge_sources.add(src_id)
            self._merge_source_count += 1
        self._total_merges += 1
        return delta

    def decay(self):
        """Epoch boundary reset."""
        self._bits = bytearray(self._bytes)
        self._bits_set = 0
        self._merge_source_count = 0
        self._merge_delta_last = 0
        self._merge_sources = set()
        self._epoch += 1

    def saturation(self):
        """Ratio of set bits to total bits (0.0 to 1.0)."""
        return self._bits_set / self._m

    def saturation_pct(self):
        """Saturation as percentage (0.0 to 100.0)."""
        return self.saturation() * 100.0

    def state(self):
        """Export telemetry dict matching swarm_state.schema.json."""
        return {
            "node_id": self._node_id,
            "epoch_id": self._epoch,
            "saturation_pct": self.saturation_pct(),
            "merge_source_count": self._merge_source_count,
            "merge_delta_last": self._merge_delta_last,
            "ghost_trigger_count": self._ghost_trigger_count,
            "false_neg_budget": 0.0,
            "layer_b_zone": self._zone,
            "total_merges_lifetime": self._total_merges,
        }

    def raw_bits(self):
        """Return reference to internal bit array."""
        return self._bits

    def node_id(self):
        return self._node_id

    def epoch(self):
        return self._epoch

    def _count_bits(self):
        count = 0
        for b in self._bits:
            d = b
            d = d - ((d >> 1) & 0x55)
            d = (d & 0x33) + ((d >> 2) & 0x33)
            count += (d + (d >> 4)) & 0x0F
        return count


# ---------------------------------------------------------------------------
# Invariant test harness — 7 tests matching C++ suite
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    KEY = 0xDEADBEEFCAFEBABE
    passed = 0
    failed = 0

    def check(name, condition):
        global passed, failed
        if condition:
            print("  PASS: " + name)
            passed += 1
        else:
            print("  FAIL: " + name)
            failed += 1

    print("=== Ghost Meadow MicroPython Tests ===")

    a = GhostMeadow(KEY, 0, m=1024, k=3)
    b = GhostMeadow(KEY, 1, m=1024, k=3)

    obs_a = bytes([0x01, 0x02, 0x03])
    obs_b = bytes([0xAA, 0xBB, 0xCC])
    a.seed(obs_a)
    b.seed(obs_b)

    # TEST 1: seed + query — no false negatives
    check("seed+query no false negative", a.query(obs_a))

    # TEST 2: merge delta >= 0
    sat_before = a.saturation()
    delta = a.merge_raw(b.raw_bits(), b.node_id())
    check("merge delta >= 0", delta >= 0)

    # TEST 3: saturation non-decreasing after merge
    check("saturation non-decreasing", a.saturation() >= sat_before)

    # TEST 4: idempotent re-merge
    delta2 = a.merge_raw(b.raw_bits(), b.node_id())
    check("idempotent re-merge (delta=0)", delta2 == 0)

    # TEST 5: query finds both observations after merge
    check("query finds merged obs", a.query(obs_a) and a.query(obs_b))

    # TEST 6: decay resets saturation to 0
    a.decay()
    check("decay resets saturation", a.saturation() == 0.0 and a.epoch() == 1)

    # TEST 7: post-decay query returns False (epoch isolation)
    check("epoch isolation (no carry-over)", not a.query(obs_a))

    print()
    print("Results: %d passed, %d failed" % (passed, failed))
    if failed == 0:
        print("ALL PASSED")
