"""
security_tokens.py
Realistic synthetic security token model for Ghost Meadow security benchmarks.

Tokens represent security-relevant observations that a local detector would
produce. They are structured enough to model real detection scenarios without
pretending to be actual IDS signatures.

Each token is encoded as bytes suitable for seeding into a Bloom filter.
Token encoding: [category_byte][subcategory_byte][variant_bytes...]
"""

import struct

# Token category constants
CAT_EXPLOIT_FAMILY = 0x01
CAT_SUSPICIOUS_PATH = 0x02
CAT_SCANNER_BEHAVIOR = 0x03
CAT_AUTH_ABUSE = 0x04
CAT_BOT_SIGNATURE = 0x05
CAT_IOT_ANOMALY = 0x06
CAT_LATERAL_MOVEMENT = 0x07
CAT_PROTOCOL_ANOMALY = 0x08

CATEGORY_NAMES = {
    CAT_EXPLOIT_FAMILY: "exploit_family",
    CAT_SUSPICIOUS_PATH: "suspicious_path",
    CAT_SCANNER_BEHAVIOR: "scanner_behavior",
    CAT_AUTH_ABUSE: "auth_abuse",
    CAT_BOT_SIGNATURE: "bot_signature",
    CAT_IOT_ANOMALY: "iot_anomaly",
    CAT_LATERAL_MOVEMENT: "lateral_movement",
    CAT_PROTOCOL_ANOMALY: "protocol_anomaly",
}

ALL_CATEGORIES = list(CATEGORY_NAMES.keys())


# Subcategory definitions per category
SUBCATEGORIES = {
    CAT_EXPLOIT_FAMILY: list(range(1, 16)),      # 15 exploit families
    CAT_SUSPICIOUS_PATH: list(range(1, 12)),     # 11 suspicious paths
    CAT_SCANNER_BEHAVIOR: list(range(1, 8)),     # 7 scanner types
    CAT_AUTH_ABUSE: list(range(1, 10)),           # 9 auth abuse patterns
    CAT_BOT_SIGNATURE: list(range(1, 13)),       # 12 bot signatures
    CAT_IOT_ANOMALY: list(range(1, 9)),          # 8 IoT anomaly types
    CAT_LATERAL_MOVEMENT: list(range(1, 7)),     # 6 lateral movement types
    CAT_PROTOCOL_ANOMALY: list(range(1, 11)),    # 10 protocol anomalies
}


def encode_token(category, subcategory, variant=0):
    """Encode a security token as bytes for Bloom filter seeding."""
    return struct.pack("BBH", category, subcategory, variant & 0xFFFF)


def encode_token_with_source(category, subcategory, variant=0, source_hint=0):
    """Encode with an optional source hint for correlated-but-not-identical sigs."""
    return struct.pack("BBHB", category, subcategory, variant & 0xFFFF,
                       source_hint & 0xFF)


class TokenGenerator:
    """Deterministic token generator for reproducible benchmarks."""

    def __init__(self, seed):
        self._state = seed & 0xFFFFFFFFFFFFFFFF
        if self._state == 0:
            self._state = 1

    def _next(self):
        # xorshift64
        x = self._state
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 7)
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self._state = x
        return x

    def _rand_int(self, n):
        return self._next() % n

    def _rand_float(self):
        return (self._next() % 10000) / 10000.0

    def random_benign_token(self):
        """Generate a benign background noise token.
        Benign tokens are spread across categories with low variant diversity."""
        cat = ALL_CATEGORIES[self._rand_int(len(ALL_CATEGORIES))]
        subs = SUBCATEGORIES[cat]
        sub = subs[self._rand_int(len(subs))]
        variant = self._rand_int(50)  # low variant range
        return encode_token(cat, sub, variant)

    def random_false_positive(self):
        """Generate a token that resembles a real detection but is benign.
        Uses the same encoding as real tokens — indistinguishable at the
        Bloom filter level, which is the point."""
        cat = ALL_CATEGORIES[self._rand_int(len(ALL_CATEGORIES))]
        subs = SUBCATEGORIES[cat]
        sub = subs[self._rand_int(len(subs))]
        variant = 1000 + self._rand_int(500)  # distinct variant range
        return encode_token(cat, sub, variant)

    def campaign_token(self, campaign_id, wave=0):
        """Generate a token from a specific attack campaign.
        Correlated: same category/subcategory, varying variants.
        Models nodes independently detecting related malicious patterns."""
        cat = CAT_EXPLOIT_FAMILY if campaign_id % 3 == 0 else (
            CAT_SCANNER_BEHAVIOR if campaign_id % 3 == 1 else CAT_AUTH_ABUSE)
        sub = (campaign_id % len(SUBCATEGORIES[cat])) + 1
        # Correlated but not identical: variant differs per wave and node
        variant = (campaign_id * 100 + wave) & 0xFFFF
        return encode_token(cat, sub, variant)

    def campaign_token_correlated(self, campaign_id, node_id, step):
        """Generate correlated-but-not-identical campaign tokens.
        Different nodes seeing the same campaign produce tokens that share
        category and subcategory but differ in variant. This models how
        real distributed attacks look: related but not byte-identical."""
        cat = CAT_EXPLOIT_FAMILY if campaign_id % 2 == 0 else CAT_LATERAL_MOVEMENT
        sub = (campaign_id % len(SUBCATEGORIES[cat])) + 1
        # Core variant from campaign; slight variation from node perspective
        base_variant = campaign_id * 37
        variant = (base_variant + (step // 10)) & 0xFFFF
        source_hint = node_id & 0xFF
        return encode_token_with_source(cat, sub, variant, source_hint)

    def poison_token(self, attacker_id, step):
        """Generate a poisoning token — high rate, concentrated categories."""
        cat = ALL_CATEGORIES[step % len(ALL_CATEGORIES)]
        sub = ((attacker_id * 7 + step) % len(SUBCATEGORIES[cat])) + 1
        variant = (attacker_id * 1000 + step) & 0xFFFF
        return encode_token(cat, sub, variant)

    def namespace_flood_token(self, attacker_id, index):
        """Generate diverse tokens to maximize Bloom filter saturation.
        Sprays across all categories and subcategories with unique variants."""
        cat = ALL_CATEGORIES[index % len(ALL_CATEGORIES)]
        sub = (index % len(SUBCATEGORIES[cat])) + 1
        variant = (attacker_id * 10000 + index) & 0xFFFF
        return encode_token(cat, sub, variant)

    def stale_replay_token(self, original_step, replay_step):
        """Generate a token that was valid in a previous epoch but is
        being replayed. Uses the same encoding as the original."""
        cat = CAT_EXPLOIT_FAMILY
        sub = (original_step % 15) + 1
        variant = original_step & 0xFFFF
        return encode_token(cat, sub, variant)

    def iot_anomaly_token(self, device_class, anomaly_type):
        """Generate IoT-specific anomaly tokens."""
        sub = (anomaly_type % len(SUBCATEGORIES[CAT_IOT_ANOMALY])) + 1
        variant = device_class & 0xFFFF
        return encode_token(CAT_IOT_ANOMALY, sub, variant)

    def low_and_slow_token(self, campaign_id, step):
        """Generate low-rate, spread-out campaign tokens.
        Models APT-like slow reconnaissance or gradual lateral movement."""
        cat = CAT_LATERAL_MOVEMENT
        sub = (campaign_id % len(SUBCATEGORIES[cat])) + 1
        variant = (campaign_id * 50 + step // 20) & 0xFFFF
        return encode_token(cat, sub, variant)
