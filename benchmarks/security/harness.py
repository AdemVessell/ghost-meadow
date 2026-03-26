"""
harness.py
Core simulation harness for Ghost Meadow security benchmarks.

Models a fleet of nodes exchanging suspicion signals via Ghost Meadow
(Layer A Bloom filter + Layer B security policy) and compares against
baseline approaches.

Each node has:
  - local event stream (security token generator)
  - local detector producing suspicion tokens
  - Ghost Meadow instance
  - optional trust weighting / peer class
  - Layer B security policy
  - metrics collection
"""

import sys
import os
import copy

# Add project root to path for ghost_meadow.py import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from ghost_meadow import GhostMeadow

from security_tokens import TokenGenerator, ALL_CATEGORIES, encode_token
from security_policy import (SecurityPolicy, TrustModel, TRUST_FULL,
                             ZONE_NOMINAL, ZONE_ELEVATED, ZONE_SUSPICIOUS,
                             ZONE_COORDINATED, ZONE_CONTAINMENT, ZONE_NAMES)


# ---- PRNG for simulation-level randomness ----
class SimRNG:
    def __init__(self, seed):
        self._state = seed & 0xFFFFFFFFFFFFFFFF
        if self._state == 0:
            self._state = 1

    def next_u64(self):
        x = self._state
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 7)
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self._state = x
        return x

    def rand_int(self, n):
        if n <= 0:
            return 0
        return self.next_u64() % n

    def rand_float(self):
        return (self.next_u64() % 10000) / 10000.0

    def rand_bool(self, p):
        return self.rand_float() < p


# ---- Topology generators ----
def make_topology(num_nodes, topo_type, rng):
    """Return adjacency dict: {node_id: set of neighbor_ids}."""
    adj = {i: set() for i in range(num_nodes)}

    if topo_type == "full_mesh":
        for i in range(num_nodes):
            for j in range(num_nodes):
                if i != j:
                    adj[i].add(j)

    elif topo_type == "chain":
        for i in range(num_nodes - 1):
            adj[i].add(i + 1)
            adj[i + 1].add(i)

    elif topo_type == "ring":
        for i in range(num_nodes):
            adj[i].add((i + 1) % num_nodes)
            adj[(i + 1) % num_nodes].add(i)

    elif topo_type == "star_sparse":
        hub = 0
        for i in range(1, num_nodes):
            adj[hub].add(i)
            adj[i].add(hub)
            # Add some sparse cross-links
            if i > 1 and rng.rand_bool(0.15):
                peer = rng.rand_int(i)
                adj[i].add(peer)
                adj[peer].add(i)

    elif topo_type == "regional_mesh":
        # 3 clusters, dense within, sparse between
        cluster_size = num_nodes // 3
        clusters = []
        for c in range(3):
            start = c * cluster_size
            end = start + cluster_size if c < 2 else num_nodes
            cluster = list(range(start, end))
            clusters.append(cluster)
            for i in cluster:
                for j in cluster:
                    if i != j:
                        adj[i].add(j)
        # Sparse cross-cluster links
        for c1 in range(len(clusters)):
            for c2 in range(c1 + 1, len(clusters)):
                bridge1 = clusters[c1][0]
                bridge2 = clusters[c2][0]
                adj[bridge1].add(bridge2)
                adj[bridge2].add(bridge1)

    elif topo_type == "partitioned_clusters":
        # Two clusters with a single weak bridge
        half = num_nodes // 2
        for i in range(half):
            for j in range(half):
                if i != j:
                    adj[i].add(j)
        for i in range(half, num_nodes):
            for j in range(half, num_nodes):
                if i != j:
                    adj[i].add(j)
        # Single bridge
        adj[half - 1].add(half)
        adj[half].add(half - 1)

    else:
        # Default: range-based like existing chaos tests
        for i in range(num_nodes):
            for j in range(num_nodes):
                if i != j and abs(i - j) <= 3:
                    adj[i].add(j)

    return adj


# ---- Security Node ----
class SecurityNode:
    """A node in the security benchmark fleet.

    Wraps a GhostMeadow instance with:
      - local token generation
      - security policy evaluation
      - metrics tracking
    """

    def __init__(self, node_id, mission_key, bloom_m=4096, bloom_k=2,
                 policy_variant="composite", quorum_k=3,
                 trust_class=TRUST_FULL, is_malicious=False):
        self.node_id = node_id
        self.meadow = GhostMeadow(mission_key, node_id, m=bloom_m, k=bloom_k)
        self.policy = SecurityPolicy(
            variant=policy_variant, quorum_k=quorum_k,
            trust_class=trust_class)
        self.is_malicious = is_malicious
        self.trust_class = trust_class
        self.bloom_m = bloom_m
        self.bloom_k = bloom_k

        # Metrics accumulators
        self.tokens_seeded = 0
        self.merges_performed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.zone_history = []
        self.saturation_history = []
        self.merge_delta_history = []
        self.local_campaign_tokens = []  # tokens from real campaigns
        self.first_campaign_detect_step = None
        self.first_elevated_step = None
        self.first_coordinated_step = None

    def seed_token(self, token_bytes):
        self.meadow.seed(token_bytes)
        self.tokens_seeded += 1

    def merge_from(self, other_node):
        """OR-merge from another node's meadow."""
        delta = self.meadow.merge_raw(
            other_node.meadow.raw_bits(), other_node.node_id)
        self.merges_performed += 1
        payload_bytes = len(other_node.meadow.raw_bits())
        self.bytes_received += payload_bytes + 8  # +8 for transport overhead
        other_node.bytes_sent += payload_bytes + 8
        self.merge_delta_history.append(delta)
        return delta

    def evaluate_policy(self, step):
        """Run Layer B policy and record metrics."""
        state = self.meadow.state()
        result = self.policy.evaluate(state)
        self.zone_history.append(result["zone"])
        self.saturation_history.append(state["saturation_pct"])

        if (result["zone"] >= ZONE_ELEVATED and
                self.first_elevated_step is None):
            self.first_elevated_step = step

        if (result["zone"] >= ZONE_COORDINATED and
                self.first_coordinated_step is None):
            self.first_coordinated_step = step

        return result

    def decay_epoch(self):
        self.meadow.decay()
        self.policy.reset_epoch()

    def can_query_token(self, token_bytes):
        return self.meadow.query(token_bytes)


# ---- Baseline: Local-Only Detection ----
class LocalOnlyNode:
    """Baseline 1: each node acts only on its own detector stream.
    No cross-node suspicion sharing. Uses exact token set for detection."""

    def __init__(self, node_id, policy_variant="basic", quorum_k=1):
        self.node_id = node_id
        self.policy = SecurityPolicy(variant=policy_variant, quorum_k=quorum_k)
        self.is_malicious = False
        self.local_tokens = set()
        self.tokens_seeded = 0
        self.merges_performed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.zone_history = []
        self.saturation_history = []
        self.first_elevated_step = None
        self.first_coordinated_step = None

    def seed_token(self, token_bytes):
        self.local_tokens.add(token_bytes)
        self.tokens_seeded += 1

    def merge_from(self, other):
        pass  # no merging in local-only mode

    def evaluate_policy(self, step):
        # Simulate saturation based on token count
        # Use a rough mapping: saturation_pct ~ 100 * (1 - (1-k/m)^n)
        # For simplicity, use token count / capacity as proxy
        capacity = 500  # rough capacity at useful saturation
        pseudo_sat = min(95.0, (len(self.local_tokens) / capacity) * 100.0)
        state = {
            "saturation_pct": pseudo_sat,
            "merge_source_count": 0,
            "merge_delta_last": 0,
        }
        result = self.policy.evaluate(state)
        self.zone_history.append(result["zone"])
        self.saturation_history.append(pseudo_sat)

        if result["zone"] >= ZONE_ELEVATED and self.first_elevated_step is None:
            self.first_elevated_step = step
        if (result["zone"] >= ZONE_COORDINATED and
                self.first_coordinated_step is None):
            self.first_coordinated_step = step
        return result

    def decay_epoch(self):
        self.local_tokens.clear()
        self.policy.reset_epoch()

    def can_query_token(self, token_bytes):
        return token_bytes in self.local_tokens


# ---- Baseline: Exact Lightweight Gossip ----
class ExactGossipNode:
    """Baseline 2: nodes share exact suspicion token sets.
    Capped at MAX_SHARED tokens to keep it lightweight."""

    MAX_SHARED = 200  # cap to keep bandwidth bounded

    def __init__(self, node_id, policy_variant="quorum_gated", quorum_k=3):
        self.node_id = node_id
        self.policy = SecurityPolicy(variant=policy_variant, quorum_k=quorum_k)
        self.is_malicious = False
        self.local_tokens = set()
        self.shared_tokens = set()  # tokens received from peers
        self.merge_sources = set()
        self.tokens_seeded = 0
        self.merges_performed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.zone_history = []
        self.saturation_history = []
        self.first_elevated_step = None
        self.first_coordinated_step = None

    def seed_token(self, token_bytes):
        self.local_tokens.add(token_bytes)
        self.tokens_seeded += 1

    def merge_from(self, other):
        """Share exact token sets, capped."""
        other_tokens = other.local_tokens | other.shared_tokens
        to_share = set(list(other_tokens)[:self.MAX_SHARED])
        new_tokens = to_share - self.shared_tokens - self.local_tokens
        self.shared_tokens |= to_share
        self.merge_sources.add(other.node_id)
        self.merges_performed += 1
        # Bandwidth: 4 bytes per token shared
        bytes_transferred = len(to_share) * 4
        self.bytes_received += bytes_transferred
        other.bytes_sent += bytes_transferred
        return len(new_tokens)

    def evaluate_policy(self, step):
        all_tokens = self.local_tokens | self.shared_tokens
        capacity = 500
        pseudo_sat = min(95.0, (len(all_tokens) / capacity) * 100.0)
        state = {
            "saturation_pct": pseudo_sat,
            "merge_source_count": len(self.merge_sources),
            "merge_delta_last": 0,
        }
        result = self.policy.evaluate(state)
        self.zone_history.append(result["zone"])
        self.saturation_history.append(pseudo_sat)
        if result["zone"] >= ZONE_ELEVATED and self.first_elevated_step is None:
            self.first_elevated_step = step
        if (result["zone"] >= ZONE_COORDINATED and
                self.first_coordinated_step is None):
            self.first_coordinated_step = step
        return result

    def decay_epoch(self):
        self.local_tokens.clear()
        self.shared_tokens.clear()
        self.merge_sources.clear()
        self.policy.reset_epoch()

    def can_query_token(self, token_bytes):
        return token_bytes in self.local_tokens or token_bytes in self.shared_tokens


# ---- Baseline: Counter/Rate Aggregation ----
class CounterAggNode:
    """Baseline 3: nodes share per-category counters periodically."""

    def __init__(self, node_id, policy_variant="basic", quorum_k=1):
        self.node_id = node_id
        self.policy = SecurityPolicy(variant=policy_variant, quorum_k=quorum_k)
        self.is_malicious = False
        self.local_counters = {}  # category -> count
        self.peer_counters = {}  # category -> aggregated count from peers
        self.merge_sources = set()
        self.local_tokens = set()
        self.tokens_seeded = 0
        self.merges_performed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.zone_history = []
        self.saturation_history = []
        self.first_elevated_step = None
        self.first_coordinated_step = None

    def seed_token(self, token_bytes):
        self.local_tokens.add(token_bytes)
        cat = token_bytes[0] if token_bytes else 0
        self.local_counters[cat] = self.local_counters.get(cat, 0) + 1
        self.tokens_seeded += 1

    def merge_from(self, other):
        """Share per-category counters."""
        for cat, count in other.local_counters.items():
            old = self.peer_counters.get(cat, 0)
            self.peer_counters[cat] = max(old, count)
        for cat, count in other.peer_counters.items():
            old = self.peer_counters.get(cat, 0)
            self.peer_counters[cat] = max(old, count)
        self.merge_sources.add(other.node_id)
        self.merges_performed += 1
        # Bandwidth: 2 bytes per category entry
        bytes_transferred = len(other.local_counters) * 2 + len(other.peer_counters) * 2
        self.bytes_received += bytes_transferred
        other.bytes_sent += bytes_transferred

    def evaluate_policy(self, step):
        total_local = sum(self.local_counters.values())
        total_peer = sum(self.peer_counters.values())
        total = total_local + total_peer
        capacity = 500
        pseudo_sat = min(95.0, (total / capacity) * 100.0)
        state = {
            "saturation_pct": pseudo_sat,
            "merge_source_count": len(self.merge_sources),
            "merge_delta_last": 0,
        }
        result = self.policy.evaluate(state)
        self.zone_history.append(result["zone"])
        self.saturation_history.append(pseudo_sat)
        if result["zone"] >= ZONE_ELEVATED and self.first_elevated_step is None:
            self.first_elevated_step = step
        if (result["zone"] >= ZONE_COORDINATED and
                self.first_coordinated_step is None):
            self.first_coordinated_step = step
        return result

    def decay_epoch(self):
        self.local_counters.clear()
        self.peer_counters.clear()
        self.merge_sources.clear()
        self.local_tokens.clear()
        self.policy.reset_epoch()

    def can_query_token(self, token_bytes):
        return token_bytes in self.local_tokens


# ---- Fleet Simulation ----
class Fleet:
    """Manages a fleet of nodes and runs simulation steps."""

    def __init__(self, num_nodes, topology_type, contact_prob,
                 bloom_m=4096, bloom_k=2, mission_key=0xDEADBEEFCAFEBABE,
                 policy_variant="composite", quorum_k=3,
                 trust_mode="all_equal", seed=12345,
                 node_class=SecurityNode,
                 corruption_rate=0.0, drop_rate=0.0):
        self.num_nodes = num_nodes
        self.contact_prob = contact_prob
        self.rng = SimRNG(seed)
        self.corruption_rate = corruption_rate
        self.drop_rate = drop_rate
        self.step = 0

        trust_model = TrustModel(num_nodes, trust_mode)
        self.trust_model = trust_model
        self.topology = make_topology(num_nodes, topology_type, self.rng)

        self.nodes = []
        for i in range(num_nodes):
            if node_class == SecurityNode:
                node = SecurityNode(
                    node_id=i,
                    mission_key=mission_key,
                    bloom_m=bloom_m,
                    bloom_k=bloom_k,
                    policy_variant=policy_variant,
                    quorum_k=quorum_k,
                    trust_class=trust_model.get_trust(i))
            elif node_class == LocalOnlyNode:
                node = LocalOnlyNode(i, policy_variant="basic", quorum_k=1)
            elif node_class == ExactGossipNode:
                node = ExactGossipNode(i, policy_variant="quorum_gated",
                                       quorum_k=quorum_k)
            elif node_class == CounterAggNode:
                node = CounterAggNode(i, policy_variant="basic", quorum_k=1)
            else:
                node = node_class(i)
            self.nodes.append(node)

    def run_merge_phase(self):
        """Run one round of merges based on topology and contact probability."""
        for i in range(self.num_nodes):
            if self.nodes[i].is_malicious and not isinstance(
                    self.nodes[i], SecurityNode):
                continue
            for j in self.topology.get(i, set()):
                if i == j:
                    continue
                if not self.rng.rand_bool(self.contact_prob):
                    continue
                # Packet drop
                if self.drop_rate > 0 and self.rng.rand_bool(self.drop_rate):
                    continue
                # Corruption simulation for GM nodes
                if (self.corruption_rate > 0 and
                        isinstance(self.nodes[i], SecurityNode) and
                        self.rng.rand_bool(self.corruption_rate)):
                    # Corrupted merge: create garbage bits
                    # CRC would catch this in real transport; simulate rejection
                    continue  # packet rejected by CRC
                self.nodes[i].merge_from(self.nodes[j])

    def run_policy_phase(self):
        """Evaluate policy on all nodes."""
        results = []
        for node in self.nodes:
            result = node.evaluate_policy(self.step)
            results.append(result)
        return results

    def run_decay(self):
        """Epoch boundary."""
        for node in self.nodes:
            node.decay_epoch()

    def advance_step(self):
        self.step += 1

    def get_saturation_stats(self):
        """Return mean and variance of saturation across honest nodes."""
        honest_sats = []
        for n in self.nodes:
            if not n.is_malicious:
                if hasattr(n, 'saturation_history') and n.saturation_history:
                    honest_sats.append(n.saturation_history[-1])
        if not honest_sats:
            return 0.0, 0.0
        mean = sum(honest_sats) / len(honest_sats)
        var = sum((s - mean) ** 2 for s in honest_sats) / len(honest_sats)
        return mean, var

    def get_zone_distribution(self):
        """Return count of honest nodes in each zone."""
        dist = {z: 0 for z in range(5)}
        for n in self.nodes:
            if not n.is_malicious and n.zone_history:
                dist[n.zone_history[-1]] = dist.get(n.zone_history[-1], 0) + 1
        return dist

    def total_bytes_transferred(self):
        return sum(n.bytes_sent for n in self.nodes)
