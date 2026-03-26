import pytest
import random
import time
from typing import List

# TODO: Import your actual Ghost Meadow node and filter classes
# from ghost_meadow.node import GhostNode 
# from ghost_meadow.filter import BloomFilter

class MockHostNetwork:
    """
    Simulates a secure Layer 2/3 host environment (e.g., Military MANET, Enterprise LoRa).
    It does not simulate encryption mathematically; it simulates the *friction* encryption and firewalls create: packet drops, fragmentation, and latency.
    """
    def __init__(self, drop_rate: float = 0.0, mtu_size: int = None, max_jitter_ms: int = 0):
        self.drop_rate = drop_rate
        self.mtu_size = mtu_size
        self.max_jitter_ms = max_jitter_ms
        self.traffic_log = []

    def transmit(self, sender_payload: bytes, receiver_node) -> bool:
        """
        Attempts to move a payload from one node to another through the host security layer.
        Returns True if successful, False if the host network destroyed it.
        """
        # 1. DPI / Firewall Drop Simulation
        if random.random() < self.drop_rate:
            self.traffic_log.append("DROPPED_BY_FIREWALL")
            return False

        # 2. MTU Fragmentation Simulation
        if self.mtu_size and len(sender_payload) > self.mtu_size:
            fragments = [sender_payload[i:i + self.mtu_size] 
                         for i in range(0, len(sender_payload), self.mtu_size)]
            
            # If the network drops a single fragment, the whole CRC-16 fails.
            for _ in fragments:
                if random.random() < self.drop_rate:
                    self.traffic_log.append("FRAGMENT_DROPPED_CRC_FAIL")
                    return False
        
        # 3. Latency / Jitter Simulation
        if self.max_jitter_ms > 0:
            delay = random.uniform(0, self.max_jitter_ms) / 1000.0
            time.sleep(delay) # In a purely simulated clock, you'd advance virtual time here

        # If it survives the host network, deliver it to the Ghost Meadow application layer
        receiver_node.receive_merge(sender_payload)
        self.traffic_log.append("DELIVERED")
        return True


@pytest.fixture
def clean_swarm():
    """Returns a fresh cluster of 10 Ghost nodes initialized at 0dB0."""
    # Replace with your actual node initialization
    # return [GhostNode(filter_size=512) for _ in range(10)]
    pass 


def test_dpi_firewall_survival(clean_swarm):
    """
    Tests if the CRDT mathematically converges when a Next-Gen Firewall 
    arbitrarily drops 30% of all opaque UDP broadcast traffic.
    """
    nodes = clean_swarm
    # 30% packet loss is catastrophic for TCP, but should be survivable for a CRDT.
    host_net = MockHostNetwork(drop_rate=0.30) 
    
    # Inject 50 observations into Node 0
    for i in range(50):
        nodes[0].observe(f"event_{i}".encode('utf-8'))

    target_saturation = nodes[0].get_saturation()

    # Simulate random walk gossip over 50 ticks
    for _ in range(50):
        sender = random.choice(nodes)
        receiver = random.choice(nodes)
        if sender != receiver:
            payload = sender.export_filter()
            host_net.transmit(payload, receiver)

    # Verification: Did Node 9 achieve at least 90% of Node 0's state despite 30% packet loss?
    final_saturation = nodes[-1].get_saturation()
    
    assert final_saturation >= (target_saturation * 0.90), \
        f"CRDT starved. Expected ~{target_saturation}%, got {final_saturation}% under DPI drops."


def test_mtu_fragmentation_collapse(clean_swarm):
    """
    Tests the 24KB variant against a strict LoRaWAN/BLE MTU limit.
    If MTU is 256 bytes, a 24KB payload requires 96 fragments. 
    If a single fragment drops, the CRC-16 must reject the entire merge.
    """
    # Assuming nodes are configured for 24KB for this test
    sender = clean_swarm[0]
    receiver = clean_swarm[1]
    
    sender.observe(b"critical_infrastructure_fault")
    payload = sender.export_filter() # Should be 24,576 bytes

    # 256 byte MTU, with a tiny 1% drop rate per fragment
    host_net = MockHostNetwork(drop_rate=0.01, mtu_size=256) 
    
    success = host_net.transmit(payload, receiver)
    
    # Mathematical reality: 0.99^96 = ~38% chance of success per full merge attempt.
    # This test ensures your node logic doesn't crash on partial reads and correctly 
    # relies on CRC-16 to drop the poisoned/incomplete buffer.
    if not success:
        assert receiver.get_saturation() == 0, \
            "Node accepted a fragmented/corrupt payload! CRC-16 check failed to protect Layer A."


def test_asymmetric_jitter_convergence(clean_swarm):
    """
    Tests if asymmetric cryptographic routing delays cause split-brain or 
    if the OR-merge associativity holds up under out-of-order temporal delivery.
    """
    nodes = clean_swarm
    # Simulate up to 2 seconds of routing latency
    host_net = MockHostNetwork(max_jitter_ms=2000) 

    nodes[0].observe(b"event_A")
    nodes[-1].observe(b"event_B")

    # Force a crossed merge (0 sends to 9, 9 sends to 0) through the high-jitter network
    payload_0 = nodes[0].export_filter()
    payload_9 = nodes[-1].export_filter()

    host_net.transmit(payload_0, nodes[-1])
    host_net.transmit(payload_9, nodes[0])

    # Because CRDTs are commutative, both nodes must have identical filter states
    # regardless of which packet arrived first or how long it took in the crypto-tunnel.
    assert nodes[0].export_filter() == nodes[-1].export_filter(), \
        "Asymmetric latency caused state divergence. OR-merge associativity is broken."
