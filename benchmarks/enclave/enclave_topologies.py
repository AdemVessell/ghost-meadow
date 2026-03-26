"""
enclave_topologies.py
Cooperative-enclave topology generators for bakeoff scenarios.

Each topology models a realistic physical layout for a facility/campus
where nodes have short-range or wired local connectivity.
"""


def make_corridor(num_nodes, rng):
    """Linear hallway with occasional skip-links.
    Models: sensor array along a corridor, pipeline, or conveyor."""
    adj = {i: set() for i in range(num_nodes)}
    for i in range(num_nodes - 1):
        adj[i].add(i + 1)
        adj[i + 1].add(i)
    # Skip-links every ~4 nodes (doors, cross-corridors)
    for i in range(0, num_nodes - 2, 4):
        j = min(i + 2, num_nodes - 1)
        adj[i].add(j)
        adj[j].add(i)
    return adj


def make_wing_gateway(num_nodes, rng):
    """Two dense room-clusters connected through 1-2 gateway nodes.
    Models: building wing with restricted inter-wing access."""
    adj = {i: set() for i in range(num_nodes)}
    half = num_nodes // 2

    # Wing A: dense mesh
    for i in range(half):
        for j in range(half):
            if i != j:
                adj[i].add(j)

    # Wing B: dense mesh
    for i in range(half, num_nodes):
        for j in range(half, num_nodes):
            if i != j:
                adj[i].add(j)

    # Gateways: last node of wing A and first node of wing B
    gw_a = half - 1
    gw_b = half
    adj[gw_a].add(gw_b)
    adj[gw_b].add(gw_a)

    # Optional second gateway if enough nodes
    if num_nodes >= 16:
        gw_a2 = half // 2
        gw_b2 = half + half // 2
        adj[gw_a2].add(gw_b2)
        adj[gw_b2].add(gw_a2)

    return adj


def make_campus_building(num_nodes, rng):
    """4 room-clusters connected via backbone ring of gateway nodes.
    Models: multi-zone facility with structured backbone."""
    adj = {i: set() for i in range(num_nodes)}
    cluster_size = num_nodes // 4
    clusters = []

    for c in range(4):
        start = c * cluster_size
        end = start + cluster_size if c < 3 else num_nodes
        cluster = list(range(start, end))
        clusters.append(cluster)
        # Dense intra-cluster
        for i in cluster:
            for j in cluster:
                if i != j:
                    adj[i].add(j)

    # Backbone ring: gateway of each cluster connects to next
    for c in range(4):
        gw_this = clusters[c][0]
        gw_next = clusters[(c + 1) % 4][0]
        adj[gw_this].add(gw_next)
        adj[gw_next].add(gw_this)

    return adj
