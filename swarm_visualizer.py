#!/usr/bin/env python3
"""
swarm_visualizer.py
Ghost Meadow — Network Topology Visualizer

Replays a swarm simulation and renders merge propagation across nodes.
Two modes:
  1. Terminal (default) — ASCII frames with ANSI color, no dependencies
  2. Matplotlib — animated plot if matplotlib is available

Usage:
  python3 swarm_visualizer.py                  # terminal mode
  python3 swarm_visualizer.py --plot           # matplotlib mode
  python3 swarm_visualizer.py --nodes 16       # custom node count
  python3 swarm_visualizer.py --topology chain # chain topology
  python3 swarm_visualizer.py --steps 200      # custom step count
"""

import sys
import os
import time
import argparse
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ghost_meadow import GhostMeadow

# ---------------------------------------------------------------------------
# PRNG — xorshift64, matches C++ for reproducibility
# ---------------------------------------------------------------------------
_rng_state = 0x12345678ABCDEF01


def _xorshift64():
    global _rng_state
    x = _rng_state & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 7) & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
    _rng_state = x
    return x


def rng_u32():
    return _xorshift64() & 0xFFFFFFFF


def rng_f32():
    return (rng_u32() % 10000) / 10000.0


def rng_reset(seed):
    global _rng_state
    _rng_state = seed


# ---------------------------------------------------------------------------
# Simulation engine — records per-step state for replay
# ---------------------------------------------------------------------------
KEY = 0xDEADBEEFCAFEBABE


class SimRecord:
    """One step of simulation state."""
    __slots__ = ('step', 'saturations', 'zones', 'merges', 'merge_edges')

    def __init__(self, step, saturations, zones, merges, merge_edges):
        self.step = step
        self.saturations = saturations  # list[float] per node
        self.zones = zones              # list[int] per node
        self.merges = merges            # list[int] cumulative per node
        self.merge_edges = merge_edges  # list[(src, dst)] merges this step


def run_simulation(num_nodes, num_steps, topology, contact_range, decay_step,
                   seed=0x12345678ABCDEF01):
    """Run simulation, return list of SimRecord."""
    rng_reset(seed)
    nodes = [GhostMeadow(KEY, i, m=4096, k=2) for i in range(num_nodes)]
    records = []

    for step in range(1, num_steps + 1):
        # Epoch decay
        if decay_step and step == decay_step:
            for n in nodes:
                n.decay()

        # Seed phase
        for i, n in enumerate(nodes):
            if rng_f32() < 0.6:
                count = 1 + (rng_u32() % 3)
                for _ in range(count):
                    val = rng_u32()
                    n.seed(bytes([val & 0xFF, (val >> 8) & 0xFF,
                                  (val >> 16) & 0xFF, (val >> 24) & 0xFF]))

        # Merge phase
        merge_edges = []
        for i in range(num_nodes):
            for j in range(num_nodes):
                if i == j:
                    continue
                d = abs(i - j)
                in_range = False
                if topology == 'mesh':
                    in_range = True
                elif topology == 'chain':
                    in_range = (d <= 1)
                elif topology == 'ring':
                    in_range = (d <= 1 or d >= num_nodes - 1)
                else:  # default — contact range
                    in_range = (d <= contact_range)
                if in_range and rng_f32() < 0.4:
                    nodes[i].merge_raw(nodes[j].raw_bits(), nodes[j].node_id())
                    merge_edges.append((j, i))

        # Record state
        sats = [n.saturation_pct() for n in nodes]
        zones = [n.state()['layer_b_zone'] for n in nodes]
        merges = [n.state()['total_merges_lifetime'] for n in nodes]
        records.append(SimRecord(step, sats, zones, merges, merge_edges))

    return records


# ---------------------------------------------------------------------------
# ANSI terminal renderer
# ---------------------------------------------------------------------------
ZONE_COLORS = [
    '\033[32m',  # green — nominal
    '\033[33m',  # yellow
    '\033[38;5;208m',  # orange
    '\033[31m',  # red
]
RESET = '\033[0m'
DIM = '\033[2m'
BOLD = '\033[1m'
CYAN = '\033[36m'


def sat_bar(pct, width=30):
    """Render a saturation bar."""
    filled = int(pct / 100.0 * width)
    filled = min(filled, width)
    return '█' * filled + '░' * (width - filled)


def render_terminal_frame(rec, num_nodes, frame_delay=0.05):
    """Render one simulation step to terminal."""
    lines = []
    lines.append(f'{BOLD}─── Step {rec.step:3d} ───{RESET}')

    # Compute variance
    mean = sum(rec.saturations) / num_nodes
    var = sum((s - mean) ** 2 for s in rec.saturations) / num_nodes

    for i in range(num_nodes):
        sat = rec.saturations[i]
        zone = rec.zones[i]
        zone_names = ['NOM', 'YLW', 'ORG', 'RED']
        color = ZONE_COLORS[min(zone, 3)]

        # Show merge arrows for this step
        incoming = [src for src, dst in rec.merge_edges if dst == i]
        merge_str = ''
        if incoming:
            merge_str = f' {DIM}←{",".join(str(s) for s in incoming[:4])}{RESET}'
            if len(incoming) > 4:
                merge_str += f'{DIM}+{len(incoming)-4}{RESET}'

        lines.append(
            f'  {color}N{i:<2d}{RESET} '
            f'{color}{sat_bar(sat)}{RESET} '
            f'{sat:6.2f}% '
            f'{color}[{zone_names[min(zone, 3)]}]{RESET}'
            f'{merge_str}'
        )

    lines.append(f'  {CYAN}variance={var:.6f}  merges_this_step={len(rec.merge_edges)}{RESET}')

    # Edge map — compact view of which merges happened
    if rec.merge_edges:
        edge_set = set()
        for src, dst in rec.merge_edges:
            a, b = min(src, dst), max(src, dst)
            edge_set.add((a, b))
        edge_str = ' '.join(f'{a}↔{b}' for a, b in sorted(edge_set)[:12])
        if len(edge_set) > 12:
            edge_str += f' +{len(edge_set)-12} more'
        lines.append(f'  {DIM}edges: {edge_str}{RESET}')

    lines.append('')
    print('\n'.join(lines))
    time.sleep(frame_delay)


def run_terminal(records, num_nodes, print_interval=10, frame_delay=0.05):
    """Replay simulation in terminal."""
    print(f'{BOLD}=== Ghost Meadow Topology Visualizer ==={RESET}')
    print(f'{DIM}Nodes: {num_nodes} | Steps: {len(records)} | '
          f'Showing every {print_interval} steps{RESET}\n')

    for rec in records:
        if rec.step % print_interval == 0 or rec.step == 1 or rec.step == len(records):
            render_terminal_frame(rec, num_nodes, frame_delay)

    # Final summary
    final = records[-1]
    mean = sum(final.saturations) / num_nodes
    var = sum((s - mean) ** 2 for s in final.saturations) / num_nodes
    total_merges = sum(final.merges)

    print(f'{BOLD}=== Final Summary ==={RESET}')
    print(f'  Final variance:  {var:.6f}')
    print(f'  Sat range:       {min(final.saturations):.2f}% – {max(final.saturations):.2f}%')
    print(f'  Total merges:    {total_merges}')
    print(f'  Converged:       {"yes" if var < 0.01 else "no"} (threshold=0.01)')


# ---------------------------------------------------------------------------
# Matplotlib renderer
# ---------------------------------------------------------------------------
def run_matplotlib(records, num_nodes, topology):
    """Animated matplotlib plot."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from matplotlib.patches import FancyArrowPatch
        import matplotlib.animation as animation
    except ImportError:
        print("matplotlib not available. Install with: pip install matplotlib")
        print("Falling back to terminal mode.")
        return False

    steps = [r.step for r in records]
    sat_series = {i: [r.saturations[i] for r in records] for i in range(num_nodes)}

    fig, (ax_graph, ax_sat) = plt.subplots(1, 2, figsize=(16, 8))
    fig.suptitle('Ghost Meadow — Swarm Convergence Visualization', fontsize=14, fontweight='bold')

    # --- Left: Network topology graph ---
    # Position nodes in a circle
    angles = [2 * math.pi * i / num_nodes for i in range(num_nodes)]
    pos_x = [math.cos(a) for a in angles]
    pos_y = [math.sin(a) for a in angles]

    zone_colors_mpl = ['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c']

    def draw_frame(frame_idx):
        rec = records[frame_idx]
        ax_graph.clear()
        ax_graph.set_xlim(-1.6, 1.6)
        ax_graph.set_ylim(-1.6, 1.6)
        ax_graph.set_aspect('equal')
        ax_graph.set_title(f'Step {rec.step} — Topology: {topology}')
        ax_graph.axis('off')

        # Draw merge edges
        for src, dst in rec.merge_edges:
            ax_graph.annotate('',
                              xy=(pos_x[dst], pos_y[dst]),
                              xytext=(pos_x[src], pos_y[src]),
                              arrowprops=dict(arrowstyle='->', color='#3498db',
                                              alpha=0.3, lw=1))

        # Draw nodes
        for i in range(num_nodes):
            zone = min(rec.zones[i], 3)
            color = zone_colors_mpl[zone]
            size = 200 + rec.saturations[i] * 8
            ax_graph.scatter(pos_x[i], pos_y[i], s=size, c=color,
                             edgecolors='black', linewidth=1.5, zorder=5)
            ax_graph.annotate(f'{i}\n{rec.saturations[i]:.1f}%',
                              (pos_x[i], pos_y[i]),
                              ha='center', va='center', fontsize=7,
                              fontweight='bold', zorder=6)

        # Variance annotation
        mean = sum(rec.saturations) / num_nodes
        var = sum((s - mean) ** 2 for s in rec.saturations) / num_nodes
        ax_graph.text(-1.5, -1.4, f'variance={var:.6f}', fontsize=9,
                      fontfamily='monospace')

    def draw_saturation():
        ax_sat.clear()
        ax_sat.set_title('Saturation Over Time')
        ax_sat.set_xlabel('Step')
        ax_sat.set_ylabel('Saturation %')
        colors = plt.cm.tab10(range(num_nodes))
        for i in range(num_nodes):
            ax_sat.plot(steps, sat_series[i], label=f'N{i}',
                        color=colors[i % 10], linewidth=1)
        ax_sat.legend(loc='upper left', fontsize=7, ncol=2)
        ax_sat.set_ylim(0, 100)
        ax_sat.grid(True, alpha=0.3)

    # Draw static saturation plot + sample frames
    draw_saturation()
    sample_frames = [0, len(records) // 4, len(records) // 2,
                     3 * len(records) // 4, len(records) - 1]
    for idx in sample_frames:
        draw_frame(idx)

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'swarm_topology.png')
    # Final composite: draw last frame
    draw_frame(len(records) - 1)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    print(f'Saved topology visualization to {output_path}')
    plt.close()

    # Also save a multi-frame strip
    fig2, axes = plt.subplots(1, 5, figsize=(25, 5))
    fig2.suptitle('Ghost Meadow — Convergence Timeline', fontsize=14, fontweight='bold')
    for ax_idx, frame_idx in enumerate(sample_frames):
        ax = axes[ax_idx]
        rec = records[frame_idx]
        ax.set_xlim(-1.6, 1.6)
        ax.set_ylim(-1.6, 1.6)
        ax.set_aspect('equal')
        ax.set_title(f'Step {rec.step}', fontsize=10)
        ax.axis('off')

        for src, dst in rec.merge_edges:
            ax.annotate('', xy=(pos_x[dst], pos_y[dst]),
                        xytext=(pos_x[src], pos_y[src]),
                        arrowprops=dict(arrowstyle='->', color='#3498db',
                                        alpha=0.3, lw=0.5))
        for i in range(num_nodes):
            zone = min(rec.zones[i], 3)
            color = zone_colors_mpl[zone]
            size = 100 + rec.saturations[i] * 4
            ax.scatter(pos_x[i], pos_y[i], s=size, c=color,
                       edgecolors='black', linewidth=1, zorder=5)
            ax.annotate(str(i), (pos_x[i], pos_y[i]),
                        ha='center', va='center', fontsize=6,
                        fontweight='bold', zorder=6)

    strip_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'swarm_timeline.png')
    fig2.tight_layout()
    fig2.savefig(strip_path, dpi=150)
    print(f'Saved timeline strip to {strip_path}')
    plt.close()
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='Ghost Meadow Topology Visualizer')
    parser.add_argument('--nodes', type=int, default=8, help='Number of nodes (default: 8)')
    parser.add_argument('--steps', type=int, default=200, help='Simulation steps (default: 200)')
    parser.add_argument('--topology', choices=['default', 'chain', 'mesh', 'ring'],
                        default='default', help='Network topology')
    parser.add_argument('--range', type=int, default=3, dest='contact_range',
                        help='Contact range for default topology (default: 3)')
    parser.add_argument('--decay', type=int, default=0,
                        help='Epoch decay at step N (0=no decay)')
    parser.add_argument('--plot', action='store_true', help='Generate matplotlib plots')
    parser.add_argument('--interval', type=int, default=10,
                        help='Print interval for terminal mode (default: 10)')
    parser.add_argument('--delay', type=float, default=0.05,
                        help='Frame delay for terminal mode (default: 0.05)')
    parser.add_argument('--seed', type=lambda x: int(x, 0), default=0x12345678ABCDEF01,
                        help='PRNG seed')
    args = parser.parse_args()

    print(f'Simulating {args.nodes} nodes, {args.steps} steps, topology={args.topology}...')
    records = run_simulation(args.nodes, args.steps, args.topology,
                             args.contact_range, args.decay, args.seed)

    if args.plot:
        success = run_matplotlib(records, args.nodes, args.topology)
        if not success:
            run_terminal(records, args.nodes, args.interval, args.delay)
    else:
        run_terminal(records, args.nodes, args.interval, args.delay)


if __name__ == '__main__':
    main()
