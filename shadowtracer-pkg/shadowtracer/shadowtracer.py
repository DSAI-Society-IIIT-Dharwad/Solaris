#!/usr/bin/env python3
"""
shadowtracer.py
───────────────
Single CLI entry point for shadowtracerv1.

Usage
  python shadowtracer.py [--json FILE | --input FILE] [COMMAND] [OPTIONS]

Run  python shadowtracer.py --help  for the full man-page.
"""

import argparse
import os
import sys
import textwrap
from datetime import datetime

# ── lazy imports so --help works even without networkx installed ───────────
def _load_graph(path):
    """Load the JSON graph file and return an AttackPathGraph instance."""
    from .graph_builder import AttackPathGraph
    ag = AttackPathGraph()
    if not ag.load_from_json(path):
        _die(f"Failed to load graph from '{path}'.")
    return ag


def _die(msg, code=1):
    print(f"\n[!] {msg}", file=sys.stderr)
    sys.exit(code)


# ═══════════════════════════════════════════════════════════════
# DISPLAY HELPERS  (match the terminal report style)
# ═══════════════════════════════════════════════════════════════

DIVIDER = "══════════════════════════════════════════════════════════════════"
THIN    = "────────────────────────────────────────────────────────────────"


def _severity(score):
    if score >= 15: return "CRITICAL"
    if score >= 8:  return "HIGH"
    if score >= 4:  return "MEDIUM"
    return "LOW"


def _fmt_node(nid, G):
    d    = G.nodes.get(nid, {})
    name = d.get("name", nid.split(":")[-1] if ":" in nid else nid)
    kind = d.get("type", "")
    return f"{name} ({kind})"


def _fmt_cve(nid, G):
    d    = G.nodes.get(nid, {})
    cves = d.get("cves", [])
    if cves:
        return f"  [CVE: {cves[0]}, CVSS {d.get('risk_score', '')}]"
    return ""


def _ascii_bar(value, maximum, width=20):
    if maximum == 0:
        return ""
    filled = int(round(value / maximum * width))
    return "█" * filled + "░" * (width - filled)


def _print_path(idx, p_data, G, prefix=""):
    score = p_data["total_risk_score"]
    hops  = p_data["total_hops"]
    sev   = _severity(score)
    path  = p_data["path"]

    print(f"  {prefix}Path #{idx}  |  {hops} hops  |  Risk Score: {score}  [{sev}]")
    print(f"  {THIN}")
    for u, v in zip(path[:-1], path[1:]):
        rel  = G[u][v].get("relationship", G[u][v].get("relation", "?"))
        cve  = _fmt_cve(u, G)
        print(f"  {_fmt_node(u, G)}{cve}  --[{rel}]-->  {_fmt_node(v, G)}")
    print()


# ═══════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════

# ── --blast-radius ────────────────────────────────────────────

def cmd_blast_radius(ag, node_id, hops):
    G = ag.G

    # Friendly node resolution: accept partial names
    if node_id not in G:
        matches = [n for n in G.nodes()
                   if node_id.lower() in n.lower()
                   or node_id.lower() in G.nodes[n].get("name", "").lower()]
        if len(matches) == 1:
            node_id = matches[0]
            print(f"[*] Resolved to node: {node_id}")
        elif len(matches) > 1:
            print(f"[!] Ambiguous node '{node_id}'. Matches:")
            for m in matches:
                print(f"      {m}  ({G.nodes[m].get('type','')})")
            _die("Provide a more specific node id.")
        else:
            _die(f"Node '{node_id}' not found in graph.\n"
                 f"    Tip: run  --list-nodes  to see all node IDs.")

    result = ag.get_blast_radius(node_id, max_hops=hops)
    if "error" in result:
        _die(result["error"])

    src_name = G.nodes[node_id].get("name", node_id)
    total    = result["total_reachable"]
    by_hop   = result["by_hop"]

    print()
    print(DIVIDER)
    print(f"  BLAST RADIUS ANALYSIS (BFS, depth={hops})")
    print(f"  Source : {src_name}  ({G.nodes[node_id].get('type','')})")
    print(f"  Node ID: {node_id}")
    print(DIVIDER)
    print()
    print(f"  {total} resource(s) reachable within {hops} hop(s)\n")

    for hop_num in sorted(by_hop.keys()):
        nodes = by_hop[hop_num]
        names = [G.nodes[n].get("name", n) for n in nodes]
        print(f"    Hop {hop_num}: {', '.join(names)}")

    print()
    print(DIVIDER)
    print()


# ── --source / --target (shortest path) ──────────────────────

def cmd_shortest_path(ag, source, target):
    G = ag.G

    for label, nid in [("source", source), ("target", target)]:
        if nid not in G:
            _die(f"{label.capitalize()} node '{nid}' not found.\n"
                 f"    Tip: run  --list-nodes  to see all node IDs.")

    result = ag.get_shortest_path(source, target)
    if "error" in result:
        print(f"\n  {result['error']}\n")
        return

    path  = result["path"]
    score = result["total_risk_score"]
    hops  = result["total_hops"]
    sev   = _severity(score)

    print()
    print(DIVIDER)
    print(f"  SHORTEST PATH  (Dijkstra)")
    print(f"  {_fmt_node(source, G)}  →  {_fmt_node(target, G)}")
    print(DIVIDER)
    print()
    print(f"  Hops       : {hops}")
    print(f"  Risk Score : {score}  [{sev}]")
    print(f"  {THIN}")

    for u, v in zip(path[:-1], path[1:]):
        rel = G[u][v].get("relationship", G[u][v].get("relation", "?"))
        cve = _fmt_cve(u, G)
        print(f"  {_fmt_node(u, G)}{cve}  --[{rel}]-->  {_fmt_node(v, G)}")

    # print crown jewel label on last node
    last = path[-1]
    sink = G.nodes[last].get("is_sink", False)
    crown = "  ← CROWN JEWEL" if sink else ""
    print(f"  {_fmt_node(last, G)}{crown}")
    print()
    print(DIVIDER)
    print()


# ── --cycles ─────────────────────────────────────────────────

def cmd_cycles(ag):
    G      = ag.G
    cycles = ag.detect_cycles()

    print()
    print(DIVIDER)
    print("  CIRCULAR PERMISSION DETECTION (DFS)")
    print(DIVIDER)
    print()

    if not cycles:
        print("  ✅  No circular permissions detected.\n")
    else:
        print(f"  ⚠  {len(cycles)} cycle(s) found:\n")
        for i, cycle in enumerate(cycles, 1):
            names = [G.nodes[n].get("name", n) for n in cycle]
            chain = " ↔ ".join(names) + " ↔ " + names[0]
            print(f"  Cycle #{i}: {chain}")
        print()

    print(DIVIDER)
    print()


# ── --critical-node ───────────────────────────────────────────

def cmd_critical_node(ag):
    G = ag.G
    entry_points = ag.get_entry_points()
    crown_jewels = ag.get_crown_jewels()
    all_pods     = [n for n, d in G.nodes(data=True) if d.get("type") == "Pod"]
    all_sources  = list(set(entry_points) | set(all_pods))

    if not crown_jewels:
        _die("No crown jewels (sink nodes) found in graph.")

    print()
    print(DIVIDER)
    print("  CRITICAL NODE ANALYSIS")
    print("  Computing... (removing each node and recounting paths)")
    print(DIVIDER)
    print()

    result   = ag.identify_critical_node(all_sources, crown_jewels)
    baseline = result.get("total_paths", 0)
    print(f"  Baseline attack paths : {baseline}\n")

    if "node" not in result:
        print(f"  {result.get('message', 'No critical node found.')}\n")
    else:
        n_name = result["node_name"]
        n_type = result["node_type"]
        elim   = result["paths_eliminated"]
        print(f"  ★  RECOMMENDATION:")
        print(f"     {result['recommendation']}")
        print()

        top5 = result.get("top5", [])
        if top5:
            max_red = top5[0][1]
            print(f"  Top 5 highest-impact nodes to remove:")
            for node_id, reduction, _ in top5:
                name = G.nodes[node_id].get("name", node_id)
                kind = G.nodes[node_id].get("type", "")
                bar  = _ascii_bar(reduction, max_red)
                pct  = int(round(reduction / baseline * 100)) if baseline else 0
                print(f"    {name:<30} ({kind:<15})  "
                      f"-{reduction} paths ({pct}%)  {bar}")
        print()

    print(DIVIDER)
    print()


# ── --full-report ─────────────────────────────────────────────

def cmd_full_report(ag):
    """Delegates to the existing generate_report() — identical to normal run."""
    from .graph_builder import generate_report
    generate_report(ag)


# ── --list-nodes (helper flag) ────────────────────────────────

def cmd_list_nodes(ag, filter_type=None):
    G = ag.G
    print()
    print(DIVIDER)
    hdr = f"  ALL NODES{f'  (type={filter_type})' if filter_type else ''}"
    print(hdr)
    print(DIVIDER)
    print(f"  {'ID':<45} {'TYPE':<20} {'NAME':<25} SRC  SINK")
    print(f"  {THIN}")

    for nid, data in sorted(G.nodes(data=True), key=lambda x: x[0]):
        if filter_type and data.get("type", "").lower() != filter_type.lower():
            continue
        name = data.get("name", "")
        kind = data.get("type", "")
        src  = "✓" if data.get("is_source") else " "
        sink = "✓" if data.get("is_sink")   else " "
        print(f"  {nid:<45} {kind:<20} {name:<25} {src:<4} {sink}")

    print()
    print(DIVIDER)
    print()


# ═══════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════

EPILOG = textwrap.dedent("""\
  ──────────────────────────────────────────────────────────────────
  EXAMPLES

    # Full report from mock graph (offline / demo mode)
    python shadowtracer.py --json mock-cluster-graph.json --full-report

    # Blast radius of the internet entry point (3 hops)
    python shadowtracer.py --json mock-cluster-graph.json \\
        --blast-radius internet

    # Blast radius with custom hop depth
    python shadowtracer.py --json mock-cluster-graph.json \\
        --blast-radius internet --hops 5

    # Shortest path from internet to the production database
    python shadowtracer.py --json mock-cluster-graph.json \\
        --source internet --target db-production

    # Shortest path between two arbitrary nodes
    python shadowtracer.py --json mock-cluster-graph.json \\
        --source user-dev1 --target node-worker-1

    # Cycle detection only
    python shadowtracer.py --json mock-cluster-graph.json --cycles

    # Critical node analysis only
    python shadowtracer.py --json mock-cluster-graph.json --critical-node

    # List every node in the graph (useful for finding node IDs)
    python shadowtracer.py --json mock-cluster-graph.json --list-nodes

    # List only Pod nodes
    python shadowtracer.py --json mock-cluster-graph.json \\
        --list-nodes --type Pod

    # Live cluster mode (requires kubectl context)
    python shadowtracer.py --full-report

  ──────────────────────────────────────────────────────────────────
  NODE ID FORMAT
    Node IDs depend on which graph format is loaded.

    mock-cluster-graph.json  →  flat slugs:
      internet, user-dev1, pod-webfront, sa-webapp,
      role-secret-reader, secret-db-creds, db-production …

    cluster-graph.json (live scan output)  →  Kind:namespace:name:
      Pod:default:nginx, ServiceAccount:kube-system:coredns …

    Run  --list-nodes  to see all IDs in your loaded graph.

  ──────────────────────────────────────────────────────────────────
  FLAGS REFERENCE

    --json / --input  FILE    Graph JSON to analyse (skips kubectl).
                              --json and --input are identical aliases.
    --blast-radius    NODE    BFS from NODE (default depth 3 hops).
    --hops            N       Max hop depth for --blast-radius [default: 3].
    --source          NODE    Source node for Dijkstra shortest-path.
    --target          NODE    Target node for Dijkstra shortest-path.
                              --source and --target must be used together.
    --cycles                  Run DFS cycle detection only.
    --critical-node           Run critical-node analysis only.
    --full-report             Run the complete kill-chain report
                              (identical to the default run mode).
    --list-nodes              Print all node IDs in the graph.
    --type            TYPE    Filter --list-nodes by node type
                              (Pod, ServiceAccount, Role, ClusterRole,
                               Secret, Service, Node, ExternalActor …).
    --help            -h      Show this help page and exit.

  ──────────────────────────────────────────────────────────────────
""")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="shadowtracer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
          ══════════════════════════════════════════════════════════════════
            shadowtracerv1 — Kubernetes Attack Path Visualizer & Analyzer
          ══════════════════════════════════════════════════════════════════

          Models a Kubernetes cluster as a directed graph and surfaces hidden
          multi-hop attack chains using BFS, Dijkstra, DFS, and critical-node
          analysis.

          Supply a graph JSON with  --json FILE  (offline / demo mode) or omit
          it to run a live kubectl ingestion against your cluster context.
        """),
        epilog=EPILOG,
    )

    # ── Input ─────────────────────────────────────────────────
    input_grp = parser.add_argument_group("Input")
    input_grp.add_argument(
        "--json", "--input",
        dest="input_file",
        metavar="FILE",
        default=None,
        help=(
            "Path to a cluster-graph JSON file. "
            "Skips live kubectl ingestion. "
            "Accepts both the mock format (flat slugs) and the "
            "live-scan format (Kind:ns:name IDs). "
            "Example: --json mock-cluster-graph.json"
        ),
    )

    # ── Commands ──────────────────────────────────────────────
    cmd_grp = parser.add_argument_group("Commands  (pick one, or combine)")
    cmd_grp.add_argument(
        "--blast-radius",
        metavar="NODE",
        dest="blast_node",
        default=None,
        help=(
            "BFS blast-radius analysis starting from NODE. "
            "Reports every resource reachable within --hops hops. "
            "Example: --blast-radius internet"
        ),
    )
    cmd_grp.add_argument(
        "--hops",
        type=int,
        default=3,
        metavar="N",
        help=(
            "Maximum hop depth for --blast-radius. "
            "Default: 3."
        ),
    )
    cmd_grp.add_argument(
        "--source",
        metavar="NODE",
        default=None,
        help=(
            "Source node for Dijkstra shortest-path query. "
            "Must be used together with --target. "
            "Example: --source internet"
        ),
    )
    cmd_grp.add_argument(
        "--target",
        metavar="NODE",
        default=None,
        help=(
            "Target node for Dijkstra shortest-path query. "
            "Must be used together with --source. "
            "Example: --target db-production"
        ),
    )
    cmd_grp.add_argument(
        "--cycles",
        action="store_true",
        help=(
            "Run DFS cycle detection. "
            "Reports all circular permission bindings in the cluster."
        ),
    )
    cmd_grp.add_argument(
        "--critical-node",
        action="store_true",
        dest="critical_node",
        help=(
            "Identify the single node whose removal breaks the most "
            "attack paths (attack-path betweenness). "
            "Shows top-5 candidates with impact bars."
        ),
    )
    cmd_grp.add_argument(
        "--full-report",
        action="store_true",
        dest="full_report",
        help=(
            "Run the complete kill-chain report: "
            "all attack paths, blast radius, cycle detection, "
            "critical-node analysis, temporal analysis, "
            "Rich dashboard, PDF export, and HTML visualizer."
        ),
    )
    cmd_grp.add_argument(
        "--list-nodes",
        action="store_true",
        dest="list_nodes",
        help=(
            "Print every node ID in the graph with its type, "
            "name, and source/sink flags. "
            "Useful for finding the right node ID to pass to other flags."
        ),
    )
    cmd_grp.add_argument(
        "--type",
        metavar="TYPE",
        default=None,
        help=(
            "Filter --list-nodes by node type. "
            "Example: --list-nodes --type Pod"
        ),
    )

    return parser


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    from .cli_dashboard import display_splash
    print()
    display_splash()
    parser = build_parser()
    args   = parser.parse_args()

    # ── Validate flag combinations ────────────────────────────
    source_target_flags = (args.source is not None, args.target is not None)
    if any(source_target_flags) and not all(source_target_flags):
        parser.error("--source and --target must always be used together.")

    commands_given = any([
        args.blast_node,
        args.source,
        args.cycles,
        args.critical_node,
        args.full_report,
        args.list_nodes,
    ])

    # If no command given, default to --full-report
    if not commands_given:
        args.full_report = True

    # ── Resolve the graph input file ─────────────────────────
    graph_file = args.input_file

    if graph_file is None and not args.full_report:
        # For focused commands without a file, check for default graph
        if os.path.exists("cluster-graph.json"):
            graph_file = "cluster-graph.json"
        elif os.path.exists("mock-cluster-graph.json"):
            graph_file = "mock-cluster-graph.json"
        else:
            _die(
                "No graph file specified and no default cluster-graph.json found.\n"
                "  Use  --json FILE  to specify one, or omit it to run live kubectl ingestion."
            )

    # ── Full-report path: may need live ingestion ─────────────
    if args.full_report and graph_file is None:
        _run_full_report_with_ingestion()
        return

    # ── Load graph ────────────────────────────────────────────
    print(f"[*] Loading graph: {graph_file}")
    ag = _load_graph(graph_file)
    G  = ag.G
    print(f"[*] {G.number_of_nodes()} nodes, {G.number_of_edges()} edges loaded.\n")

    # ── Dispatch commands ─────────────────────────────────────

    if args.list_nodes:
        cmd_list_nodes(ag, filter_type=args.type)

    if args.blast_node:
        cmd_blast_radius(ag, args.blast_node, args.hops)

    if args.source and args.target:
        cmd_shortest_path(ag, args.source, args.target)

    if args.cycles:
        cmd_cycles(ag)

    if args.critical_node:
        cmd_critical_node(ag)

    if args.full_report:
        cmd_full_report(ag)


def _run_full_report_with_ingestion():
    """Run live kubectl ingestion then full report (original cli_dashboard flow)."""
    from .cli_dashboard import run_analysis_dashboard
    run_analysis_dashboard()


if __name__ == "__main__":
    main()