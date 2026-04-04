import json
import networkx as nx
import argparse
from datetime import datetime
from pdf_reporter import export_full_pdf_report
import os


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def short_label(node_id, G):
    """Return (name, type) from a full node ID like 'Pod:default:nginx'."""
    data = G.nodes.get(node_id, {})
    name = data.get("name", node_id.split(":")[-1])
    kind = data.get("type", node_id.split(":")[0])
    return name, kind


def fmt_node(node_id, G):
    name, kind = short_label(node_id, G)
    return f"{name} ({kind})"


def fmt_cve(node_id, G):
    """Return '  [CVE: X, CVSS Y]' if node has recorded vulnerabilities."""
    data = G.nodes.get(node_id, {})
    # cves is a list of CVE-id strings; use node risk_score as the score
    cves = data.get("cves", [])
    if cves:
        cve_id = cves[0]
        score  = data.get("risk_score", 0)
        return f"  [CVE: {cve_id}, CVSS {score}]"
    return ""


def severity_label(score):
    if score >= 15:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def ascii_bar(value, maximum, width=20):
    if maximum == 0:
        return ""
    filled = int(round(value / maximum * width))
    return "█" * filled


DIVIDER = "══════════════════════════════════════════════════════════════════"
THIN    = "────────────────────────────────────────────────────────────"


# ══════════════════════════════════════════════════════════════════
# GRAPH CLASS
# ══════════════════════════════════════════════════════════════════

class AttackPathGraph:
    def __init__(self):
        self.G = nx.DiGraph()

    def load_from_json(self, filepath):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            for node in data.get("nodes", []):
                nc = dict(node)
                nid = nc.pop("id")
                self.G.add_node(nid, **nc)
            for edge in data.get("edges", []):
                # Skip edges that don't have source and target (e.g., comment objects)
                if "source" not in edge or "target" not in edge:
                    continue
                ec = dict(edge)
                src = ec.pop("source")
                tgt = ec.pop("target")
                self.G.add_edge(src, tgt, **ec)
            print(f"[*] Graph loaded: {self.G.number_of_nodes()} Nodes, {self.G.number_of_edges()} Edges.")
            return True
        except Exception as e:
            print(f"[!] Error loading graph: {e}")
            return False

    def get_entry_points(self):
        return [n for n, a in self.G.nodes(data=True)
                if a.get("is_source") is True]

    def get_crown_jewels(self):
        return [n for n, a in self.G.nodes(data=True)
                if a.get("is_sink") is True]

    # ── Algorithm 1: BFS Blast Radius ──────────────────────────────
    def get_blast_radius(self, source_node, max_hops=3):
        if source_node not in self.G:
            return {"error": "Source not found."}
        lengths = nx.single_source_shortest_path_length(
            self.G, source=source_node, cutoff=max_hops
        )
        by_hop = {}
        for node, dist in lengths.items():
            if node == source_node or dist == 0:
                continue
            by_hop.setdefault(dist, []).append(node)
        total = sum(len(v) for v in by_hop.values())
        return {
            "total_reachable": total,
            "by_hop": by_hop,
            "max_hops_checked": max_hops,
        }

    # ── Algorithm 2: Dijkstra ───────────────────────────────────────
    def get_shortest_path(self, source_node, target_node):
        if source_node not in self.G or target_node not in self.G:
            return {"error": "Source or target not found."}
        try:
            path = nx.dijkstra_path(
                self.G, source=source_node, target=target_node, weight="weight"
            )
            risk = sum(
                self.G[u][v].get("cvss") or self.G[u][v].get("risk_score", 0)
                for u, v in zip(path[:-1], path[1:])
            )
            return {"path": path, "total_hops": len(path) - 1,
                    "total_risk_score": round(risk, 2)}
        except nx.NetworkXNoPath:
            return {"error": "No path exists."}

    # ── Algorithm 3: DFS Cycle Detection ───────────────────────────
    def detect_cycles(self):
        return [c for c in nx.simple_cycles(self.G) if len(c) > 1]

    # ── Task 4: Critical Node Analysis ─────────────────────────────
    def identify_critical_node(self, sources, crown_jewels, cutoff=8):
        if not sources or not crown_jewels:
            return {"message": "No sources or crown jewels.", "recommendation": "Cluster appears secure.", "top5": []}

        def _all_paths(G):
            # Use Dijkstra (one path per pair) to stay consistent with
            # find_all_attack_paths — ensures baseline count matches display
            paths = set()
            seen = set()
            for src in sources:
                for tgt in crown_jewels:
                    if (src, tgt) in seen:
                        continue
                    seen.add((src, tgt))
                    if src not in G or tgt not in G:
                        continue
                    try:
                        p = nx.dijkstra_path(G, source=src, target=tgt, weight="weight")
                        paths.add(tuple(p))
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        pass
            return paths

        baseline = _all_paths(self.G)
        baseline_count = len(baseline)

        if baseline_count == 0:
            return {"message": "No attack paths.", "recommendation": "Cluster appears secure.", "top5": [], "total_paths": 0}

        excluded = set(sources) | set(crown_jewels)
        candidates = [n for n in self.G.nodes() if n not in excluded]

        results = []
        for node in candidates:
            G_tmp = self.G.copy()
            G_tmp.remove_node(node)
            remaining = len(_all_paths(G_tmp))
            reduction = baseline_count - remaining
            if reduction > 0:
                results.append((node, reduction, remaining))

        results.sort(key=lambda x: x[1], reverse=True)

        if not results:
            return {
                "message": "No single node removal significantly reduces paths.",
                "recommendation": "Apply defence-in-depth.",
                "top5": [],
                "total_paths": baseline_count,
            }

        best_node, max_reduction, _ = results[0]
        node_data = self.G.nodes[best_node]
        node_type = node_data.get("type", "unknown")
        name, _ = short_label(best_node, self.G)

        from config import REMEDIATION_MAP
        hint_key = {
            "ServiceAccount": "runs-as-sa",
            "Role": "wildcard-rbac",
            "ClusterRole": "wildcard-rbac",
            "Node": "node-admin",
            "Secret": "secret-reader",
        }.get(node_type, "default-remediation")

        recommendation = (
            f"Remove permission binding '{name}' ({node_type}) "
            f"to eliminate {max_reduction} of {baseline_count} attack paths."
        )

        return {
            "node": best_node,
            "node_name": name,
            "node_type": node_type,
            "paths_eliminated": max_reduction,
            "total_paths": baseline_count,
            "recommendation": recommendation,
            "top5": results[:5],
        }


# ══════════════════════════════════════════════════════════════════
# PATH ENUMERATION
# ══════════════════════════════════════════════════════════════════

def find_all_attack_paths(graph, sources, crown_jewels, cutoff=8):
    """
    Returns ONE shortest (Dijkstra) path per unique (source, sink) pair.
    Using all_simple_paths explodes to hundreds of paths because noise edges
    create alternative routes through the graph. Dijkstra gives exactly one
    canonical path per pair — the easiest/most dangerous route an attacker
    would actually take.
    """
    all_paths = []
    seen_pairs = set()
    for src in sources:
        for tgt in crown_jewels:
            pair = (src, tgt)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            try:
                p = nx.dijkstra_path(graph.G, source=src, target=tgt, weight="weight")
                risk = sum(
                    graph.G[u][v].get("weight",0)
                    for u, v in zip(p[:-1], p[1:])
                )
                all_paths.append({
                    "source": src,
                    "target": tgt,
                    "path": p,
                    "total_risk_score": round(risk, 2),
                    "total_hops": len(p) - 1,
                })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
    return all_paths


# ══════════════════════════════════════════════════════════════════
# TEMPORAL ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════

def perform_temporal_analysis(current_paths, history_file=".shadowtracer_history.json"):
    """
    Compares the current attack paths against the previous scan's paths.
    Returns: (list_of_new_paths, is_first_run_boolean)
    """
    # Create unique string signatures for current paths (e.g., "nodeA->nodeB->nodeC")
    current_signatures = {"->".join(p["path"]): p for p in current_paths}
    is_first_run = not os.path.exists(history_file)

    prev_signatures = {}
    if not is_first_run:
        try:
            with open(history_file, "r") as f:
                prev_data = json.load(f)
            # prev_data is expected to be a list of path lists
            prev_signatures = {"->".join(p): True for p in prev_data}
        except Exception as e:
            print(f"[!] Could not read temporal history: {e}")

    # Identify paths that exist now but didn't exist in the previous run
    new_paths = [p for sig, p in current_signatures.items() if sig not in prev_signatures]

    # Save the current state for the next run
    try:
        with open(history_file, "w") as f:
            json.dump([p["path"] for p in current_paths], f)
    except Exception as e:
        print(f"[!] Warning: Could not save temporal history: {e}")

    return new_paths, is_first_run

# ══════════════════════════════════════════════════════════════════
# REPORT GENERATOR  —  matches sample-output format exactly
# ══════════════════════════════════════════════════════════════════

def generate_report(graph, blast_radius_node=None):
    G = graph.G
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry_points = graph.get_entry_points()
    crown_jewels = graph.get_crown_jewels()

    if not crown_jewels:
        print("[!] No crown jewels found. Aborting.")
        return

    # ── Collect ALL attack paths ────────────────────────────────────
    all_paths = find_all_attack_paths(graph, entry_points, crown_jewels)

    # Deduplicate; sort ascending by risk score (lowest risk first, as in sample)
    unique = {tuple(p["path"]): p for p in all_paths}
    all_paths = sorted(unique.values(), key=lambda x: x["total_risk_score"])

    worst_path = all_paths[-1] if all_paths else None

    # Run Temporal Analysis
    new_paths, is_first_run = perform_temporal_analysis(all_paths)

    # ══════════════════════════════════════════════════════════════
    # HEADER
    # ══════════════════════════════════════════════════════════════
    print(DIVIDER)
    print(f"  KILL CHAIN REPORT  —  {ts}")
    print(f"  Cluster : live-cluster")
    print(f"  Nodes   : {G.number_of_nodes()}  |  Edges: {G.number_of_edges()}")
    print(DIVIDER)
    print()

    # ══════════════════════════════════════════════════════════════
    # SECTION 1 — ALL ATTACK PATHS
    # ══════════════════════════════════════════════════════════════
    print("[ SECTION 1 — ATTACK PATH DETECTION (Dijkstra) ]")
    if not all_paths:
        print("  ✅  No attack paths detected.\n")
    else:
        print(f"  ⚠  {len(all_paths)} attack path(s) detected\n")
        for idx, p_data in enumerate(all_paths, 1):
            score = p_data["total_risk_score"]
            hops  = p_data["total_hops"]
            sev   = severity_label(score)
            path  = p_data["path"]

            print(f"  Path #{idx}  |  {hops} hops  |  Risk Score: {score}  [{sev}]")
            print(f"  {THIN}")

            for u, v in zip(path[:-1], path[1:]):
                rel       = G[u][v].get("relationship", G[u][v].get("relation", "?"))
                cve_note  = fmt_cve(u, G)
                u_label   = fmt_node(u, G)
                v_label   = fmt_node(v, G)
                print(f"  {u_label}{cve_note}  --[{rel}]-->  {v_label}")

            print()

    # ══════════════════════════════════════════════════════════════
    # SECTION 2 — BLAST RADIUS FOR ALL SOURCE NODES
    # ══════════════════════════════════════════════════════════════
    print("[ SECTION 2 — BLAST RADIUS ANALYSIS (BFS, depth=3) ]")
    print()

    # Every unique source that appears in any attack path
    seen_sources = {}
    for p in all_paths:
        src = p["source"]
        if src not in seen_sources:
            seen_sources[src] = True

    blast_sources = list(seen_sources.keys())

    # Include custom CLI blast node if given and not already in list
    if blast_radius_node and blast_radius_node in G and blast_radius_node not in seen_sources:
        blast_sources.insert(0, blast_radius_node)

    # Fall back to entry points if no paths found
    if not blast_sources:
        blast_sources = entry_points

    total_blast_nodes = set()

    for src in blast_sources:
        result = graph.get_blast_radius(src, max_hops=3)
        if "error" in result:
            continue

        src_name, _ = short_label(src, G)
        total = result["total_reachable"]
        by_hop = result["by_hop"]

        print(f"  Source: {src_name}  →  {total} reachable resource(s) within 3 hops")
        for hop_num in sorted(by_hop.keys()):
            nodes = by_hop[hop_num]
            total_blast_nodes.update(nodes)
            names = [short_label(n, G)[0] for n in nodes]
            print(f"    Hop {hop_num}: {', '.join(names)}")
        print()

    # ══════════════════════════════════════════════════════════════
    # SECTION 3 — CYCLE DETECTION
    # ══════════════════════════════════════════════════════════════
    print("[ SECTION 3 — CIRCULAR PERMISSION DETECTION (DFS) ]")
    cycles = graph.detect_cycles()
    if not cycles:
        print("  ✅  No circular permissions detected.\n")
    else:
        print(f"  ⚠  {len(cycles)} cycle(s) detected\n")
        for i, cycle in enumerate(cycles, 1):
            names = [short_label(n, G)[0] for n in cycle]
            chain = " ↔ ".join(names) + " ↔ " + names[0]
            print(f"  Cycle #{i}: {chain}")
        print()

    # ══════════════════════════════════════════════════════════════
    # SECTION 4 — CRITICAL NODE ANALYSIS
    # ══════════════════════════════════════════════════════════════
    print("[ SECTION 4 — CRITICAL NODE ANALYSIS ]")
    print("  Computing... (removing each node and recounting paths)\n")

    all_pods     = [n for n, d in G.nodes(data=True) if d.get('type') == 'Pod']
    all_sources = list(set(p["source"] for p in all_paths) | set(entry_points) | set(all_pods))
    critical_res = graph.identify_critical_node(all_sources, crown_jewels)

    baseline_count = critical_res.get("total_paths", len(all_paths))
    print(f"  Baseline attack paths : {baseline_count}\n")

    if "node" in critical_res:
        print(f"  ★  RECOMMENDATION:")
        print(f"     {critical_res['recommendation']}")
        print()

        top5 = critical_res.get("top5", [])
        if top5:
            max_reduction = top5[0][1]
            print(f"  Top 5 highest-impact nodes to remove:")
            for node_id, reduction, _ in top5:
                n_name, n_type = short_label(node_id, G)
                b = ascii_bar(reduction, max_reduction)
                print(f"    {n_name:<30} ({n_type:<15})  -{reduction} paths  {b}")
    else:
        print(f"  {critical_res.get('message', '')}")
    print()

    # ══════════════════════════════════════════════════════════════
    # SECTION 5 — TEMPORAL ANALYSIS (State-Diffing)
    # ══════════════════════════════════════════════════════════════
    print("[ SECTION 5 — TEMPORAL ANALYSIS (State-Diffing Engine) ]")
    
    if is_first_run:
        print("  [i] First run detected. Baseline cluster state recorded.")
        print("      Future scans will alert on newly discovered attack paths.\n")
    elif not new_paths:
        print("  ✅  No new attack paths detected since last scan. Cluster state is stable.\n")
    else:
        print(f"  🚨  ALERT: {len(new_paths)} NEW attack path(s) detected since last scan!\n")
        for idx, p_data in enumerate(new_paths, 1):
            score = p_data["total_risk_score"]
            hops  = p_data["total_hops"]
            sev   = severity_label(score)
            path  = p_data["path"]

            print(f"  [NEW] Path #{idx}  |  {hops} hops  |  Risk Score: {score}  [{sev}]")
            print(f"  {THIN}")

            for u, v in zip(path[:-1], path[1:]):
                rel       = G[u][v].get("relationship", G[u][v].get("relation", "?"))
                cve_note  = fmt_cve(u, G)
                u_label   = fmt_node(u, G)
                v_label   = fmt_node(v, G)
                print(f"  {u_label}{cve_note}  --[{rel}]-->  {v_label}")
            print()

    # ══════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════
    print(DIVIDER)
    print(f"  SUMMARY")
    print(f"  Attack paths found   : {len(all_paths)}")
    print(f"  Circular permissions : {len(cycles)}")
    print(f"  Total blast-radius nodes exposed : {len(total_blast_nodes)}")
    if "node_name" in critical_res:
        print(f"  Critical node to remove : {critical_res['node_name']}")
    print(DIVIDER)
    print()

    # ══════════════════════════════════════════════════════════════
    # RICH DASHBOARD + PDF + INTERACTIVE GRAPH VISUALIZER
    # ══════════════════════════════════════════════════════════════
    blast_for_dashboard = {"total_reachable": len(total_blast_nodes), "max_hops_checked": 3}

    from cli_ui_components import display_rich_dashboard
    display_rich_dashboard(worst_path, blast_for_dashboard, cycles, critical_res, graph)

    # Pass temporal data to the PDF reporter
    export_full_pdf_report(all_paths, graph, new_paths=new_paths, is_first_run=is_first_run)

    # Bonus Task 1 — Interactive HTML Attack Graph
    try:
        from graph_visualizer import export_html_visualizer
        html_path = export_html_visualizer(
            all_paths    = all_paths,
            cycles       = cycles,
            critical_res = critical_res,
            graph_ref    = graph,
            blast_sources= blast_sources if blast_sources else entry_points,
        )
        print(f"\n[+] Interactive graph visualizer: {html_path}")
        print(f"    Open in any browser — no server required.\n")
    except Exception as e:
        print(f"[!] Graph visualizer export failed: {e}")


# ══════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Attack Path Visualizer — Graph Engine")
    parser.add_argument("-i", "--input", default="cluster-graph.json")
    parser.add_argument("-b", "--blast-node", default=None)
    args = parser.parse_args()

    ag = AttackPathGraph()
    if ag.load_from_json(args.input):
        generate_report(ag, blast_radius_node=args.blast_node)