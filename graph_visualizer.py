"""
graph_visualizer.py — Shadow Tracer
Interactive HTML Attack Graph Visualizer

Serializes the full analysis output (nodes, edges, attack paths, critical node,
cycles, blast radius) into a single self-contained HTML file powered by D3.js.
The file requires no server, no build step, and no internet connection after
the initial CDN load — share it anywhere, open it in any browser.
"""

import json
import os
from datetime import datetime


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def export_html_visualizer(all_paths, cycles, critical_res, graph_ref,
                           blast_sources=None, filename="attack_graph.html"):
    """
    Generate a self-contained interactive HTML visualizer.

    Parameters
    ----------
    all_paths    : list[dict]  — output of find_all_attack_paths()
    cycles       : list[list]  — output of detect_cycles()
    critical_res : dict        — output of identify_critical_node()
    graph_ref    : AttackPathGraph — the live graph object
    blast_sources: list[str]   — source node IDs used for BFS (optional)
    filename     : str         — output filename

    Returns
    -------
    str — absolute path to the written HTML file
    """
    payload = _build_payload(all_paths, cycles, critical_res, graph_ref, blast_sources)
    html    = _build_html(payload)

    report_dir = os.getenv("REPORT_PATH", ".")
    out_path   = os.path.join(report_dir, filename)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    return os.path.abspath(out_path)


# ══════════════════════════════════════════════════════════════════════════════
# DATA SERIALISATION
# ══════════════════════════════════════════════════════════════════════════════

def _build_payload(all_paths, cycles, critical_res, graph_ref, blast_sources):
    """Collect every piece of analysis data the front-end needs."""
    G = graph_ref.G

    # ── Nodes ──────────────────────────────────────────────────────────────
    nodes = []
    for nid, attrs in G.nodes(data=True):
        nodes.append({
            "id":         nid,
            "name":       attrs.get("name", nid),
            "type":       attrs.get("type", "Unknown"),
            "namespace":  attrs.get("namespace", "cluster"),
            "risk_score": round(float(attrs.get("risk_score", 0)), 2),
            "is_source":  bool(attrs.get("is_source", False)),
            "is_sink":    bool(attrs.get("is_sink", False)),
            "cves":       list(attrs.get("cves", [])),
        })

    # ── Edges ──────────────────────────────────────────────────────────────
    edges = []
    for u, v, attrs in G.edges(data=True):
        edges.append({
            "source":       u,
            "target":       v,
            "relationship": attrs.get("relationship", attrs.get("relation", "access")),
            "weight":       round(float(attrs.get("weight", 1.0)), 2),
            "cve":          attrs.get("cve"),
            "cvss":         attrs.get("cvss"),
        })

    # ── Attack paths — collect every node/edge on any path ────────────────
    path_node_sets = []
    path_edge_sets = []
    for p in all_paths:
        path_node_sets.append(list(p["path"]))
        path_edge_sets.append([
            {"source": u, "target": v}
            for u, v in zip(p["path"][:-1], p["path"][1:])
        ])

    all_path_nodes = set(n for ns in path_node_sets for n in ns)
    all_path_edges = set(
        (e["source"], e["target"])
        for es in path_edge_sets for e in es
    )

    serialisable_paths = []
    for p in all_paths:
        score = p.get("total_risk_score", 0)
        serialisable_paths.append({
            "source":           p["source"],
            "target":           p["target"],
            "path":             p["path"],
            "total_risk_score": score,
            "total_hops":       p["total_hops"],
            "severity":         _severity(score),
        })

    # ── Cycles ─────────────────────────────────────────────────────────────
    cycle_node_set = set(n for c in cycles for n in c)
    cycle_edge_set = set()
    for c in cycles:
        for i in range(len(c)):
            cycle_edge_set.add((c[i], c[(i + 1) % len(c)]))

    # ── Critical node ──────────────────────────────────────────────────────
    critical_node_id = critical_res.get("node")
    top5 = [
        {"id": nid, "reduction": red, "remaining": rem}
        for nid, red, rem in critical_res.get("top5", [])
    ]

    # ── Blast radius ────────────────────────────────────────────────────────
    blast_data = {}
    if blast_sources:
        for src in blast_sources:
            result = graph_ref.get_blast_radius(src, max_hops=3)
            if "error" not in result:
                blast_data[src] = result

    # ── Metadata ───────────────────────────────────────────────────────────
    metadata = {
        "generated":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "node_count":        G.number_of_nodes(),
        "edge_count":        G.number_of_edges(),
        "attack_path_count": len(all_paths),
        "cycle_count":       len(cycles),
        "critical_node":     critical_node_id,
        "recommendation":    critical_res.get("recommendation", ""),
        "total_paths":       critical_res.get("total_paths", len(all_paths)),
    }

    return {
        "metadata":        metadata,
        "nodes":           nodes,
        "edges":           edges,
        "attack_paths":    serialisable_paths,
        "all_path_nodes":  list(all_path_nodes),
        "all_path_edges":  [{"source": s, "target": t} for s, t in all_path_edges],
        "cycles":          [list(c) for c in cycles],
        "cycle_nodes":     list(cycle_node_set),
        "cycle_edges":     [{"source": s, "target": t} for s, t in cycle_edge_set],
        "critical_node":   critical_node_id,
        "top5_nodes":      top5,
        "blast_radius":    blast_data,
    }


def _severity(score):
    if score >= 15:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
# HTML TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════

def _build_html(payload):
    data_json = json.dumps(payload, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Shadow Tracer — Attack Graph</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7"></script><link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Exo+2:wght@300;400;600&display=swap" rel="stylesheet"/>

<style>
/* ═══════════════════════════════════════════════════
   DESIGN SYSTEM — Shadow Tracer Threat Intelligence
   Aesthetic: Military-grade SOC terminal, neon-on-obsidian
   ═══════════════════════════════════════════════════ */
:root {{
  --bg-void:       #050709;
  --bg-panel:      #090c10;
  --bg-card:       #0d1117;
  --bg-card-hover: #111820;
  --border:        #1c2a3a;
  --border-bright: #1e3a5f;

  --text-primary:  #c9d8e8;
  --text-secondary:#6a8aaa;
  --text-muted:    #354a60;
  --text-mono:     #7eb8d4;

  --accent-cyan:   #00d4ff;
  --accent-cyan-dim: #005f80;
  --accent-green:  #00ff88;
  --accent-green-dim: #004d2a;
  --accent-red:    #ff3355;
  --accent-red-dim:#5c0018;
  --accent-amber:  #ffaa00;
  --accent-amber-dim: #4d3300;
  --accent-purple: #b060ff;
  --accent-purple-dim: #2a0060;
  --accent-orange: #ff6600;

  /* Node type palette */
  --node-pod:       #00aaff;
  --node-sa:        #00ccaa;
  --node-role:      #8888ff;
  --node-secret:    #ffaa00;
  --node-service:   #44aaff;
  --node-external:  #ff3355;
  --node-user:      #ff6644;
  --node-db:        #ffcc00;
  --node-node:      #ff4488;
  --node-ns:        #66aacc;
  --node-default:   #668899;

  --shadow-glow-red:    0 0 20px rgba(255,51,85,0.6),  0 0 40px rgba(255,51,85,0.2);
  --shadow-glow-cyan:   0 0 20px rgba(0,212,255,0.5),  0 0 40px rgba(0,212,255,0.15);
  --shadow-glow-purple: 0 0 24px rgba(176,96,255,0.7), 0 0 48px rgba(176,96,255,0.25);
  --shadow-glow-amber:  0 0 20px rgba(255,170,0,0.6),  0 0 40px rgba(255,170,0,0.2);
}}

*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  font-family: 'Exo 2', sans-serif;
  background: var(--bg-void);
  color: var(--text-primary);
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}}

/* ── SCANLINE OVERLAY ─────────────────────────────── */
body::before {{
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.03) 2px,
    rgba(0,0,0,0.03) 4px
  );
  pointer-events: none;
  z-index: 9999;
}}

/* ── TOPBAR ───────────────────────────────────────── */
.topbar {{
  display: flex;
  align-items: center;
  gap: 0;
  padding: 0 20px;
  height: 54px;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  position: relative;
  overflow: hidden;
}}
.topbar::after {{
  content: '';
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
  animation: scanline 4s ease-in-out infinite;
}}
@keyframes scanline {{
  0%,100% {{ opacity: 0.3; transform: scaleX(0.3); }}
  50% {{ opacity: 1; transform: scaleX(1); }}
}}

.brand {{
  font-family: 'Rajdhani', sans-serif;
  font-weight: 700;
  font-size: 20px;
  letter-spacing: 4px;
  color: var(--accent-cyan);
  text-transform: uppercase;
  text-shadow: var(--shadow-glow-cyan);
  margin-right: 24px;
  white-space: nowrap;
}}
.brand span {{ color: var(--text-muted); font-weight: 400; }}

.topbar-divider {{
  width: 1px;
  height: 28px;
  background: var(--border);
  margin: 0 16px;
}}

.stat-pill {{
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
}}
.stat-pill .label {{ color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }}
.stat-pill .value {{ color: var(--text-primary); font-size: 13px; }}
.stat-pill .value.critical {{ color: var(--accent-red); text-shadow: var(--shadow-glow-red); }}
.stat-pill .value.warn  {{ color: var(--accent-amber); }}
.stat-pill .value.ok    {{ color: var(--accent-green); }}

.topbar-right {{
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 10px;
}}

.ts {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-muted);
}}

/* ── MAIN LAYOUT ─────────────────────────────────── */
.workspace {{
  display: flex;
  flex: 1;
  overflow: hidden;
}}

/* ── GRAPH CANVAS ─────────────────────────────────── */
#graph-container {{
  flex: 1;
  position: relative;
  overflow: hidden;
  background: radial-gradient(ellipse at center, #060c14 0%, #050709 70%);
}}

svg#graph {{
  width: 100%;
  height: 100%;
  cursor: grab;
}}
svg#graph:active {{ cursor: grabbing; }}

/* D3 node circles */
.node-circle {{
  stroke-width: 1.5;
  transition: r 0.2s, filter 0.2s;
  cursor: pointer;
}}
.node-circle:hover {{
  stroke-width: 2.5;
}}
.node-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  fill: var(--text-secondary);
  pointer-events: none;
  dominant-baseline: middle;
}}

/* Edge arrows */
.link {{
  fill: none;
  stroke-width: 1.2;
  stroke: #1c2a3a;
  opacity: 0.6;
}}
.link.attack-edge {{
  stroke: var(--accent-red);
  stroke-width: 2.2;
  opacity: 0.85;
  stroke-dasharray: 8 4;
  animation: dash-flow 1.2s linear infinite;
}}
.link.cycle-edge {{
  stroke: var(--accent-orange);
  stroke-width: 1.8;
  stroke-dasharray: 5 3;
  opacity: 0.75;
  animation: dash-flow 2s linear infinite;
}}
@keyframes dash-flow {{
  to {{ stroke-dashoffset: -24; }}
}}

/* Special node states */
.node-critical-ring {{
  fill: none;
  stroke: var(--accent-purple);
  stroke-width: 2;
  animation: pulse-ring 1.5s ease-in-out infinite;
  pointer-events: none;
}}
@keyframes pulse-ring {{
  0%,100% {{ stroke-opacity: 1; r: 18; }}
  50%      {{ stroke-opacity: 0.2; r: 26; }}
}}

.node-source-ring {{
  fill: none;
  stroke: var(--accent-red);
  stroke-width: 1.5;
  animation: pulse-ring 2s ease-in-out infinite;
  pointer-events: none;
}}

.node-sink-ring {{
  fill: none;
  stroke: var(--accent-amber);
  stroke-width: 1.5;
  animation: pulse-ring 2.5s ease-in-out infinite;
  pointer-events: none;
}}

/* Edge tooltip */
.edge-tooltip {{
  position: absolute;
  background: var(--bg-card);
  border: 1px solid var(--border-bright);
  border-radius: 4px;
  padding: 8px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-primary);
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.15s;
  max-width: 220px;
  z-index: 100;
}}
.edge-tooltip.visible {{ opacity: 1; }}

/* ── NODE HOVER TOOLTIP ──────────────────────────── */
.node-tooltip {{
  position: absolute;
  background: var(--bg-card);
  border: 1px solid var(--border-bright);
  border-radius: 5px;
  padding: 10px 13px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-primary);
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.12s;
  z-index: 200;
  min-width: 170px;
  box-shadow: 0 4px 24px rgba(0,0,0,0.5);
}}
.node-tooltip.visible {{ opacity: 1; }}
.node-tooltip .nt-name {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 14px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 5px;
  line-height: 1.2;
}}
.node-tooltip .nt-badge {{
  display: inline-block;
  font-size: 8px;
  letter-spacing: 1px;
  padding: 2px 6px;
  border-radius: 2px;
  border: 1px solid;
  margin-bottom: 7px;
}}
.node-tooltip .nt-row {{
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 2px 0;
  border-bottom: 1px solid var(--border);
  font-size: 9px;
}}
.node-tooltip .nt-row:last-child {{ border-bottom: none; }}
.node-tooltip .nt-k {{ color: var(--text-muted); }}
.node-tooltip .nt-v {{ color: var(--text-primary); font-weight: 600; }}
.node-tooltip .nt-cve {{ color: var(--accent-red); }}
.node-tooltip .nt-paths {{ color: var(--accent-amber); }}

/* ── SIDE PANEL ───────────────────────────────────── */
.side-panel {{
  width: 320px;
  flex-shrink: 0;
  background: var(--bg-panel);
  border-left: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}}

.panel-tabs {{
  display: flex;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}}
.panel-tab {{
  flex: 1;
  padding: 10px 4px;
  font-family: 'Rajdhani', sans-serif;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--text-muted);
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s;
}}
.panel-tab:hover {{ color: var(--text-secondary); }}
.panel-tab.active {{
  color: var(--accent-cyan);
  border-bottom-color: var(--accent-cyan);
}}

.panel-body {{
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}}
.panel-body::-webkit-scrollbar {{ width: 4px; }}
.panel-body::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

.tab-pane {{ display: none; }}
.tab-pane.active {{ display: block; }}

/* ── SECTION WITHIN PANEL ─────────────────────────── */
.section-label {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-secondary);
  margin-bottom: 8px;
  padding-bottom: 4px;
  border-bottom: 1px solid var(--border-bright);
}}

/* ── NODE DETAIL CARD ─────────────────────────────── */
.node-detail-empty {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 200px;
  color: var(--text-muted);
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  text-align: center;
  gap: 8px;
}}
.node-detail-empty .icon {{ font-size: 28px; opacity: 0.4; }}

.node-detail-header {{
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin-bottom: 12px;
}}
.node-type-badge {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  letter-spacing: 1px;
  padding: 3px 7px;
  border-radius: 3px;
  border: 1px solid;
  white-space: nowrap;
  margin-top: 2px;
}}
.node-name {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
  word-break: break-all;
  line-height: 1.2;
}}
.node-ns {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-muted);
  margin-top: 2px;
}}

.detail-row {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 5px 0;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
}}
.detail-row .dk {{ color: var(--text-muted); font-family: 'Share Tech Mono', monospace; font-size: 10px; }}
.detail-row .dv {{ color: var(--text-primary); font-weight: 600; font-size: 12px; }}

.cve-tag {{
  display: inline-block;
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  padding: 2px 6px;
  background: var(--accent-red-dim);
  color: var(--accent-red);
  border: 1px solid var(--accent-red);
  border-radius: 2px;
  margin: 2px 2px 0 0;
}}

.edge-list-item {{
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 0;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-secondary);
  border-bottom: 1px solid var(--border);
}}
.edge-rel {{
  color: var(--accent-cyan-dim);
  border: 1px solid var(--accent-cyan-dim);
  padding: 1px 5px;
  border-radius: 2px;
  font-size: 9px;
  white-space: nowrap;
}}
.edge-dir {{ color: var(--text-muted); font-size: 9px; }}
.edge-peer {{ color: var(--text-secondary); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

/* ── ATTACK PATH LIST ─────────────────────────────── */
.path-card {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 4px;
  margin-bottom: 8px;
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
  overflow: hidden;
}}
.path-card:hover {{ border-color: var(--border-bright); background: var(--bg-card-hover); }}
.path-card.selected {{ border-color: var(--accent-cyan); }}

.path-card-header {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
}}
.path-idx {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-muted);
  min-width: 28px;
}}
.path-sev {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1px;
  padding: 2px 6px;
  border-radius: 2px;
}}
.sev-CRITICAL {{ background: var(--accent-red-dim);   color: var(--accent-red);    border: 1px solid var(--accent-red); }}
.sev-HIGH     {{ background: var(--accent-amber-dim); color: var(--accent-amber);  border: 1px solid var(--accent-amber); }}
.sev-MEDIUM   {{ background: #2a2000;                 color: #ffdd44;              border: 1px solid #ffdd44; }}
.sev-LOW      {{ background: #001a0d;                 color: var(--accent-green);  border: 1px solid var(--accent-green); }}

.path-score {{
  margin-left: auto;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-primary);
}}
.path-hops {{ font-size: 10px; color: var(--text-muted); font-family: 'Share Tech Mono', monospace; }}

.path-chain {{
  padding: 0 10px 8px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  color: var(--text-muted);
  line-height: 1.8;
  word-break: break-all;
}}

/* ── CRITICAL NODE CARD ───────────────────────────── */
.critical-card {{
  background: linear-gradient(135deg, var(--accent-purple-dim), var(--bg-card));
  border: 1px solid var(--accent-purple);
  border-radius: 4px;
  padding: 12px;
  margin-bottom: 12px;
  box-shadow: var(--shadow-glow-purple);
}}
.critical-card .cn-label {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--accent-purple);
  text-transform: uppercase;
  margin-bottom: 6px;
}}
.critical-card .cn-name {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 14px;
  color: var(--text-primary);
  margin-bottom: 4px;
}}
.critical-card .cn-impact {{
  font-size: 11px;
  color: var(--text-primary);
  opacity: 0.85;
}}
.critical-card .cn-rec {{
  margin-top: 8px;
  font-size: 11px;
  color: var(--accent-amber);
  line-height: 1.6;
  border-top: 1px solid var(--border-bright);
  padding-top: 8px;
  font-weight: 500;
}}

.top5-row {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 0;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  border-bottom: 1px solid var(--border);
}}
.top5-name {{ color: var(--text-primary); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; }}
.top5-bar-bg {{ width: 60px; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }}
.top5-bar-fill {{ height: 100%; background: var(--accent-purple); border-radius: 2px; box-shadow: 0 0 4px rgba(176,96,255,0.5); }}
.top5-count {{ color: var(--accent-red); min-width: 36px; text-align: right; font-size: 11px; font-weight: 600; }}

/* ── CYCLE ITEM ───────────────────────────────────── */
.cycle-item {{
  background: var(--bg-card);
  border: 1px solid var(--accent-orange);
  border-radius: 4px;
  padding: 8px 10px;
  margin-bottom: 8px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--accent-orange);
  line-height: 1.8;
}}
.cycle-label {{
  font-size: 9px;
  color: var(--text-muted);
  margin-bottom: 4px;
  font-family: 'Rajdhani', sans-serif;
  letter-spacing: 1px;
  text-transform: uppercase;
}}

/* ── FILTER TOOLBAR ───────────────────────────────── */
.toolbar {{
  height: 40px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 0 14px;
  background: var(--bg-panel);
  border-top: 1px solid var(--border);
}}
.toolbar-label {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-right: 4px;
}}
.filter-btn {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
  padding: 4px 10px;
  border-radius: 3px;
  border: 1px solid var(--border);
  background: none;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s;
}}
.filter-btn:hover {{ border-color: var(--border-bright); color: var(--text-primary); }}
.filter-btn.active {{
  border-color: var(--accent-cyan);
  color: var(--accent-cyan);
  background: rgba(0,212,255,0.06);
}}
.filter-btn.active.red   {{ border-color: var(--accent-red); color: var(--accent-red); background: rgba(255,51,85,0.06); }}
.filter-btn.active.amber {{ border-color: var(--accent-amber); color: var(--accent-amber); background: rgba(255,170,0,0.06); }}
.filter-btn.active.orange{{ border-color: var(--accent-orange); color: var(--accent-orange); background: rgba(255,102,0,0.06); }}
.filter-btn.active.purple{{ border-color: var(--accent-purple); color: var(--accent-purple); background: rgba(176,96,255,0.06); }}

.toolbar-right {{
  margin-left: auto;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-muted);
}}

/* ── LEGEND ───────────────────────────────────────── */
.legend-container {{
  position: absolute;
  bottom: 52px;
  left: 12px;
  background: rgba(9,12,16,0.92);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 10px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  color: var(--text-muted);
  backdrop-filter: blur(4px);
  z-index: 10;
}}
.legend-title {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-secondary);
  margin-bottom: 6px;
}}
.legend-row {{
  display: flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 3px;
}}
.legend-dot {{
  width: 10px; height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}}
.legend-sep {{ height: 1px; background: var(--border); margin: 4px 0; }}
.legend-line {{ width: 20px; height: 3px; border-radius: 1px; flex-shrink: 0; }}

/* ── ZOOM CONTROLS ─────────────────────────────────── */
.zoom-controls {{
  position: absolute;
  bottom: 52px;
  right: 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  z-index: 10;
}}
.zoom-btn {{
  width: 28px; height: 28px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-secondary);
  font-size: 16px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: border-color 0.15s, color 0.15s;
  font-family: monospace;
  line-height: 1;
}}
.zoom-btn:hover {{ border-color: var(--accent-cyan); color: var(--accent-cyan); }}

/* ── SCROLLABLE MISC ──────────────────────────────── */
.empty-msg {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-muted);
  text-align: center;
  padding: 20px 0;
}}
</style>
</head>

<body>

<!-- ════════════════════ TOPBAR ════════════════════ -->
<div class="topbar">
  <div class="brand">Shadow<span>Tracer</span></div>
  <div class="topbar-divider"></div>
  <div class="stat-pill">
    <span class="label">Nodes</span>
    <span class="value" id="stat-nodes">—</span>
  </div>
  <div class="topbar-divider"></div>
  <div class="stat-pill">
    <span class="label">Edges</span>
    <span class="value" id="stat-edges">—</span>
  </div>
  <div class="topbar-divider"></div>
  <div class="stat-pill">
    <span class="label">Attack Paths</span>
    <span class="value critical" id="stat-paths">—</span>
  </div>
  <div class="topbar-divider"></div>
  <div class="stat-pill">
    <span class="label">Cycles</span>
    <span class="value warn" id="stat-cycles">—</span>
  </div>
  <div class="topbar-divider"></div>
  <div class="stat-pill">
    <span class="label">Critical Node</span>
    <span class="value" style="color:var(--accent-purple)" id="stat-critical">—</span>
  </div>
  <div class="topbar-right">
    <span class="ts" id="stat-ts">—</span>
  </div>
</div>

<!-- ════════════════════ WORKSPACE ════════════════════ -->
<div class="workspace">

  <!-- ── GRAPH CANVAS ── -->
  <div id="graph-container">
    <svg id="graph">
      <defs>
        <!-- Arrow markers for different edge types -->
        <marker id="arrow-default" markerWidth="8" markerHeight="8" refX="12" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#1c2a3a"/>
        </marker>
        <marker id="arrow-attack" markerWidth="8" markerHeight="8" refX="12" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#ff3355"/>
        </marker>
        <marker id="arrow-cycle" markerWidth="8" markerHeight="8" refX="12" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#ff6600"/>
        </marker>
      </defs>
      <g id="graph-root"></g>
    </svg>

    <!-- Legend -->
    <div class="legend-container">
      <div class="legend-title">Legend</div>
      <div class="legend-row"><div class="legend-dot" style="background:var(--node-external)"></div>Entry Point (Internet/User)</div>
      <div class="legend-row"><div class="legend-dot" style="background:var(--node-pod)"></div>Pod</div>
      <div class="legend-row"><div class="legend-dot" style="background:var(--node-sa)"></div>Service Account</div>
      <div class="legend-row"><div class="legend-dot" style="background:var(--node-role)"></div>Role / ClusterRole</div>
      <div class="legend-row"><div class="legend-dot" style="background:var(--node-secret)"></div>Secret</div>
      <div class="legend-row"><div class="legend-dot" style="background:var(--node-db)"></div>Crown Jewel (DB / Sink)</div>
      <div class="legend-sep"></div>
      <div class="legend-row"><div class="legend-line" style="background:var(--accent-red)"></div>Attack Path Edge</div>
      <div class="legend-row"><div class="legend-line" style="background:var(--accent-orange)"></div>Circular Permission</div>
      <div class="legend-row"><div class="legend-line" style="background:var(--border)"></div>Normal Relationship</div>
      <div class="legend-sep"></div>
      <div class="legend-row"><div class="legend-dot" style="background:var(--accent-purple);box-shadow:0 0 6px var(--accent-purple)"></div>Critical Node (remove first)</div>
    </div>

    <!-- Zoom buttons -->
    <div class="zoom-controls">
      <button class="zoom-btn" id="zoom-in">+</button>
      <button class="zoom-btn" id="zoom-out">−</button>
      <button class="zoom-btn" id="zoom-fit" title="Fit to view" style="font-size:11px">⊡</button>
    </div>

    <!-- Edge tooltip -->
    <div class="edge-tooltip" id="edge-tooltip"></div>
    <!-- Node hover tooltip -->
    <div class="node-tooltip" id="node-tooltip"></div>
  </div>

  <!-- ── SIDE PANEL ── -->
  <div class="side-panel">
    <div class="panel-tabs">
      <button class="panel-tab active" data-tab="node">Node Detail</button>
      <button class="panel-tab" data-tab="paths">Attack Paths</button>
      <button class="panel-tab" data-tab="analysis">Analysis</button>
    </div>

    <!-- NODE DETAIL TAB -->
    <div class="panel-body tab-pane active" id="tab-node">
      <div class="node-detail-empty" id="node-empty">
        <div class="icon">⬡</div>
        <div>Click any node to inspect</div>
      </div>
      <div id="node-detail" style="display:none"></div>
    </div>

    <!-- ATTACK PATHS TAB -->
    <div class="panel-body tab-pane" id="tab-paths">
      <div id="paths-list"></div>
    </div>

    <!-- ANALYSIS TAB -->
    <div class="panel-body tab-pane" id="tab-analysis">
      <div id="analysis-content"></div>
    </div>
  </div>
</div>

<!-- ════════════════════ TOOLBAR ════════════════════ -->
<div class="toolbar">
  <span class="toolbar-label">View:</span>
  <button class="filter-btn active" id="btn-all">All Nodes</button>
  <button class="filter-btn" id="btn-paths" data-color="red">Attack Paths</button>
  <button class="filter-btn" id="btn-cycles" data-color="orange">Cycles</button>
  <button class="filter-btn" id="btn-blast" data-color="amber">Blast Radius</button>
  <button class="filter-btn" id="btn-critical" data-color="purple">Critical Node</button>
  <button class="filter-btn" id="btn-reset">Reset</button>
  <div class="toolbar-right" id="toolbar-hint">Scroll to zoom · Drag to pan · Click node to inspect</div>
</div>

<!-- ════════════════════ D3 VISUALIZATION ════════════════════ -->
<script>
// ═══════════════════════════════════════════════════════════════
// INJECTED DATA
// ═══════════════════════════════════════════════════════════════
const DATA = {data_json};

// ═══════════════════════════════════════════════════════════════
// CONSTANTS & COLOUR MAP
// ═══════════════════════════════════════════════════════════════
const TYPE_COLOR = {{
  Pod:              '#00aaff',
  ServiceAccount:   '#00ccaa',
  Role:             '#8888ff',
  ClusterRole:      '#aaaaff',
  Secret:           '#ffaa00',
  ConfigMap:        '#88aacc',
  Service:          '#44aaff',
  ExternalActor:    '#ff3355',
  User:             '#ff6644',
  Database:         '#ffcc00',
  Node:             '#ff4488',
  Namespace:        '#66aacc',
  PersistentVolume: '#dd88ff',
  Vulnerability:    '#ff6622',
}};
const DEFAULT_COLOR = '#668899';

function nodeColor(d) {{
  if (d.is_sink)   return '#ffcc00';
  if (d.is_source) return '#ff3355';
  return TYPE_COLOR[d.type] || DEFAULT_COLOR;
}}
function nodeRadius(d) {{
  let r = 10;
  if (d.is_source || d.is_sink) r = 14;
  if (d.id === DATA.critical_node) r = 16;
  return r;
}}

// ═══════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════
let selectedNode     = null;
let selectedPathIdx  = -1;
let activeFilter     = 'all';  // all | paths | cycles | blast | critical

// Sets of highlighted IDs for current filter
let hlNodes = new Set();
let hlEdges = new Set(); // "src::tgt" keys

// ═══════════════════════════════════════════════════════════════
// TOPBAR STATS
// ═══════════════════════════════════════════════════════════════
const m = DATA.metadata;
document.getElementById('stat-nodes').textContent    = m.node_count;
document.getElementById('stat-edges').textContent    = m.edge_count;
document.getElementById('stat-paths').textContent    = m.attack_path_count;
document.getElementById('stat-cycles').textContent   = m.cycle_count;
document.getElementById('stat-ts').textContent       = m.generated;

const cn = DATA.nodes.find(n => n.id === DATA.critical_node);
document.getElementById('stat-critical').textContent = cn ? cn.name : 'None';

// ═══════════════════════════════════════════════════════════════
// D3 FORCE SIMULATION
// ═══════════════════════════════════════════════════════════════
const svg    = d3.select('#graph');
const root   = d3.select('#graph-root');
const W      = () => document.getElementById('graph-container').offsetWidth;
const H      = () => document.getElementById('graph-container').offsetHeight;

// Build node & link arrays for D3 (clone so simulation can mutate them)
const simNodes = DATA.nodes.map(d => ({{ ...d }}));
const simLinks = DATA.edges.map(e => ({{ ...e }}));

// Map node ids for D3 lookup
const nodeById = {{}};
simNodes.forEach(n => nodeById[n.id] = n);

// Resolve link source/target to objects
simLinks.forEach(l => {{
  l._source_id = l.source;
  l._target_id = l.target;
}});

const simulation = d3.forceSimulation(simNodes)
  .force('link', d3.forceLink(simLinks)
    .id(d => d.id)
    .distance(d => {{
      // Longer distance for attack path edges so kill chains spread out
      const key = d._source_id + '::' + d._target_id;
      return DATA.all_path_edges.some(e => e.source === d._source_id && e.target === d._target_id)
        ? 130 : 80;
    }})
    .strength(0.4))
  .force('charge', d3.forceManyBody().strength(-280))
  .force('center', d3.forceCenter(W() / 2, H() / 2))
  .force('collide', d3.forceCollide(28))
  .alphaDecay(0.025);

// ── ZOOM ──────────────────────────────────────────────────────
const zoom = d3.zoom()
  .scaleExtent([0.1, 5])
  .on('zoom', e => root.attr('transform', e.transform));
svg.call(zoom);

// ── EDGES ─────────────────────────────────────────────────────
const linkSel = root.append('g').attr('class', 'links-layer')
  .selectAll('line')
  .data(simLinks)
  .join('line')
  .attr('class', d => {{
    const key = d._source_id + '::' + d._target_id;
    const isAttack = DATA.all_path_edges.some(e => e.source === d._source_id && e.target === d._target_id);
    const isCycle  = DATA.cycle_edges.some(e => e.source === d._source_id && e.target === d._target_id);
    return 'link' + (isAttack ? ' attack-edge' : '') + (isCycle ? ' cycle-edge' : '');
  }})
  .attr('marker-end', d => {{
    const isAttack = DATA.all_path_edges.some(e => e.source === d._source_id && e.target === d._target_id);
    const isCycle  = DATA.cycle_edges.some(e => e.source === d._source_id && e.target === d._target_id);
    return isAttack ? 'url(#arrow-attack)' : isCycle ? 'url(#arrow-cycle)' : 'url(#arrow-default)';
  }})
  .attr('data-key', d => d._source_id + '::' + d._target_id);

// ── OVERLAY LAYER (blast rings, critical badge) ───────────────
const overlayG = root.append('g').attr('class', 'overlay-layer');

// ── NODES ─────────────────────────────────────────────────────
const nodeG = root.append('g').attr('class', 'nodes-layer')
  .selectAll('g')
  .data(simNodes)
  .join('g')
  .attr('class', 'node-g')
  .attr('data-id', d => d.id)
  .call(d3.drag()
    .on('start', dragStart)
    .on('drag',  dragging)
    .on('end',   dragEnd));

// Pulse ring for source / sink / critical
nodeG.each(function(d) {{
  const g = d3.select(this);
  if (d.id === DATA.critical_node) {{
    g.append('circle').attr('class', 'node-critical-ring').attr('r', 20);
  }} else if (d.is_source) {{
    g.append('circle').attr('class', 'node-source-ring').attr('r', 18);
  }} else if (d.is_sink) {{
    g.append('circle').attr('class', 'node-sink-ring').attr('r', 18);
  }}
}});

// Main circle
nodeG.append('circle')
  .attr('class', 'node-circle')
  .attr('r', nodeRadius)
  .attr('fill', nodeColor)
  .attr('stroke', d => d3.color(nodeColor(d)).darker(0.5))
  .on('click', onNodeClick)
  .on('mouseenter', onNodeHover)
  .on('mouseleave', onNodeLeave);

// Label
nodeG.append('text')
  .attr('class', 'node-label')
  .attr('dy', d => nodeRadius(d) + 12)
  .attr('text-anchor', 'middle')
  .text(d => d.name.length > 18 ? d.name.slice(0, 17) + '…' : d.name);

// Edge hover tooltip
linkSel
  .on('mouseenter', function(event, d) {{
    const tip = document.getElementById('edge-tooltip');
    const box = document.getElementById('graph-container').getBoundingClientRect();
    const lines = [
      '<b>' + d.relationship + '</b>',
      'From: ' + (nodeById[d._source_id] ? nodeById[d._source_id].name : d._source_id),
      'To: '   + (nodeById[d._target_id] ? nodeById[d._target_id].name : d._target_id),
      d.weight != null ? 'Weight: ' + d.weight : '',
      d.cvss   != null ? 'CVSS: '   + d.cvss   : '',
      d.cve               ? 'CVE: '    + d.cve   : '',
    ].filter(Boolean).join('<br/>');
    tip.innerHTML = lines;
    tip.style.left = (event.clientX - box.left + 12) + 'px';
    tip.style.top  = (event.clientY - box.top  + 12) + 'px';
    tip.classList.add('visible');
  }})
  .on('mousemove', function(event) {{
    const tip = document.getElementById('edge-tooltip');
    const box = document.getElementById('graph-container').getBoundingClientRect();
    tip.style.left = (event.clientX - box.left + 12) + 'px';
    tip.style.top  = (event.clientY - box.top  + 12) + 'px';
  }})
  .on('mouseleave', function() {{
    document.getElementById('edge-tooltip').classList.remove('visible');
  }});

// ── SIMULATION TICK ───────────────────────────────────────────
simulation.on('tick', () => {{
  linkSel
    .attr('x1', d => d.source.x)
    .attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x)
    .attr('y2', d => d.target.y);

  nodeG.attr('transform', d => `translate(${{d.x}},${{d.y}})`);

  // Keep blast rings in sync with node positions during simulation
  if (activeFilter === 'blast') {{
    overlayG.selectAll('circle.blast-ring').each(function(_, i) {{
      // Rings are rebuilt on next applyFilter call — just trigger a redraw
    }});
  }}

  applyFilter(activeFilter, false);
}});

// ── DRAG ──────────────────────────────────────────────────────
function dragStart(event, d) {{
  if (!event.active) simulation.alphaTarget(0.3).restart();
  d.fx = d.x; d.fy = d.y;
}}
function dragging(event, d) {{
  d.fx = event.x; d.fy = event.y;
}}
function dragEnd(event, d) {{
  if (!event.active) simulation.alphaTarget(0);
  d.fx = null; d.fy = null;
}}

// ── ZOOM BUTTONS ──────────────────────────────────────────────
document.getElementById('zoom-in').onclick  = () => svg.transition().call(zoom.scaleBy, 1.4);
document.getElementById('zoom-out').onclick = () => svg.transition().call(zoom.scaleBy, 0.7);
document.getElementById('zoom-fit').onclick  = fitView;

function fitView() {{
  const w = W(), h = H(), pad = 60;
  const xs = simNodes.map(n => n.x), ys = simNodes.map(n => n.y);
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  const y0 = Math.min(...ys), y1 = Math.max(...ys);
  const gw = x1 - x0 || 1, gh = y1 - y0 || 1;
  const scale = Math.min((w - pad*2) / gw, (h - pad*2) / gh, 2);
  const tx = (w - scale*gw)/2 - scale*x0;
  const ty = (h - scale*gh)/2 - scale*y0;
  svg.transition().duration(600).call(
    zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale)
  );
}}

// ═══════════════════════════════════════════════════════════════
// NODE INTERACTION
// ═══════════════════════════════════════════════════════════════
function onNodeClick(event, d) {{
  selectedNode = d;
  renderNodeDetail(d);
  // Switch to Node Detail tab
  switchTab('node');
  event.stopPropagation();
}}

function onNodeHover(event, d) {{
  const tip   = document.getElementById('node-tooltip');
  const box   = document.getElementById('graph-container').getBoundingClientRect();
  const color = nodeColor(d);
  const cveCnt  = d.cves ? d.cves.length : 0;
  const pathCnt = DATA.attack_paths.filter(p => p.path.includes(d.id)).length;
  const riskCol = d.risk_score >= 8 ? 'var(--accent-red)' : d.risk_score >= 4 ? 'var(--accent-amber)' : 'var(--accent-green)';
  const flags   = [];
  if (d.is_source) flags.push('ENTRY POINT');
  if (d.is_sink)   flags.push('CROWN JEWEL');
  if (d.id === DATA.critical_node) flags.push('⚠ CRITICAL');
  tip.innerHTML = `
    <div class="nt-name">${{d.name}}</div>
    <div class="nt-badge" style="color:${{color}};border-color:${{color}}">${{d.type.toUpperCase()}}${{flags.length ? ' · '+flags.join(' · ') : ''}}</div>
    <div class="nt-row"><span class="nt-k">Namespace</span><span class="nt-v">${{d.namespace}}</span></div>
    <div class="nt-row"><span class="nt-k">Risk Score</span><span class="nt-v" style="color:${{riskCol}}">${{d.risk_score}}</span></div>
    ${{cveCnt > 0 ? `<div class="nt-row"><span class="nt-k">CVEs</span><span class="nt-v nt-cve">${{cveCnt}} found</span></div>` : ''}}
    ${{pathCnt > 0 ? `<div class="nt-row"><span class="nt-k">Attack Paths</span><span class="nt-v nt-paths">${{pathCnt}} through here</span></div>` : ''}}
  `;
  // Position tooltip: prefer right of cursor, flip left if near right edge
  let x = event.clientX - box.left + 14;
  let y = event.clientY - box.top  - 10;
  if (x + 190 > box.width) x = event.clientX - box.left - 190;
  tip.style.left = x + 'px';
  tip.style.top  = y + 'px';
  tip.classList.add('visible');
  // Keep toolbar hint minimal
  document.getElementById('toolbar-hint').textContent =
    d.type + ' · ' + d.name + '  |  click to inspect';
}}
function onNodeLeave() {{
  document.getElementById('node-tooltip').classList.remove('visible');
  document.getElementById('toolbar-hint').textContent =
    'Scroll to zoom · Drag to pan · Click node to inspect';
}}

svg.on('click', () => {{
  selectedNode = null;
  document.getElementById('node-empty').style.display = '';
  document.getElementById('node-detail').style.display = 'none';
}});

// ═══════════════════════════════════════════════════════════════
// NODE DETAIL RENDERER
// ═══════════════════════════════════════════════════════════════
function renderNodeDetail(d) {{
  document.getElementById('node-empty').style.display = 'none';
  const el = document.getElementById('node-detail');
  el.style.display = '';

  const color  = nodeColor(d);
  const isCrit = d.id === DATA.critical_node;

  // Connected edges
  const outEdges = DATA.edges.filter(e => e.source === d.id);
  const inEdges  = DATA.edges.filter(e => e.target === d.id);

  // Attack paths that pass through this node
  const myPaths = DATA.attack_paths.filter(p => p.path.includes(d.id));

  el.innerHTML = `
    <div class="node-detail-header">
      <div>
        <div class="node-type-badge" style="color:${{color}};border-color:${{color}}">
          ${{d.type.toUpperCase()}}
        </div>
      </div>
      <div>
        <div class="node-name">${{d.name}}</div>
        <div class="node-ns">ns: ${{d.namespace}}</div>
      </div>
    </div>

    ${{isCrit ? `<div class="critical-card" style="margin-bottom:10px">
      <div class="cn-label">⚠ Critical Node</div>
      <div style="font-size:11px;color:var(--text-secondary)">
        Removing this node eliminates the most attack paths.
      </div>
    </div>` : ''}}

    <div class="section-label" style="margin-top:8px">Properties</div>
    <div class="detail-row"><span class="dk">Risk Score</span><span class="dv" style="color:${{d.risk_score >= 8 ? 'var(--accent-red)' : d.risk_score >= 4 ? 'var(--accent-amber)' : 'var(--accent-green)'}}">${{d.risk_score}}</span></div>
    <div class="detail-row"><span class="dk">Entry Point</span><span class="dv">${{d.is_source ? '✓ Yes' : '—'}}</span></div>
    <div class="detail-row"><span class="dk">Crown Jewel</span><span class="dv">${{d.is_sink ? '✓ Yes' : '—'}}</span></div>
    <div class="detail-row"><span class="dk">Attack Paths</span><span class="dv" style="color:${{myPaths.length > 0 ? 'var(--accent-red)':''}}">
      ${{myPaths.length > 0 ? myPaths.length + ' path(s)' : 'Not on any path'}}
    </span></div>

    ${{d.cves && d.cves.length > 0 ? `
      <div class="section-label" style="margin-top:10px">CVEs (${{d.cves.length}})</div>
      <div>${{d.cves.map(c => `<span class="cve-tag">${{c}}</span>`).join('')}}</div>
    ` : ''}}

    <div class="section-label" style="margin-top:10px">Outbound (${{outEdges.length}})</div>
    ${{outEdges.length === 0 ? '<div class="empty-msg">None</div>' :
      outEdges.map(e => `
        <div class="edge-list-item">
          <span class="edge-dir">→</span>
          <span class="edge-rel">${{e.relationship}}</span>
          <span class="edge-peer">${{(DATA.nodes.find(n=>n.id===e.target)||{{name:e.target}}).name}}</span>
        </div>`).join('')}}

    <div class="section-label" style="margin-top:10px">Inbound (${{inEdges.length}})</div>
    ${{inEdges.length === 0 ? '<div class="empty-msg">None</div>' :
      inEdges.map(e => `
        <div class="edge-list-item">
          <span class="edge-dir">←</span>
          <span class="edge-rel">${{e.relationship}}</span>
          <span class="edge-peer">${{(DATA.nodes.find(n=>n.id===e.source)||{{name:e.source}}).name}}</span>
        </div>`).join('')}}
  `;
}}

// ═══════════════════════════════════════════════════════════════
// ATTACK PATHS TAB
// ═══════════════════════════════════════════════════════════════
function renderPathsList() {{
  const el = document.getElementById('paths-list');
  if (!DATA.attack_paths.length) {{
    el.innerHTML = '<div class="empty-msg">✅ No attack paths detected</div>';
    return;
  }}
  el.innerHTML = DATA.attack_paths.map((p, i) => {{
    const chain = p.path.map(nid => {{
      const n = DATA.nodes.find(x => x.id === nid);
      return n ? n.name : nid;
    }}).join(' → ');
    return `
    <div class="path-card" data-path-idx="${{i}}" onclick="selectPath(${{i}})">
      <div class="path-card-header">
        <span class="path-idx">#${{i+1}}</span>
        <span class="path-sev sev-${{p.severity}}">${{p.severity}}</span>
        <span class="path-hops">${{p.total_hops}} hops</span>
        <span class="path-score">Score: ${{p.total_risk_score}}</span>
      </div>
      <div class="path-chain">${{chain}}</div>
    </div>`;
  }}).join('');
}}

window.selectPath = function selectPath(idx) {{
  selectedPathIdx = idx;
  // Update card selection
  document.querySelectorAll('.path-card').forEach((c, i) => {{
    c.classList.toggle('selected', i === idx);
  }});
  // Highlight that specific path in the graph
  const p = DATA.attack_paths[idx];
  const pathEdgeKeys = new Set();
  for (let i = 0; i < p.path.length - 1; i++) {{
    pathEdgeKeys.add(p.path[i] + '::' + p.path[i+1]);
  }}
  highlightSpecificPath(new Set(p.path), pathEdgeKeys);
}}

function highlightSpecificPath(nodeSet, edgeSet) {{
  nodeG.select('circle.node-circle')
    .style('opacity', d => nodeSet.has(d.id) ? 1 : 0.12)
    .attr('stroke-width', d => nodeSet.has(d.id) ? 3 : 1.5);
  nodeG.select('text').style('opacity', d => nodeSet.has(d.id) ? 1 : 0.1);
  linkSel
    .style('opacity', d => {{
      const key = d._source_id + '::' + d._target_id;
      return edgeSet.has(key) ? 1 : 0.05;
    }})
    .attr('stroke-width', d => {{
      const key = d._source_id + '::' + d._target_id;
      return edgeSet.has(key) ? 3.5 : 1.2;
    }});
}}

// ═══════════════════════════════════════════════════════════════
// ANALYSIS TAB
// ═══════════════════════════════════════════════════════════════
function renderAnalysis() {{
  const el = document.getElementById('analysis-content');
  const cr = DATA.critical_node ? DATA.nodes.find(n => n.id === DATA.critical_node) : null;
  const top5Max = DATA.top5_nodes.length > 0 ? DATA.top5_nodes[0].reduction : 1;

  const cyclesHtml = DATA.cycles.length === 0
    ? '<div class="empty-msg">✅ No circular permissions detected</div>'
    : DATA.cycles.map((c, i) => {{
        const names = c.map(nid => {{
          const n = DATA.nodes.find(x => x.id === nid);
          return n ? n.name : nid;
        }});
        return `<div class="cycle-item">
          <div class="cycle-label">Cycle #${{i+1}} — ${{c.length}} nodes</div>
          ${{names.join(' ↔ ')}} ↔ ${{names[0]}}
        </div>`;
      }}).join('');

  const top5Html = DATA.top5_nodes.map(t => {{
    const n = DATA.nodes.find(x => x.id === t.id);
    const name = n ? n.name : t.id;
    const pct  = Math.round((t.reduction / top5Max) * 100);
    return `<div class="top5-row">
      <span class="top5-name" title="${{t.id}}">${{name}}</span>
      <div class="top5-bar-bg"><div class="top5-bar-fill" style="width:${{pct}}%"></div></div>
      <span class="top5-count">−${{t.reduction}}</span>
    </div>`;
  }}).join('');

  el.innerHTML = `
    <div class="section-label">Critical Node Analysis</div>
    ${{cr ? `
    <div class="critical-card">
      <div class="cn-label">★ Highest-Impact Removal Target</div>
      <div class="cn-name">${{cr.name}}</div>
      <div class="cn-impact">Type: ${{cr.type}} · Namespace: ${{cr.namespace}}</div>
      <div class="cn-rec">${{m.recommendation || 'Remove this node to maximally reduce attack surface.'}}</div>
    </div>
    <div class="section-label">Top 5 Removal Candidates</div>
    ${{top5Html || '<div class="empty-msg">None computed</div>'}}
    ` : '<div class="empty-msg">No critical node identified</div>'}}

    <div class="section-label" style="margin-top:14px">Circular Permission Detection</div>
    ${{cyclesHtml}}

    <div class="section-label" style="margin-top:14px">Summary</div>
    <div class="detail-row"><span class="dk">Total Nodes</span><span class="dv">${{m.node_count}}</span></div>
    <div class="detail-row"><span class="dk">Total Edges</span><span class="dv">${{m.edge_count}}</span></div>
    <div class="detail-row"><span class="dk">Attack Paths</span><span class="dv" style="color:var(--accent-red)">${{m.attack_path_count}}</span></div>
    <div class="detail-row"><span class="dk">Cycles Detected</span><span class="dv" style="color:var(--accent-orange)">${{m.cycle_count}}</span></div>
    <div class="detail-row"><span class="dk">Baseline Paths</span><span class="dv">${{m.total_paths}}</span></div>
    <div class="section-label" style="margin-top:14px">Blast Radius Legend</div>
    <div style="font-family:'Share Tech Mono',monospace;font-size:9px;line-height:2">
      <span style="color:#ff3355">●</span> Source (Hop 0) &nbsp;
      <span style="color:#ffaa00">●</span> Hop 1 &nbsp;
      <span style="color:#ff6600">●</span> Hop 2 &nbsp;
      <span style="color:#005f80;background:#00d4ff22;padding:1px 4px;border-radius:2px">●</span> Hop 3<br/>
      <span style="color:var(--text-muted)">Click "Blast Radius" toolbar button to visualise on graph</span>
    </div>
  `;
}}

// ═══════════════════════════════════════════════════════════════
// FILTER / VIEW MODES
// ═══════════════════════════════════════════════════════════════
function applyFilter(mode, animate=true) {{
  const dur = animate ? 300 : 0;

  if (mode === 'all') {{
    nodeG.select('circle.node-circle')
      .transition().duration(dur)
      .style('opacity', 1).attr('stroke-width', 1.5)
      .attr('fill', nodeColor)
      .attr('stroke', d => {{ const c = d3.color(nodeColor(d)); return c ? c.darker(0.6).toString() : '#334455'; }});
    nodeG.select('text').transition().duration(dur).style('opacity', 1);
    linkSel.transition().duration(dur).style('opacity', 0.6).attr('stroke-width', 1.2);

  }} else if (mode === 'paths') {{
    const ns = new Set(DATA.all_path_nodes);
    const es = new Set(DATA.all_path_edges.map(e => e.source + '::' + e.target));
    nodeG.select('circle.node-circle').transition().duration(dur)
      .style('opacity', d => ns.has(d.id) ? 1 : 0.08)
      .attr('stroke-width', d => ns.has(d.id) ? 2.5 : 1.5);
    nodeG.select('text').transition().duration(dur)
      .style('opacity', d => ns.has(d.id) ? 1 : 0.05);
    linkSel.transition().duration(dur)
      .style('opacity', d => es.has(d._source_id + '::' + d._target_id) ? 0.95 : 0.04)
      .attr('stroke-width', d => es.has(d._source_id + '::' + d._target_id) ? 2.5 : 1.2);

  }} else if (mode === 'cycles') {{
    const ns = new Set(DATA.cycle_nodes);
    const es = new Set(DATA.cycle_edges.map(e => e.source + '::' + e.target));
    nodeG.select('circle.node-circle').transition().duration(dur)
      .style('opacity', d => ns.has(d.id) ? 1 : 0.08)
      .attr('stroke-width', 1.5);
    nodeG.select('text').transition().duration(dur)
      .style('opacity', d => ns.has(d.id) ? 1 : 0.05);
    linkSel.transition().duration(dur)
      .style('opacity', d => es.has(d._source_id + '::' + d._target_id) ? 0.95 : 0.04)
      .attr('stroke-width', d => es.has(d._source_id + '::' + d._target_id) ? 2.5 : 1.2);

  }} else if (mode === 'critical') {{
    if (!DATA.critical_node) return;
    const critEdges = DATA.edges.filter(e => e.source === DATA.critical_node || e.target === DATA.critical_node);
    const ns = new Set([DATA.critical_node, ...critEdges.map(e => e.source), ...critEdges.map(e => e.target)]);
    const es = new Set(critEdges.map(e => e.source + '::' + e.target));
    nodeG.select('circle.node-circle').transition().duration(dur)
      .style('opacity', d => ns.has(d.id) ? 1 : 0.06)
      .attr('stroke-width', d => d.id === DATA.critical_node ? 4 : 1.5)
      .attr('stroke', d => d.id === DATA.critical_node ? 'var(--accent-purple)' : null);
    nodeG.select('text').transition().duration(dur)
      .style('opacity', d => ns.has(d.id) ? 1 : 0.04);
    linkSel.transition().duration(dur)
      .style('opacity', d => es.has(d._source_id + '::' + d._target_id) ? 0.95 : 0.03)
      .attr('stroke-width', d => es.has(d._source_id + '::' + d._target_id) ? 2.5 : 1.2);
    // Draw a "REMOVE THIS" SVG badge above the critical node
    const critNode = simNodes.find(n => n.id === DATA.critical_node);
    if (critNode && critNode.x != null) {{
      overlayG.selectAll('*').remove();
      const badgeG = overlayG.append('g').attr('transform', `translate(${{critNode.x}},${{critNode.y - 30}})`);
      badgeG.append('rect')
        .attr('x', -42).attr('y', -11).attr('width', 84).attr('height', 18)
        .attr('rx', 3).attr('fill', '#2a0060').attr('stroke', '#b060ff').attr('stroke-width', 1);
      badgeG.append('text')
        .attr('text-anchor', 'middle').attr('dy', '0.35em')
        .attr('fill', '#b060ff')
        .attr('font-family', 'Share Tech Mono, monospace')
        .attr('font-size', '8px').attr('letter-spacing', '1px')
        .text('⚠ REMOVE FIRST');
      // Draw lines to each immediate neighbour with impact count label
      const top5ids = new Set(DATA.top5_nodes.map(t => t.id));
      critEdges.forEach(e => {{
        const peerId = e.source === DATA.critical_node ? e.target : e.source;
        const peer   = simNodes.find(n => n.id === peerId);
        if (!peer || peer.x == null) return;
        overlayG.append('line')
          .attr('x1', critNode.x).attr('y1', critNode.y)
          .attr('x2', peer.x).attr('y2', peer.y)
          .attr('stroke', top5ids.has(peerId) ? '#b060ff' : '#354a60')
          .attr('stroke-width', 1).attr('stroke-dasharray', '3 2').attr('opacity', 0.6);
      }});
    }}

  }} else if (mode === 'blast') {{
    // Build hop-level sets: hop0=sources, hop1,hop2,hop3
    const hopSets = {{ 0: new Set(), 1: new Set(), 2: new Set(), 3: new Set() }};
    const hopColors = {{ 0:'#ff3355', 1:'#ffaa00', 2:'#ff6600', 3:'#005f80' }};
    Object.entries(DATA.blast_radius).forEach(([srcId, br]) => {{
      hopSets[0].add(srcId);
      Object.entries(br.by_hop || {{}}).forEach(([hop, nodes]) => {{
        nodes.forEach(n => hopSets[parseInt(hop)].add(n));
      }});
    }});
    const allBlast = new Set([...hopSets[0], ...hopSets[1], ...hopSets[2], ...hopSets[3]]);

    // Draw concentric hop rings on the overlay layer
    overlayG.selectAll('*').remove();
    simNodes.forEach(nd => {{
      let hop = -1;
      for (let h = 0; h <= 3; h++) {{ if (hopSets[h].has(nd.id)) {{ hop = h; break; }} }}
      if (hop < 0) return;
      const ringR = (nodeRadius(nd) + 6) + hop * 7;
      overlayG.append('circle')
        .attr('cx', nd.x || 0).attr('cy', nd.y || 0)
        .attr('r', ringR)
        .attr('fill', 'none')
        .attr('stroke', hopColors[hop])
        .attr('stroke-width', hop === 0 ? 2.5 : 1.5)
        .attr('stroke-dasharray', hop === 0 ? 'none' : '4 3')
        .attr('opacity', 0.7)
        .attr('class', 'blast-ring');
    }});

    nodeG.select('circle.node-circle').transition().duration(dur)
      .style('opacity', d => allBlast.has(d.id) ? 1 : 0.06)
      .attr('fill', d => {{
        for (let h = 0; h <= 3; h++) {{
          if (hopSets[h].has(d.id)) return hopColors[h];
        }}
        return nodeColor(d);
      }})
      .attr('stroke-width', d => hopSets[0].has(d.id) ? 3 : 1.5);
    nodeG.select('text').transition().duration(dur)
      .style('opacity', d => allBlast.has(d.id) ? 1 : 0.04);
    linkSel.transition().duration(dur)
      .style('opacity', 0.12).attr('stroke-width', 1.2);

  }}
  // Always clear overlay rings unless in blast mode
  if (mode !== 'blast') overlayG.selectAll('*').remove();
}}

// ── FILTER BUTTONS ────────────────────────────────────────────
const filterMap = {{
  'btn-all':      'all',
  'btn-paths':    'paths',
  'btn-cycles':   'cycles',
  'btn-blast':    'blast',
  'btn-critical': 'critical',
  'btn-reset':    'all',
}};

Object.entries(filterMap).forEach(([btnId, mode]) => {{
  document.getElementById(btnId).onclick = function() {{
    activeFilter = mode;
    selectedPathIdx = -1;
    // Update button states
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active', 'red', 'amber', 'orange', 'purple'));
    this.classList.add('active');
    const color = this.dataset.color;
    if (color) this.classList.add(color);
    applyFilter(mode);
  }};
}});
// 'all' btn is active by default — already set in HTML

// ═══════════════════════════════════════════════════════════════
// PANEL TABS
// ═══════════════════════════════════════════════════════════════
function switchTab(name) {{
  document.querySelectorAll('.panel-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
}}

document.querySelectorAll('.panel-tab').forEach(tab => {{
  tab.onclick = () => switchTab(tab.dataset.tab);
}});

// ═══════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════
renderPathsList();
renderAnalysis();

// Auto-fit after simulation settles
setTimeout(fitView, 2800);
</script>
</body>
</html>"""
