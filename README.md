# shadowtracerv1: Kubernetes Attack Path Visualizer

**shadowtracerv1** models a Kubernetes cluster as a Directed Acyclic Graph and applies classical graph algorithms to surface hidden, multi-hop attack chains before an adversary exploits them.

> "Security is not about preventing every possible attack — it is about making every attack path visible."

---

## 🚀 Key Features

| Feature | Details |
|---|---|
| **Multi-Hop Kill Chain Detection** | Finds chains across Users → Pods → ServiceAccounts → Roles → Secrets |
| **BFS Blast Radius** | Scopes incident response: how many resources can an attacker reach in N hops? |
| **Dijkstra's Shortest Path** | Finds the lowest-cost route from the internet to each crown jewel |
| **DFS Cycle Detection** | Flags circular permission bindings that amplify every attack path |
| **Critical Node Analysis** | Identifies the single node whose removal breaks the most attack paths |
| **Assumed Breach Mode** | Pivots to internal Pod scanning if no external entry points are found |
| **Rich Terminal Dashboard** | Live layout with kill chain tree, analytics, and remediation strategy |
| **PDF Security Audit** | Multi-page report with executive summary, kill chains, and remediation roadmap |
| **Offline / Mock Mode** | Full analysis without a live cluster — perfect for demos |

---

## 🧠 Algorithm Reference

### Algorithm 1 — Blast Radius (BFS)
```
Input : Compromised source node
Method: nx.single_source_shortest_path_length(G, source, cutoff=N)
Output: All nodes reachable within N hops ("Danger Zone")
```

### Algorithm 2 — Shortest Path to Crown Jewels (Dijkstra)
```
Input : Public entry point → target crown jewel
Method: nx.dijkstra_path(G, source, target, weight='weight')
Output: Lowest-cost attack path + cumulative risk score
```

### Algorithm 3 — Circular Permission Detection (DFS)
```
Input : Full cluster graph
Method: nx.simple_cycles(G)
Output: All circular RBAC bindings (privilege escalation loops)
```

### Algorithm 4 — Critical Node (Attack-Path Betweenness)
```
For each candidate node:
    Temporarily remove node from G
    Re-enumerate all source→crown_jewel paths
    Measure reduction vs baseline path count
Return: Node with maximum reduction
Output: "Remove 'Role-X' to eliminate 8 of 11 attack paths"
```

---

## 🛠 Installation & Setup

### Prerequisites
- Docker Desktop (or Docker Engine on Linux)
- `kubectl` configured to point at your target cluster (for live mode)

### Build the Image

**Windows:**
```bat
.\setup.bat
```

**Linux / macOS:**
```bash
chmod +x setup.sh && ./setup.sh
```

### Load from .tar (no source needed)
```bash
docker load -i shadowtracerv1.tar
```

---

## 🔍 Usage

### Live Cluster Mode (requires kubectl context)
```bash
# Linux / macOS
./run.sh

# Windows
.\run.bat
```

### Offline / Demo Mode (no cluster needed)
Uses the bundled `cluster-graph.json` — ideal for judges and demos:
```bash
# Linux / macOS
./run.sh --mock

# Windows
.\run.bat --mock
```

### Direct Python (dev mode)
```bash
# Live ingestion then analysis
python cli_dashboard.py

# Mock/offline mode
python cli_dashboard.py --mock

# Specify a custom graph file
python cli_dashboard.py --mock --input path/to/graph.json

# Specify blast radius source node
python cli_dashboard.py --mock --blast-node "Pod:default:my-pod"

# Graph engine only (no kubectl)
python graph_builder.py --input cluster-graph.json
```

---

## 📊 Outputs

### 1. Interactive CLI Dashboard (Rich)
- **Primary Kill Chain Tree** — visual hop-by-hop attack path
- **Analytics Summary** — risk score, hop count, blast radius, cycle count
- **Remediation Strategy** — context-aware fix for the most dangerous edge

### 2. Full Security Audit — `Full_Security_Audit.pdf`
| Section | Content |
|---|---|
| Executive Summary | Total paths, critical count, cluster status |
| Kill Chain Analysis | Top 10 paths with hop-by-hop breakdown |
| Critical Node Analysis | Node removal impact table + recommendation |
| Remediation Roadmap | Per-vulnerability-type fix table |

The PDF is written to your current directory via the Docker volume mount.

---

## 🏗 Technical Architecture

| Layer | Technology |
|---|---|
| Language | Python 3.10 |
| Graph Engine | NetworkX (DiGraph) |
| Algorithms | BFS, Dijkstra's, DFS, Attack-Path Betweenness |
| Terminal UI | Rich (layouts, trees, tables, progress bars) |
| PDF Report | ReportLab |
| Containerisation | Docker |

### Graph Schema
| Concept | Graph Element | Examples |
|---|---|---|
| Cluster entity | Node | Pod, ServiceAccount, Role, Secret, Database |
| Trust relationship | Directed Edge | `runs-as-sa`, `bound-to`, `secret-reader` |
| Exploitability | Edge `weight` | Difficulty weight (lower = easier to exploit) |
| Risk | Edge `risk_score` + Node `risk_score` | CVSS-derived |
| Crown Jewel | Sink node (`crown_jewel: true`) | Production DB, Secret Store, Admin Role |
| Entry Point | Source node (`entry_point: true`) | Internet, LoadBalancer |

---

## 📦 Shipping / Distribution

```bash
# Build
docker build -t shadowtracerv1 .

# Export as single portable file
docker save -o shadowtracerv1.tar shadowtracerv1

# Share: shadowtracerv1.tar + run.bat + run.sh + cluster-graph.json + README.md
```

Recipients need only Docker — no Python, no kubectl for mock mode.
