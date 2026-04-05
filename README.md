# shadowtracer

> "Security is not about preventing every possible attack — it is about making every attack path visible."

**shadowtracer** models a Kubernetes cluster as a directed graph and applies classical graph algorithms to surface hidden, multi-hop attack chains before an adversary exploits them.

---

## Features

| Feature | Description |
|---|---|
| **Multi-Hop Kill Chain Detection** | Traces attack chains across Users → Pods → ServiceAccounts → Roles → Secrets |
| **BFS Blast Radius** | Scopes incident response: how many resources can an attacker reach in N hops? |
| **Dijkstra Shortest Path** | Finds the lowest-cost route from any entry point to each crown jewel |
| **DFS Cycle Detection** | Flags circular RBAC bindings that amplify every attack path |
| **Critical Node Analysis** | Identifies the single node whose removal breaks the most attack paths |
| **Assumed Breach Mode** | Pivots to internal pod scanning if no external entry points are found |
| **CVE Scoring** | Queries the NIST NVD API for real CVE scores per container image |
| **Rich Terminal Dashboard** | Live layout with kill chain tree, analytics summary, and remediation strategy |
| **PDF Security Audit** | Multi-page report with executive summary, kill chains, and remediation roadmap |
| **Temporal Analysis** | State-diffs between scans to detect newly introduced attack paths |
| **Offline / Mock Mode** | Full analysis without a live cluster — ideal for demos |

---

## Installation

### Prerequisites

- Python 3.10 or higher
- `pip`
- `kubectl` configured to point at your target cluster *(live mode only)*

### Install the CLI

Clone or download the repository, then run:

```bash
cd shadowtracer-pkg
pip install -e .
```

The `-e` flag installs in **editable mode** — any changes you make to the source files take effect immediately without reinstalling.

### Windows: PATH note

If pip prints a warning like:

```
WARNING: The script shadowtracer.exe is installed in '...\Scripts' which is not on PATH.
```

Add that Scripts folder to your PATH permanently. Open PowerShell and run:

```powershell
[System.Environment]::SetEnvironmentVariable(
    "PATH",
    $env:PATH + ";C:\Users\<you>\AppData\Roaming\Python\Python3XX\Scripts",
    "User"
)
```

Then close and reopen your terminal. Alternatively, reinstall using the Python that is already on your PATH:

```powershell
C:\Python3XX\python.exe -m pip install -e .
```

### Verify the install

```bash
shadowtracer --help
```

---

## Usage

### Offline / Demo mode *(no cluster needed)*

Run a full analysis on the bundled mock graph:

```bash
shadowtracer --json mock-cluster-graph.json
```

### Live cluster mode *(requires kubectl)*

Omit `--json` to trigger live kubectl ingestion:

```bash
shadowtracer
```

---

## Commands

All commands accept `--json FILE` or `--input FILE` (they are aliases — use one, not both) to load a graph file instead of running a live scan.

### Full report

Runs everything: kill chain analysis, blast radius, cycle detection, critical node, temporal diff, Rich dashboard, and PDF export.

```bash
shadowtracer --json mock-cluster-graph.json --full-report

# --full-report is the default, so this is equivalent:
shadowtracer --json mock-cluster-graph.json
```

### Blast radius

BFS from a source node. Reports every resource reachable within N hops.

```bash
shadowtracer --json mock-cluster-graph.json --blast-radius internet
shadowtracer --json mock-cluster-graph.json --blast-radius internet --hops 5
shadowtracer --json mock-cluster-graph.json --blast-radius user-dev1 --hops 2
```

`--hops` defaults to `3` if not specified.

### Shortest path

Dijkstra shortest path between any two nodes.

```bash
shadowtracer --json mock-cluster-graph.json --source internet --target db-production
shadowtracer --json mock-cluster-graph.json --source user-dev1 --target node-worker-1
```

`--source` and `--target` must always be used together.

### Cycle detection

DFS scan for circular RBAC permission bindings.

```bash
shadowtracer --json mock-cluster-graph.json --cycles
```

### Critical node analysis

Identifies the node whose removal eliminates the most attack paths.

```bash
shadowtracer --json mock-cluster-graph.json --critical-node
```

### List nodes

Prints every node ID in the graph with its type, name, and source/sink flags. Useful for finding the right ID to pass to other commands.

```bash
# All nodes
shadowtracer --json mock-cluster-graph.json --list-nodes

# Filter by type
shadowtracer --json mock-cluster-graph.json --list-nodes --type Pod
shadowtracer --json mock-cluster-graph.json --list-nodes --type ServiceAccount
```

---

## Outputs

### Terminal dashboard

Rendered by [Rich](https://github.com/Textualize/rich) directly in your terminal:

- **Primary Attack Path** — visual hop-by-hop kill chain tree
- **Analytics Summary** — risk level, score, hop count, blast radius, cycle count
- **Temporal Alert** — flags any new attack paths since the last scan
- **Remediation Strategy** — context-aware fix for the most dangerous edge

### PDF security audit — `Full_Security_Audit.pdf`

Written to the current working directory after every full report run.

| Section | Content |
|---|---|
| Executive Summary | Total paths, critical count, cluster status |
| Kill Chain Analysis | Top attack paths with hop-by-hop breakdown |
| Blast Radius Analysis | Per-source reachability table |
| Cycle Detection | Circular RBAC bindings |
| Critical Node Analysis | Node removal impact table + top 5 candidates |
| Temporal Analysis | New paths detected since last scan |
| Remediation Roadmap | Per-vulnerability-type fix table |

### HTML visualizer — `attack_graph.html`

Interactive force-directed graph of the cluster. Open in any browser.

---

## Node ID format

Node IDs depend on which graph file is loaded.

**mock-cluster-graph.json** uses flat slugs:
```
internet, user-dev1, pod-webfront, sa-webapp,
role-secret-reader, secret-db-creds, db-production ...
```

**cluster-graph.json** (live scan output) uses `Kind:namespace:name`:
```
Pod:default:nginx, ServiceAccount:kube-system:coredns ...
```

Run `--list-nodes` to see all IDs in your loaded graph.

---

## Algorithm reference

**Blast Radius (BFS)**
```
Input : Compromised source node
Method: nx.single_source_shortest_path_length(G, source, cutoff=N)
Output: All nodes reachable within N hops
```

**Shortest Path to Crown Jewels (Dijkstra)**
```
Input : Entry point → target crown jewel
Method: nx.dijkstra_path(G, source, target, weight='weight')
Output: Lowest-cost attack path + cumulative risk score
```

**Circular Permission Detection (DFS)**
```
Input : Full cluster graph
Method: nx.simple_cycles(G)
Output: All circular RBAC bindings (privilege escalation loops)
```

**Critical Node (Attack-Path Betweenness)**
```
For each candidate node:
    Temporarily remove node from G
    Re-enumerate all source → crown_jewel paths
    Measure reduction vs baseline path count
Return: Node with maximum reduction
Output: "Remove 'sa-worker' to eliminate 12 of 33 attack paths"
```

---

## Technical architecture

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Graph Engine | NetworkX (DiGraph) |
| Algorithms | BFS, Dijkstra, DFS, Attack-Path Betweenness |
| Terminal UI | Rich |
| PDF Report | ReportLab |
| CVE Data | NIST NVD API |

### Graph schema

| Concept | Graph Element | Examples |
|---|---|---|
| Cluster entity | Node | Pod, ServiceAccount, Role, Secret, Database |
| Trust relationship | Directed Edge | `runs-as-sa`, `bound-to`, `secret-reader` |
| Exploitability | Edge `weight` | Difficulty weight (lower = easier to exploit) |
| Risk | Edge + Node `risk_score` | CVSS-derived |
| Crown Jewel | Sink node | Production DB, Secret Store, Admin Role |
| Entry Point | Source node | Internet, LoadBalancer |

---

## Environment variables

| Variable | Description |
|---|---|
| `NVD_API_KEY` | NIST NVD API key. Without it, requests are rate-limited to 5 per 30 seconds. Get one free at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key). |

Create a `.env` file in the project root:

```
NVD_API_KEY=your-key-here
```

---

## Project structure

```
shadowtracer-pkg/
├── pyproject.toml               ← Package manifest and entry point
├── README.md
├── mock-cluster-graph.json      ← Bundled offline demo graph
├── cluster-graph.json           ← Written here after a live scan
│
└── shadowtracer/
    ├── __init__.py
    ├── shadowtracer.py          ← CLI entry point (main lives here)
    ├── cli_dashboard.py         ← Rich dashboard + kubectl ingestion
    ├── cli_ui_components.py     ← Rich layout widgets
    ├── graph_builder.py         ← Core graph engine and algorithms
    ├── graph_visualizer.py      ← HTML attack graph exporter
    ├── data_collector.py        ← kubectl runner and cluster parser
    ├── cve_scorer.py            ← NVD API CVE scorer
    ├── config.py                ← Risk matrix, remediation map
    └── pdf_reporter.py          ← PDF report generator
```