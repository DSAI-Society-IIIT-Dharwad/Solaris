import time
import argparse
import os
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.align import Align
from rich.text import Text

from .data_collector import UnifiedK8sCollector
from .graph_builder import AttackPathGraph, generate_report
from .config import RESOURCE_TYPES

console = Console()

GRAPH_FILE = "cluster-graph.json"


def display_splash():
    ascii_art = r"""
    [bold cyan]
 ██████  ██   ██  █████  ██████   ██████  ██     ██ 
██       ██   ██ ██   ██ ██   ██ ██    ██ ██     ██ 
 ██████  ███████ ███████ ██   ██ ██    ██ ██  █  ██ 
      ██ ██   ██ ██   ██ ██   ██ ██    ██ ██ ███ ██ 
 ██████  ██   ██ ██   ██ ██████   ██████   ███ ███  

████████ ██████   █████   ██████ ███████ ██████  
   ██    ██   ██ ██   ██ ██      ██      ██   ██ 
   ██    ██████  ███████ ██      █████   ██████  
   ██    ██   ██ ██   ██ ██      ██      ██   ██ 
   ██    ██   ██ ██   ██  ██████ ███████ ██   ██
    [/bold cyan]
    """
    console.print(Align.center(ascii_art))
    console.print(Align.center("[bold white]Kubernetes Attack Path Visualizer & Risk Analyzer[/bold white]"))
    console.print(Align.center("[dim]BFS · Dijkstra · DFS · Critical Node Analysis[/dim]"))
    console.print()


def run_live_ingestion():
    """Phase 1: collect from a live cluster via kubectl.
    
    Returns:
        collector: UnifiedK8sCollector with cluster data
        
    Raises:
        RuntimeError: If kubectl is not available or data collection fails completely
    """
    collector = UnifiedK8sCollector()
    
    # Fetch all resources concurrently
    success, error_detail = collector.fetch_all_concurrently()
    
    if not success:
        # Complete failure - no data collected at all
        raise RuntimeError(
            "Unable to connect to Kubernetes cluster.\n"
            "Please check your kubeconfig and cluster connection."
        )
    
    # Validate that we actually collected data
    if not collector.snapshot or all(len(v.get("items", [])) == 0 for v in collector.snapshot.values()):
        raise RuntimeError(
            "Kubernetes cluster returned no resources.\n"
            "Please verify you have permissions to access the cluster."
        )
    
    collector.process_cluster_data()
    collector.export(GRAPH_FILE)
    return collector, success, error_detail


def run_mock_mode(input_file):
    """
    Mock / offline mode: skip kubectl entirely and load a pre-built
    cluster-graph.json directly.  Perfect for judges without a live cluster.
    """
    console.print(Panel(
        Text(f"[MOCK MODE] Loading pre-built graph from: {input_file}", justify="center", style="bold yellow"),
        border_style="yellow",
    ))
    if not os.path.exists(input_file):
        console.print(f"[bold red][!] File not found: {input_file}[/bold red]")
        raise SystemExit(1)


def run_analysis_dashboard(blast_radius_node=None, mock=False, mock_file=GRAPH_FILE):
    display_splash()

    if mock:
        # ── OFFLINE / MOCK MODE ───────────────────────────────────────────
        run_mock_mode(mock_file)
        graph_input = mock_file
    else:
        # ── LIVE CLUSTER MODE ─────────────────────────────────────────────
        console.print("[bold blue][*] Phase 1 — Live cluster ingestion via kubectl[/bold blue]\n")
        try:
            run_live_ingestion()
            graph_input = GRAPH_FILE
        except RuntimeError as e:
            # Clean error message with actionable suggestions
            error_msg = str(e)
            console.print(f"[bold red][!] {error_msg}[/bold red]\n")
            console.print("[bold white]Suggested Actions:[/bold white]")
            console.print(f"  1. Use local graph:      [cyan]shadowtracer --json cluster-graph.json[/cyan]")
            console.print(f"  2. Check kubectl:        [cyan]kubectl config current-context[/cyan]")
            console.print(f"  3. Check k8s access:     [cyan]kubectl get nodes[/cyan]")
            
            if os.path.exists(mock_file):
                console.print(f"  4. Use specific file:    [cyan]shadowtracer --json {mock_file}[/cyan]")
            
            console.print()
            raise SystemExit(1)
        except Exception as e:
            console.print(f"[bold red][!] Unexpected error: {e}[/bold red]")
            raise SystemExit(1)

    console.print("\n[bold blue][*] Phase 2 — Building Attack Graph...[/bold blue]")
    ag = AttackPathGraph()
    if not ag.load_from_json(graph_input):
        console.print("[bold red][!] Graph construction failed.[/bold red]")
        raise SystemExit(1)

    console.print("[bold green][+] Analysis complete — generating report...[/bold green]\n")
    generate_report(ag, blast_radius_node=blast_radius_node)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="shadowtracer — Kubernetes Attack Path Visualizer"
    )
    parser.add_argument(
        "-b", "--blast-node", default=None,
        help="Node ID to use as blast-radius source (defaults to worst-path source)",
    )
    parser.add_argument(
        "--json", dest="json_file", default=None,
        help="Load cluster graph from JSON file instead of kubectl (e.g., shadowtracer --json cluster-graph.json)",
    )
    args = parser.parse_args()

    # If --json is provided, use it as the input file (sets mock=True)
    # Otherwise try live kubectl
    use_json_file = args.json_file is not None
    input_file = args.json_file if use_json_file else GRAPH_FILE

    try:
        run_analysis_dashboard(
            blast_radius_node=args.blast_node,
            mock=use_json_file,
            mock_file=input_file,
        )
    except KeyboardInterrupt:
        console.print("\n[bold red]Terminated by user.[/bold red]")