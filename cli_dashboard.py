import time
import argparse
import os
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.align import Align
from rich.text import Text

from final_data_collector import UnifiedK8sCollector
from final_graph_builder import AttackPathGraph, generate_report
from config import RESOURCE_TYPES

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
    """Phase 1: collect from a live cluster via kubectl."""
    collector = UnifiedK8sCollector()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        overall = progress.add_task("[yellow]Scanning Cluster...", total=len(RESOURCE_TYPES))

        with collector.executor_class(max_workers=6) as executor:
            futures = {executor.submit(collector.run_kubectl_json, r): r for r in RESOURCE_TYPES}
            for future in collector.as_completed_func(futures):
                res_name = futures[future]
                collector.snapshot[res_name] = future.result()
                progress.update(overall, advance=1, description=f"[green]Fetched {res_name}")
                time.sleep(0.05)

    collector.process_cluster_data()
    collector.export(GRAPH_FILE)
    return collector


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
        console.print("[bold blue][*] Phase 1 — Live cluster ingestion via kubectl[/bold blue]")
        try:
            run_live_ingestion()
        except Exception as e:
            console.print(f"[yellow][!] kubectl ingestion failed ({e}). Falling back to mock file.[/yellow]")
            if not os.path.exists(mock_file):
                console.print(f"[bold red][!] No fallback file found at '{mock_file}'. Aborting.[/bold red]")
                raise SystemExit(1)
            console.print(f"[yellow]    Using existing: {mock_file}[/yellow]")
        graph_input = GRAPH_FILE

    console.print("\n[bold blue][*] Phase 2 — Building Attack Graph...[/bold blue]")
    ag = AttackPathGraph()
    if not ag.load_from_json(graph_input):
        console.print("[bold red][!] Graph construction failed.[/bold red]")
        raise SystemExit(1)

    console.print("[bold green][+] Analysis complete — generating report...[/bold green]\n")
    generate_report(ag, blast_radius_node=blast_radius_node)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="shadowtracerv1 — Kubernetes Attack Path Visualizer"
    )
    parser.add_argument(
        "-b", "--blast-node", default=None,
        help="Node ID to use as blast-radius source (defaults to worst-path source)",
    )
    parser.add_argument(
        "-m", "--mock", action="store_true",
        help="Skip kubectl and load a pre-built cluster-graph.json (offline/demo mode)",
    )
    parser.add_argument(
        "-i", "--input", default=GRAPH_FILE,
        help=f"Path to cluster-graph.json when using --mock (default: {GRAPH_FILE})",
    )
    args = parser.parse_args()

    try:
        run_analysis_dashboard(
            blast_radius_node=args.blast_node,
            mock=args.mock,
            mock_file=args.input,
        )
    except KeyboardInterrupt:
        console.print("\n[bold red]Terminated by user.[/bold red]")
