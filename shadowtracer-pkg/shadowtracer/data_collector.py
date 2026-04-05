#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import shlex
from datetime import date
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import RESOURCE_TYPES, CROWN_JEWEL_KEYWORDS, evaluate_permission
from .cve_scorer import fetch_live_cves


# ---------------------------------------------------------------------------
# Relation name map  (our internal name -> mock/org canonical name)
# ---------------------------------------------------------------------------
RELATION_MAP = {
    "routes-traffic":   "routes-to",
    "internet-exposed": "reaches",
    "ingress-exposed":  "reaches",
    "runs-as-sa":       "uses",
    "potential-ssrf":   "reaches",
    "container-escape": "mounts",
    "secret-access":    "can-read",
    # can-exploit is split further below:
    #   wildcard/admin  -> "admin-over"
    #   normal exploit  -> "can-exec"
    "bound-to":         "bound-to",   # unchanged
}

# Node types that are always treated as entry points (is_source = true)
ENTRY_POINT_TYPES = {"ExternalActor", "User"}

# Node types that are always treated as sinks / crown jewels (is_sink = true)
SINK_TYPES = {"Database", "PersistentVolume", "Vulnerability"}


def _slug(kind: str, name: str, namespace: str | None) -> str:
    """
    Build a flat, human-readable node ID matching the mock format.
    Examples:
      Pod,  "web-frontend",  "default"  -> "pod-web-frontend"
      ServiceAccount, "sa-webapp", "default" -> "sa-sa-webapp"
      External, "Internet", None  -> "internet"
      Node, "worker-1", "cluster" -> "node-worker-1"
      Secret, "db-credentials", "default" -> "secret-db-credentials"
    """
    # Special-case the internet entry point so it stays "internet"
    if kind == "ExternalActor" and name.lower() == "internet":
        return "internet"

    # Kind prefix used in mock IDs
    prefix_map = {
        "ExternalActor":    "ext",
        "User":             "user",
        "Pod":              "pod",
        "ServiceAccount":   "sa",
        "Role":             "role",
        "ClusterRole":      "clusterrole",
        "Secret":           "secret",
        "ConfigMap":        "configmap",
        "Service":          "svc",
        "Node":             "node",
        "Namespace":        "ns",
        "PersistentVolume": "pvc",
        "Database":         "db",
    }
    prefix = prefix_map.get(kind, kind.lower())

    # Sanitize name: lowercase, replace non-alphanumeric runs with "-"
    clean = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")

    return f"{prefix}-{clean}"


class UnifiedK8sCollector:
    def __init__(self):
        self.executor_class = ThreadPoolExecutor
        self.as_completed_func = as_completed
        self.snapshot = {}
        self.node_index = {}   # slug_id -> node dict
        self.edges = []

    # ------------------------------------------------------------------
    # Kubectl helper
    # ------------------------------------------------------------------

    def run_kubectl_json(self, resource):
        """Fetch resource from kubectl. Raises exception on failure."""
        cmd = f"kubectl get {resource} -A -o json"
        try:
            result = subprocess.run(
                shlex.split(cmd), capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                raise RuntimeError(f"kubectl failed for {resource}: {error_msg}")
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON from kubectl get {resource}: {e}")
        except FileNotFoundError:
            raise RuntimeError("kubectl not found in PATH. Install kubectl or use --mock mode.")
        except Exception as e:
            raise RuntimeError(f"Error fetching {resource}: {e}")

    def fetch_all_concurrently(self):
        """Collect all K8s resources. Returns tuple (success, error_details).
        Suppresses verbose errors and only reports overall status."""
        print("[*] Collecting Kubernetes resources...")
        failed_count = 0
        successful_resources = []
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(self.run_kubectl_json, r): r for r in RESOURCE_TYPES}
            for future in as_completed(futures):
                resource_name = futures[future]
                try:
                    self.snapshot[resource_name] = future.result()
                    successful_resources.append(resource_name)
                except Exception:
                    # Silently track failures without printing verbose errors
                    failed_count += 1
        
        # Only report overall status
        if not successful_resources:
            # All resources failed - fatal error
            return False, None
        
        if failed_count > 0:
            # Some resources failed but we have partial data
            return True, f"Warning: {failed_count} resource(s) unavailable"
        
        return True, None

    # ------------------------------------------------------------------
    # Node helpers
    # ------------------------------------------------------------------

    def node_id(self, kind, name, namespace=None):
        """Return the flat slug id for a node."""
        return _slug(kind, name, namespace)

    def add_node(self, kind, name, namespace=None, *,
                 is_source=None, is_sink=None, cves=None):
        """
        Create or retrieve a node in the mock format:
          { id, type, name, namespace, risk_score, is_source, is_sink, cves }

        is_source / is_sink default to type-based heuristics if not given.
        """
        nid = self.node_id(kind, name, namespace)

        if nid not in self.node_index:
            # Determine is_source
            if is_source is None:
                is_source = kind in ENTRY_POINT_TYPES
            # Determine is_sink
            if is_sink is None:
                is_sink = kind in SINK_TYPES

            self.node_index[nid] = {
                "id":         nid,
                "type":       kind,
                "name":       name,
                "namespace":  namespace if namespace else "cluster",
                "risk_score": 0.0,
                "is_source":  is_source,
                "is_sink":    is_sink,
                "cves":       cves if cves is not None else [],
            }
        else:
            # Allow callers to upgrade flags on an existing node
            node = self.node_index[nid]
            if is_source:
                node["is_source"] = True
            if is_sink:
                node["is_sink"] = True
            if cves:
                existing = set(node["cves"])
                for c in cves:
                    if c not in existing:
                        node["cves"].append(c)

        return self.node_index[nid]

    # ------------------------------------------------------------------
    # Edge helper
    # ------------------------------------------------------------------

    def add_edge(self, src, tgt, internal_relation, weight, risk_score,
                 cve_id=None):
        """
        Append a directed edge in the mock format:
          { source, target, relationship, weight, cve, cvss }

        internal_relation is our old name (e.g. 'runs-as-sa').
        It is translated to the mock canonical name here.
        """
        # Translate relation name
        relationship = RELATION_MAP.get(internal_relation, internal_relation)

        # can-exploit: decide between "admin-over" and "can-exec"
        if internal_relation == "can-exploit":
            relationship = "admin-over" if risk_score >= 9.0 else "can-exec"

        # secret-access that comes from a wildcard rule also becomes "admin-over"
        if internal_relation == "secret-access" and risk_score >= 9.0:
            relationship = "admin-over"

        self.edges.append({
            "source":       src,
            "target":       tgt,
            "relationship": relationship,
            "weight":       weight,
            "cve":          cve_id,
            "cvss":         risk_score if risk_score > 0 else None,
        })

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def process_cluster_data(self):
        print("[*] Building the Graph Nodes and Edges...")

        # 1. Internet entry point (ExternalActor, not External)
        internet = self.add_node("ExternalActor", "Internet", None,
                                 is_source=True, is_sink=False)

        # Ingress parsing
        for ing in self.snapshot.get("ingresses", {}).get("items", []):
            ns = ing["metadata"]["namespace"]
            for rule in ing.get("spec", {}).get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    svc_name = path.get("backend", {}).get("service", {}).get("name")
                    if svc_name:
                        svc_id = self.node_id("Service", svc_name, ns)
                        self.add_edge(internet["id"], svc_id,
                                      "ingress-exposed", weight=1.0, risk_score=5.0)

        # 2. Services -> Pods
        for svc in self.snapshot.get("services", {}).get("items", []):
            name = svc["metadata"]["name"]
            ns   = svc["metadata"]["namespace"]
            svc_type = svc["spec"].get("type", "ClusterIP")
            selector = svc["spec"].get("selector", {})

            # LoadBalancer/NodePort are publicly reachable -> is_source=True
            is_pub = svc_type in ("LoadBalancer", "NodePort")
            svc_node = self.add_node("Service", name, ns, is_source=is_pub)

            if is_pub:
                self.add_edge(internet["id"], svc_node["id"],
                              "internet-exposed", weight=1.0, risk_score=0.0)

            if selector:
                for pod in self.snapshot.get("pods", {}).get("items", []):
                    if pod["metadata"]["namespace"] == ns:
                        labels = pod["metadata"].get("labels", {})
                        if all(labels.get(k) == v for k, v in selector.items()):
                            pod_id = self.node_id("Pod", pod["metadata"]["name"], ns)
                            self.add_edge(svc_node["id"], pod_id,
                                          "routes-traffic", weight=1.0, risk_score=0.0)

        # 3. Pods -> ServiceAccounts (with CVE scanning)
        for p in self.snapshot.get("pods", {}).get("items", []):
            name    = p["metadata"]["name"]
            ns      = p["metadata"]["namespace"]
            sa_name = p["spec"].get("serviceAccountName", "default")
            images  = [c.get("image", "") for c in p["spec"].get("containers", [])]

            pod_cve_ids = []
            pod_risk    = 0.0
            top_cve_id  = None

            for img in images:
                cves, cvss_score = fetch_live_cves(img)
                for c in cves:
                    pod_cve_ids.append(c["cve"])
                if cvss_score > pod_risk:
                    pod_risk   = cvss_score
                    top_cve_id = cves[0]["cve"] if cves else None

            pod_node = self.add_node("Pod", name, ns, cves=pod_cve_ids)
            pod_node["risk_score"] = pod_risk

            sa_node = self.add_node("ServiceAccount", sa_name, ns)
            self.add_edge(pod_node["id"], sa_node["id"],
                          "runs-as-sa", weight=1.0, risk_score=pod_risk,
                          cve_id=top_cve_id)

        # 4. Deep Pod inspection: container escapes + SSRF
        for pod in self.snapshot.get("pods", {}).get("items", []):
            p_name = pod["metadata"]["name"]
            p_ns   = pod["metadata"]["namespace"]
            p_id   = self.node_id("Pod", p_name, p_ns)

            spec       = pod.get("spec", {})
            containers = spec.get("containers", [])

            is_privileged  = any(c.get("securityContext", {}).get("privileged", False)
                                 for c in containers)
            has_host_mount = any(v.get("hostPath") for v in spec.get("volumes", []))

            if is_privileged or has_host_mount:
                node_name = spec.get("nodeName")
                if node_name:
                    # Node is a high-value sink when escaped into
                    k8s_node = self.add_node("Node", node_name, "cluster",
                                             is_sink=True)
                    self.add_edge(p_id, k8s_node["id"],
                                  "container-escape", weight=0.5, risk_score=9.0)

            # Cloud Metadata API reachability
            metadata_node = self.add_node("ExternalActor", "Cloud-Metadata-API", "cloud",
                                          is_sink=True)
            self.add_edge(p_id, metadata_node["id"],
                          "potential-ssrf", weight=2.0, risk_score=5.0)

        # 5. Secrets
        secrets_cache = {}
        for s in self.snapshot.get("secrets", {}).get("items", []):
            name = s["metadata"]["name"]
            ns   = s["metadata"]["namespace"]
            is_jewel = any(k in name.lower() for k in CROWN_JEWEL_KEYWORDS)
            node = self.add_node("Secret", name, ns, is_sink=is_jewel)
            secrets_cache[(ns, name)] = node

        # 6. Roles + Bindings
        roles_cache = {}
        for r in (self.snapshot.get("roles", {}).get("items", []) +
                  self.snapshot.get("clusterroles", {}).get("items", [])):
            ns = r["metadata"].get("namespace", "cluster")
            roles_cache[(ns, r["metadata"]["name"])] = r

        for rb in (self.snapshot.get("rolebindings", {}).get("items", []) +
                   self.snapshot.get("clusterrolebindings", {}).get("items", [])):
            ns       = rb["metadata"].get("namespace", "cluster")
            role_ref = rb["roleRef"]
            role_ns  = ns if role_ref["kind"] == "Role" else "cluster"

            role_data = roles_cache.get((role_ns, role_ref["name"]))
            if not role_data:
                continue

            role_node = self.add_node(role_ref["kind"], role_ref["name"], role_ns)

            for subj in rb.get("subjects", []):
                if subj["kind"] == "ServiceAccount":
                    sa_ns  = subj.get("namespace",
                                      ns if ns != "cluster" else "default")
                    sa_node = self.add_node("ServiceAccount", subj["name"], sa_ns)
                    self.add_edge(sa_node["id"], role_node["id"],
                                  "bound-to", weight=1.0, risk_score=5.0)

            # 7. Risk matrix -> edges from role to targets
            for rule in role_data.get("rules", []):
                resources = rule.get("resources", [])
                verbs     = rule.get("verbs", [])
                risk_data = evaluate_permission(resources, verbs)

                if not risk_data:
                    continue

                if "secrets" in resources and any(v in verbs for v in ["get", "list", "*"]):
                    # Edge goes directly to each reachable secret (is_sink if crown jewel)
                    target_secrets = [
                        s for (sns, _), s in secrets_cache.items()
                        if sns == role_ns or role_ns == "cluster"
                    ]
                    for sec in target_secrets:
                        # Mark high-risk secrets as sinks
                        if risk_data["risk_score"] >= 8.0:
                            sec["is_sink"] = True
                        self.add_edge(role_node["id"], sec["id"],
                                      "secret-access",
                                      risk_data["difficulty_weight"],
                                      risk_data["risk_score"])
                else:
                    # Non-secret exploit: create a Vulnerability node as the
                    # target (same as original logic). is_sink=True marks it
                    # as a crown jewel so graph_builder finds it.
                    is_critical = risk_data["risk_score"] >= 9.0
                    vuln_node = self.add_node(
                        "Vulnerability", risk_data["desc"], "cluster",
                        is_source=False, is_sink=is_critical,
                    )
                    self.add_edge(role_node["id"], vuln_node["id"],
                                  "can-exploit",
                                  risk_data["difficulty_weight"],
                                  risk_data["risk_score"])

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export(self, output_file):
        nodes_list = list(self.node_index.values())
        metadata = {
            "cluster":    "live-cluster",
            "generated":  str(date.today()),
            "node_count": len(nodes_list),
            "edge_count": len(self.edges),
        }
        final = {
            "metadata": metadata,
            "nodes":    nodes_list,
            "edges":    self.edges,
        }
        with open(output_file, "w") as f:
            json.dump(final, f, indent=2)
        print(f"[+] Output written to {output_file} "
              f"({len(nodes_list)} nodes, {len(self.edges)} edges)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="cluster-graph.json")
    args = parser.parse_args()

    collector = UnifiedK8sCollector()
    collector.fetch_all_concurrently()
    collector.process_cluster_data()
    collector.export(args.output)