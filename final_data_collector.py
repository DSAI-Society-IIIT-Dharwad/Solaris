#!/usr/bin/env python3
import argparse
import json
import subprocess
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import all configurations and threat intel from our separate module
from config import RESOURCE_TYPES, CROWN_JEWEL_KEYWORDS, evaluate_permission
from cve_scorer import fetch_live_cves

class UnifiedK8sCollector:
    def __init__(self):
        self.executor_class = ThreadPoolExecutor
        self.as_completed_func = as_completed
        self.snapshot = {}
        self.node_index = {}
        self.edges = []

    def run_kubectl_json(self, resource):
        """Fetches resource JSON from the cluster."""
        cmd = f"kubectl get {resource} -A -o json"
        try:
            result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except:
            return {"items": []}

    def fetch_all_concurrently(self):
        """Uses ThreadPoolExecutor for rapid data ingestion."""
        print("[*] Collecting Kubernetes resources concurrently...")
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(self.run_kubectl_json, r): r for r in RESOURCE_TYPES}
            for future in as_completed(futures):
                resource_name = futures[future]
                self.snapshot[resource_name] = future.result()
                print(f"[+] {resource_name} collected")

    def node_id(self, kind, name, namespace=None):
        """Standardized ID generator."""
        ns = namespace if namespace else "cluster"
        return f"{kind}:{ns}:{name}"

    def add_node(self, kind, name, namespace=None, meta=None):
        """Creates or updates a node, preventing duplicates."""
        nid = self.node_id(kind, name, namespace)
        if nid not in self.node_index:
            self.node_index[nid] = {
                "id": nid,
                "type": kind,
                "name": name,
                "namespace": namespace,
                "risk_score": 0.0, 
                "meta": meta or {}
            }
        return self.node_index[nid]

    def add_edge(self, src, tgt, relation, weight, risk_score):
        """Appends a directed edge for the Phase 2 graph."""
        self.edges.append({
            "source": src,
            "target": tgt,
            "relation": relation,
            "weight": weight,
            "risk_score": risk_score
        })

    

    def process_cluster_data(self):
        """The main pipeline combining Nodes and Edges."""
        print("[*] Building the Graph Nodes and Edges...")
        
        # 1. Map the Internet Entry Point
        internet = self.add_node("External", "Internet", None, {"entry_point": True})

        # GENERIC FIX: Add generic Ingress parsing (how real clusters route traffic)
        for ing in self.snapshot.get("ingresses", {}).get("items", []):
            ns = ing["metadata"]["namespace"]
            for rule in ing.get("spec", {}).get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    svc_name = path.get("backend", {}).get("service", {}).get("name")
                    if svc_name:
                        svc_id = self.node_id("Service", svc_name, ns)
                        self.add_edge(internet["id"], svc_id, "ingress-exposed", weight=1.0, risk_score=5.0)

        # 2. Map Services to Pods (Remove the 'goat' hardcode!)
        for svc in self.snapshot.get("services", {}).get("items", []):
            name = svc["metadata"]["name"]
            ns = svc["metadata"]["namespace"]
            svc_type = svc["spec"].get("type", "ClusterIP")
            selector = svc["spec"].get("selector", {})
            
            svc_node = self.add_node("Service", name, ns, {"type": svc_type})
            
            # Only genuinely public services get the direct internet edge
            if svc_type in ("LoadBalancer", "NodePort"):
                self.add_edge(internet["id"], svc_node["id"], "internet-exposed", weight=1.0, risk_score=0.0)

            if selector:
                for pod in self.snapshot.get("pods", {}).get("items", []):
                    if pod["metadata"]["namespace"] == ns:
                        labels = pod["metadata"].get("labels", {})
                        if all(labels.get(k) == v for k, v in selector.items()):
                            pod_id = self.node_id("Pod", pod["metadata"]["name"], ns)
                            self.add_edge(svc_node["id"], pod_id, "routes-traffic", weight=1.0, risk_score=0.0)

        # 3. Map Pods to ServiceAccounts with CVE Scanning
        for p in self.snapshot.get("pods", {}).get("items", []):
            name = p["metadata"]["name"]
            ns = p["metadata"]["namespace"]
            sa_name = p["spec"].get("serviceAccountName", "default")
            
            images = [c.get("image", "") for c in p["spec"].get("containers", [])]
            
            pod_cves = []
            pod_risk = 1.0
            for img in images:
                cves, cvss_score = fetch_live_cves(img)
                pod_cves.extend(cves)
                if cvss_score > pod_risk:
                    pod_risk = cvss_score
            
            pod_node = self.add_node("Pod", name, ns, {
                "images": images,
                "vulnerabilities": pod_cves 
            })
            pod_node["risk_score"] = pod_risk 
            
            sa_node = self.add_node("ServiceAccount", sa_name, ns)
            self.add_edge(pod_node["id"], sa_node["id"], "runs-as-sa", weight=1.0, risk_score=pod_risk)

        # New Step: Deep Pod Inspection for Escapes & Lateral Movement
        for pod in self.snapshot.get("pods", {}).get("items", []):
            p_name = pod["metadata"]["name"]
            p_ns = pod["metadata"]["namespace"]
            p_id = self.node_id("Pod", p_name, p_ns)
            
            spec = pod.get("spec", {})
            containers = spec.get("containers", [])
            
            # 1. Check for Privileged Escapes (Pod -> Node)
            is_privileged = any(c.get("securityContext", {}).get("privileged", False) for c in containers)
            has_host_mount = any(v.get("hostPath") for v in spec.get("volumes", []))
            
            if is_privileged or has_host_mount:
                node_name = spec.get("nodeName")
                if node_name:
                    # add_node MUST be called first to register it
                    k8s_node = self.add_node("Node", node_name, "cluster")
                    self.add_edge(p_id, k8s_node["id"], "container-escape", weight=0.5, risk_score=9.0)
            
            # 2. Generic Metadata SSRF (Standard in Cloud K8s)
            metadata_node = self.add_node("External", "Cloud-Metadata-API", "cloud", {"crown_jewel": True})
            self.add_edge(p_id, metadata_node["id"], "potential-ssrf", weight=2.0, risk_score=5.0)

        # 4. Map Crown Jewel Secrets
        secrets_cache = {}
        for s in self.snapshot.get("secrets", {}).get("items", []):
            name = s["metadata"]["name"]
            ns = s["metadata"]["namespace"]
            is_jewel = any(k in name.lower() for k in CROWN_JEWEL_KEYWORDS)
            
            node = self.add_node("Secret", name, ns, {"crown_jewel": is_jewel})
            secrets_cache[(ns, name)] = node

        # 5. Map Bindings (SA -> Role)
        roles_cache = {}
        for r in self.snapshot.get("roles", {}).get("items", []) + self.snapshot.get("clusterroles", {}).get("items", []):
            ns = r["metadata"].get("namespace", "cluster")
            roles_cache[(ns, r["metadata"]["name"])] = r

        for rb in self.snapshot.get("rolebindings", {}).get("items", []) + self.snapshot.get("clusterrolebindings", {}).get("items", []):
            ns = rb["metadata"].get("namespace", "cluster")
            role_ref = rb["roleRef"]
            role_ns = ns if role_ref["kind"] == "Role" else "cluster"
            
            role_data = roles_cache.get((role_ns, role_ref["name"]))
            if not role_data: continue

            role_node = self.add_node(role_ref["kind"], role_ref["name"], role_ns)

            for subj in rb.get("subjects", []):
                if subj["kind"] == "ServiceAccount":
                    sa_ns = subj.get("namespace", ns if ns != "cluster" else "default")
                    sa_node = self.add_node("ServiceAccount", subj["name"], sa_ns)
                    
                    self.add_edge(sa_node["id"], role_node["id"], "bound-to", weight=1.0, risk_score=5.0)

            # 6. Apply Risk Matrix to Role Rules via config.evaluate_permission
            for rule in role_data.get("rules", []):
                resources = rule.get("resources", [])
                verbs = rule.get("verbs", [])
                
                # Check our external risk matrix!
                risk_data = evaluate_permission(resources, verbs)
                
                if risk_data:
                    if "secrets" in resources and any(v in verbs for v in ["get", "list", "*"]):
                        target_secrets = [s for (sns, sname), s in secrets_cache.items() if sns == role_ns or role_ns == "cluster"]
                        for sec in target_secrets:
                            self.add_edge(role_node["id"], sec["id"], "secret-access", risk_data["difficulty_weight"], risk_data["risk_score"])
                    else:
                        # GENERIC FIX: Any vulnerability >= 9.0 is automatically a Crown Jewel (e.g., Cluster Takeover)
                        is_critical = risk_data["risk_score"] >= 9.0
                        target_node = self.add_node("Vulnerability", risk_data["desc"], "cluster", meta={"crown_jewel": is_critical})
                        self.add_edge(role_node["id"], target_node["id"], "can-exploit", risk_data["difficulty_weight"], risk_data["risk_score"])

    def export(self, output_file):
        nodes_list = list(self.node_index.values())
        final = {"nodes": nodes_list, "edges": self.edges}
        with open(output_file, "w") as f:
            json.dump(final, f, indent=2)
        print(f"[+] Output written to {output_file} ({len(nodes_list)} nodes, {len(self.edges)} edges)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="cluster-graph.json")
    args = parser.parse_args()

    collector = UnifiedK8sCollector()
    collector.fetch_all_concurrently()
    collector.process_cluster_data()
    collector.export(args.output)