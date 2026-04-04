#!/bin/bash
# shadowtracerv1 — Kubernetes Attack Path Visualizer
# Usage:
#   ./run.sh           → live cluster analysis (requires kubectl context)
#   ./run.sh --mock    → offline/demo mode using cluster-graph.json

rm -f Full_Security_Audit.pdf
echo "[*] Launching shadowtracerv1..."

MOCK_FLAG=""
if [[ "$1" == "--mock" ]]; then
  MOCK_FLAG="--mock"
  echo "[*] Mock mode: skipping kubectl, loading cluster-graph.json"
fi

docker run -it --rm \
  -v ~/.kube:/root/.kube \
  -v "$(pwd):/app/reports" \
  --network host \
  shadowtracerv1 $MOCK_FLAG
