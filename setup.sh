#!/bin/bash
echo "[*] Building shadowtracerv1 Standalone Image..."
docker build -t shadowtracerv1 .
chmod +x run.sh
echo "[!] Setup Complete. Use ./run.sh to analyze clusters."