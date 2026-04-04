@echo off
:: shadowtracerv1 - Kubernetes Attack Path Visualizer
:: Usage:
::   .\run.bat          -> live cluster analysis (requires kubectl context)
::   .\run.bat --mock   -> offline/demo mode using cluster-graph.json

if exist Full_Security_Audit.pdf del /f Full_Security_Audit.pdf
echo [*] Launching shadowtracerv1...

set MOCK_FLAG=
if "%1"=="--mock" (
  set MOCK_FLAG=--mock
  echo [*] Mock mode: skipping kubectl, loading cluster-graph.json
)

docker run -it --rm ^
  -v "%USERPROFILE%\.kube:/root/.kube" ^
  -v "%cd%:/app/reports" ^
  --network host ^
  shadowtracerv1 %MOCK_FLAG%
