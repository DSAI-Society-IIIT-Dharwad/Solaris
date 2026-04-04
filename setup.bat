@echo off
echo [*] Building shadowtracerv1 Standalone Image...
docker build -t shadowtracerv1 .
echo [!] Setup Complete. You can now use run.bat to analyze clusters.
pause