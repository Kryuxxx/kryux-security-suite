#!/bin/bash
# KRYUX // SECURITY SUITE — Starter
# Hinweis: einmalig ausführbar machen mit: chmod +x run.sh
# Start: ./run.sh  (oder: bash run.sh)

set -euo pipefail

# In das Verzeichnis dieses Skripts wechseln (damit main.py gefunden wird)
cd "$(dirname "$0")"

# Python-Prüfung (mind. Python 3.10 für str|None-Syntax, Ziel: Python 3.14)
if ! command -v python3 >/dev/null 2>&1; then
    echo "[KRYUX] FEHLER: python3 nicht gefunden. Bitte Python 3.14 installieren."
    exit 1
fi

echo "[KRYUX] Starte KRYUX // SECURITY SUITE ..."
exec python3 main.py "$@"
