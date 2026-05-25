#!/bin/bash
# run.sh — ZombieShield one-click setup and launch
# Usage: bash run.sh
# Optional: export ANTHROPIC_API_KEY=your_key before running

set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         ZombieShield — iDEA 2.0          ║"
echo "║   API Security & Governance Platform     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Create virtualenv if missing
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate

# Install dependencies
echo "[1/3] Installing dependencies..."
pip install -r requirements.txt -q

# Generate data + run full pipeline
echo "[2/3] Running data generation + classification pipeline..."
python -c "from engine.bootstrap import run_full_pipeline; run_full_pipeline()"

# Launch dashboard
echo "[3/3] Launching Streamlit dashboard..."
echo ""
echo "  → Open http://localhost:8501 in your browser"
echo ""

streamlit run streamlit_app.py --server.port 8501
