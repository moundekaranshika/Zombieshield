"""
bootstrap.py
Ensure synthetic source data exists and run the full ZombieShield pipeline.
"""

import subprocess
import sys
from pathlib import Path

from engine.classifier import run_classification
from engine.drift_detector import detect_drift
from engine.git_mapper import build_accountability_report
from engine.ml_scorer import run_ml_scoring

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"


def ensure_source_data() -> None:
    """Generate api_registry, swagger, and git_log if missing."""
    registry = DATA_DIR / "api_registry.csv"
    if registry.exists():
        return

    script = DATA_DIR / "generate_data.py"
    if not script.exists():
        raise FileNotFoundError(f"Missing data generator: {script}")

    subprocess.run([sys.executable, str(script)], cwd=str(ROOT), check=True)


def run_full_pipeline() -> None:
    """Generate source data (if needed) and refresh all pipeline outputs."""
    ensure_source_data()
    run_classification()
    run_ml_scoring()
    detect_drift()
    build_accountability_report()
