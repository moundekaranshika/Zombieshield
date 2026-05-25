"""
config.py — Resolve Anthropic API key from env, .env file, or explicit override.
"""

import os
from pathlib import Path

ROOT = Path(__file__).parent.parent


def load_dotenv() -> None:
    """Load .env from project root if python-dotenv is available."""
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv as _load
        _load(env_path)
    except ImportError:
        pass


def resolve_api_key(explicit: str | None = None) -> str:
    """
    Priority: explicit (e.g. Streamlit session) → env → .env file.
    """
    if explicit and str(explicit).strip():
        return str(explicit).strip()

    load_dotenv()
    return os.environ.get("ANTHROPIC_API_KEY", "").strip()
