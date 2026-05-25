"""
streamlit_app.py
Root entry point for Streamlit Community Cloud (one-click deploy).
Local run: streamlit run streamlit_app.py
"""

from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).parent / "dashboard" / "app.py"), run_name="__main__")
