"""Shared pytest configuration.

Inserts ``Model/`` on ``sys.path`` so test files can import the detector
modules with bare names (matching how ``bench/run.py`` consumes them).
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = REPO_ROOT / "Model"

if str(MODEL_DIR) not in sys.path:
    sys.path.insert(0, str(MODEL_DIR))
