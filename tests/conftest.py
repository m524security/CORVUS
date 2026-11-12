"""
Pytest bootstrap for CORVUS.

Ensures the repository root (which contains ``corvus_core.py`` and the
``corvus`` package) is importable regardless of where pytest is invoked from,
and pins deterministic settings so tests never depend on hash randomisation,
colour output, or network access.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Deterministic, quiet, no-colour test runs.
os.environ.setdefault("PYTHONHASHSEED", "0")
os.environ.pop("CORVUS_FORCE_COLOR", None)
