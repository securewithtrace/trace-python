from __future__ import annotations

import importlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_str = str(PROJECT_ROOT)
if project_root_str in sys.path:
    sys.path.remove(project_root_str)
sys.path.insert(0, project_root_str)

# Avoid resolving to stdlib `trace.py` during test imports.
module = sys.modules.get("trace")
if module is not None and not hasattr(module, "__path__"):
    del sys.modules["trace"]

# Force-load the local package so subsequent imports resolve correctly.
importlib.import_module("trace")
