"""
CORVUS — Autonomous Web & API Security Framework
==================================================
Codename: NIGHT REAPER   |   v11.0.0

This package is the self-directing "brain" layered on top of the existing
detection modules in ``corvus_core.py``. Instead of running every module in a
fixed order, CORVUS maintains *state* about the target and *decides* what to
do next based on what it has learned.

Public surface
--------------
    from corvus import Engine, Profile, ScopeGuard, TargetState
    from corvus.profiles import PASSIVE, SAFE, AGGRESSIVE

Design pillars
--------------
1. Decision engine   — state graph + planner + fingerprint gating (engine.py)
2. OAST verification — out-of-band confirmation of blind vulns   (oast.py)
3. Async core        — high-throughput crawling / probing         (asynccore.py)
4. Plugins + profiles— extensibility + safety rails               (plugins.py / profiles.py)

Authorized testing only. CORVUS performs *detection and reporting*; it does
not weaponize, exploit, or maintain access.
"""

from __future__ import annotations

__version__ = "11.0.0"
__codename__ = "NIGHT REAPER"

from .state import TargetState, Finding
from .profiles import Profile, ScopeGuard, PASSIVE, SAFE, AGGRESSIVE, get_profile
from .engine import Engine, ModuleSpec, Planner

__all__ = [
    "Engine", "ModuleSpec", "Planner",
    "TargetState", "Finding",
    "Profile", "ScopeGuard", "get_profile",
    "PASSIVE", "SAFE", "AGGRESSIVE",
    "__version__", "__codename__",
]
