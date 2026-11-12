"""
Smoke tests — import safety and structural invariants.

A security scanner that crashes on import, or whose engine silently registers
zero modules, is worse than useless. These tests fail loudly if either happens.
"""
import importlib


def test_core_imports_without_side_effects():
    core = importlib.import_module("corvus_core")
    assert hasattr(core, "CVSS31")
    assert hasattr(core, "make_finding")
    assert core.VERSION  # non-empty


def test_module_count_is_reported_honestly():
    """
    Count the detection modules that actually exist. This is the number the
    README should quote — not an aspirational one.
    """
    core = importlib.import_module("corvus_core")
    modules = [n for n in dir(core) if n.startswith("module_") and callable(getattr(core, n))]
    # Lower bound guard: if a refactor accidentally drops modules, this trips.
    assert len(modules) >= 90, f"expected the full module set, found only {len(modules)}"


def test_version_is_consistent_across_surfaces():
    core = importlib.import_module("corvus_core")
    pkg = importlib.import_module("corvus")
    assert core.VERSION == pkg.__version__, (
        f"version drift: core={core.VERSION} package={pkg.__version__}"
    )


def test_engine_registers_modules():
    """The autonomous engine must wire in a non-trivial set of core modules."""
    from corvus.engine import build_core_specs
    from corvus.profiles import AGGRESSIVE
    specs = build_core_specs(AGGRESSIVE)
    assert len(specs) >= 20, f"engine registered only {len(specs)} module specs"
    names = {s.name for s in specs}
    # A few load-bearing modules that must always be present.
    for expected in ("module_sqli", "module_xss", "module_default_creds"):
        assert expected in names, f"engine missing {expected}"


def test_default_creds_db_is_nontrivial():
    core = importlib.import_module("corvus_core")
    assert len(core.DEFAULT_CREDS_DB) >= 100
    # every entry is a (user, pass) pair
    assert all(isinstance(pair, tuple) and len(pair) == 2 for pair in core.DEFAULT_CREDS_DB)
