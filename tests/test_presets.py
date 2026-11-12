"""
Integrity of the per-module CVSS preset table.

These tests guard against the class of bug where a preset key is defined twice
(Python silently keeps the last, so the first becomes dead code and scoring can
change without warning). They also assert every preset produces a valid,
in-range score with a rating consistent with that score.
"""
import re

import corvus_core as core

PRESETS = core.CVSS31.PRESETS


def test_preset_keys_are_unique_in_source():
    """
    The dict literal itself must not contain duplicate keys.

    We scan the source rather than the built dict, because Python has already
    collapsed duplicates by the time PRESETS exists — so a runtime len() check
    can't see them. This catches duplicates at their source.
    """
    src = (core.__file__)
    text = open(src, encoding="utf-8", errors="ignore").read()
    m = re.search(r"PRESETS\s*=\s*\{(.*?)\n    \}", text, re.S)
    assert m, "could not locate PRESETS literal in source"
    keys = re.findall(r'"([a-z0-9_]+)"\s*:', m.group(1))
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"duplicate preset keys in source: {sorted(dupes)}"


def test_every_preset_scores_valid_and_in_range():
    for key, metrics in PRESETS.items():
        assert len(metrics) == 8, f"{key} preset must have 8 metrics, got {len(metrics)}"
        score, vector, rating = core.CVSS31.score(*metrics)
        assert 0.0 <= score <= 10.0, f"{key} scored out of range: {score}"
        assert vector.startswith("CVSS:3.1/")
        assert rating in {"None", "Low", "Medium", "High", "Critical"}


def test_rating_matches_score_band():
    """The rating a preset yields must fall in the correct numeric band."""
    for key, metrics in PRESETS.items():
        score, _, rating = core.CVSS31.score(*metrics)
        expected = (
            "Critical" if score >= 9.0 else
            "High" if score >= 7.0 else
            "Medium" if score >= 4.0 else
            "Low" if score > 0.0 else
            "None"
        )
        assert rating == expected, f"{key}: score {score} rated {rating}, expected {expected}"


def test_high_impact_modules_are_severe():
    """Sanity: the classes we call Critical in the docs must actually score high."""
    for key in ("sqli", "default_creds", "cmd_injection", "rfi", "ssti"):
        assert key in PRESETS, f"expected preset for {key}"
        score, _, _ = core.CVSS31.score(*PRESETS[key])
        assert score >= 7.0, f"{key} should be High/Critical, scored {score}"
