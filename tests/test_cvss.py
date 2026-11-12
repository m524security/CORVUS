"""
CVSS v3.1 engine correctness.

The base scores below are the values published by FIRST.org for these exact
vectors. If ``CVSS31.score`` ever drifts from the specification, these tests
fail. This is the single most important correctness guarantee in the project:
every finding's severity is derived from this engine.
"""
import math

import pytest

import corvus_core as core

CVSS = core.CVSS31

# (expected_base_score, av, ac, pr, ui, s, c, i, a)
REFERENCE_VECTORS = [
    (9.8, "N", "L", "N", "N", "U", "H", "H", "H"),  # unauth RCE
    (10.0, "N", "L", "N", "N", "C", "H", "H", "H"),  # scope-changed full compromise
    (9.1, "N", "L", "N", "N", "U", "H", "H", "N"),
    (7.5, "N", "L", "N", "N", "U", "H", "N", "N"),  # network info disclosure
    (6.1, "N", "L", "N", "R", "C", "L", "L", "N"),  # canonical reflected XSS
    (5.9, "N", "H", "N", "N", "U", "H", "N", "N"),
    (7.8, "L", "L", "L", "N", "U", "H", "H", "H"),  # local privilege escalation
    (8.8, "N", "L", "L", "N", "U", "H", "H", "H"),
    (4.3, "N", "L", "L", "N", "U", "L", "N", "N"),
    (6.5, "N", "L", "L", "N", "U", "H", "N", "N"),  # authenticated IDOR-style
    (0.0, "P", "H", "H", "R", "U", "N", "N", "N"),  # no impact
]


@pytest.mark.parametrize("expected,av,ac,pr,ui,s,c,i,a", REFERENCE_VECTORS)
def test_reference_vectors(expected, av, ac, pr, ui, s, c, i, a):
    score, vector, rating = CVSS.score(av, ac, pr, ui, s, c, i, a)
    assert score == pytest.approx(expected, abs=0.05), (
        f"{vector} scored {score}, expected {expected}"
    )
    # The vector string must round-trip the exact metrics we passed in.
    assert vector == f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def test_rating_boundaries():
    """Severity bands must match the CVSS v3.1 qualitative scale exactly."""
    assert CVSS.score("P", "H", "H", "R", "U", "N", "N", "N")[2] == "None"      # 0.0
    assert CVSS.score("N", "L", "L", "N", "U", "L", "N", "N")[2] == "Medium"    # 4.3
    assert CVSS.score("N", "L", "N", "N", "U", "H", "N", "N")[2] == "High"      # 7.5
    assert CVSS.score("N", "L", "N", "N", "U", "H", "H", "H")[2] == "Critical"  # 9.8


def test_score_never_out_of_range():
    """No metric combination may ever produce a score outside 0.0–10.0."""
    opts = {
        "av": "NALP", "ac": "LH", "pr": "NLH", "ui": "NR",
        "s": "UC", "c": "NLH", "i": "NLH", "a": "NLH",
    }
    import itertools
    combos = itertools.product(*[list(v) for v in opts.values()])
    for av, ac, pr, ui, s, c, i, a in combos:
        score, _, rating = CVSS.score(av, ac, pr, ui, s, c, i, a)
        assert 0.0 <= score <= 10.0, f"out-of-range score {score}"
        assert rating in {"None", "Low", "Medium", "High", "Critical"}


def test_scope_change_increases_or_equals_score():
    """Changing scope from U to C must never *lower* the score for the same CIA."""
    base_u = CVSS.score("N", "L", "N", "N", "U", "H", "H", "H")[0]
    base_c = CVSS.score("N", "L", "N", "N", "C", "H", "H", "H")[0]
    assert base_c >= base_u


def test_roundup_is_ceiling_to_one_decimal():
    """CVSS v3.1 uses 'round up' (ceil to 1 decimal), not banker's rounding."""
    score, _, _ = CVSS.score("N", "L", "N", "R", "C", "L", "L", "N")  # 6.1 canonical
    assert score == 6.1
    # Score must always be expressible as an exact tenth.
    assert math.isclose(score * 10, round(score * 10))
