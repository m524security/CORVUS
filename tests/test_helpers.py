"""
Pure helper functions — deterministic, no network.

These are the primitives every injection module relies on (parameter
injection, query parsing, entropy for secret detection, payload capping).
"""
from urllib.parse import parse_qs, urlparse

import corvus_core as core


def test_extract_params():
    assert core.extract_params("http://x/p?a=1&b=2") == ["a", "b"]
    assert core.extract_params("http://x/p") == []


def test_inject_param_replaces_value():
    out = core.inject_param("http://x/p?id=1&ref=2", "id", "PAYLOAD")
    q = parse_qs(urlparse(out).query)
    assert q["id"] == ["PAYLOAD"]
    assert q["ref"] == ["2"], "other params must be preserved"


def test_inject_param_adds_missing_param():
    out = core.inject_param("http://x/p", "q", "V")
    q = parse_qs(urlparse(out).query)
    assert q["q"] == ["V"]


def test_inject_param_preserves_scheme_and_host():
    out = core.inject_param("https://host.tld/a/b?x=1", "x", "2")
    p = urlparse(out)
    assert p.scheme == "https"
    assert p.netloc == "host.tld"
    assert p.path == "/a/b"


def test_entropy_ordering():
    """High-entropy strings (keys/tokens) must score above natural-language text."""
    low = core.entropy("aaaaaaaaaaaaaaaa")
    med = core.entropy("password")
    high = core.entropy("f3a9Kd8Lm2Qp7Zx1Vb6Nc0Rt5Yh4Wj")
    assert low < med < high
    assert core.entropy("") == 0


def test_variants_respects_cap(monkeypatch):
    payloads = ["a", "b", "c", "d", "e"]
    monkeypatch.setattr(core, "PAYLOAD_VARIANTS", 2, raising=False)
    assert core._variants(payloads) == ["a", "b"]
    monkeypatch.setattr(core, "PAYLOAD_VARIANTS", 0, raising=False)
    assert core._variants(payloads) == payloads   # 0 = no cap
