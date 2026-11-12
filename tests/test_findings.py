"""
Finding construction: the make_finding() contract.

Guards the regression where findings shipped with an empty cvss_score field
even though the JSON/SARIF schema (and the README) promise a populated score.
Also verifies OWASP/MITRE tagging and the serialisable shape consumers depend on.
"""
import corvus_core as core

REQUIRED_KEYS = {
    "title", "severity", "description", "recommendation", "url", "payload",
    "cwe", "confidence", "owasp_id", "mitre_id", "timestamp",
    "cvss_score", "cvss_vector", "cvss_rating",
}


def test_make_finding_attaches_cvss():
    f = core.make_finding(
        "sqli", "Error-Based SQLi in 'id'", "Critical",
        "desc", "use prepared statements", url="http://x/?id=1'", payload="'", cwe="CWE-89",
    )
    d = f.to_dict()
    assert d["cvss_score"] != "", "cvss_score must be populated"
    assert isinstance(d["cvss_score"], (int, float))
    assert 0.0 <= float(d["cvss_score"]) <= 10.0
    assert d["cvss_vector"].startswith("CVSS:3.1/")
    assert d["cvss_rating"] in {"None", "Low", "Medium", "High", "Critical"}


def test_make_finding_tags_owasp_and_mitre():
    f = core.make_finding("sqli", "t", "Critical", "d", "r")
    d = f.to_dict()
    assert d["owasp_id"] == "A03"
    assert d["mitre_id"] == "T1190"


def test_finding_to_dict_has_full_schema():
    f = core.make_finding("xss", "Reflected XSS", "Medium", "d", "r",
                          url="http://x/?q=1", payload="<x>", cwe="CWE-79")
    d = f.to_dict()
    missing = REQUIRED_KEYS - set(d.keys())
    assert not missing, f"finding dict missing keys: {sorted(missing)}"


def test_unknown_module_still_scores_and_serialises():
    """A module_key with no preset/tagging must not raise and must still score."""
    f = core.make_finding("totally_unknown_module", "t", "Low", "d", "r")
    d = f.to_dict()
    assert d["cvss_vector"].startswith("CVSS:3.1/")   # falls back to a default vector
    assert d["owasp_id"] == ""                          # no tag, but no crash
