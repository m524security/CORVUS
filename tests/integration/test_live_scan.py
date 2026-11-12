"""
Live end-to-end detection tests against a deliberately-vulnerable local target.

This is the proof the scanner actually works: real HTTP requests, real modules,
real findings — plus negative controls that assert clean endpoints produce NO
findings (no false positives). These tests would have caught the four detection
regressions fixed in the hardening pass:

  1. requests.Response truthiness discarding 4xx/5xx (broke error-based SQLi)
  2. XSS echo-all gate suppressing all reflected XSS
  3. XSS baseline-similarity gate suppressing XSS on large pages
  4. XSS encoded-form check matching the canary (always false-skipping)
"""
import pytest

import corvus_core as core
from tests.integration.vuln_server import VulnServer


@pytest.fixture(scope="module")
def live():
    core.QUIET = True
    with VulnServer() as srv:
        yield srv


@pytest.fixture()
def session(live):
    sess = core.make_session()
    core._scan_ctx = core.ScanContext(live.base_url, sess)
    yield sess
    core._scan_ctx = None


def _titles(findings):
    return [f.title for f in (findings or [])]


# ── True positives: these MUST fire ──────────────────────────────────────────

def test_error_based_sqli_fires(live, session):
    findings = core.module_sqli(live.base_url + "/item?id=1", session)
    assert findings, "error-based SQLi must be detected on /item?id="
    d = findings[0].to_dict()
    assert "SQL Injection" in findings[0].title
    assert d["severity"] == "Critical"
    assert float(d["cvss_score"]) >= 7.0


def test_reflected_xss_fires(live, session):
    findings = core.module_xss(live.base_url + "/search?q=test", session)
    assert findings, "reflected XSS must be detected on /search?q="
    assert "XSS" in findings[0].title
    assert findings[0].to_dict()["cvss_vector"].startswith("CVSS:3.1/")


def test_open_redirect_fires(live, session):
    findings = core.module_open_redirect(live.base_url + "/go?url=1", session)
    assert findings, "open redirect must be detected on /go?url="


def test_sensitive_files_fire(live, session):
    findings = core.module_sensitive_files(live.base_url + "/", session)
    titles = " ".join(_titles(findings))
    assert findings, "exposed .git / .env must be detected"
    assert "Git" in titles or "Environment" in titles


def test_security_headers_fire(live, session):
    findings = core.module_security_headers(live.base_url + "/", session)
    assert findings, "missing security headers must be reported"


# ── Negative controls: these MUST stay clean (no false positives) ────────────

def test_encoded_reflection_is_not_xss(live, session):
    """/safe HTML-encodes its input — must NOT be reported as XSS."""
    findings = core.module_xss(live.base_url + "/safe?name=x", session)
    assert not findings, f"false positive on encoded output: {_titles(findings)}"


def test_no_sink_param_is_not_xss(live, session):
    findings = core.module_xss(live.base_url + "/ping?x=1", session)
    assert not findings, f"false positive on non-reflecting param: {_titles(findings)}"


def test_no_sink_param_is_not_sqli(live, session):
    findings = core.module_sqli(live.base_url + "/ping?x=1", session)
    assert not findings, f"false positive SQLi on clean endpoint: {_titles(findings)}"


def test_every_live_finding_carries_cvss(live, session):
    """Regression guard: findings must ship a populated CVSS score."""
    findings = core.module_sqli(live.base_url + "/item?id=1", session)
    for f in findings:
        d = f.to_dict()
        assert d["cvss_score"] != "" and float(d["cvss_score"]) > 0
        assert d["cvss_vector"].startswith("CVSS:3.1/")
