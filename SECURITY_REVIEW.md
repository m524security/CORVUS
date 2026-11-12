# CORVUS — Code Review & Hardening Report

An independent, red-team–style review of the codebase originally released under a different name,
followed by concrete fixes, a test suite, and CI. Everything below was verified
against the source and — for the detection bugs — against a **live vulnerable
target**, not against the marketing.

---

## Verdict

**A genuinely-engineered offensive-security framework whose flagship detections
were silently broken.** The hard parts — the CVSS engine, the multi-gate FP
architecture, the OAST design, the decision engine — are real and well built. But
live testing showed that **error-based SQLi and reflected XSS never actually fired**
against a vulnerable target, because of four subtle bugs. All four are now fixed and
locked behind regression tests. The tool went from *looks real* to *proven real*.

---

## Method

A dependency-free, deliberately-vulnerable target (`tests/integration/vuln_server.py`)
was built with controlled instances of reflected XSS, error-based SQLi, open redirect,
missing security headers, and exposed `.git`/`.env` — plus **negative controls**
(HTML-encoded reflection, non-reflecting params). The real detection modules were run
against it. This both proves true positives fire and proves clean endpoints stay
silent (no false positives).

---

## Verified genuinely correct

| Area | Result |
|---|---|
| **CVSS v3.1 engine** | 11/11 official FIRST.org reference vectors reproduced exactly (incl. scope-changed cases and the canonical reflected-XSS 6.1). |
| **Command safety** | No `shell=True`, no `eval`/`exec` on dynamic data; subprocess uses arg arrays — target input can't inject shell commands. |
| **Secrets** | None hardcoded. |
| **OAST design** | Real out-of-band callback listener; blind classes gated on a genuine callback. |
| **Decision engine** | Real expected-value scheduler with fingerprint gating, budgeting, profiles. |
| **Reporting** | JSON / HTML / CSV / SARIF 2.1.0 / Markdown all real and spec-shaped. |

---

## Detection bugs found via live testing (critical)

**1. `requests.Response` truthiness discarded every error response.**
`Response.__bool__` returns `.ok` (False for 4xx/5xx), so the idiom
`if not resp: continue` — used at **68 sites** — silently threw away every error
response. Error-based SQLi depends on the 500 that carries the DB error, so it
**never fired**. Fixed globally: a `Response` object is now always truthy, so the
check means "no response object", never "error status".

**2–4. Reflected XSS never fired** — three independent gate bugs, each fatal:
- an "echo-all" guard skipped any parameter that reflected input — but *every*
  reflected-XSS parameter reflects input, so all true positives were suppressed;
- a `0.98` baseline-similarity gate dropped reflections on large pages (the canary
  is a small delta, so the page stays ~98% similar to baseline);
- the entity-encoding check built its "encoded form" from the **canary** (which has
  no angle brackets), so it always matched the raw canary and false-skipped.

All rewritten so a finding requires the **raw payload markup to survive verbatim**
while genuinely-encoded output is still correctly skipped.

**5. Findings shipped without CVSS.** `make_finding()` left `cvss_score` /
`cvss_vector` / `cvss_rating` empty despite the documented schema. Now auto-attached
from the per-module preset.

### Result — live scan, after fixes

```
[PASS] sqli (error-based)   Critical  cvss=9.1   fires
[PASS] xss (reflected)      High      cvss=4.3   fires
[PASS] open_redirect        Medium    cvss=4.3   fires
[PASS] sensitive_files      Critical  cvss=7.5   fires (.git / .env)
[PASS] security_headers     High      cvss=5.3   fires (+5)
[PASS] clickjacking         Medium    cvss=4.3   fires
[PASS] encoded reflection             (clean)    ← no false positive
[PASS] non-reflecting param           (clean)    ← no false positive
[PASS] non-injectable param           (clean)    ← no false positive
```

---

## Reliability & safety fixes

- Removed a **duplicate `tool_sslyze_v8`** definition (dead/shadowed) and duplicate
  `CVSS31.PRESETS` keys (`rfi`, `smtp_relay`, `webdav`).
- **Import no longer mutates the host** (`pip install` on import only when run as a
  script; imported as a library it raises).
- **Safe-by-default installs** — non-interactive runs no longer auto-run
  `sudo apt/gem/go`; opt in with `--install-tools`.
- Version standardized across all surfaces (was `10.0.0` vs `10.1.1`; now `11.0.0`).

---

## Corrected claims (now honest)

| Was claimed | Actual | Now stated |
|---|---|---|
| 150+ modules | **100** | 100 |
| 500+ cred pairs | **130** | 130 |
| 100+ signatures | **85** | 85 |
| Zero-FP | multi-gate reduction | "multi-gate FP control" |
| 40+ tools | **58** | 58 (was under-claimed) |

---

## Tests & CI added

- **43 tests** (`pytest -q`): CVSS reference vectors, preset integrity, finding
  schema + CVSS attach, pure helpers, import/engine smoke, and a **live integration
  suite** against the bundled vulnerable target.
- **GitHub Actions CI**: byte-compile + suite on Python 3.8/3.10/3.12 + CLI smoke.

---

## Recommended next (Phase 3+)

- Unify the two front doors so the engine drives all 100 modules (today ~37 wired).
- Add POST / JSON-body / header injection points (core injection is GET/query today).
- Add a bundled DVWA / Juice-Shop CI job for broader golden-target coverage.
- Split the monolith into an installable package.
