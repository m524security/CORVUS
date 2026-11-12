# CORVUS — Architecture

This document explains how CORVUS works end to end: how it decides what to test,
how it confirms a finding before reporting it, and how the pieces fit together.

For the engine internals specifically, see [`ENGINE.md`](ENGINE.md).

---

## 1. Design goals

1. **Evidence over guesses.** A finding is only emitted after multi-gate
   confirmation. Blind vulnerability classes require an out-of-band callback.
2. **Spend budget where it pays.** The engine ranks checks by expected value and
   gates them behind fingerprints, instead of firing everything in a fixed order.
3. **Correct severity.** Every finding is scored with a spec-accurate CVSS v3.1
   engine (verified against FIRST.org reference vectors) and tagged to OWASP + MITRE.
4. **Safe by default.** Detection and reporting only. No exploitation, no
   persistence, and no silent system modification.

---

## 2. Component map

```
corvus.py                → primary entrypoint: the autonomous runner
                           (crawl, fingerprint, decide, schedule, verify, report)
corvus_core.py         → the engine core + classic interface:
    ├─ CVSS31            → CVSS v3.1 scoring + per-module presets
    ├─ TECH_SIGNATURES   → 85 technology fingerprints
    ├─ DEFAULT_CREDS_DB  → 130 default-credential pairs
    ├─ ScanContext       → baseline cache, dedup, adaptive rate control
    ├─ Finding / make_finding → finding model (+CVSS, OWASP, MITRE)
    ├─ module_* (×100)   → detection modules (OWASP Web + API Top 10)
    ├─ tool_*  (×58)     → external-tool integrations (optional)
    └─ save_* reporters  → JSON · HTML · CSV · SARIF · Markdown
corvus/                → the decision-engine package
    ├─ engine.py         → expected-value scheduler + fingerprint gating
    ├─ state.py          → ScanState: everything learned about the target
    ├─ oast.py           → out-of-band callback listener
    ├─ profiles.py       → Stealth / Balanced / Aggressive
    ├─ asynccore.py      → throughput accelerator (optional)
    └─ plugins.py        → third-party module loading
plugins/                 → drop-in community modules
tests/                   → unit + live integration suite
```

---

## 3. Scan lifecycle

```
seed URL
   │
   ▼
recon + fingerprint ──▶ ScanState  (server, tech stack, endpoints, params)
   │                        │
   │                        ▼
   │                 Decision engine
   │                 for each candidate module:
   │                   value = (cvss_weight · confidence_prior · budget_factor) / cost
   │                   skip if fingerprint rules it out
   │                        │
   │                        ▼ (highest value first)
   │                 run module ──▶ multi-gate confirmation ──▶ Finding?
   │                        │                                     │
   │                        ▼                                     ▼
   │                 update ScanState  ◀── new endpoints/params ──┘
   │                        │
   └────────────────────────┘  repeat until request budget exhausted
                            │
                            ▼
                    aggregate + score + write report
```

The loop is what makes CORVUS *autonomous*: findings feed new work back into the
state (a discovered parameter becomes a new injection candidate), and the engine
keeps choosing the highest-value remaining action rather than marching through a
static list.

---

## 4. The decision engine

Implemented in `corvus/engine.py`. Each module is registered as a `ModuleSpec`
with a cost, a confidence prior, a CVSS weight, and a fingerprint predicate.

```
value(spec) = spec.cvss_weight × spec.confidence_prior × budget_factor
              ────────────────────────────────────────────────────────
                                    spec.cost
```

- **Fingerprint gating** — a WordPress-specific module never runs against a target
  that didn't fingerprint as WordPress, so budget isn't wasted.
- **Budget factor** decays as the request budget is consumed, biasing early spend
  toward high-certainty, high-impact checks.
- **Profiles** (`corvus/profiles.py`) scale cost/aggression: Stealth throttles
  and narrows; Aggressive widens payload sets and parallelism.

---

## 5. Multi-gate confirmation (why false positives stay low)

Each detection module must pass several independent gates before it emits a
finding. Two worked examples:

**Error-based SQL injection** (`module_sqli`)
1. Establish a stable baseline (skip if the page is highly dynamic).
2. Baseline must **not** already contain a DB-error signature.
3. Inject; the response must differ from baseline.
4. A database error pattern (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/DB2) must appear.
5. The matched error must not sit inside an HTML/JS comment.
   → only then: Critical finding with the exact DB engine and payload as evidence.

**Reflected XSS** (`module_xss`)
1. A unique canary must be **absent** from the baseline.
2. A benign markup probe determines whether the app HTML-encodes markup (if it
   does, the parameter is safe → skip — this is the true false-positive guard).
3. Response `Content-Type` must be HTML.
4. The **raw payload (with its markup)** must appear verbatim — proving the markup
   survived unencoded.
5. The payload must contain real breakout characters (`< > " '`), so a benign
   plain-string reflection is never reported as XSS.
6. The reflection must not sit inside an HTML comment.

Blind classes (SSRF, blind RCE/XXE/SSTI) add a further gate: a genuine
**out-of-band callback** to the OAST listener, or no finding is raised.

---

## 6. Out-of-band verification (OAST)

`corvus/oast.py` runs a local callback listener (with optional interactsh
support). Payloads embed a unique callback token; a finding for a blind class is
only produced if that token is actually contacted out-of-band — eliminating the
"payload sent, therefore vulnerable" false positive that plagues naive scanners.

---

## 7. Scoring & tagging

`CVSS31` implements the CVSS v3.1 base-score algorithm (exploitability × impact,
scope handling, and "round-up" to one decimal). It is verified against 11 official
FIRST.org reference vectors in `tests/test_cvss.py`. Every finding created through
`make_finding()` is automatically assigned:

- `cvss_score`, `cvss_vector`, `cvss_rating` from the per-module preset,
- `owasp_id` / `owasp_name` (OWASP Top 10 2021),
- `mitre_id` / `mitre_technique` (ATT&CK).

---

## 8. Reporting

Findings serialize to five formats, each carrying full CVSS + OWASP + MITRE +
evidence:

| Format | Use |
|---|---|
| JSON | machine-readable / pipelines |
| HTML | human review |
| CSV | spreadsheets / triage |
| **SARIF 2.1.0** | GitHub code-scanning / IDE integration |
| Markdown | tickets / PR comments |

---

## 9. Extending CORVUS

Drop a module into `plugins/` exposing a `module_<name>(target, session)` function
that returns a list of findings via `make_finding(...)`. The plugin loader
(`corvus/plugins.py`) registers it; the engine schedules it like any built-in.
See `plugins/example_security_txt.py` for a template.
