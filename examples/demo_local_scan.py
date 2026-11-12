#!/usr/bin/env python3
"""
CORVUS — self-contained demo (no external target required).

Spins up the bundled deliberately-vulnerable app on localhost and runs a handful
of real CORVUS detection modules against it, printing the findings with their
CVSS scores. This is a safe way to see CORVUS actually detect something without
scanning anyone else's system.

    python examples/demo_local_scan.py
"""
import os
import sys

# Make the repo root importable when run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "integration"))

import corvus_core as core          # noqa: E402
from vuln_server import VulnServer    # noqa: E402


def main():
    core.QUIET = True
    with VulnServer() as srv:
        base = srv.base_url
        sess = core.make_session()
        core._scan_ctx = core.ScanContext(base, sess)

        print(f"\n  CORVUS demo — scanning bundled vulnerable app at {base}\n")
        checks = [
            ("module_sqli",             base + "/item?id=1"),
            ("module_xss",              base + "/search?q=test"),
            ("module_open_redirect",    base + "/go?url=1"),
            ("module_sensitive_files",  base + "/"),
            ("module_security_headers", base + "/"),
        ]
        total = 0
        for modname, url in checks:
            findings = getattr(core, modname)(url, sess) or []
            total += len(findings)
            for f in findings:
                d = f.to_dict()
                print(f"  [{d['severity']:8s}] cvss={d['cvss_score']:<4} "
                      f"{f.title}  ({d['owasp_id']}/{d['mitre_id']})")

        print(f"\n  {total} findings. Every one carries a CVSS vector, OWASP id, "
              f"and MITRE technique.\n")


if __name__ == "__main__":
    main()
