"""
scanner/xss_scanner.py — Reflected Cross-Site Scripting scanner for Murphy.

Injects unique XSS payloads into each GET parameter and checks whether the
payload is reflected unescaped in the response body.

Works against any URL with a query string; auto-authenticates to DVWA.
"""

import re
import requests
from urllib.parse import urlparse, parse_qs

from scanner.session_helper import (
    build_dvwa_session,
    inject_param,
    make_finding,
    DVWA_BASE,
)


# Payloads: (raw_payload, regex_to_detect_in_response)
# We use a unique marker so we only detect OUR injected script,
# not other scripts already on the page.
MARKER = "mrfy_xss_9x7"

XSS_PAYLOADS = [
    (f"<script>alert('{MARKER}')</script>",
     rf"<script>\s*alert\(\s*['\"]{MARKER}['\"]\s*\)\s*</script>"),

    (f"\"><script>alert('{MARKER}')</script>",
     rf"<script>\s*alert\(\s*['\"]{MARKER}['\"]\s*\)\s*</script>"),

    (f"'><img src=x onerror=alert('{MARKER}')>",
     rf"<img[^>]+onerror\s*=\s*alert\(\s*['\"]?{MARKER}"),

    (f"<svg/onload=alert('{MARKER}')>",
     rf"<svg[^>]*onload\s*=\s*alert\(\s*['\"]?{MARKER}"),
]


def _payload_reflected(html, regex):
    """Return True if the raw payload pattern appears unescaped."""
    return re.search(regex, html, re.IGNORECASE) is not None


def scan_xss(url, session=None, param=None):
    """
    Scan `url` for reflected XSS.
    Returns list of finding dicts.
    """
    findings = []

    # session handling
    if session is None:
        if url.startswith(DVWA_BASE):
            session = build_dvwa_session()
            if session is None:
                print("[!] Could not build DVWA session — aborting")
                return findings
        else:
            session = requests.Session()

    params = parse_qs(urlparse(url).query)
    if not params:
        print(f"[!] No GET parameters in {url}")
        return findings

    target_params = [param] if param else list(params.keys())

    for p in target_params:
        print(f"[*] Testing param '{p}' for reflected XSS")

        for payload, regex in XSS_PAYLOADS:
            test_url = inject_param(url, p, payload)
            try:
                r = session.get(test_url, timeout=10, allow_redirects=True)
            except requests.RequestException as e:
                print(f"    [!] request failed: {e}")
                continue

            reflected_raw = _payload_reflected(r.text, regex)
            print(f"    [{payload[:40]!r:45}] "
                  f"status={r.status_code} reflected={reflected_raw}")

            if reflected_raw:
                findings.append(make_finding(
                    vuln_type="Reflected Cross-Site Scripting (XSS)",
                    severity="High",
                    description=(
                        f"Parameter '{p}' reflects unescaped user input. "
                        f"Injected script tag was found verbatim in the "
                        f"response body."
                    ),
                    payload=payload,
                    affected_url=test_url,
                    remediation=(
                        "HTML-encode all user-controlled output. Use a "
                        "templating engine with auto-escaping enabled. "
                        "Deploy a Content-Security-Policy header."
                    ),
                ))
                print(f"    [+] XSS confirmed on '{p}' with {payload[:40]!r}")
                break

    return findings


if __name__ == "__main__":
    # DVWA reflected XSS page: ?name=<value>
    target = "http://localhost/dvwa/vulnerabilities/xss_r/?name=test"
    print(f"\n=== Scanning {target}\n")
    results = scan_xss(target, param="name")
    print(f"\n=== {len(results)} finding(s) ===")
    for f in results:
        print(f"- {f['vuln_type']} [{f['severity']}]")
        print(f"  payload: {f['payload_used']}")
        print(f"  url:     {f['affected_url']}")
        print()