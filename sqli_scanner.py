"""
scanner/sqli_scanner.py — SQL Injection scanner for Murphy.

Uses the shared session helper. Works against any URL with a query string;
automatically logs into DVWA if the URL is under localhost/dvwa.

Two detection techniques:
  1. Error-based  — regex on MySQL/PG/MSSQL/SQLite error signatures
  2. Boolean-based — compares result-table presence between true/false payloads
"""

import re
import requests
from urllib.parse import urlparse, parse_qs

from scanner.session_helper import (
    build_dvwa_session,
    inject_param,
    has_result_table,
    contains_sql_error,
    make_finding,
    DVWA_BASE,
)


# ---------- Payloads ----------
ERROR_PAYLOADS = [
    "'",
    '"',
    "1'",
    "1\"",
    "1' OR '1'='1",
    "') OR ('1'='1",
    "1 AND 1=1",
]

BOOLEAN_PAYLOADS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1",     "1 AND 1=2"),
    ("1' OR '1'='1",  "1' OR '1'='2"),
]


# ---------- helper ----------
def _do_request(session, url, param, payload, use_post):
    """
    Send one payload. If `use_post` is True, POST {param: payload, Submit:Submit}
    to the URL with the query string stripped. Otherwise GET with injected
    query string.
    Returns the requests response, or None on failure.
    """
    try:
        if use_post:
            post_url = url.split("?")[0]
            return session.post(
                post_url,
                data={param: payload, "Submit": "Submit"},
                timeout=10, allow_redirects=True,
            )
        else:
            get_url = inject_param(url, param, payload)
            return session.get(get_url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        print(f"    [!] request failed: {e}")
        return None


# ---------- main scan ----------
def scan_sqli(url, session=None, param=None):
    """
    Scan a URL for SQL injection.
    - If `param` is given, only test that one; else test all query params.
    - If url starts with DVWA_BASE, use a DVWA-authenticated session.
    Returns a list of finding dicts.
    """
    findings = []

    # Auto-attach a DVWA session for localhost targets
    if session is None:
        if url.startswith(DVWA_BASE):
            session = build_dvwa_session()
            if session is None:
                print("[!] Could not build DVWA session — aborting")
                return findings
        else:
            session = requests.Session()

    # Decide GET vs POST: DVWA drops GET query strings on redirect, so
    # we must POST for DVWA targets.
    use_post = url.startswith(DVWA_BASE)

    params = parse_qs(urlparse(url).query)
    if not params:
        print(f"[!] No GET parameters in {url}")
        return findings

    target_params = [param] if param else list(params.keys())

    for p in target_params:
        print(f"[*] Testing param '{p}' ({'POST' if use_post else 'GET'})")

        # ---------- Error-based ----------
        for payload in ERROR_PAYLOADS:
            r = _do_request(session, url, p, payload, use_post)
            if r is None:
                continue

            table = has_result_table(r.text)
            print(f"    [{payload!r:20}] status={r.status_code} "
                  f"len={len(r.text):5} table={table}")

            err = contains_sql_error(r.text)
            if err:
                findings.append(make_finding(
                    vuln_type="SQL Injection (Error-based)",
                    severity="Critical",
                    description=(
                        f"Parameter '{p}' is vulnerable to error-based SQLi. "
                        f"DB error signature matched: '{err[:80]}'."
                    ),
                    payload=payload,
                    affected_url=url,
                    remediation=(
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate user input into SQL strings. "
                        "Validate and whitelist input types."
                    ),
                ))
                print(f"    [+] Error-based SQLi confirmed via payload {payload!r}")
                break

        # ---------- Boolean-based ----------
        for true_p, false_p in BOOLEAN_PAYLOADS:
            r_t = _do_request(session, url, p, true_p, use_post)
            r_f = _do_request(session, url, p, false_p, use_post)
            if r_t is None or r_f is None:
                continue

            t_table = has_result_table(r_t.text)
            f_table = has_result_table(r_f.text)
            print(f"    [{true_p!r:22}] table={t_table} | "
                  f"[{false_p!r:22}] table={f_table}")

            if t_table and not f_table:
                findings.append(make_finding(
                    vuln_type="SQL Injection (Boolean-based blind)",
                    severity="High",
                    description=(
                        f"Parameter '{p}' shows boolean-based blind SQLi: "
                        f"true payload returns rows, false payload returns none."
                    ),
                    payload=f"{true_p}  vs  {false_p}",
                    affected_url=url,
                    remediation=(
                        "Use parameterized queries / prepared statements. "
                        "Do not rely on input sanitization alone; use an ORM."
                    ),
                ))
                print(f"    [+] Boolean-based SQLi confirmed on '{p}'")
                break

    return findings


# ---------- standalone test ----------
if __name__ == "__main__":
    target = ("http://localhost/dvwa/vulnerabilities/sqli/"
              "index.php?id=1&Submit=Submit")
    print(f"\n=== Scanning {target}\n")
    results = scan_sqli(target, param="id")
    print(f"\n=== {len(results)} finding(s) ===")
    for f in results:
        print(f"- {f['vuln_type']} [{f['severity']}]")
        print(f"  payload: {f['payload_used']}")
        print(f"  url:     {f['affected_url']}")
        print()