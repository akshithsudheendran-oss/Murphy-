"""
scanner/session_helper.py — Shared session helpers for Murphy scanners.

Provides:
  - build_dvwa_session()   : login to DVWA, set security=low, return session
  - get_dvwa_session()     : cached singleton so we only login once per run
  - inject_param()         : replace a query param value in a URL
  - has_result_table()     : DVWA success indicator
  - contains_sql_error()   : match MySQL/PG/MSSQL/SQLite error signatures

Any scanner that needs to hit DVWA should import from here.
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ---------- DVWA config ----------
DVWA_BASE      = "http://localhost/dvwa"
DVWA_LOGIN_URL = f"{DVWA_BASE}/login.php"

# ---------- SQL error signatures (multi-DBMS) ----------
SQL_ERROR_PATTERNS = [
    r"You have an error in your SQL syntax",
    r"Warning:\s*mysqli?_",
    r"Fatal error.*mysqli_sql_exception",
    r"mysqli_sql_exception",
    r"check the manual that (corresponds to|fits) your MySQL server version",
    r"Unknown column .* in .where clause",
    r"SQL syntax.*MySQL",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"ODBC SQL Server Driver",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Oracle error",
    r"ORA-\d{5}",
    r"quoted string not properly terminated",
]


# ---------- session cache ----------
_SESSION_CACHE = {}


def build_dvwa_session(username="admin", password="password",
                       security="low", base=DVWA_BASE):
    """
    Log into DVWA with a requests.Session, set the security cookie,
    prime the session state (DVWA 302s on first hit to the SQLi page
    unless primed), and return the session.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Murphy-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml",
    })

    # 1. Get CSRF token
    try:
        r = session.get(f"{base}/login.php", timeout=10)
    except requests.RequestException as e:
        print(f"[!] DVWA unreachable at {base}: {e}")
        return None

    m = re.search(
        r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", r.text
    )
    user_token = m.group(1) if m else ""

    # 2. Login
    session.post(
        f"{base}/login.php",
        data={"username": username, "password": password,
              "Login": "Login", "user_token": user_token},
        allow_redirects=True, timeout=10,
    )

    # 3. Force DVWA server-side security level to LOW
    #    (Must be done via security.php — a cookie alone won't override
    #     a session that's already set to 'impossible' or 'high'.)
    session.cookies.set("security", security)

    # Open the security page to establish session
    sec_page = session.get(f"{base}/security.php", timeout=10,
                           allow_redirects=True)

    # Extract CSRF token from the security form, if present
    csrf_m = re.search(
        r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]",
        sec_page.text,
    )
    csrf_token = csrf_m.group(1) if csrf_m else ""

    # POST the security form to set it to LOW server-side
    post_data = {
        "security": security,
        "seclev_submit": "Submit",
    }
    if csrf_token:
        post_data["user_token"] = csrf_token
    session.post(
        f"{base}/security.php",
        data=post_data,
        allow_redirects=True, timeout=10,
    )

    # Re-set cookie in case DVWA cleared it during the POST
    session.cookies.set("security", security)

    # 5. Warm-up: hit SQLi page once so the next request isn't 302'd
    session.get(f"{base}/vulnerabilities/sqli/", timeout=10,
                allow_redirects=True)

    return session


def get_dvwa_session(base=DVWA_BASE):
    """
    Return a cached DVWA session; create one on first call.
    """
    if base not in _SESSION_CACHE or _SESSION_CACHE[base] is None:
        _SESSION_CACHE[base] = build_dvwa_session(base=base)
    return _SESSION_CACHE[base]


# ---------- helpers ----------
def inject_param(url, param, payload):
    """Return URL with `param` replaced by `payload`."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def has_result_table(html):
    """DVWA prints 'First name' / 'Surname' on a successful query."""
    return "First name" in html and "Surname" in html


def contains_sql_error(text):
    """Return the matching signature string, or None."""
    for pat in SQL_ERROR_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return pat
    return None


def make_finding(vuln_type=None, severity=None, description=None,
                 payload_used=None, affected_url=None, remediation=None,
                 **kwargs):
    """
    Uniform finding dict — matches the vulnerabilities table columns.
    Accepts keyword args (and tolerates a stray positional `vt`/`sev`
    from older callers via **kwargs).
    """
    # Backwards-compat: some callers pass positional (vt, sev, desc, payload, url, rem)
    if vuln_type is None and "vt" in kwargs:
        vuln_type = kwargs.pop("vt")
    if severity is None and "sev" in kwargs:
        severity = kwargs.pop("sev")
    if description is None and "desc" in kwargs:
        description = kwargs.pop("desc")
    if payload_used is None and "payload" in kwargs:
        payload_used = kwargs.pop("payload")
    if affected_url is None and "url" in kwargs:
        affected_url = kwargs.pop("url")
    if remediation is None and "rem" in kwargs:
        remediation = kwargs.pop("rem")

    return {
        "vuln_type":    vuln_type,
        "severity":     severity,
        "description":  description,
        "payload_used": payload_used,
        "affected_url": affected_url,
        "remediation":  remediation,
    }