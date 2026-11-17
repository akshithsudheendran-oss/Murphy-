"""
scanner/admin_finder.py — Admin panel / sensitive-path finder for Murphy.

Probes a short list of common admin and configuration paths on the target
host, and reports any that return 200 OK (or 401/403, which still reveal
the path exists). Deliberately short list to stay fast and non-intrusive.
"""

import requests
from urllib.parse import urlparse, urljoin

from scanner.session_helper import make_finding


# path -> (severity, description, remediation)
ADMIN_PATHS = {
    "/admin":            ("High",   "Admin login panel is exposed.",
                         "Restrict admin paths by IP allowlist or VPN."),
    "/admin/":           ("High",   "Admin login panel is exposed.",
                         "Restrict admin paths by IP allowlist or VPN."),
    "/administrator":    ("High",   "Administrator login panel is exposed.",
                         "Restrict admin paths by IP allowlist or VPN."),
    "/login":            ("Low",    "Login page is publicly accessible.",
                         "Ensure login page has rate-limiting and MFA."),
    "/wp-admin":         ("High",   "WordPress admin panel is exposed.",
                         "Restrict /wp-admin by IP or use a security plugin."),
    "/wp-login.php":     ("High",   "WordPress login is exposed.",
                         "Restrict by IP. Enable rate-limiting + 2FA."),
    "/phpmyadmin":       ("Critical", "phpMyAdmin is exposed.",
                         "Remove phpMyAdmin from production or restrict by IP."),
    "/phpmyadmin/":      ("Critical", "phpMyAdmin is exposed.",
                         "Remove phpMyAdmin from production or restrict by IP."),
    "/.git/config":      ("Critical", "Git repository is publicly readable.",
                         "Block access to dotfiles at the web server level."),
    "/.env":             ("Critical", ".env file (secrets) is publicly readable.",
                         "Block dotfiles at the web server level."),
    "/backup.sql":       ("Critical", "Database backup is publicly downloadable.",
                         "Store backups outside the webroot."),
    "/config.php":       ("High",   "Configuration file is accessible.",
                         "Move config files outside the webroot."),
    "/server-status":    ("Medium", "Apache server-status page is exposed.",
                         "Restrict /server-status to localhost."),
    "/phpinfo.php":      ("Medium", "phpinfo() output is publicly visible.",
                         "Remove phpinfo files from production."),
}


def _probe(session, url):
    """Return status code, or None on failure."""
    try:
        r = session.head(url, timeout=6, allow_redirects=False)
        # Some servers reject HEAD; fall back to GET
        if r.status_code >= 400 and r.status_code != 401 and r.status_code != 403:
            r = session.get(url, timeout=6, allow_redirects=False)
        return r.status_code
    except requests.RequestException:
        return None


def scan_admin_paths(url, session=None):
    """
    Probe common admin / sensitive paths on the target host.
    Returns a list of finding dicts.
    """
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if session is None:
        session = requests.Session()
        session.headers.update({"User-Agent": "Murphy-Scanner/1.0"})

    print(f"[*] Probing {len(ADMIN_PATHS)} admin/sensitive paths on {base}")

    for path, (severity, description, remediation) in ADMIN_PATHS.items():
        probe_url = urljoin(base, path)
        status = _probe(session, probe_url)

        # Treat 200/401/403 as "exposed"
        exposed = status in (200, 401, 403)
        marker = f"HTTP {status}" if status else "no-response"
        print(f"    [{marker:12}] {path}")

        if exposed:
            findings.append(make_finding(
                vuln_type=f"Exposed Admin/Sensitive Path: {path}",
                severity=severity,
                description=description,
                payload_used=f"HEAD/GET {probe_url}",
                affected_url=probe_url,
                remediation=remediation,
            ))

    return findings


if __name__ == "__main__":
    target = "http://localhost/dvwa"
    print(f"\n=== Probing {target}\n")
    results = scan_admin_paths(target)
    print(f"\n=== {len(results)} finding(s) ===")
    for f in results:
        print(f"- {f['vuln_type']} [{f['severity']}]")
        print(f"  url: {f['affected_url']}")