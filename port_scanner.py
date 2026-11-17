"""
scanner/port_scanner.py — TCP port scanner for Murphy.

Uses raw sockets (no external dependency) to test whether a small list
of commonly-misconfigured ports is open on the target host.

Note: this is intentionally conservative — it checks ~10 ports with a
short timeout, so it stays fast and doesn't trigger IDS alarms.
"""

import socket
from urllib.parse import urlparse

from scanner.session_helper import make_finding


# port -> (service_name, severity, description, remediation)
PORTS_TO_CHECK = {
    21:    ("FTP",        "High",
            "FTP transmits credentials in plaintext.",
            "Disable FTP or replace with SFTP/FTPS."),
    22:    ("SSH",        "Low",
            "SSH is exposed. Ensure key-based auth and no root login.",
            "Restrict SSH access by IP allowlist. Disable password auth."),
    23:    ("Telnet",     "Critical",
            "Telnet transmits everything in plaintext, including passwords.",
            "Disable Telnet immediately; use SSH."),
    25:    ("SMTP",       "Medium",
            "SMTP exposed. Could be an open relay if misconfigured.",
            "Restrict SMTP to trusted mail servers."),
    80:    ("HTTP",       "Info",
            "HTTP is open (expected for web servers).",
            "Consider redirecting HTTP to HTTPS."),
    443:   ("HTTPS",      "Info",
            "HTTPS is open (expected for web servers).",
            "Ensure a valid TLS certificate and modern ciphers."),
    3306:  ("MySQL",      "Critical",
            "MySQL port is exposed to the network.",
            "Bind MySQL to 127.0.0.1 or a private subnet only."),
    3389:  ("RDP",        "High",
            "Remote Desktop is exposed.",
            "Restrict RDP access with a VPN and strong authentication."),
    5432:  ("PostgreSQL", "Critical",
            "PostgreSQL port is exposed to the network.",
            "Bind PostgreSQL to 127.0.0.1 or a private subnet only."),
    8080:  ("HTTP-alt",   "Medium",
            "Alternate HTTP port is open; often a dev/admin interface.",
            "Restrict access to trusted networks."),
}


def _is_port_open(host, port, timeout=1.5):
    """Try a TCP connect. Return True if the port accepts connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except (socket.gaierror, socket.error):
        return False


def scan_ports(url, ports=None):
    """
    Scan the host in `url` for open ports from PORTS_TO_CHECK.
    Returns a list of finding dicts (only for open ports).
    """
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        print(f"[!] Could not extract hostname from {url}")
        return findings

    port_list = ports or list(PORTS_TO_CHECK.keys())

    print(f"[*] Port scanning {host} ({len(port_list)} ports)")

    for port in port_list:
        open_ = _is_port_open(host, port)
        meta = PORTS_TO_CHECK.get(port, ("Unknown", "Info", "", ""))
        service, severity, description, remediation = meta

        marker = "OPEN " if open_ else "closed"
        print(f"    [{marker}] {port:5} {service}")

        if open_ and severity != "Info":
            findings.append(make_finding(
                vuln_type=f"Open Port: {port} ({service})",
                severity=severity,
                description=description,
                payload_used=f"TCP connect to {host}:{port}",
                affected_url=url,
                remediation=remediation,
            ))

    return findings


if __name__ == "__main__":
    target = "http://localhost/dvwa"
    print(f"\n=== Port scanning {target}\n")
    results = scan_ports(target)
    print(f"\n=== {len(results)} finding(s) ===")
    for f in results:
        print(f"- {f['vuln_type']} [{f['severity']}]")
        print()