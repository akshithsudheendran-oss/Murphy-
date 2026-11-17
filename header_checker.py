"""
scanner/header_checker.py - Checks security headers on a target URL.

Security headers are HTTP response headers that tell the browser how to
behave when handling the site. Missing headers = weak security posture.
"""
import requests
from urllib.parse import urlparse


# The security headers we check for and their importance
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Forces HTTPS connections. Prevents SSL-strip attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Restricts where scripts/styles can load from. Prevents XSS.",
        "remediation": "Add a strict CSP header, e.g. default-src 'self'.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Prevents clickjacking by blocking iframe embedding.",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Stops MIME-type sniffing. Prevents drive-by downloads.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer info is sent with requests.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
}


def check_headers(url):
    """
    Check a URL for missing security headers.
    Returns a dict: { url, status, missing: [...], present: [...] }
    Each finding in 'missing' has: type, severity, description, remediation
    """
    result = {
        "url": url,
        "status": "unknown",
        "missing": [],
        "present": [],
    }

    try:
        # Make the request with a short timeout
        response = requests.get(url, timeout=8, allow_redirects=True)
        headers = response.headers

        # Check each security header
        for header_name, meta in SECURITY_HEADERS.items():
            if header_name in headers:
                result["present"].append(header_name)
            else:
                result["missing"].append({
                    "type": "Missing Security Header: " + header_name,
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "remediation": meta["remediation"],
                    "affected_url": url,
                })

        result["status"] = "success"

    except requests.exceptions.Timeout:
        result["status"] = "timeout"
    except requests.exceptions.ConnectionError:
        result["status"] = "connection_error"
    except requests.exceptions.RequestException as e:
        result["status"] = "error: " + str(e)

    return result

# ---- Quick self-test ----
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    test_urls = [
        "https://example.com",
        "https://github.com",
        "https://httpbin.org",
    ]

    for test_url in test_urls:
        print("=" * 60)
        print("Scanning: " + test_url)
        result = check_headers(test_url)
        print("Status: " + result["status"])
        print("Present headers (" + str(len(result["present"])) + "):")
        for h in result["present"]:
            print("   - " + h)
        print("Missing headers (" + str(len(result["missing"])) + "):")
        for m in result["missing"]:
            print("   - " + m["type"] + "  [" + m["severity"] + "]")
        print("")