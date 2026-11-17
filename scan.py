"""
models/scan.py — Scan + vulnerability persistence for Murphy.

A "scan" is one run of the scanners against one URL.
Each finding is stored in the `vulnerabilities` table linked by scan_id.
"""

from database.db import get_db_connection


# ---------- helpers ----------
def _row_to_dict(cursor, row):
    return {col[0]: val for col, val in zip(cursor.description, row)}


def _count_by_severity(findings):
    """Return (total, critical, high, medium, low) counts from a findings list."""
    total = len(findings)
    c = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical")
    h = sum(1 for f in findings if (f.get("severity") or "").lower() == "high")
    m = sum(1 for f in findings if (f.get("severity") or "").lower() == "medium")
    l = sum(1 for f in findings if (f.get("severity") or "").lower() == "low")
    return total, c, h, m, l


# ---------- public API ----------
def create_scan(user_id, target_url, status="running"):
    """
    Insert a new scan row. Returns the new scan_id, or None on failure.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO scans (user_id, target_url, scan_status, "
            "total_vulnerabilities, critical_count, high_count, "
            "medium_count, low_count) "
            "VALUES (%s, %s, %s, 0, 0, 0, 0, 0)",
            (user_id, target_url, status),
        )
        conn.commit()
        scan_id = cursor.lastrowid
    except Exception as e:
        print(f"[DB ERROR] create_scan failed: {e}")
        cursor.close()
        conn.close()
        return None
    cursor.close()
    conn.close()
    return scan_id


def save_vulnerabilities(scan_id, findings):
    """
    Bulk-insert a list of finding dicts, then update the parent scan's
    counts and mark it completed.
    """
    if not findings:
        # Nothing to save — just mark completed with zero counts
        update_scan_status(scan_id, "completed",
                           total=0, critical=0, high=0, medium=0, low=0)
        return True

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        for f in findings:
            cursor.execute(
                "INSERT INTO vulnerabilities "
                "(scan_id, vuln_type, severity, description, "
                "payload_used, affected_url, remediation) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    scan_id,
                    f.get("vuln_type", "Unknown"),
                    f.get("severity", "Info"),
                    f.get("description", ""),
                    f.get("payload_used", ""),
                    f.get("affected_url", ""),
                    f.get("remediation", ""),
                ),
            )
        conn.commit()

        total, c, h, m, l = _count_by_severity(findings)
        cursor.execute(
            "UPDATE scans SET scan_status = 'completed', "
            "total_vulnerabilities = %s, critical_count = %s, "
            "high_count = %s, medium_count = %s, low_count = %s "
            "WHERE id = %s",
            (total, c, h, m, l, scan_id),
        )
        conn.commit()
    except Exception as e:
        print(f"[DB ERROR] save_vulnerabilities failed: {e}")
        cursor.close()
        conn.close()
        return False

    cursor.close()
    conn.close()
    return True


def update_scan_status(scan_id, status, total=None, critical=None,
                       high=None, medium=None, low=None):
    """
    Update a scan's status and (optionally) its counts.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if total is None:
            cursor.execute(
                "UPDATE scans SET scan_status = %s WHERE id = %s",
                (status, scan_id),
            )
        else:
            cursor.execute(
                "UPDATE scans SET scan_status = %s, total_vulnerabilities = %s, "
                "critical_count = %s, high_count = %s, medium_count = %s, "
                "low_count = %s WHERE id = %s",
                (status, total, critical or 0, high or 0, medium or 0,
                 low or 0, scan_id),
            )
        conn.commit()
    except Exception as e:
        print(f"[DB ERROR] update_scan_status failed: {e}")
        cursor.close()
        conn.close()
        return False
    cursor.close()
    conn.close()
    return True


def get_scan(scan_id):
    """Return a scan as a dict, or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, user_id, target_url, scan_status, "
        "total_vulnerabilities, critical_count, high_count, "
        "medium_count, low_count, report_path, created_at "
        "FROM scans WHERE id = %s",
        (scan_id,),
    )
    row = cursor.fetchone()
    if not row:
        cursor.close()
        conn.close()
        return None
    scan = _row_to_dict(cursor, row)
    cursor.close()
    conn.close()
    return scan


def get_scan_history(user_id, limit=50):
    """Return the most recent scans for a given user, newest first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, user_id, target_url, scan_status, "
        "total_vulnerabilities, critical_count, high_count, "
        "medium_count, low_count, report_path, created_at "
        "FROM scans WHERE user_id = %s "
        "ORDER BY created_at DESC LIMIT %s",
        (user_id, limit),
    )
    rows = cursor.fetchall()
    scans = [_row_to_dict(cursor, r) for r in rows]
    cursor.close()
    conn.close()
    return scans


def get_vulnerabilities(scan_id):
    """Return all findings for a scan."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, scan_id, vuln_type, severity, description, "
        "payload_used, affected_url, remediation, created_at "
        "FROM vulnerabilities WHERE scan_id = %s ORDER BY id",
        (scan_id,),
    )
    rows = cursor.fetchall()
    vulns = [_row_to_dict(cursor, r) for r in rows]
    cursor.close()
    conn.close()
    return vulns


# ---------- self-test ----------
if __name__ == "__main__":
    from models.user import create_user

    # Make a temp user
    ok, msg, uid = create_user("scan_test", "scan@murphy.local", "password123")
    print(f"create_user: {ok} {msg} id={uid}")
    if not ok:
        # Already exists — look it up
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = 'scan_test'")
        uid = cur.fetchone()[0]
        cur.close()
        conn.close()
        print(f"using existing user id={uid}")

    # Create scan
    sid = create_scan(uid, "http://localhost/dvwa")
    print(f"create_scan -> scan_id={sid}")

    # Save a couple of findings
    fake = [
        {"vuln_type": "SQL Injection (Error-based)", "severity": "Critical",
         "description": "test", "payload_used": "'",
         "affected_url": "http://x/?id=1", "remediation": "fix it"},
        {"vuln_type": "Missing Security Header: CSP", "severity": "High",
         "description": "test2", "payload_used": "-",
         "affected_url": "http://x/", "remediation": "add CSP"},
    ]
    ok = save_vulnerabilities(sid, fake)
    print(f"save_vulnerabilities -> {ok}")

    # Read back
    s = get_scan(sid)
    print(f"get_scan -> {s['target_url']} status={s['scan_status']} "
          f"total={s['total_vulnerabilities']} crit={s['critical_count']} "
          f"high={s['high_count']}")

    vulns = get_vulnerabilities(sid)
    print(f"get_vulnerabilities -> {len(vulns)} rows")
    for v in vulns:
        print(f"   - {v['severity']}: {v['vuln_type']}")

    # Cleanup
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM vulnerabilities WHERE scan_id = %s", (sid,))
    cur.execute("DELETE FROM scans WHERE id = %s", (sid,))
    cur.execute("DELETE FROM users WHERE id = %s", (uid,))
    conn.commit()
    cur.close()
    conn.close()
    print("Cleaned up.")