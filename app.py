"""
app.py — Murphy Web Vulnerability Scanner
"""

import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, jsonify,
)

from database.db import get_db_connection
from models.user import create_user, verify_user, get_user_by_id
from models.scan import (
    create_scan, save_vulnerabilities, get_scan,
    get_scan_history, get_vulnerabilities, update_scan_status,
)

# Scanners
from scanner.header_checker import check_headers
from scanner.sqli_scanner import scan_sqli
from scanner.xss_scanner import scan_xss
from scanner.port_scanner import scan_ports
from scanner.admin_finder import scan_admin_paths

# Reports
from reports.pdf_generator import generate_pdf, REPORTS_DIR


# ---------- app ----------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "murphy-dev-secret-change-in-production")


# ---------- auth helpers ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    """Return the logged-in user dict, or None."""
    uid = session.get("user_id")
    if not uid:
        return None
    return get_user_by_id(uid)


# ---------- context processor ----------
@app.context_processor
def inject_user():
    return {"current_user": current_user()}


# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    scans = get_scan_history(session["user_id"], limit=5)
    return render_template("scan.html", recent_scans=scans)


@app.route("/history")
@login_required
def history():
    scans = get_scan_history(session["user_id"], limit=100)
    return render_template("history.html", scans=scans)


@app.route("/results/<int:scan_id>")
@login_required
def results(scan_id):
    scan = get_scan(scan_id)
    if not scan or scan["user_id"] != session["user_id"]:
        flash("Scan not found.", "error")
        return redirect(url_for("dashboard"))
    vulns = get_vulnerabilities(scan_id)
    return render_template("results.html", scan=scan, vulnerabilities=vulns)


@app.route("/download/<int:scan_id>")
@login_required
def download_report(scan_id):
    scan = get_scan(scan_id)
    if not scan or scan["user_id"] != session["user_id"]:
        flash("Scan not found.", "error")
        return redirect(url_for("dashboard"))

    vulns = get_vulnerabilities(scan_id)
    pdf_path = os.path.join(REPORTS_DIR, f"murphy_report_scan_{scan_id}.pdf")

    if not os.path.exists(pdf_path):
        generate_pdf(scan, vulns, output_path=pdf_path)

    return send_file(pdf_path, as_attachment=True,
                     download_name=f"murphy_report_scan_{scan_id}.pdf")


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        ok, message, uid = create_user(username, email, password)
        if ok:
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash(message, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = verify_user(username, password)
        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


# ============================================================
# SCAN API
# ============================================================

@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    """
    Run all scanners against the target URL, save findings to the DB,
    and return the new scan_id.
    """
    data = request.get_json() or {}
    target_url = (data.get("targetUrl") or "").strip()

    if not target_url or not target_url.startswith(("http://", "https://")):
        return jsonify({"status": "error",
                        "message": "Enter a valid URL starting with http:// or https://"}), 400

    scan_id = create_scan(session["user_id"], target_url, status="running")
    if not scan_id:
        return jsonify({"status": "error",
                        "message": "Could not create scan record"}), 500

    # Run every scanner. Each returns a list of finding dicts.
    findings = []
    try:
        # 1. Security headers
        try:
            header_result = check_headers(target_url)
            for m in header_result.get("missing", []):
                findings.append({
                    "vuln_type":    m.get("type", "Missing Header"),
                    "severity":     m.get("severity", "Low"),
                    "description":  m.get("description", ""),
                    "payload_used": "-",
                    "affected_url": m.get("affected_url", target_url),
                    "remediation":  m.get("remediation", ""),
                })
        except Exception as e:
            print(f"[scan] header_checker error: {e}")

        # 2. SQL injection
        try:
            findings.extend(scan_sqli(target_url))
        except Exception as e:
            print(f"[scan] sqli error: {e}")

        # 3. XSS (only if there is at least one query parameter)
        if "?" in target_url and "=" in target_url:
            try:
                findings.extend(scan_xss(target_url))
            except Exception as e:
                print(f"[scan] xss error: {e}")

        # 4. Port scan
        try:
            findings.extend(scan_ports(target_url))
        except Exception as e:
            print(f"[scan] port error: {e}")

        # 5. Admin finder
        try:
            findings.extend(scan_admin_paths(target_url))
        except Exception as e:
            print(f"[scan] admin_finder error: {e}")

        save_vulnerabilities(scan_id, findings)
    except Exception as e:
        print(f"[scan] fatal: {e}")
        update_scan_status(scan_id, "failed")

    return jsonify({"status": "success", "scan_id": scan_id})


@app.route("/api/scan-status/<int:scan_id>")
@login_required
def api_scan_status(scan_id):
    """
    Since scanners run synchronously, this always reports completion.
    Kept for compatibility with scan.js.
    """
    scan = get_scan(scan_id)
    if not scan or scan["user_id"] != session["user_id"]:
        return jsonify({"status": "failed"}), 404
    return jsonify({
        "status":         scan["scan_status"],
        "progress":       100,
        "current_module": "Done",
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html",
                           error_message="Page not found (404)"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html",
                           error_message="Server error (500)"), 500


# ============================================================
if __name__ == "__main__":
    app.run(debug=True)