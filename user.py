"""
models/user.py — User model for Murphy.

Uses werkzeug.security for password hashing (ships with Flask).
All functions accept/return plain dicts so they're easy to serialize.
"""

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from database.db import get_db_connection


def _row_to_dict(cursor, row):
    """Convert a MySQL row into a dict using cursor column names."""
    return {col[0]: val for col, val in zip(cursor.description, row)}


def create_user(username, email, password):
    """
    Insert a new user. Returns (success, message, user_id or None).
    Validates username, email, and password strength server-side.
    """
    import re

    # --- Normalize ---
    username = (username or "").strip()
    email    = (email or "").strip().lower()
    password = password or ""

    # --- Username checks ---
    if not username:
        return False, "Username is required.", None
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be 3–30 characters.", None
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return False, "Username may only contain letters, numbers, '.', '_', '-'.", None

    # --- Email checks ---
    # RFC-ish: something@something.tld
    email_re = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    if not email:
        return False, "Email is required.", None
    if len(email) > 254:
        return False, "Email is too long.", None
    if not re.match(email_re, email):
        return False, "Enter a valid email address (e.g. name@example.com).", None

    # --- Password checks ---
    if len(password) < 8:
        return False, "Password must be at least 8 characters.", None
    if len(password) > 128:
        return False, "Password must be 128 characters or fewer.", None
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter.", None
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter.", None
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number.", None
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one symbol (!@#$%^&* etc.).", None
    if username.lower() in password.lower() or email.split("@")[0].lower() in password.lower():
        return False, "Password must not contain your username or email.", None

    # --- Duplicate check ---
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM users WHERE username = %s OR email = %s",
        (username, email),
    )
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return False, "Username or email already registered.", None

    # --- Hash & insert ---
    pw_hash = generate_password_hash(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) "
            "VALUES (%s, %s, %s)",
            (username, email, pw_hash),
        )
        conn.commit()
        user_id = cursor.lastrowid
    except Exception as e:
        cursor.close()
        conn.close()
        return False, f"Database error: {e}", None

    cursor.close()
    conn.close()
    return True, "User registered successfully.", user_id


def verify_user(username, password):
    """
    Return user dict if credentials match, else None.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, email, password_hash, created_at "
        "FROM users WHERE username = %s",
        (username,),
    )
    row = cursor.fetchone()

    if not row:
        cursor.close()
        conn.close()
        return None

    user = _row_to_dict(cursor, row)
    cursor.close()
    conn.close()

    if not check_password_hash(user["password_hash"], password):
        return None

    user.pop("password_hash", None)  # never expose the hash
    return user


def get_user_by_id(user_id):
    """Fetch a user by primary key. Never returns the password hash."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = %s",
        (user_id,),
    )
    row = cursor.fetchone()

    if not row:
        cursor.close()
        conn.close()
        return None

    user = _row_to_dict(cursor, row)
    cursor.close()
    conn.close()
    return user


# ---------- self-test ----------
if __name__ == "__main__":
    # Create test user
    ok, msg, uid = create_user("murphy_test", "test@murphy.local", "password123")
    print(f"create_user: ok={ok} msg={msg} id={uid}")

    # Verify correct password
    user = verify_user("murphy_test", "password123")
    print(f"verify_user (correct): {user}")

    # Verify wrong password
    user = verify_user("murphy_test", "wrongpass")
    print(f"verify_user (wrong):   {user}")

    # Cleanup
    if ok:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username = 'murphy_test'")
        conn.commit()
        cur.close()
        conn.close()
        print("Cleaned up test user.")