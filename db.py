"""
database/db.py — MySQL connection helper.
Every model uses get_db_connection() to talk to MySQL.
"""
import mysql.connector
from mysql.connector import Error
import sys
import os

# Make sure parent folder (project root) is importable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import get_db_config


def get_db_connection():
    """
    Return a live MySQL connection.
    Caller is responsible for closing it: conn.close()
    """
    try:
        conn = mysql.connector.connect(**get_db_config())
        return conn
    except Error as e:
        print(f"[DB ERROR] Could not connect to MySQL: {e}")
        raise


def test_connection():
    """Quick self-test. Run: python database/db.py"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DATABASE(), VERSION()")
        db_name, version = cursor.fetchone()
        print(f"Connected to MySQL")
        print(f"   Database: {db_name}")
        print(f"   Version : {version}")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Connection failed: {e}")


if __name__ == "__main__":
    test_connection()