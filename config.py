"""
config.py — Loads environment variables from .env
Keeps secrets out of source code.
"""
import os
from dotenv import load_dotenv

# Load .env file into environment variables
load_dotenv()

# Database config
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "murphy_db")

# Flask config
SECRET_KEY = os.getenv("SECRET_KEY", "dev-fallback-secret")


def get_db_config():
    """Return a dict of DB config for mysql.connector."""
    return {
        "host": DB_HOST,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "database": DB_NAME,
    }