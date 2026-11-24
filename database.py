"""SQLite scan history for WebGuard."""
import sqlite3
from datetime import datetime

DB_PATH = "webguard.db"


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   scanned_at TEXT,
                   scan_type TEXT,
                   content TEXT,
                   score INTEGER,
                   category TEXT
               )"""
        )


def save_scan(scan_type, content, score, category):
    with _conn() as c:
        c.execute(
            "INSERT INTO scans (scanned_at, scan_type, content, score, category) VALUES (?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_type, content[:500], score, category),
        )


def get_history(limit=50):
    with _conn() as c:
        return c.execute(
            "SELECT scanned_at, scan_type, content, score, category FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


def clear_history():
    with _conn() as c:
        c.execute("DELETE FROM scans")
