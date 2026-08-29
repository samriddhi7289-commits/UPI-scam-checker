"""
Persistence layer for VPA check history.
Kept separate from rule_engine.py on purpose: rule_engine stays a pure,
stateless function of its input (easy to test, easy to explain).
This module is the only thing that touches storage/state.
"""

import sqlite3
import time
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "scan_history.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vpa_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vpa TEXT NOT NULL,
            amount REAL,
            risk_level TEXT,
            score INTEGER,
            timestamp REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vpa ON vpa_checks(vpa)")
    conn.commit()
    conn.close()


def log_vpa_check(vpa: str, amount, risk_level: str, score: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO vpa_checks (vpa, amount, risk_level, score, timestamp) VALUES (?, ?, ?, ?, ?)",
        (vpa.lower().strip(), amount, risk_level, score, time.time())
    )
    conn.commit()
    conn.close()


def get_micro_transaction_pattern(vpa: str, window_days: int = 30, amount_threshold: float = 10.0, min_count: int = 3):
    """
    Looks at this VPA's recent check history and flags a 'salami slicing'
    pattern: several small ('micro') amounts sent to the same VPA in a
    short window. This is a known real fraud tactic — small amounts stay
    under bank fraud-alert thresholds.

    Returns (count, total_amount) if the pattern is met, else (0, 0).
    """
    conn = sqlite3.connect(DB_PATH)
    cutoff = time.time() - (window_days * 86400)
    rows = conn.execute(
        """SELECT amount FROM vpa_checks
           WHERE vpa = ? AND timestamp >= ? AND amount IS NOT NULL AND amount <= ?""",
        (vpa.lower().strip(), cutoff, amount_threshold)
    ).fetchall()
    conn.close()

    count = len(rows)
    if count >= min_count:
        total = sum(r[0] for r in rows)
        return count, total
    return 0, 0


def get_vpa_check_count(vpa: str, window_days: int = 30):
    """Total number of times this VPA has been checked recently, regardless of amount."""
    conn = sqlite3.connect(DB_PATH)
    cutoff = time.time() - (window_days * 86400)
    row = conn.execute(
        "SELECT COUNT(*) FROM vpa_checks WHERE vpa = ? AND timestamp >= ?",
        (vpa.lower().strip(), cutoff)
    ).fetchone()
    conn.close()
    return row[0] if row else 0
