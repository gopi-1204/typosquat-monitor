"""
db.py
SQLite storage and lifecycle management for detected typosquat candidates.
Supports triage status, analyst notes, multi-signal telemetry, and metrics summaries.
"""

import sqlite3
import os
from datetime import datetime, timezone

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "monitor.db")


def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables and performs idempotent schema migrations."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            decoded_domain TEXT DEFAULT NULL,
            matched_brand TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            is_live INTEGER DEFAULT NULL,
            ip_address TEXT DEFAULT NULL,
            has_mx_record INTEGER DEFAULT 0,
            ssl_issuer TEXT DEFAULT NULL,
            visual_similarity REAL DEFAULT NULL,
            has_login_form INTEGER DEFAULT NULL,
            suspicious_phrases TEXT DEFAULT NULL,
            risk_score REAL DEFAULT NULL,
            risk_level TEXT DEFAULT NULL,
            screenshot_path TEXT DEFAULT NULL,
            status TEXT DEFAULT 'new',
            analyst_notes TEXT DEFAULT NULL,
            takedown_report_path TEXT DEFAULT NULL
        )
    """)
    conn.commit()

    # Dynamic column migrations for existing databases
    cursor.execute("PRAGMA table_info(candidates)")
    existing_cols = {col["name"] for col in cursor.fetchall()}

    new_cols = {
        "ip_address": "TEXT DEFAULT NULL",
        "has_mx_record": "INTEGER DEFAULT 0",
        "ssl_issuer": "TEXT DEFAULT NULL",
        "suspicious_phrases": "TEXT DEFAULT NULL",
        "analyst_notes": "TEXT DEFAULT NULL",
        "takedown_report_path": "TEXT DEFAULT NULL"
    }

    for col_name, col_type in new_cols.items():
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE candidates ADD COLUMN {col_name} {col_type}")

    conn.commit()
    conn.close()


def insert_candidate(domain, matched_brand, decoded_domain=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO candidates (domain, decoded_domain, matched_brand, detected_at, status)
        VALUES (?, ?, ?, ?, 'new')
    """, (domain, decoded_domain, matched_brand, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    candidate_id = cursor.lastrowid
    conn.close()
    return candidate_id


def update_liveness(candidate_id, is_live, ip_address=None):
    conn = get_connection()
    cursor = conn.cursor()
    if ip_address:
        cursor.execute("UPDATE candidates SET is_live = ?, ip_address = ? WHERE id = ?",
                       (1 if is_live else 0, ip_address, candidate_id))
    else:
        cursor.execute("UPDATE candidates SET is_live = ? WHERE id = ?",
                       (1 if is_live else 0, candidate_id))
    conn.commit()
    conn.close()


def update_screenshot_path(candidate_id, path):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET screenshot_path = ? WHERE id = ?", (path, candidate_id))
    conn.commit()
    conn.close()


def update_visual_similarity(candidate_id, score):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET visual_similarity = ? WHERE id = ?", (score, candidate_id))
    conn.commit()
    conn.close()


def update_content_signals(candidate_id, has_login_form, suspicious_phrases=None):
    conn = get_connection()
    cursor = conn.cursor()
    phrases_str = ", ".join(suspicious_phrases) if isinstance(suspicious_phrases, list) else suspicious_phrases
    cursor.execute("""
        UPDATE candidates 
        SET has_login_form = ?, suspicious_phrases = COALESCE(?, suspicious_phrases)
        WHERE id = ?
    """, (1 if has_login_form else 0, phrases_str, candidate_id))
    conn.commit()
    conn.close()


def update_mail_and_ssl(candidate_id, has_mx, ssl_issuer):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE candidates 
        SET has_mx_record = ?, ssl_issuer = ?
        WHERE id = ?
    """, (1 if has_mx else 0, ssl_issuer, candidate_id))
    conn.commit()
    conn.close()


def update_risk_score(candidate_id, score, level):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET risk_score = ?, risk_level = ? WHERE id = ?", (score, level, candidate_id))
    conn.commit()
    conn.close()


def update_takedown_report(candidate_id, report_path):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET takedown_report_path = ? WHERE id = ?", (report_path, candidate_id))
    conn.commit()
    conn.close()


def update_status(candidate_id, status, notes=None):
    """
    Updates incident triage status:
    Valid statuses: 'new', 'investigating', 'takedown_requested', 'resolved', 'false_positive'
    """
    conn = get_connection()
    cursor = conn.cursor()
    if notes is not None:
        cursor.execute("UPDATE candidates SET status = ?, analyst_notes = ? WHERE id = ?", (status, notes, candidate_id))
    else:
        cursor.execute("UPDATE candidates SET status = ? WHERE id = ?", (status, candidate_id))
    conn.commit()
    conn.close()


def get_candidate_by_id(candidate_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_candidates(brand=None, risk_level=None, status=None, search=None):
    """Retrieves candidates with optional multi-parameter filtering."""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM candidates WHERE 1=1"
    params = []

    if brand:
        query += " AND matched_brand = ?"
        params.append(brand)

    if risk_level:
        query += " AND risk_level = ?"
        params.append(risk_level)

    if status:
        query += " AND status = ?"
        params.append(status)

    if search:
        query += " AND (domain LIKE ? OR decoded_domain LIKE ?)"
        like_search = f"%{search}%"
        params.extend([like_search, like_search])

    query += " ORDER BY risk_score DESC, detected_at DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_metrics_summary():
    """Calculates aggregate metrics for executive dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM candidates")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM candidates WHERE risk_level = 'HIGH'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM candidates WHERE risk_level = 'MEDIUM'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM candidates WHERE risk_level = 'LOW'")
    low = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM candidates WHERE status = 'takedown_requested'")
    takedowns = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM candidates WHERE status = 'resolved'")
    resolved = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM candidates WHERE risk_score IS NOT NULL")
    avg_score = cursor.fetchone()[0] or 0.0

    cursor.execute("SELECT COUNT(DISTINCT matched_brand) FROM candidates")
    brands_count = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "takedowns_active": takedowns,
        "resolved": resolved,
        "avg_risk_score": round(avg_score, 1),
        "brands_monitored": brands_count
    }


def delete_candidate(candidate_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM candidates WHERE id = ?", (candidate_id,))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized and migrated at {DB_PATH}")
    summary = get_metrics_summary()
    print(f"Metrics: {summary}")
