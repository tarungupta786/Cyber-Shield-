import sqlite3
from datetime import datetime
from database import get_db_connection


def init_auth_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            replaced_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL,
            ip_address TEXT DEFAULT '',
            details TEXT DEFAULT '',
            timestamp TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_security (
            user_id INTEGER PRIMARY KEY,
            sessions_revoked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


def store_refresh_token(jti, user_id, token_hash, expires_at):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO refresh_tokens (jti, user_id, token_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (jti, user_id, token_hash, expires_at, now))
    conn.commit()
    conn.close()


def get_refresh_token(jti):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM refresh_tokens WHERE jti = ?", (jti,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def revoke_token(jti):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?", (jti,))
    conn.commit()
    conn.close()


def revoke_all_user_tokens(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def mark_replaced(old_jti, new_jti):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE refresh_tokens SET replaced_by = ?, revoked = 1 WHERE jti = ?",
        (new_jti, old_jti)
    )
    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def set_sessions_revoked(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO user_security (user_id, sessions_revoked_at) VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET sessions_revoked_at = ?
    """, (user_id, now, now))
    conn.commit()
    conn.close()


def get_sessions_revoked_at(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sessions_revoked_at FROM user_security WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row and row["sessions_revoked_at"]:
        return datetime.strptime(row["sessions_revoked_at"], "%Y-%m-%d %H:%M:%S")
    return None


def log_auth_event(user_id, username, event_type, ip_address="", details=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO auth_audit_log (user_id, username, event_type, ip_address, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, username, event_type, ip_address, details, ts))
    conn.commit()
    conn.close()


def get_auth_logs(limit=200):
    import pandas as pd
    conn = get_db_connection()
    df = pd.read_sql_query(
        "SELECT * FROM auth_audit_log ORDER BY timestamp DESC LIMIT ?",
        conn, params=(limit,)
    )
    conn.close()
    return df


def cleanup_expired_tokens():
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "DELETE FROM refresh_tokens WHERE expires_at < ? AND revoked = 1", (now,)
    )
    conn.commit()
    conn.close()


init_auth_tables()
