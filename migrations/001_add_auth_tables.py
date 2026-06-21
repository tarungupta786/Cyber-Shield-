"""
Adds JWT auth tables to existing cybershield.db.
Safe to run multiple times (IF NOT EXISTS).
"""
import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "cybershield.db")


def run():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
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

    c.execute("""
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

    # Tracks when a user's sessions were bulk-revoked, so access tokens
    # issued before that timestamp can be rejected without a full blacklist.
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_security (
            user_id INTEGER PRIMARY KEY,
            sessions_revoked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("Migration 001: auth tables created (or already exist)")


if __name__ == "__main__":
    run()
