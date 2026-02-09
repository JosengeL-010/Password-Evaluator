from __future__ import annotations

from pathlib import Path

SCHEMA_SQLITE = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS password_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  password_mask TEXT,
  tool TEXT,
  source TEXT NOT NULL DEFAULT 'user_input',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS password_features (
  entry_id INTEGER PRIMARY KEY,
  Length INTEGER NOT NULL,
  HasUpper INTEGER NOT NULL,
  HasLower INTEGER NOT NULL,
  HasDigit INTEGER NOT NULL,
  HasSymbol INTEGER NOT NULL,
  CountUpper INTEGER NOT NULL,
  CountLower INTEGER NOT NULL,
  CountDigit INTEGER NOT NULL,
  CountSymbol INTEGER NOT NULL,
  StartsWithDigit INTEGER NOT NULL,
  EndsWithSymbol INTEGER NOT NULL,
  HasRepeatedChars INTEGER NOT NULL,
  HasDictionaryWord INTEGER NOT NULL,
  IsPalindrome INTEGER NOT NULL,
  HasSequential INTEGER NOT NULL,
  UniqueChars INTEGER NOT NULL,
  AsciiRange INTEGER NOT NULL,
  RiskIndex REAL NOT NULL,
  AutoRiskLabel TEXT NOT NULL,
  FOREIGN KEY(entry_id) REFERENCES password_entries(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_entries_created_at ON password_entries(created_at);
CREATE INDEX IF NOT EXISTS idx_features_risklabel ON password_features(AutoRiskLabel);
"""

def get_conn(db_path: str | Path):
    """
    If st.secrets["DATABASE_URL"] exists -> connect to Postgres (Supabase).
    Else -> connect to local SQLite.
    """
    try:
        import streamlit as st
        db_url = st.secrets.get("DATABASE_URL", "").strip()
    except Exception:
        db_url = ""

    if db_url.startswith("postgresql://") or db_url.startswith("postgres://"):
        import psycopg2
        # psycopg2 reads sslmode from the URL query string (e.g. ?sslmode=require)
        return psycopg2.connect(db_url)

    import sqlite3
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(conn) -> None:
    # Only initialize schema automatically for SQLite.
    # For Supabase/Postgres you already ran the SQL in the dashboard.
    if conn.__class__.__module__.startswith("sqlite3"):
        conn.executescript(SCHEMA_SQLITE)
        conn.commit()
