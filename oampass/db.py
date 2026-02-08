from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_SQL = """
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

def get_conn(db_path: str | Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()
