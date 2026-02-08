from __future__ import annotations

import time
import hashlib
import secrets
import sqlite3
from typing import Any, Iterable

FEATURE_KEYS = [
    "Length","HasUpper","HasLower","HasDigit","HasSymbol",
    "CountUpper","CountLower","CountDigit","CountSymbol",
    "StartsWithDigit","EndsWithSymbol","HasRepeatedChars","HasDictionaryWord",
    "IsPalindrome","HasSequential","UniqueChars","AsciiRange",
]

def _mask_password(pw: str) -> str:
    """Return a non-sensitive, human-friendly mask for display/debug.

    Example: 'P@ssw0rd123' -> 'P*********23' (keeps first + last 2 chars when possible)
    """
    if not pw:
        return ""
    if len(pw) <= 3:
        return "*" * len(pw)
    first = pw[0]
    last2 = pw[-2:] if len(pw) >= 5 else pw[-1:]
    stars = "*" * max(1, len(pw) - (1 + len(last2)))
    return f"{first}{stars}{last2}"


def _salted_sha256(pw: str) -> tuple[str, str]:
    """Return (hash_hex, salt_hex) using SHA-256(salt || password)."""
    salt = secrets.token_bytes(16)
    h = hashlib.sha256(salt + pw.encode("utf-8")).hexdigest()
    return h, salt.hex()


def insert_entry(conn: sqlite3.Connection, password: str, tool: str | None, source: str = "user_input") -> int:
    """Insert a new entry storing only a salted hash (no plaintext password)."""
    now = int(time.time())
    pw_hash, salt_hex = _salted_sha256(password)
    pw_mask = _mask_password(password)
    cur = conn.execute(
        "INSERT INTO password_entries(password_hash, salt, password_mask, tool, source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (pw_hash, salt_hex, pw_mask, tool, source, now),
    )
    conn.commit()
    return int(cur.lastrowid)

def insert_features(conn: sqlite3.Connection, entry_id: int, feats: dict[str, Any], risk_index: float, auto_label: str) -> None:
    values = [entry_id] + [int(feats.get(k, 0)) for k in FEATURE_KEYS] + [float(risk_index), str(auto_label)]
    conn.execute(
        f"""INSERT INTO password_features(
            entry_id,{",".join(FEATURE_KEYS)},RiskIndex,AutoRiskLabel
        ) VALUES ({",".join(["?"]*(len(values)))})""",
        values,
    )
    conn.commit()

def fetch_joined(conn: sqlite3.Connection, limit: int = 1000) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT e.id, e.password_hash, e.password_mask, e.tool, e.source, e.created_at,
                  f.Length, f.HasUpper, f.HasLower, f.HasDigit, f.HasSymbol,
                  f.CountUpper, f.CountLower, f.CountDigit, f.CountSymbol,
                  f.StartsWithDigit, f.EndsWithSymbol, f.HasRepeatedChars, f.HasDictionaryWord,
                  f.IsPalindrome, f.HasSequential, f.UniqueChars, f.AsciiRange,
                  f.RiskIndex, f.AutoRiskLabel
           FROM password_entries e
           JOIN password_features f ON f.entry_id = e.id
           ORDER BY e.created_at DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
