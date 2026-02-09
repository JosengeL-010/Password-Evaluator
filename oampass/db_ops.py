import time
import hashlib
import secrets
from typing import Any

FEATURE_KEYS = [
    "Length","HasUpper","HasLower","HasDigit","HasSymbol",
    "CountUpper","CountLower","CountDigit","CountSymbol",
    "StartsWithDigit","EndsWithSymbol","HasRepeatedChars","HasDictionaryWord",
    "IsPalindrome","HasSequential","UniqueChars","AsciiRange",
]

def _is_sqlite(conn) -> bool:
    return conn.__class__.__module__.startswith("sqlite3")

def _mask_password(pw: str) -> str:
    if not pw:
        return ""
    if len(pw) <= 3:
        return "*" * len(pw)
    first = pw[0]
    last2 = pw[-2:] if len(pw) >= 5 else pw[-1:]
    stars = "*" * max(1, len(pw) - (1 + len(last2)))
    return f"{first}{stars}{last2}"

def _salted_sha256(pw: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    h = hashlib.sha256(salt + pw.encode("utf-8")).hexdigest()
    return h, salt.hex()

def insert_entry(conn, password: str, tool: str | None, source: str = "user_input") -> int:
    now = int(time.time())
    pw_hash, salt_hex = _salted_sha256(password)
    pw_mask = _mask_password(password)

    if _is_sqlite(conn):
        cur = conn.execute(
            "INSERT INTO password_entries(password_hash, salt, password_mask, tool, source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (pw_hash, salt_hex, pw_mask, tool, source, now),
        )
        conn.commit()
        return int(cur.lastrowid)

    # Postgres
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO password_entries(password_hash, salt, password_mask, tool, source, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (pw_hash, salt_hex, pw_mask, tool, source, now),
        )
        entry_id = cur.fetchone()[0]
    conn.commit()
    return int(entry_id)

def insert_features(conn, entry_id: int, feats: dict[str, Any], risk_index: float, auto_label: str) -> None:
    values = [entry_id] + [int(feats.get(k, 0)) for k in FEATURE_KEYS] + [float(risk_index), str(auto_label)]

    if _is_sqlite(conn):
        conn.execute(
            f"""INSERT INTO password_features(
                entry_id,{",".join(FEATURE_KEYS)},RiskIndex,AutoRiskLabel
            ) VALUES ({",".join(["?"]*(len(values)))})""",
            values,
        )
        conn.commit()
        return

    cols = ["entry_id"] + FEATURE_KEYS + ["RiskIndex", "AutoRiskLabel"]
    placeholders = ",".join(["%s"] * len(values))
    sql = f'INSERT INTO password_features({",".join(f""""{c}"""" if c[0].isupper() else c for c in cols)}) VALUES ({placeholders})'

    with conn.cursor() as cur:
        cur.execute(sql, values)
    conn.commit()

def fetch_joined(conn, limit: int = 1000):
    sql = """
    SELECT e.id, e.password_hash, e.password_mask, e.tool, e.source, e.created_at,
           f."Length", f."HasUpper", f."HasLower", f."HasDigit", f."HasSymbol",
           f."CountUpper", f."CountLower", f."CountDigit", f."CountSymbol",
           f."StartsWithDigit", f."EndsWithSymbol", f."HasRepeatedChars", f."HasDictionaryWord",
           f."IsPalindrome", f."HasSequential", f."UniqueChars", f."AsciiRange",
           f."RiskIndex", f."AutoRiskLabel"
    FROM password_entries e
    JOIN password_features f ON f.entry_id = e.id
    ORDER BY e.created_at DESC
    LIMIT {limit}
    """

    if _is_sqlite(conn):
        return conn.execute(sql.replace('"', ""), ()).fetchall()

    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
        # convert to list-of-dicts to match Streamlit display expectations
        colnames = [d[0] for d in cur.description]
        return [dict(zip(colnames, r)) for r in rows]
