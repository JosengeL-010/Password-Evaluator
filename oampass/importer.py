from __future__ import annotations

import pandas as pd
import sqlite3

from .features import compute_all
from .scoring import compute_risk_index, risk_label
from .db_ops import insert_entry, insert_features

def _find_column(cols: list[str], candidates: list[str]) -> str | None:
    low = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand.lower() in low:
            return low[cand.lower()]
    return None

def import_from_dataframe(conn: sqlite3.Connection, df: pd.DataFrame, source: str = "excel_import", recompute: bool = False) -> int:
    """Import rows from a DataFrame.
    Expects at least a password column. Optionally uses existing feature cols and RiskIndex.
    If recompute=True, always recompute features and RiskIndex.
    Returns number of imported rows.
    """
    cols = list(df.columns)
    pw_col = _find_column(cols, ["Password", "password", "pw", "Pass"])
    if not pw_col:
        raise ValueError("Could not find a Password column in the imported sheet.")

    tool_col = _find_column(cols, ["Tool", "tool"])
    # Manual labels are intentionally ignored in the SQLite-backed product to keep it objective.
    label_col = None
    risk_col = _find_column(cols, ["RiskIndex", "riskindex", "risk_index"])

    imported = 0
    for _, row in df.iterrows():
        pw = str(row.get(pw_col) or "").strip()
        if not pw:
            continue
        tool = str(row.get(tool_col)).strip() if tool_col and pd.notna(row.get(tool_col)) else None
        # Ignored by design.

        feats = compute_all(pw) if recompute else {}
        if not recompute:
            # If feature columns exist, take them; else compute
            needed = [
                "Length","HasUpper","HasLower","HasDigit","HasSymbol","CountUpper","CountLower","CountDigit","CountSymbol",
                "StartsWithDigit","EndsWithSymbol","HasRepeatedChars","HasDictionaryWord","IsPalindrome","HasSequential",
                "UniqueChars","AsciiRange"
            ]
            has_any = any((c in cols) for c in needed)
            if has_any:
                for k in needed:
                    if k in cols and pd.notna(row.get(k)):
                        feats[k] = int(row.get(k))
                # fill missing from compute
                missing = [k for k in needed if k not in feats]
                if missing:
                    computed = compute_all(pw)
                    for k in missing:
                        feats[k] = int(computed[k])
            else:
                feats = compute_all(pw)

        if (not recompute) and risk_col and pd.notna(row.get(risk_col)):
            rix = float(row.get(risk_col))
        else:
            rix = float(compute_risk_index(feats))
        auto = risk_label(rix)

        entry_id = insert_entry(conn, pw, tool, source=source)
        insert_features(conn, entry_id, feats, rix, auto)
        imported += 1

    return imported
