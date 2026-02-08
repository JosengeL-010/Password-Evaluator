from __future__ import annotations

from dataclasses import dataclass

from .config import DEFAULT_RISK_WEIGHTS, AUTO_RISK_LABEL_THRESHOLDS


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def compute_risk_index(row: dict, weights: dict | None = None) -> float:
    """Compute a deterministic RiskIndex in [0, 100].

    This is a transparent baseline model intended for recomputation mode.
    High values mean riskier/weaker passwords.

    If your dataset already contains RiskIndex from your thesis model, keep
    using it (default tool mode). Use recompute only when you want an
    end-to-end pipeline from raw passwords.
    """
    w = dict(DEFAULT_RISK_WEIGHTS)
    if weights:
        w.update(weights)

    risk = float(w["base"])

    # penalties: missing classes
    if int(row.get("HasUpper", 0)) == 0:
        risk += w["missing_upper"]
    if int(row.get("HasLower", 0)) == 0:
        risk += w["missing_lower"]
    if int(row.get("HasDigit", 0)) == 0:
        risk += w["missing_digit"]
    if int(row.get("HasSymbol", 0)) == 0:
        risk += w["missing_symbol"]

    # pattern penalties
    if int(row.get("HasDictionaryWord", 0)) == 1:
        risk += w["dictionary_word"]
    if int(row.get("HasSequential", 0)) == 1:
        risk += w["sequential"]
    if int(row.get("HasRepeatedChars", 0)) == 1:
        risk += w["repeated"]
    if int(row.get("IsPalindrome", 0)) == 1:
        risk += w["palindrome"]
    if int(row.get("StartsWithDigit", 0)) == 1:
        risk += w["startswith_digit"]
    if int(row.get("EndsWithSymbol", 0)) == 1:
        risk += w["endswith_symbol"]

    # credits: length and diversity reduce risk
    L = float(row.get("Length", 0) or 0)
    U = float(row.get("UniqueChars", 0) or 0)

    length_credit = clamp(L * float(w["length_credit_per_char"]), 0, float(w["length_credit_cap"]))
    unique_credit = clamp(U * float(w["unique_credit_per_char"]), 0, float(w["unique_credit_cap"]))

    risk -= (length_credit + unique_credit)

    return float(clamp(risk, 0, 100))


def risk_label(risk_index: float, thresholds: dict | None = None) -> str:
    """Map RiskIndex -> categorical label used by the demo UI.

    Defaults:
      - Risky:  >= 70
      - Medium: >= 40
      - Safe:   < 40
    """
    t = dict(AUTO_RISK_LABEL_THRESHOLDS)
    if thresholds:
        t.update(thresholds)

    x = float(risk_index)
    if x >= float(t["risky"]):
        return "Risky"
    if x >= float(t["medium"]):
        return "Medium"
    return "Safe"
