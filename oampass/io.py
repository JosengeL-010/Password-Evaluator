from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import hashlib
import pandas as pd

from .config import MIN_REQUIRED_COLUMNS, OPTIONAL_COLUMNS, OAMPASS_DERIVED_COLUMNS
from .features import compute_all
from .scoring import compute_risk_index

@dataclass(frozen=True)
class LoadResult:
    df: pd.DataFrame
    dataset_sha256: str
    source_sheet: str

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _normalize_boolish(s: pd.Series) -> pd.Series:
    # Excel sometimes stores booleans as True/False, 0/1, or blank.
    # Convert to 0/1 integers where applicable.
    mapping = {True: 1, False: 0, "TRUE": 1, "FALSE": 0, "True": 1, "False": 0}
    out = s.map(mapping).where(~s.isna(), s)
    return pd.to_numeric(out, errors="ignore")

def load_oampass_excel(path: str | Path, *, recompute_missing: bool = False, recompute_riskindex: bool = False) -> LoadResult:
    """Load an OAMpass workbook and return the evaluation table.

    Strategy:
    - Prefer sheet named 'Raw' (it contains Password + attributes + RiskIndex + Label + Tool)
    - Fall back to other sheets if needed.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)

    xls = pd.ExcelFile(p)
    sheet = "Raw" if "Raw" in xls.sheet_names else xls.sheet_names[0]

    # Raw has a decorative first row; the true headers are on row 2 (0-indexed header=1),
    # and then the first data row repeats the column names.
    df = pd.read_excel(p, sheet_name=sheet, header=1)
    if df.shape[0] < 2:
        raise ValueError("Sheet is too small to parse as OAMpass Raw.")

    # Row 0 contains the true header names (Password, Length, ...)
    header_row = df.iloc[0].tolist()
    df = df.iloc[1:].reset_index(drop=True)
    df.columns = header_row

    # Drop completely empty columns (the first column in Raw is empty in the provided file)
    df = df.loc[:, [c for c in df.columns if str(c).strip().lower() != "nan"]]

    # Basic cleaning
    for col in df.columns:
        if col in ("Password", "Label", "Tool"):
            df[col] = df[col].astype(str).str.strip()
        else:
            df[col] = _normalize_boolish(df[col])

    # Drop empty placeholder rows (Excel often yields 'nan' strings)
    df = df[df["Password"].astype(str).str.strip().ne("")].copy()
    df = df[df["Password"].astype(str).str.lower().ne("nan")].copy()

    # Minimum schema validation
    missing_min = [c for c in MIN_REQUIRED_COLUMNS if c not in df.columns]
    if missing_min:
        raise ValueError(f"Missing required columns: {missing_min}")

    # Ensure optional columns exist so the rest of the pipeline can run
    for c in OPTIONAL_COLUMNS:
        if c not in df.columns:
            df[c] = "" if c in ("Label", "Tool") else pd.NA

    # If requested, compute derived attributes when missing.
    if recompute_missing:
        for col in OAMPASS_DERIVED_COLUMNS:
            if col not in df.columns:
                df[col] = pd.NA

        # Fill derived columns row-by-row (deterministic)
        derived_rows = df["Password"].astype(str).fillna("").map(compute_all)
        derived_df = pd.DataFrame(list(derived_rows.values))
        for col in OAMPASS_DERIVED_COLUMNS:
            # Only overwrite missing/NA columns or NA values
            if col not in df.columns:
                df[col] = derived_df[col]
            else:
                df[col] = df[col].where(~df[col].isna(), derived_df[col])

    # RiskIndex handling
    if "RiskIndex" not in df.columns:
        df["RiskIndex"] = pd.NA

    if recompute_riskindex:
        # Require derived columns (compute if needed)
        if not recompute_missing:
            # compute derived attributes into missing cells
            for col in OAMPASS_DERIVED_COLUMNS:
                if col not in df.columns:
                    raise ValueError(
                        "RiskIndex recomputation requires derived columns. "
                        "Run with recompute_missing=True or provide OAMpass-derived columns."
                    )
        df["RiskIndex"] = df.apply(lambda r: compute_risk_index(r.to_dict()), axis=1)

    # Type enforcement (lightweight) if available
    if "RiskIndex" in df.columns:
        df["RiskIndex"] = pd.to_numeric(df["RiskIndex"], errors="coerce")
    if "Length" in df.columns:
        df["Length"] = pd.to_numeric(df["Length"], errors="coerce")

    # Drop rows without RiskIndex unless we recomputed it
    if not recompute_riskindex:
        df = df[~df["RiskIndex"].isna()].copy()

    # If RiskIndex is still missing, fail: ranking needs it
    if df.empty or df["RiskIndex"].isna().all():
        raise ValueError(
            "RiskIndex is missing/empty. Provide RiskIndex in the input, or run with --recompute-riskindex."
        )

    return LoadResult(df=df, dataset_sha256=_sha256_file(p), source_sheet=sheet)
