from __future__ import annotations
import argparse
from datetime import datetime, timezone
from pathlib import Path

from .io import load_oampass_excel
from .analysis import summarize, export_artifacts

def main() -> int:
    ap = argparse.ArgumentParser(description="Process OAMpass v3 workbook and export ranked results + summaries.")
    ap.add_argument("--input", required=True, help="Path to OAMpass v3 Excel workbook (.xlsx)")
    ap.add_argument("--outdir", default="outputs", help="Output directory for artifacts")
    ap.add_argument(
        "--recompute-missing",
        action="store_true",
        help="Compute missing derived columns (Length, HasUpper, etc.) from Password.",
    )
    ap.add_argument(
        "--recompute-riskindex",
        action="store_true",
        help="Recompute RiskIndex from Password using the built-in baseline scoring model.",
    )
    args = ap.parse_args()

    lr = load_oampass_excel(
        args.input,
        recompute_missing=bool(args.recompute_missing or args.recompute_riskindex),
        recompute_riskindex=bool(args.recompute_riskindex),
    )
    summaries = summarize(lr.df)

    run_log = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "input_path": str(Path(args.input).resolve()),
        "source_sheet": lr.source_sheet,
        "dataset_sha256": lr.dataset_sha256,
        "rows": int(lr.df.shape[0]),
        "columns": list(lr.df.columns),
        "recompute_missing": bool(args.recompute_missing or args.recompute_riskindex),
        "recompute_riskindex": bool(args.recompute_riskindex),
    }

    paths = export_artifacts(summaries, args.outdir, run_log)
    print("Artifacts written:")
    for k, v in paths.items():
        print(f"- {k}: {v}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
