from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json
import pandas as pd

@dataclass(frozen=True)
class SummaryTables:
    ranked: pd.DataFrame
    by_tool: pd.DataFrame
    by_label: pd.DataFrame

def make_ranked(df: pd.DataFrame) -> pd.DataFrame:
    ranked = df.copy()
    ranked = ranked.sort_values(["RiskIndex", "Password"], ascending=[False, True]).reset_index(drop=True)
    ranked.insert(0, "Rank", ranked.index + 1)
    return ranked

def summarize(df: pd.DataFrame) -> SummaryTables:
    ranked = make_ranked(df)

    by_tool = (
        df.groupby("Tool", dropna=False)["RiskIndex"]
        .agg(count="count", mean="mean", median="median", min="min", max="max")
        .reset_index()
        .sort_values("mean", ascending=False)
    )

    by_label = (
        df.groupby("Label", dropna=False)["RiskIndex"]
        .agg(count="count", mean="mean", median="median", min="min", max="max")
        .reset_index()
        .sort_values("mean", ascending=False)
    )

    return SummaryTables(ranked=ranked, by_tool=by_tool, by_label=by_label)

def export_artifacts(summaries: SummaryTables, outdir: str | Path, run_log: dict) -> dict:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    ranked_path = out / "results_ranked.csv"
    tool_path = out / "summary_by_tool.csv"
    label_path = out / "summary_by_label.csv"
    log_path = out / "run_log.json"

    summaries.ranked.to_csv(ranked_path, index=False)
    summaries.by_tool.to_csv(tool_path, index=False)
    summaries.by_label.to_csv(label_path, index=False)

    with log_path.open("w", encoding="utf-8") as f:
        json.dump(run_log, f, indent=2, ensure_ascii=False)

    return {
        "ranked_csv": str(ranked_path),
        "summary_by_tool_csv": str(tool_path),
        "summary_by_label_csv": str(label_path),
        "run_log_json": str(log_path),
    }
