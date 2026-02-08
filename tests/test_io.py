from oampass.io import load_oampass_excel
from pathlib import Path

def test_load_oampass_excel_smoke():
    p = Path(__file__).resolve().parents[1] / "data" / "OAMpass_sample.xlsx"
    lr = load_oampass_excel(p)
    assert lr.df.shape[0] > 0
    assert "RiskIndex" in lr.df.columns
    assert lr.df["RiskIndex"].between(0, 100).all()
