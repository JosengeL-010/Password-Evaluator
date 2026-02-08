from pathlib import Path
import tempfile

from oampass.db import get_conn, init_db
from oampass.db_ops import insert_entry, insert_features, fetch_joined
from oampass.features import compute_all
from oampass.scoring import compute_risk_index, risk_label

def test_db_insert_and_fetch():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "t.sqlite"
        conn = get_conn(db_path)
        init_db(conn)

        pw = "Abc123!@#"
        feats = compute_all(pw)
        rix = float(compute_risk_index(feats))
        auto = risk_label(rix)

        entry_id = insert_entry(conn, pw, tool="Manual", source="unit_test")
        insert_features(conn, entry_id, feats, rix, auto)

        rows = fetch_joined(conn, limit=10)
        assert len(rows) == 1
        row = dict(rows[0])
        # Plaintext password must never be stored.
        assert "password" not in row
        assert row["password_hash"]
        assert row["password_hash"] != pw
        assert row["password_mask"]
        assert row["RiskIndex"] == rix
        assert row["AutoRiskLabel"] in {"Safe", "Medium", "Risky"}
