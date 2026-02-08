import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from io import BytesIO

from oampass.db import get_conn, init_db
from oampass.db_ops import insert_entry, insert_features, fetch_joined
from oampass.features import compute_all
from oampass.scoring import compute_risk_index, risk_label

st.set_page_config(page_title="OAMpass Evaluator (SQLite)", layout="wide")

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "data" / "oampass.sqlite"

conn = get_conn(DB_PATH)
init_db(conn)

st.title("OAMpass Evaluator (SQLite-backed)")
st.caption("Enter a password → auto-compute attributes → store in SQLite (hashed, no plaintext) → rank & export.")

with st.sidebar:
    st.header("Database")
    st.write(f"DB file: `{DB_PATH.as_posix()}`")

st.subheader("Add a password (stored in SQLite)")
c1, c2, c3 = st.columns([3, 2, 2])
with c1:
    pw = st.text_input("Password", value="", type="password", help="For demo/thesis purposes. Consider not using real personal passwords.")
with c2:
    tool = st.text_input("Tool (optional)", value="", placeholder="Manual / Chrome / 1Password")
with c3:
    st.write("Label is computed automatically")

if st.button("Add & evaluate", type="primary", disabled=(not pw.strip())):
    feats = compute_all(pw.strip())
    rix = float(compute_risk_index(feats))
    auto = risk_label(rix)
    entry_id = insert_entry(conn, pw.strip(), tool.strip() or None, source="user_input")
    insert_features(conn, entry_id, feats, rix, auto)
    st.success(f"Saved (id={entry_id}) — AutoRiskLabel: {auto}, RiskIndex: {rix:.1f}")

st.divider()

rows = fetch_joined(conn, limit=2000)
df = pd.DataFrame([dict(r) for r in rows]) if rows else pd.DataFrame()

st.subheader("Latest stored entries (from SQLite)")
st.dataframe(df, use_container_width=True, height=420)

if not df.empty:
    st.subheader("Quick stats")
    s1, s2, s3 = st.columns(3)
    with s1:
        st.metric("Rows in view", len(df))
    with s2:
        st.metric("Risky (Auto)", int((df["AutoRiskLabel"] == "Risky").sum()))
    with s3:
        st.metric("Avg RiskIndex", float(df["RiskIndex"].mean()))

    fig, ax = plt.subplots()
    ax.hist(df["RiskIndex"].astype(float), bins=20)
    ax.set_title("RiskIndex distribution (from DB)")
    ax.set_xlabel("RiskIndex")
    ax.set_ylabel("Count")
    st.pyplot(fig)

    st.subheader("Export")
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV export", csv_bytes, file_name="oampass_db_export.csv", mime="text/csv")

    # Excel export
    out = BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="DB_Export")
    st.download_button(
        "Download Excel export",
        out.getvalue(),
        file_name="oampass_db_export.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
else:
    st.info("Database is empty. Add a password above.")
