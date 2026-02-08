# OAMpass Evaluator (SQLite Automation Artifact)

This repository is a small, reproducible automation tool for processing the **OAMpass v3** dataset.
It now uses **SQLite** for persistence (database file stored inside the `data/` folder).

## What it does (end-to-end)
- Stores password entries and computed attributes in **SQLite** (`data/oampass.sqlite`)
- Lets you **enter a password** → auto-compute attributes → compute RiskIndex → assign AutoRiskLabel (Safe/Medium/Risky)
- Lets you **import an Excel workbook** (e.g., your OAMpass v3) into the same database
- Shows a ranked table and basic charts in a Streamlit UI
- Exports results from the database to CSV / Excel

## Quick start (Windows)

### 1) Create venv + install
```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Run the app
```bat
streamlit run app.py
```

### 3) Where the database lives
- The SQLite file is created automatically at:
  - `./data/oampass.sqlite`

## Notes
- The password input field is for demo/thesis purposes. Avoid entering real personal passwords.
- If your Excel uses a different sheet name than `Raw`, change it in the sidebar before importing.
"# OAMPass-Evaluator" 
