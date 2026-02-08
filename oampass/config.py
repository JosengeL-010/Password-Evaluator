"""Project configuration.

The automation is designed to work with the provided OAMpass v3 workbook, where
most derived columns already exist.

To "go beyond", the tool can also operate in a recomputation mode where
attributes (and optionally RiskIndex) are computed directly from Password.

This keeps the project usable even if you export a smaller dataset containing
only Password/Tool/Label.
"""

from __future__ import annotations
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORDLIST_PATH = PROJECT_ROOT / "data" / "wordlist.txt"
MIN_DICT_WORD_LEN = 4
# Minimum schema to run the pipeline
MIN_REQUIRED_COLUMNS = [
    "Password",
]

# These are the columns expected in the OAMpass v3 'Raw' sheet.
# If present, the tool will use them; if missing and recompute is enabled,
# they will be computed.
OAMPASS_DERIVED_COLUMNS = [
    "Length",
    "HasUpper",
    "HasLower",
    "HasDigit",
    "HasSymbol",
    "CountUpper",
    "CountLower",
    "CountDigit",
    "CountSymbol",
    "StartsWithDigit",
    "EndsWithSymbol",
    "HasRepeatedChars",
    "HasDictionaryWord",
    "IsPalindrome",
    "HasSequential",
    "UniqueChars",
    "AsciiRange",
]

# Optional columns used for summaries
OPTIONAL_COLUMNS = [
    "Label",
    "Tool",
    "RiskIndex",
]

# A small, transparent default scoring model.
# High RiskIndex means weaker password (riskier).
DEFAULT_RISK_WEIGHTS = {
    # penalties for missing character classes
    "missing_upper": 12,
    "missing_lower": 12,
    "missing_digit": 18,
    "missing_symbol": 18,
    # pattern penalties
    "dictionary_word": 25,
    "sequential": 15,
    "repeated": 10,
    "palindrome": 10,
    "startswith_digit": 6,
    "endswith_symbol": 4,
    # length effect: each char reduces risk by this amount (capped)
    "length_credit_per_char": 2.5,
    "length_credit_cap": 40,
    # diversity effect: each additional unique char reduces risk (capped)
    "unique_credit_per_char": 1.0,
    "unique_credit_cap": 15,
    # base risk before credits/penalties
    "base": 85,
}

# A compact dictionary list for the built-in dictionary-word heuristic.
# You can extend this in code or (better) in a config file later.
COMMON_WEAK_WORDS = [
    "password",
    "pass",
    "admin",
    "welcome",
    "qwerty",
    "letmein",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "login",
    "abc",
    "user",
]


# Automatic risk label thresholds for the demo UI/CLI
AUTO_RISK_LABEL_THRESHOLDS = {
    'risky': 70.0,
    'medium': 40.0,
}
