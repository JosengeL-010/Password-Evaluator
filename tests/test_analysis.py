import pandas as pd
from oampass.analysis import summarize

def test_summarize_sorts_rank_desc():
    df = pd.DataFrame({
        "Password": ["a","b","c"],
        "Length": [1,1,1],
        "HasUpper":[0,0,0],
        "HasLower":[1,1,1],
        "HasDigit":[0,0,0],
        "HasSymbol":[0,0,0],
        "CountUpper":[0,0,0],
        "CountLower":[1,1,1],
        "CountDigit":[0,0,0],
        "CountSymbol":[0,0,0],
        "StartsWithDigit":[0,0,0],
        "EndsWithSymbol":[0,0,0],
        "HasRepeatedChars":[0,0,0],
        "HasDictionaryWord":[0,0,0],
        "IsPalindrome":[0,0,0],
        "HasSequential":[0,0,0],
        "UniqueChars":[1,1,1],
        "AsciiRange":[0,0,0],
        "RiskIndex":[10, 90, 50],
        "Label":["safe","risky","risky"],
        "Tool":["Manual","Chrome","Manual"],
    })
    s = summarize(df)
    assert s.ranked.iloc[0]["RiskIndex"] == 90
    assert s.ranked.iloc[-1]["RiskIndex"] == 10
