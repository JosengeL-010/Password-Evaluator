from __future__ import annotations
from functools import lru_cache

import re
from dataclasses import dataclass

from .config import MIN_DICT_WORD_LEN, WORDLIST_PATH
_SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")


def _is_symbol(ch: str) -> bool:
    return bool(_SYMBOL_RE.match(ch))


def length(pw: str) -> int:
    return len(pw or "")


def count_upper(pw: str) -> int:
    return sum(1 for c in pw if c.isupper())


def count_lower(pw: str) -> int:
    return sum(1 for c in pw if c.islower())


def count_digit(pw: str) -> int:
    return sum(1 for c in pw if c.isdigit())


def count_symbol(pw: str) -> int:
    return sum(1 for c in pw if _is_symbol(c))


def has_upper(pw: str) -> int:
    return 1 if any(c.isupper() for c in pw) else 0


def has_lower(pw: str) -> int:
    return 1 if any(c.islower() for c in pw) else 0


def has_digit(pw: str) -> int:
    return 1 if any(c.isdigit() for c in pw) else 0


def has_symbol(pw: str) -> int:
    return 1 if any(_is_symbol(c) for c in pw) else 0


def starts_with_digit(pw: str) -> int:
    return 1 if (pw[:1].isdigit()) else 0


def ends_with_symbol(pw: str) -> int:
    return 1 if (len(pw) > 0 and _is_symbol(pw[-1])) else 0


def unique_chars(pw: str) -> int:
    return len(set(pw)) if pw else 0


def ascii_range(pw: str) -> int:
    if not pw:
        return 0
    codes = [ord(c) for c in pw]
    return max(codes) - min(codes)


def is_palindrome(pw: str) -> int:
    """Detect palindromes robustly (case-insensitive, ignores non-alphanumerics).

    Returns 1 if the normalized password is a palindrome and has length >= 4.
    """
    if not pw:
        return 0
    # normalize: keep only letters+digits, lowercase
    t = re.sub(r"[^A-Za-z0-9]", "", pw).lower()
    if len(t) < 3:
        return 0
    return 1 if t == t[::-1] else 0


def has_repeated_chars(pw: str) -> int:
    """Flags repeated characters.

    Heuristic: returns 1 if any character repeats consecutively (e.g., "aa") OR
    if the password has low diversity (unique/len <= 0.5).
    """
    if not pw:
        return 0
    if any(pw[i] == pw[i - 1] for i in range(1, len(pw))):
        return 1
    if len(pw) >= 6 and (unique_chars(pw) / len(pw)) <= 0.5:
        return 1
    return 0


def has_dictionary_word(pw: str) -> int:
    s = (pw or "").lower()
    # remove separators to catch "pass_word" -> "password"
    compact = re.sub(r"[^a-z0-9]", "", s)

    for w in _load_wordlist():
        if w in s or w in compact:
            return 1
    return 0


@lru_cache(maxsize=1)
def _load_wordlist() -> tuple[str, ...]:
    try:
        text = WORDLIST_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return tuple()
    words: list[str] = []
    for line in text.splitlines():
        w = line.strip().lower()
        if not w or w.startswith("#") or len(w) < MIN_DICT_WORD_LEN:
            continue
        words.append(w)
    return tuple(words)


def has_sequential(pw: str) -> int:
    """Detect simple ascending/descending sequences of length >= 3.

    Examples flagged: abc, cba, 123, 321, xyz, 987
    """
    if not pw or len(pw) < 3:
        return 0

    # Normalize letters to lower for alpha sequence checking
    p = pw.lower()

    def _is_seq(a: str, b: str, c: str) -> bool:
        try:
            oa, ob, oc = ord(a), ord(b), ord(c)
            return (ob - oa == 1 and oc - ob == 1) or (ob - oa == -1 and oc - ob == -1)
        except Exception:
            return False

    for i in range(len(p) - 2):
        a, b, c = p[i], p[i + 1], p[i + 2]
        # numeric or alphabetic only
        if (a.isdigit() and b.isdigit() and c.isdigit()) or (a.isalpha() and b.isalpha() and c.isalpha()):
            if _is_seq(a, b, c):
                return 1
    return 0


def compute_all(pw: str) -> dict:
    pw = pw or ""
    return {
        "Length": length(pw),
        "HasUpper": has_upper(pw),
        "HasLower": has_lower(pw),
        "HasDigit": has_digit(pw),
        "HasSymbol": has_symbol(pw),
        "CountUpper": count_upper(pw),
        "CountLower": count_lower(pw),
        "CountDigit": count_digit(pw),
        "CountSymbol": count_symbol(pw),
        "StartsWithDigit": starts_with_digit(pw),
        "EndsWithSymbol": ends_with_symbol(pw),
        "HasRepeatedChars": has_repeated_chars(pw),
        "HasDictionaryWord": has_dictionary_word(pw),
        "IsPalindrome": is_palindrome(pw),
        "HasSequential": has_sequential(pw),
        "UniqueChars": unique_chars(pw),
        "AsciiRange": ascii_range(pw),
    }
