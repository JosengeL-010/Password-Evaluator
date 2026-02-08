from oampass.features import is_palindrome, compute_all

def test_is_palindrome_basic():
    assert is_palindrome("level") == 1
    assert is_palindrome("Level") == 1
    assert is_palindrome("RaceCar") == 1

def test_is_palindrome_ignores_symbols():
    assert is_palindrome("level!!") == 1
    assert is_palindrome("ra#ce$car") == 1

def test_is_palindrome_too_short():
    assert is_palindrome("aa") == 0
    assert is_palindrome("") == 0

def test_compute_all_includes_flag():
    feats = compute_all("RaceCar")
    assert "IsPalindrome" in feats
    assert feats["IsPalindrome"] == 1
