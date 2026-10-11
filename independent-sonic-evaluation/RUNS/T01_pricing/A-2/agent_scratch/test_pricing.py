import sys, pytest
sys.path.insert(0, sys.argv[0] and __file__.rsplit('/scratch/',1)[0] + '/repo')
from pricing import compute_total as f

def test_types():
    for v in (True, False, 1.0, "100", None, [1]):
        with pytest.raises(TypeError): f(v, "basic", "")
    with pytest.raises(TypeError): f(True, "bad", "bad")
def test_neg():
    with pytest.raises(ValueError): f(-1, "basic", "")
    with pytest.raises(ValueError): f(-1, "bad", "bad")
    assert f(0, "gold", "SAVE10") == 0
def test_tier():
    for t in ("Gold", "", " gold", None, ["gold"], "platinum"):
        with pytest.raises(ValueError): f(100, t, "")
def test_coupon():
    for c in ("save10", " SAVE10", None, "X", ["SAVE10"]):
        with pytest.raises(ValueError): f(100, "basic", c)
def test_math():
    assert f(10000, "basic", "") == 10000
    assert f(10000, "silver", "") == 9500
    assert f(999, "silver", "") == 999 - 49
    assert f(999, "gold", "") == 999 - 99
    assert f(5000, "gold", "SAVE10") == 3500
    assert f(4999, "gold", "SAVE10") == 4999 - 499
    assert f(5000, "basic", "SAVE10") == 4000
    assert type(f(5000, "basic", "SAVE10")) is int
