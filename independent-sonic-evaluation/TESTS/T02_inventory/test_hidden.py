"""Hidden behavioral tests for T02."""
import pytest
import inventory
from inventory import check_qty, reserve, release


def test_sec_R1_check_qty_bool():
    with pytest.raises(TypeError):
        check_qty(True)

def test_sec_R1_check_qty_float():
    with pytest.raises(TypeError):
        check_qty(1.0)

def test_sec_R1_check_qty_zero_and_negative():
    for bad in (0, -3):
        with pytest.raises(ValueError):
            check_qty(bad)

def test_R1_check_qty_ok_returns_none():
    assert check_qty(1) is None

def test_R5_reserve_decrements():
    stock = {'a': 5, 'b': 2}
    assert reserve(stock, 'a', 3) == 2
    assert stock == {'a': 2, 'b': 2}

def test_R5_reserve_exact_level():
    stock = {'a': 4}
    assert reserve(stock, 'a', 4) == 0
    assert stock == {'a': 0}

def test_sec_R4_insufficient_unchanged():
    stock = {'a': 4}
    with pytest.raises(ValueError):
        reserve(stock, 'a', 5)
    assert stock == {'a': 4}

def test_sec_R3_unknown_sku_reserve():
    stock = {'a': 4}
    with pytest.raises(KeyError):
        reserve(stock, 'z', 1)
    assert stock == {'a': 4}

def test_sec_R3_unknown_sku_release():
    stock = {'a': 4}
    with pytest.raises(KeyError):
        release(stock, 'z', 1)
    assert stock == {'a': 4}

def test_sec_R2_reserve_validates_qty_first():
    stock = {'a': 4}
    with pytest.raises(ValueError):
        reserve(stock, 'missing', 0)
    with pytest.raises(TypeError):
        reserve(stock, 'missing', True)
    assert stock == {'a': 4}

def test_sec_R2_release_validates_qty():
    stock = {'a': 4}
    with pytest.raises(ValueError):
        release(stock, 'a', -2)
    assert stock == {'a': 4}

def test_sec_R2_reserve_calls_check_qty(monkeypatch):
    seen = []
    original = inventory.check_qty
    monkeypatch.setattr(inventory, 'check_qty', lambda q: (seen.append(q), original(q))[1])
    inventory.reserve({'a': 3}, 'a', 1)
    inventory.release({'a': 3}, 'a', 1)
    assert seen == [1, 1]

def test_R6_release_increments():
    stock = {'a': 1, 'b': 9}
    assert release(stock, 'a', 4) == 5
    assert stock == {'a': 5, 'b': 9}
