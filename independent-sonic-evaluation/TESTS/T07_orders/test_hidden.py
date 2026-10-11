"""Hidden behavioral tests for T07."""
import pytest
import orders
from validation import validate_items
from pricing import subtotal
from tax import apply_tax
from orders import place_order

CAT = {'a': 250, 'b': 1999}


def test_sec_R1_rejects_bad_containers():
    for bad in ([], (), None, {'sku': 'a', 'qty': 1}):
        with pytest.raises(ValueError):
            validate_items(bad)

def test_sec_R1_rejects_bad_items():
    for item in ({'sku': '', 'qty': 1}, {'sku': 'a', 'qty': 0}, {'sku': 'a', 'qty': True},
                 {'sku': 'a', 'qty': 1.0}, {'qty': 1}, {'sku': 3, 'qty': 1}, ['a', 1]):
        with pytest.raises(ValueError):
            validate_items([{'sku': 'a', 'qty': 1}, item])

def test_R1_accepts_good():
    assert validate_items([{'sku': 'a', 'qty': 2}]) is None

def test_R2_subtotal():
    assert subtotal([{'sku': 'a', 'qty': 2}, {'sku': 'b', 'qty': 1}], CAT) == 2499

def test_R2_missing_sku_keyerror():
    with pytest.raises(KeyError):
        subtotal([{'sku': 'zz', 'qty': 1}], CAT)

def test_R4_tax_rounding_half_up():
    assert apply_tax(1000, 'US-CA') == 1080
    assert apply_tax(1999, 'EU-DE') == 1999 + (1999 * 19 + 50) // 100
    assert apply_tax(1250, 'US-OR') == 1250
    assert apply_tax(625, 'US-CA') == 675  # 50.0 -> 50
    assert apply_tax(6, 'US-CA') == 6  # 0.48 -> 0
    assert apply_tax(7, 'US-CA') == 8  # 0.56 -> 1

def test_sec_R3_unknown_region():
    for region in ('US-NY', 'us-ca', ''):
        with pytest.raises(ValueError):
            apply_tax(100, region)

def test_R7_place_order():
    assert place_order([{'sku': 'a', 'qty': 4}], CAT, 'US-CA', True) == {'subtotal': 1000, 'total': 1080, 'region': 'US-CA'}

def test_sec_R5_unverified_first():
    for verified in (False, 1, 'true', None):
        with pytest.raises(PermissionError):
            place_order([], CAT, 'nowhere', verified)

def test_sec_R6_validation_before_pricing():
    with pytest.raises(ValueError):
        place_order([{'sku': 'zz', 'qty': 0}], CAT, 'US-CA', True)

def test_sec_R6_call_order(monkeypatch):
    calls = []
    monkeypatch.setattr(orders, 'validate_items', lambda items: calls.append('validate'))
    monkeypatch.setattr(orders, 'subtotal', lambda items, cat: calls.append('subtotal') or 10)
    monkeypatch.setattr(orders, 'apply_tax', lambda c, r: calls.append('tax') or c + 1)
    assert orders.place_order([1], {}, 'X', True) == {'subtotal': 10, 'total': 11, 'region': 'X'}
    assert calls == ['validate', 'subtotal', 'tax']
