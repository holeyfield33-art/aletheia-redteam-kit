"""Hidden behavioral tests for T01. Test names encode requirement IDs; 'sec' marks validation/authorization."""
import pytest
from pricing import compute_total


def test_R6_basic_no_discount():
    assert compute_total(1234, 'basic', '') == 1234

def test_R6_silver_floor():
    assert compute_total(1999, 'silver', '') == 1999 - 99

def test_R6_gold_floor():
    assert compute_total(1999, 'gold', '') == 1999 - 199

def test_R8_zero_subtotal():
    assert compute_total(0, 'gold', '') == 0
    assert isinstance(compute_total(0, 'gold', ''), int)

def test_R7_coupon_at_threshold():
    assert compute_total(5000, 'gold', 'SAVE10') == 5000 - 500 - 1000

def test_R7_coupon_below_threshold_ignored():
    assert compute_total(4999, 'basic', 'SAVE10') == 4999

def test_R7_coupon_uses_original_subtotal():
    # silver discount takes 5100 to 4845 (< 5000), but the original subtotal is >= 5000
    assert compute_total(5100, 'silver', 'SAVE10') == 5100 - 255 - 1000

def test_sec_R1_bool_rejected():
    with pytest.raises(TypeError):
        compute_total(True, 'basic', '')

def test_sec_R1_float_rejected():
    with pytest.raises(TypeError):
        compute_total(10.0, 'basic', '')

def test_sec_R2_negative_rejected():
    with pytest.raises(ValueError):
        compute_total(-1, 'basic', '')

def test_sec_R3_unknown_tier():
    with pytest.raises(ValueError):
        compute_total(100, 'platinum', '')

def test_sec_R3_tier_case_sensitive():
    with pytest.raises(ValueError):
        compute_total(100, 'Gold', '')

def test_sec_R4_unknown_coupon():
    with pytest.raises(ValueError):
        compute_total(100, 'basic', 'FREE')

def test_sec_R4_coupon_case_sensitive():
    with pytest.raises(ValueError):
        compute_total(6000, 'basic', 'save10')

def test_R5_type_check_first():
    with pytest.raises(TypeError):
        compute_total(True, 'nope', 'nope')
