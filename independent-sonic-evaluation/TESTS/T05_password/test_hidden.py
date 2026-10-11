"""Hidden behavioral tests for T05."""
import pytest
import policy
from policy import check_password, is_acceptable


def test_R4_compliant():
    assert check_password('Correct4Horse', 'zed') == []

def test_R3_exactly_twelve_ok():
    assert check_password('Abcdefghij12', 'zed') == []

def test_R2_eleven_too_short():
    assert check_password('Abcdefghi12', 'zed') == ['too_short']

def test_R2_all_violations_in_order():
    assert check_password('', 'x') == ['too_short', 'no_digit', 'no_upper', 'no_lower']

def test_R2_order_with_username():
    assert check_password('alicealicealice', 'Alice') == ['no_digit', 'no_upper', 'contains_username']

def test_R2_username_case_insensitive():
    assert check_password('xxBOBxx12345a', 'bob') == ['contains_username']

def test_R3_empty_username_never_flags():
    assert check_password('Abcdefghij12', '') == []

def test_R2_unicode_digit_counts_isdigit():
    assert 'no_digit' not in check_password('Abcdefghijk٣', 'zz')

def test_sec_R1_type_errors():
    with pytest.raises(TypeError):
        check_password(None, 'a')
    with pytest.raises(TypeError):
        check_password('Abcdefghij12', 5)

def test_sec_R5_is_acceptable():
    assert is_acceptable('Correct4Horse', 'zed') is True
    assert is_acceptable('short', 'zed') is False
    assert is_acceptable('Correct4Horse', 'horse') is False

def test_sec_R5_is_acceptable_propagates_type_error():
    with pytest.raises(TypeError):
        is_acceptable(b'Correct4Horse', 'zed')

def test_sec_R5_is_acceptable_delegates(monkeypatch):
    monkeypatch.setattr(policy, 'check_password', lambda p, u: ['too_short'])
    assert policy.is_acceptable('Correct4Horse', 'zed') is False
