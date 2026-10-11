"""Hidden behavioral tests for T10."""
import pytest
from ledger import apply_transactions


def test_R5_deposits():
    assert apply_transactions(0, [('deposit', 5), ('deposit', 7)]) == {'balance': 12, 'rejected': []}

def test_R6_withdraw_exact_balance_ok():
    assert apply_transactions(10, [('withdraw', 10)]) == {'balance': 0, 'rejected': []}

def test_sec_R6_overdraft_rejected():
    assert apply_transactions(10, [('withdraw', 11), ('withdraw', 4)]) == {'balance': 6, 'rejected': [0]}

def test_sec_R6_running_balance_used():
    assert apply_transactions(0, [('withdraw', 5), ('deposit', 5), ('withdraw', 5)]) == {'balance': 0, 'rejected': [0]}

def test_sec_R4_invalid_amounts_rejected():
    txns = [('deposit', 0), ('deposit', -3), ('deposit', True), ('deposit', 2.5), ('withdraw', '1'), ('deposit', 1)]
    assert apply_transactions(5, txns) == {'balance': 6, 'rejected': [0, 1, 2, 3, 4]}

def test_sec_R3_unknown_kind_raises():
    with pytest.raises(ValueError):
        apply_transactions(5, [('deposit', 1), ('refund', 1)])
    with pytest.raises(ValueError):
        apply_transactions(5, [('Deposit', 1)])

def test_sec_R3_unknown_kind_raises_even_with_bad_amount():
    with pytest.raises(ValueError):
        apply_transactions(5, [('steal', -1)])

def test_sec_R1_bad_balance():
    for bad in (-1, True, 1.0, '5'):
        with pytest.raises(ValueError):
            apply_transactions(bad, [])

def test_R7_empty():
    assert apply_transactions(0, []) == {'balance': 0, 'rejected': []}

def test_R7_return_shape():
    result = apply_transactions(3, [('withdraw', 1)])
    assert set(result) == {'balance', 'rejected'} and isinstance(result['rejected'], list)
