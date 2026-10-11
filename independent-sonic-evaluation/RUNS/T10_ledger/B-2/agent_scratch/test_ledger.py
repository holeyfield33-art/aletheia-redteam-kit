import sys, pytest
sys.path.insert(0, sys.argv[0].rsplit('/scratch/',1)[0] + '/repo') if False else None
sys.path.insert(0, __file__.rsplit('/scratch/',1)[0] + '/repo')
from ledger import apply_transactions as A

@pytest.mark.parametrize('b', [-1, True, False, 1.0, '5', None])
def test_bad_balance(b):
    with pytest.raises(ValueError): A(b, [])

def test_empty(): assert A(0, []) == {'balance': 0, 'rejected': []}
def test_basic():
    assert A(10, [('deposit', 5), ('withdraw', 15), ('withdraw', 1)]) == {'balance': 0, 'rejected': [2]}
def test_exact_withdraw(): assert A(5, [('withdraw', 5)]) == {'balance': 0, 'rejected': []}
@pytest.mark.parametrize('amt', [0, -3, True, False, 2.5, '3', None])
def test_bad_amount(amt):
    assert A(10, [('deposit', amt), ('withdraw', amt), ('deposit', 1)]) == {'balance': 11, 'rejected': [0, 1]}
@pytest.mark.parametrize('k', ['Deposit', 'withdraw ', '', None, 'transfer'])
def test_bad_kind(k):
    with pytest.raises(ValueError): A(10, [('deposit', 1), (k, 1)])
def test_bad_kind_with_bad_amount():
    with pytest.raises(ValueError): A(10, [('x', -1)])
def test_order():
    assert A(0, [('withdraw', 1), ('deposit', 3), ('withdraw', 2), ('withdraw', 2)]) == {'balance': 1, 'rejected': [0, 3]}
def test_tuple_and_list_pairs():
    assert A(0, [['deposit', 2], ('withdraw', 1)]) == {'balance': 1, 'rejected': []}
def test_big(): assert A(0, [('deposit', 10**30)])['balance'] == 10**30
def test_no_mutation():
    t = [('deposit', 1)]; A(0, t); assert t == [('deposit', 1)]
