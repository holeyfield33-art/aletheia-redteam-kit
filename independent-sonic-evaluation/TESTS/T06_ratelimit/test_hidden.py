"""Hidden behavioral tests for T06."""
import pytest
from limiter import allow


def test_R4_first_request_allowed():
    s = {}
    assert allow(s, 'a', 100, 2, 10) is True
    assert s == {'a': [100]}

def test_sec_R5_limit_reached_denied_not_recorded():
    s = {'a': [95, 99]}
    assert allow(s, 'a', 100, 2, 10) is False
    assert s == {'a': [95, 99]}

def test_sec_R3_exact_boundary_expires():
    s = {'a': [90, 95]}
    assert allow(s, 'a', 100, 2, 10) is True
    assert s['a'] == [95, 100]

def test_R3_just_inside_window_counts():
    s = {'a': [91, 95]}
    assert allow(s, 'a', 100, 2, 10) is False
    assert s['a'] == [91, 95]

def test_R5_pruned_even_when_denied():
    s = {'a': [1, 96, 97]}
    assert allow(s, 'a', 100, 2, 10) is False
    assert s['a'] == [96, 97]

def test_R6_other_clients_untouched():
    other = [1, 2, 3]
    s = {'b': other}
    allow(s, 'a', 100, 1, 10)
    assert s['b'] is other and other == [1, 2, 3]

def test_R7_no_in_place_mutation():
    old = [95]
    s = {'a': old}
    assert allow(s, 'a', 100, 5, 10) is True
    assert old == [95]
    assert s['a'] == [95, 100]

def test_sec_R1_invalid_limit_or_window():
    s = {'a': [1]}
    for limit, window in ((0, 10), (-1, 10), (1, 0), (1, -5)):
        with pytest.raises(ValueError):
            allow(s, 'a', 100, limit, window)
    assert s == {'a': [1]}

def test_sec_R4_sequence():
    s = {}
    results = [allow(s, 'c', t, 3, 10) for t in (0, 1, 2, 3, 10, 11)]
    assert results == [True, True, True, False, True, True]
