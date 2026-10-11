"""Hidden behavioral tests for T04."""
import pytest
from stats import summarize


def test_R5_basic():
    assert summarize([1, 2, 3, 4]) == {'count': 4, 'min': 1, 'max': 4, 'mean': 2.5}

def test_R5_rounding():
    assert summarize([1, 1, 2])['mean'] == round(4 / 3, 2)

def test_R5_floats_and_negatives_unrounded_extremes():
    r = summarize([-1.234, 5.678, 0])
    assert r['min'] == -1.234 and r['max'] == 5.678 and r['count'] == 3
    assert r['mean'] == round((-1.234 + 5.678) / 3, 2)

def test_R5_exact_keys():
    assert set(summarize([7])) == {'count', 'min', 'max', 'mean'}

def test_R2_none_skipped():
    assert summarize([None, 10, None, 20]) == {'count': 2, 'min': 10, 'max': 20, 'mean': 15}

def test_sec_R1_tuple_rejected():
    with pytest.raises(TypeError):
        summarize((1, 2))

def test_sec_R1_none_rejected():
    with pytest.raises(TypeError):
        summarize(None)

def test_sec_R3_bool_rejected():
    with pytest.raises(TypeError):
        summarize([1, True])

def test_sec_R3_string_rejected():
    with pytest.raises(TypeError):
        summarize([1, '3'])

def test_sec_R3_nested_rejected_even_after_none():
    with pytest.raises(TypeError):
        summarize([None, [1]])

def test_sec_R4_empty():
    with pytest.raises(ValueError):
        summarize([])

def test_sec_R4_all_none():
    with pytest.raises(ValueError):
        summarize([None, None])

def test_R6_input_unchanged():
    data = [3, None, 1]
    summarize(data)
    assert data == [3, None, 1]
