"""Hidden behavioral tests for T09."""
import pytest
import grades
from grades import letter_for, assign_grades, summarize


def test_R2_boundaries():
    expected = {100: 'A', 90: 'A', 89: 'B', 80: 'B', 79: 'C', 70: 'C', 69: 'D', 60: 'D', 59: 'F', 0: 'F'}
    assert {s: letter_for(s) for s in expected} == expected

def test_sec_R1_type():
    for bad in (True, 90.0, '90', None):
        with pytest.raises(TypeError):
            letter_for(bad)

def test_sec_R1_range():
    for bad in (-1, 101):
        with pytest.raises(ValueError):
            letter_for(bad)

def test_R3_assign_order_and_new_dict():
    scores = {'zoe': 95, 'adam': 61, 'mia': 12}
    result = assign_grades(scores)
    assert list(result.items()) == [('zoe', 'A'), ('adam', 'D'), ('mia', 'F')]
    assert result is not scores and scores == {'zoe': 95, 'adam': 61, 'mia': 12}

def test_R3_empty():
    assert assign_grades({}) == {}

def test_sec_R3_propagates_errors():
    with pytest.raises(ValueError):
        assign_grades({'a': 50, 'b': 150})
    with pytest.raises(TypeError):
        assign_grades({'a': False})

def test_R3_calls_letter_for(monkeypatch):
    monkeypatch.setattr(grades, 'letter_for', lambda s: 'X')
    assert grades.assign_grades({'a': 1, 'b': 2}) == {'a': 'X', 'b': 'X'}

def test_R4_summary_counts_and_order():
    result = summarize({'a': 'A', 'b': 'C', 'c': 'A'})
    assert list(result.items()) == [('A', 2), ('B', 0), ('C', 1), ('D', 0), ('F', 0)]

def test_R4_empty_summary():
    assert summarize({}) == {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}

def test_sec_R5_unknown_letter():
    for bad in ('E', 'a', None, 'A+'):
        with pytest.raises(ValueError):
            summarize({'x': 'A', 'y': bad})
