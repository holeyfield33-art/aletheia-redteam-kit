# Implement this Python template

The accompanying score.json is the exact structural plan. template.wav is an
audible presentation of that plan; notes do not add requirements.

Fill only the __SONIC_HOLE__ placeholders. Preserve module paths, function
signatures, imports, required expressions, branch/loop nesting and statement
order. Each hole lists its allowed calls. If a requirement cannot be met within
this plan, explain the conflict and propose an explicit score revision.
Do not silently remove a check or widen the allowed calls/imports.

Run behavioral tests for the stated requirements. The template checker compares
syntax; passing it does not prove behavior, security or correctness.

## Requirements

- R1 (security/validation): letter_for raises TypeError if score is not an int or is a bool, and ValueError if score < 0 or score > 100.
- R2: letter_for returns 'A' for 90-100, 'B' for 80-89, 'C' for 70-79, 'D' for 60-69, and 'F' for 0-59.
- R3: assign_grades returns a NEW dict mapping each name in scores to letter_for(scores[name]), preserving the input's key order; it must call letter_for for every entry and propagate its exceptions. The input dict must not be modified.
- R4: summarize returns a dict with exactly the keys 'A', 'B', 'C', 'D', 'F' (in that order) giving how many values of grades equal each letter; letters with no students map to 0.
- R5 (security/validation): summarize raises ValueError if any value in grades is not one of 'A', 'B', 'C', 'D', 'F'.

## Exact scaffold

### grades.py

```python
"""Generated from an audible template. Verify behavior before use."""

def letter_for(score: int) -> str:
    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError('score must be an int')
    if score < 0 or score > 100:
        raise ValueError('score out of range')
    raise NotImplementedError('__SONIC_HOLE__:Set letter from the grade bands')
    return letter

def assign_grades(scores: dict) -> dict:
    result = {}
    for name in scores:
        raise NotImplementedError('__SONIC_HOLE__:Store letter_for(scores[name]) as result[name]')
    return result

def summarize(grades: dict) -> dict:
    counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}
    for letter in grades.values():
        if letter not in counts:
            raise ValueError('unknown letter')
        raise NotImplementedError('__SONIC_HOLE__:Increment counts[letter]')
    return counts
```
