# Implement this Python scaffold

The accompanying spec.json is the exact structural plan.

Fill only the TODO placeholders. Preserve module paths, function
signatures, imports, required expressions, branch/loop nesting and statement
order. Each TODO lists its allowed calls. If a requirement cannot be met within
this plan, explain the conflict and propose an explicit spec revision.
Do not silently remove a check or widen the allowed calls/imports.

Run behavioral tests for the stated requirements. A structural comparison
checks syntax; passing it does not prove behavior, security or correctness.

## Requirements

- R1 (security/validation): If readings is not a list, raise TypeError.
- R2: Entries that are None are skipped.
- R3 (security/validation): Any entry that is not None and is a bool, or is not an int or float, raises TypeError (e.g. '3', True, [1]).
- R4 (security/validation): If no numeric entries remain after skipping None, raise ValueError.
- R5: Return a dict with exactly the keys 'count' (number of numeric entries), 'min', 'max' and 'mean'. 'mean' is the arithmetic mean rounded with round(value, 2). 'min' and 'max' are the original values (not rounded).
- R6: The input list must not be modified.

## Exact scaffold

### stats.py

```python
"""Scaffold. Verify behavior before use."""

def summarize(readings: list) -> dict:
    if not isinstance(readings, list):
        raise TypeError('readings must be a list')
    values = []
    for item in readings:
        if item is not None and (isinstance(item, bool) or not isinstance(item, (int, float))):
            raise TypeError('non-numeric reading')
        if item is not None:
            values.append(item)
    if not values:
        raise ValueError('no numeric readings')
    raise NotImplementedError('TODO:Set result to a dict with count, min, max and mean (mean rounded to 2 places) of values')
    return result
```
