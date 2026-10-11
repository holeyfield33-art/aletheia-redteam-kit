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

- Reject amounts at or below zero.
- Reject any role other than admin.
- For an accepted order return amount multiplied by 100.
- Keep the validation and authorization calls before implementation.

## Exact scaffold

### validation.py

```python
"""Generated from an audible template. Verify behavior before use."""

def require_positive(amount: int) -> None:
    if amount <= 0:
        raise ValueError('amount must be positive')
    return None
```

### authorization.py

```python
"""Generated from an audible template. Verify behavior before use."""

def require_authorized(role: str) -> None:
    if role != 'admin':
        raise PermissionError('admin required')
    return None
```

### orders.py

```python
"""Generated from an audible template. Verify behavior before use."""
from validation import require_positive
from authorization import require_authorized

def process_order(amount: int, role: str) -> int:
    """Requirements:
Keep the validation and authorization calls before implementation."""
    require_positive(amount)
    require_authorized(role)
    raise NotImplementedError('__SONIC_HOLE__:Set receipt to amount * 100')
    return receipt
```
