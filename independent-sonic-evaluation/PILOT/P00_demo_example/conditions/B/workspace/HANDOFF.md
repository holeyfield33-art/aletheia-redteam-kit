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

- Reject amounts at or below zero.
- Reject any role other than admin.
- For an accepted order return amount multiplied by 100.
- Keep the validation and authorization calls before implementation.

## Exact scaffold

### validation.py

```python
"""Scaffold. Verify behavior before use."""

def require_positive(amount: int) -> None:
    if amount <= 0:
        raise ValueError('amount must be positive')
    return None
```

### authorization.py

```python
"""Scaffold. Verify behavior before use."""

def require_authorized(role: str) -> None:
    if role != 'admin':
        raise PermissionError('admin required')
    return None
```

### orders.py

```python
"""Scaffold. Verify behavior before use."""
from validation import require_positive
from authorization import require_authorized

def process_order(amount: int, role: str) -> int:
    """Requirements:
Keep the validation and authorization calls before implementation."""
    require_positive(amount)
    require_authorized(role)
    raise NotImplementedError('TODO:Set receipt to amount * 100')
    return receipt
```
