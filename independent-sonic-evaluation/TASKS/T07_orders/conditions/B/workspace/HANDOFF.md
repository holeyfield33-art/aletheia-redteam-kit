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

- R1 (security/validation): validate_items raises ValueError if items is not a non-empty list, or if any item is not a dict whose 'sku' is a non-empty str and whose 'qty' is an int (not bool) greater than 0. It returns None otherwise.
- R2: subtotal returns the sum of catalog[item['sku']] * item['qty'] over items (catalog maps sku -> unit price in integer cents). An sku missing from catalog raises KeyError.
- R3 (security/validation): apply_tax raises ValueError for any region other than 'US-CA' (8 percent), 'US-OR' (0 percent) and 'EU-DE' (19 percent).
- R4: apply_tax returns cents + (cents * rate + 50) // 100, where rate is the integer percent (round-half-up tax).
- R5 (security/authorization): place_order raises PermissionError if verified is not exactly True, BEFORE any other check.
- R6 (security/validation): place_order then calls validate_items(items), then subtotal(items, catalog), then apply_tax(sub, region), in that order.
- R7: place_order returns {'subtotal': sub, 'total': total, 'region': region}.

## Exact scaffold

### validation.py

```python
"""Scaffold. Verify behavior before use."""

def validate_items(items: list) -> None:
    if not isinstance(items, list) or not items:
        raise ValueError('items must be a non-empty list')
    for item in items:
        raise NotImplementedError("TODO:Set ok to True only if item is a dict whose 'sku' is a non-empty str and whose 'qty' is an int (not bool) > 0")
        if not ok:
            raise ValueError('invalid item')
    return None
```

### pricing.py

```python
"""Scaffold. Verify behavior before use."""

def subtotal(items: list, catalog: dict) -> int:
    total = 0
    for item in items:
        raise NotImplementedError("TODO:Add catalog[item['sku']] * item['qty'] to total (missing sku must raise KeyError)")
    return total
```

### tax.py

```python
"""Scaffold. Verify behavior before use."""

def apply_tax(cents: int, region: str) -> int:
    rates = {'US-CA': 8, 'US-OR': 0, 'EU-DE': 19}
    if region not in rates:
        raise ValueError('unknown region')
    raise NotImplementedError('TODO:Set taxed to cents + (cents * rate + 50) // 100 using rates[region]')
    return taxed
```

### orders.py

```python
"""Scaffold. Verify behavior before use."""
from validation import validate_items
from pricing import subtotal
from tax import apply_tax

def place_order(items: list, catalog: dict, region: str, verified: bool) -> dict:
    if verified is not True:
        raise PermissionError('unverified user')
    validate_items(items)
    sub = subtotal(items, catalog)
    total = apply_tax(sub, region)
    return {'subtotal': sub, 'total': total, 'region': region}
```
