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

- R1 (security/validation): check_qty raises TypeError if qty is not an int or is a bool, and ValueError if qty <= 0; otherwise it returns None.
- R2 (security/validation): reserve and release must call check_qty(qty) before doing anything else.
- R3 (security/validation): If sku is not a key of stock, reserve and release raise KeyError.
- R4 (security/validation): reserve raises ValueError if stock[sku] < qty, and must leave stock completely unchanged in that case.
- R5: reserve decreases stock[sku] by qty in place and returns the new level for that sku.
- R6: release increases stock[sku] by qty in place and returns the new level for that sku.
- R7: Neither function may add or remove keys of stock or change other skus.

## Exact scaffold

### inventory.py

```python
"""Generated from an audible template. Verify behavior before use."""

def check_qty(qty: int) -> None:
    if not isinstance(qty, int) or isinstance(qty, bool):
        raise TypeError('qty must be an int')
    if qty <= 0:
        raise ValueError('qty must be positive')
    return None

def reserve(stock: dict, sku: str, qty: int) -> int:
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    if stock[sku] < qty:
        raise ValueError('insufficient stock')
    raise NotImplementedError('__SONIC_HOLE__:Decrease stock[sku] by qty in place and set remaining to the new level')
    return remaining

def release(stock: dict, sku: str, qty: int) -> int:
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    raise NotImplementedError('__SONIC_HOLE__:Increase stock[sku] by qty in place and set remaining to the new level')
    return remaining
```
