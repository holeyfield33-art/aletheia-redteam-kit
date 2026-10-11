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

- R1 (security/validation): If subtotal_cents is not an int, or is a bool, raise TypeError.
- R2 (security/validation): If subtotal_cents is negative, raise ValueError. Zero is allowed.
- R3 (security/validation): tier must be exactly one of 'basic', 'silver', 'gold' (case-sensitive); otherwise raise ValueError.
- R4 (security/validation): coupon must be exactly '' (no coupon) or 'SAVE10' (case-sensitive); otherwise raise ValueError.
- R5: Checks happen in the order R1, R2, R3, R4; the first failing check determines the exception.
- R6: Tier discount percentages are basic 0, silver 5, gold 10. The discount in cents is subtotal_cents * percent // 100 (floor division). Subtract it from subtotal_cents.
- R7: If coupon is 'SAVE10' and the ORIGINAL subtotal_cents is at least 5000, subtract a further 1000 cents after the tier discount. If the original subtotal is below 5000 the coupon is silently ignored (no error).
- R8: Return the final total in cents as an int.

## Exact scaffold

### pricing.py

```python
"""Generated from an audible template. Verify behavior before use."""

def compute_total(subtotal_cents: int, tier: str, coupon: str) -> int:
    if not isinstance(subtotal_cents, int) or isinstance(subtotal_cents, bool):
        raise TypeError('subtotal_cents must be an int')
    if subtotal_cents < 0:
        raise ValueError('subtotal_cents must be non-negative')
    if tier not in ('basic', 'silver', 'gold'):
        raise ValueError('unknown tier')
    if coupon not in ('', 'SAVE10'):
        raise ValueError('unknown coupon')
    raise NotImplementedError("__SONIC_HOLE__:Set total: apply the tier percentage discount with floor division, then subtract 1000 if coupon == 'SAVE10' and subtotal_cents >= 5000")
    return total
```
