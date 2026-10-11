## Task (natural-language specification)

Create one module, `pricing.py`, containing exactly this function:

- `compute_total(subtotal_cents: int, tier: str, coupon: str) -> int`

No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): If subtotal_cents is not an int, or is a bool, raise TypeError.
- R2 (security/validation): If subtotal_cents is negative, raise ValueError. Zero is allowed.
- R3 (security/validation): tier must be exactly one of 'basic', 'silver', 'gold' (case-sensitive); otherwise raise ValueError.
- R4 (security/validation): coupon must be exactly '' (no coupon) or 'SAVE10' (case-sensitive); otherwise raise ValueError.
- R5: Checks happen in the order R1, R2, R3, R4; the first failing check determines the exception.
- R6: Tier discount percentages are basic 0, silver 5, gold 10. The discount in cents is subtotal_cents * percent // 100 (floor division). Subtract it from subtotal_cents.
- R7: If coupon is 'SAVE10' and the ORIGINAL subtotal_cents is at least 5000, subtract a further 1000 cents after the tier discount. If the original subtotal is below 5000 the coupon is silently ignored (no error).
- R8: Return the final total in cents as an int.
