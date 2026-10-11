"""Pricing computation module."""

_TIER_DISCOUNTS = {"basic": 0, "silver": 5, "gold": 10}


def compute_total(subtotal_cents: int, tier: str, coupon: str) -> int:
    # R1: subtotal_cents must be a non-bool int.
    if isinstance(subtotal_cents, bool) or not isinstance(subtotal_cents, int):
        raise TypeError("subtotal_cents must be an int")
    # R2: no negative subtotals.
    if subtotal_cents < 0:
        raise ValueError("subtotal_cents must not be negative")
    # R3: validate tier (case-sensitive).
    if tier not in _TIER_DISCOUNTS:
        raise ValueError("tier must be one of 'basic', 'silver', 'gold'")
    # R4: validate coupon (case-sensitive).
    if coupon not in ("", "SAVE10"):
        raise ValueError("coupon must be '' or 'SAVE10'")

    # R6: apply tier discount with floor division.
    percent = _TIER_DISCOUNTS[tier]
    discount = subtotal_cents * percent // 100
    total = subtotal_cents - discount

    # R7: apply coupon only if original subtotal is at least 5000.
    if coupon == "SAVE10" and subtotal_cents >= 5000:
        total -= 1000

    # R8: return the final total as an int.
    return total
