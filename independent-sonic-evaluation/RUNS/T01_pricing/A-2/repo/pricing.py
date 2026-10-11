"""Order total computation."""

_TIER_PERCENT = {"basic": 0, "silver": 5, "gold": 10}
_COUPONS = ("", "SAVE10")


def compute_total(subtotal_cents: int, tier: str, coupon: str) -> int:
    """Return the final total in cents after tier discount and coupon."""
    if isinstance(subtotal_cents, bool) or not isinstance(subtotal_cents, int):
        raise TypeError("subtotal_cents must be an int")
    if subtotal_cents < 0:
        raise ValueError("subtotal_cents must be non-negative")
    if not isinstance(tier, str) or tier not in _TIER_PERCENT:
        raise ValueError("invalid tier")
    if not isinstance(coupon, str) or coupon not in _COUPONS:
        raise ValueError("invalid coupon")

    original = int(subtotal_cents)
    total = original - original * _TIER_PERCENT[tier] // 100
    if coupon == "SAVE10" and original >= 5000:
        total -= 1000
    return int(total)
