"""Scaffold. Verify behavior before use."""

def compute_total(subtotal_cents: int, tier: str, coupon: str) -> int:
    if not isinstance(subtotal_cents, int) or isinstance(subtotal_cents, bool):
        raise TypeError('subtotal_cents must be an int')
    if subtotal_cents < 0:
        raise ValueError('subtotal_cents must be non-negative')
    if tier not in ('basic', 'silver', 'gold'):
        raise ValueError('unknown tier')
    if coupon not in ('', 'SAVE10'):
        raise ValueError('unknown coupon')
    raise NotImplementedError("TODO:Set total: apply the tier percentage discount with floor division, then subtract 1000 if coupon == 'SAVE10' and subtotal_cents >= 5000")
    return total
