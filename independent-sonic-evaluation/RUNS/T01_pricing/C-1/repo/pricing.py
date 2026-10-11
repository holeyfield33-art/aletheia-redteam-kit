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
    if tier == 'gold':
        percent = 10
    elif tier == 'silver':
        percent = 5
    else:
        percent = 0
    total = subtotal_cents - subtotal_cents * percent // 100
    if coupon == 'SAVE10' and subtotal_cents >= 5000:
        total = total - 1000
    return total
