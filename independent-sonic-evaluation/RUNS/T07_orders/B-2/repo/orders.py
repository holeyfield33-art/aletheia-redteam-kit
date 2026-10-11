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
