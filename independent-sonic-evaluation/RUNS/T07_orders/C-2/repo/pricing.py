"""Generated from an audible template. Verify behavior before use."""

def subtotal(items: list, catalog: dict) -> int:
    total = 0
    for item in items:
        total += catalog[item['sku']] * item['qty']
    return total
