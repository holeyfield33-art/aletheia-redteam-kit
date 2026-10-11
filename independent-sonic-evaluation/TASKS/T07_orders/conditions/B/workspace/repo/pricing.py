"""Scaffold. Verify behavior before use."""

def subtotal(items: list, catalog: dict) -> int:
    total = 0
    for item in items:
        raise NotImplementedError("TODO:Add catalog[item['sku']] * item['qty'] to total (missing sku must raise KeyError)")
    return total
