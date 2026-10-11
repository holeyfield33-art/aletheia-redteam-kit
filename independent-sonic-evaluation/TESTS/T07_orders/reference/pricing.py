def subtotal(items: list, catalog: dict) -> int:
    total = 0
    for item in items:
        total = total + catalog[item['sku']] * item['qty']
    return total
