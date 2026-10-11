"""Scaffold. Verify behavior before use."""

def check_qty(qty: int) -> None:
    if not isinstance(qty, int) or isinstance(qty, bool):
        raise TypeError('qty must be an int')
    if qty <= 0:
        raise ValueError('qty must be positive')
    return None

def reserve(stock: dict, sku: str, qty: int) -> int:
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    if stock[sku] < qty:
        raise ValueError('insufficient stock')
    stock[sku] -= qty
    remaining = stock[sku]
    return remaining

def release(stock: dict, sku: str, qty: int) -> int:
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    stock[sku] += qty
    remaining = stock[sku]
    return remaining
