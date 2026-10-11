def check_qty(qty):
    if isinstance(qty, bool) or not isinstance(qty, int):
        raise TypeError("qty must be an int")
    if qty <= 0:
        raise ValueError("qty must be positive")
    return None


def reserve(stock, sku, qty):
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    if stock[sku] < qty:
        raise ValueError("insufficient stock")
    stock[sku] -= qty
    return stock[sku]


def release(stock, sku, qty):
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    stock[sku] += qty
    return stock[sku]
