"""In-place inventory stock management with strict input validation."""


def check_qty(qty):
    """Validate a quantity argument.

    Raises TypeError if qty is not an int (bool counts as non-int),
    ValueError if qty <= 0. Otherwise returns None.
    """
    if isinstance(qty, bool) or not isinstance(qty, int):
        raise TypeError("qty must be an int")
    if qty <= 0:
        raise ValueError("qty must be positive")
    return None


def reserve(stock, sku, qty):
    """Reserve qty of sku, decreasing stock[sku] in place.

    Returns the new level for sku. Raises on invalid qty, unknown sku,
    or insufficient stock (leaving stock unchanged in that case).
    """
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    if stock[sku] < qty:
        raise ValueError("insufficient stock")
    stock[sku] -= qty
    return stock[sku]


def release(stock, sku, qty):
    """Release qty of sku, increasing stock[sku] in place.

    Returns the new level for sku. Raises on invalid qty or unknown sku.
    """
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    stock[sku] += qty
    return stock[sku]
