def validate_items(items: list) -> None:
    if not isinstance(items, list) or len(items) == 0:
        raise ValueError("items must be a non-empty list")
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("each item must be a dict")
        sku = item.get('sku')
        if not isinstance(sku, str) or sku == '':
            raise ValueError("item 'sku' must be a non-empty str")
        qty = item.get('qty')
        if isinstance(qty, bool) or not isinstance(qty, int) or qty <= 0:
            raise ValueError("item 'qty' must be an int greater than 0")
    return None
