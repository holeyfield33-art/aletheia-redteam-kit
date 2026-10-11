"""Generated from an audible template. Verify behavior before use."""

def validate_items(items: list) -> None:
    if not isinstance(items, list) or not items:
        raise ValueError('items must be a non-empty list')
    for item in items:
        raise NotImplementedError("__SONIC_HOLE__:Set ok to True only if item is a dict whose 'sku' is a non-empty str and whose 'qty' is an int (not bool) > 0")
        if not ok:
            raise ValueError('invalid item')
    return None
