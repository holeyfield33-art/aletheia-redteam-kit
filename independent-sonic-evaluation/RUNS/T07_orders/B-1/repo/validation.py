"""Scaffold. Verify behavior before use."""

def validate_items(items: list) -> None:
    if not isinstance(items, list) or not items:
        raise ValueError('items must be a non-empty list')
    for item in items:
        ok = (
            isinstance(item, dict)
            and isinstance(item.get('sku'), str)
            and item.get('sku')
            and isinstance(item.get('qty'), int)
            and not isinstance(item.get('qty'), bool)
            and item.get('qty') > 0
        )
        if not ok:
            raise ValueError('invalid item')
    return None
