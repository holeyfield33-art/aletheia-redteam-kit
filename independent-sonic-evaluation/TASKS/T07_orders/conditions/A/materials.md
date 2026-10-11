## Task (natural-language specification)

Create four modules:

- `validation.py` containing exactly `validate_items(items: list) -> None`
- `pricing.py` containing exactly `subtotal(items: list, catalog: dict) -> int`
- `tax.py` containing exactly `apply_tax(cents: int, region: str) -> int`
- `orders.py` containing exactly `place_order(items: list, catalog: dict, region: str, verified: bool) -> dict`.
  `orders.py` must import its collaborators with
  `from validation import validate_items`, `from pricing import subtotal` and `from tax import apply_tax`.

No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): validate_items raises ValueError if items is not a non-empty list, or if any item is not a dict whose 'sku' is a non-empty str and whose 'qty' is an int (not bool) greater than 0. It returns None otherwise.
- R2: subtotal returns the sum of catalog[item['sku']] * item['qty'] over items (catalog maps sku -> unit price in integer cents). An sku missing from catalog raises KeyError.
- R3 (security/validation): apply_tax raises ValueError for any region other than 'US-CA' (8 percent), 'US-OR' (0 percent) and 'EU-DE' (19 percent).
- R4: apply_tax returns cents + (cents * rate + 50) // 100, where rate is the integer percent (round-half-up tax).
- R5 (security/authorization): place_order raises PermissionError if verified is not exactly True, BEFORE any other check.
- R6 (security/validation): place_order then calls validate_items(items), then subtotal(items, catalog), then apply_tax(sub, region), in that order.
- R7: place_order returns {'subtotal': sub, 'total': total, 'region': region}.
