Create four modules:

- `validation.py` containing exactly `validate_items(items: list) -> None`
- `pricing.py` containing exactly `subtotal(items: list, catalog: dict) -> int`
- `tax.py` containing exactly `apply_tax(cents: int, region: str) -> int`
- `orders.py` containing exactly `place_order(items: list, catalog: dict, region: str, verified: bool) -> dict`.
  `orders.py` must import its collaborators with
  `from validation import validate_items`, `from pricing import subtotal` and `from tax import apply_tax`.

No other modules, top-level statements or third-party dependencies are required.
