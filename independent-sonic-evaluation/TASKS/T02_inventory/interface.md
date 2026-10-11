Create one module, `inventory.py`, containing exactly these functions:

- `check_qty(qty: int) -> None`
- `reserve(stock: dict, sku: str, qty: int) -> int`
- `release(stock: dict, sku: str, qty: int) -> int`

`stock` maps sku strings to integer quantities and is mutated in place.
No other modules, top-level statements or third-party dependencies are required.
