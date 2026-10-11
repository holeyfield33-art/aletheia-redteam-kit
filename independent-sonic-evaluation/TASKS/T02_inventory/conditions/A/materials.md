## Task (natural-language specification)

Create one module, `inventory.py`, containing exactly these functions:

- `check_qty(qty: int) -> None`
- `reserve(stock: dict, sku: str, qty: int) -> int`
- `release(stock: dict, sku: str, qty: int) -> int`

`stock` maps sku strings to integer quantities and is mutated in place.
No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): check_qty raises TypeError if qty is not an int or is a bool, and ValueError if qty <= 0; otherwise it returns None.
- R2 (security/validation): reserve and release must call check_qty(qty) before doing anything else.
- R3 (security/validation): If sku is not a key of stock, reserve and release raise KeyError.
- R4 (security/validation): reserve raises ValueError if stock[sku] < qty, and must leave stock completely unchanged in that case.
- R5: reserve decreases stock[sku] by qty in place and returns the new level for that sku.
- R6: release increases stock[sku] by qty in place and returns the new level for that sku.
- R7: Neither function may add or remove keys of stock or change other skus.
