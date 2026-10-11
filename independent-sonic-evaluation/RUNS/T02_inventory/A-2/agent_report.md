Done. Wrote one file: repo/inventory.py (flat module, standard library only, no top-level statements beyond function defs).

Functions implemented exactly as specified:
- check_qty(qty): raises TypeError if qty is a bool or not an int, ValueError if qty <= 0, else returns None (R1).
- reserve(stock, sku, qty): calls check_qty first (R2), then KeyError if sku absent (R3), then ValueError if stock[sku] < qty leaving stock untouched (R4), else decrements in place and returns new level (R5).
- release(stock, sku, qty): calls check_qty first (R2), KeyError if sku absent (R3), else increments in place and returns new level (R6).
Neither function adds/removes keys or touches other skus (R7).

Checks: wrote one verification script in scratch and ran it once. All requirements R1-R7 passed (including bool rejection for both True/False, validation-before-lookup ordering, insufficient-stock leaving stock unchanged, and exact-stock reserve to zero). Checks run: 1.

No requirement conflicts found; the spec is self-consistent.
