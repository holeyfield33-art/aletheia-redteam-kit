Done. Wrote four flat modules to repo/:

- validation.py — `validate_items(items)`: raises ValueError unless items is a non-empty list of dicts each with a non-empty str 'sku' and an int (bool rejected) 'qty' > 0; returns None otherwise.
- pricing.py — `subtotal(items, catalog)`: sum of catalog[sku]*qty; missing sku propagates KeyError naturally.
- tax.py — `apply_tax(cents, region)`: ValueError for any region outside US-CA(8), US-OR(0), EU-DE(19); returns cents + (cents*rate + 50)//100 (round-half-up).
- orders.py — `place_order(...)`: imports collaborators exactly as specified; raises PermissionError when `verified is not True` BEFORE any other check; then validate_items → subtotal → apply_tax; returns {'subtotal', 'total', 'region'}.

My own checks: ran verification once (1 run), all assertions passed — covering R1-R7, including bool-qty rejection, round-half-up boundaries, KeyError on missing sku, and verified-checked-first (PermissionError raised even with empty items).

No requirements conflict with the materials.
