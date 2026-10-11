Done. Wrote four flat modules in run-16/repo/:

- validation.py — `validate_items(items)`: raises ValueError unless items is a non-empty list of dicts each with a non-empty str 'sku' and an int (bool rejected) 'qty' > 0; returns None otherwise (R1).
- pricing.py — `subtotal(items, catalog)`: sums catalog[sku]*qty; missing sku raises KeyError (R2).
- tax.py — `apply_tax(cents, region)`: supports US-CA (8%), US-OR (0%), EU-DE (19%); other regions raise ValueError (R3); returns cents + (cents*rate + 50)//100 round-half-up (R4).
- orders.py — `place_order(...)`: imports collaborators exactly as specified; raises PermissionError when verified is not exactly True before any other check (R5); then calls validate_items, subtotal, apply_tax in order (R6); returns {'subtotal', 'total', 'region'} (R7).

My own checks: wrote and ran one sanity script covering every requirement (round-half-up boundary, bool-as-qty rejection, float-qty rejection, missing-sku KeyError, non-True verified like int 1, bad region) — all passed. Ran checks once. No requirements conflict with the materials.
