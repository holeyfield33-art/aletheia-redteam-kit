Completed. Filled the two TODOs in /tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-41/repo/inventory.py:
- reserve: `stock[sku] -= qty; remaining = stock[sku]; return remaining`
- release: `stock[sku] += qty; remaining = stock[sku]; return remaining`

Preserved all module paths, signatures, imports (none), branch nesting and statement order; only the TODO/return lines were replaced (both the `raise NotImplementedError` TODO line and the dangling `return remaining` after it, since `remaining` had to be assigned before it could be returned).

Checks: wrote and ran one behavioral check (1 run) covering R1 (TypeError for bool/float/str, ValueError for qty<=0), R2 (check_qty runs first — verified via reserve with missing sku + qty=0 raising ValueError not KeyError), R3 (KeyError on unknown sku), R4 (insufficient stock raises ValueError and leaves stock unchanged), R5/R6 (in-place decrement/increment and correct return), R7 (no key added/removed, other skus untouched). All passed ("OK").

No requirement conflicts with the provided materials.
