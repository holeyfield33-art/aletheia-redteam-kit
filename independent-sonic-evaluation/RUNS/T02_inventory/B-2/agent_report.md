Done. Filled the two TODO placeholders in /tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-35/repo/inventory.py, preserving all signatures, imports, and statement order from the scaffold.

Implementation:
- reserve: `stock[sku] -= qty; remaining = stock[sku]; return remaining`
- release: `stock[sku] += qty; remaining = stock[sku]; return remaining`

check_qty and all validation branches were already present in the scaffold and were left unchanged.

Checks: wrote one behavioral test script in scratch/ and ran it once — all assertions passed (ALL PASS), covering R1 (TypeError for bool/float/str, ValueError for <=0, None otherwise), R2 (check_qty runs before KeyError), R3 (KeyError for missing sku), R4 (ValueError on insufficient stock leaves dict unchanged), R5/R6 (in-place decrement/increment returning new level), and R7 (no other keys added/removed/changed).

Files written in repo/: inventory.py (only file). No requirement conflicts with the provided materials.
