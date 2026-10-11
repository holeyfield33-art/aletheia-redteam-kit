Done. Filled the two `__SONIC_HOLE__` placeholders in `/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-24/repo/inventory.py`, preserving all signatures, imports, branch/loop nesting, statement order and the `return remaining` lines.

Implementation:
- reserve hole: `stock[sku] -= qty` then `remaining = stock[sku]` (in-place decrement, no key add/remove).
- release hole: `stock[sku] += qty` then `remaining = stock[sku]` (in-place increment).

Checks: wrote one behavioral test suite in scratch/ covering R1-R7 and ran it once. Result: ALL PASS. Specifically verified check_qty is called before sku/stock checks (R2: bool qty with empty dict raises TypeError not KeyError), insufficient-stock leaves the dict completely unchanged (R4), and other skus/keys are untouched (R7).

No requirements conflict with the provided materials. Only file written in repo/: inventory.py.
