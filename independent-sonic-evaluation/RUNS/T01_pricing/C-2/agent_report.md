Done. Filled the single `__SONIC_HOLE__` in `/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-17/repo/pricing.py`.

Files written in repo/:
- pricing.py (only file; hole replaced, scaffold preserved)

Implementation of the hole (3 statements before the existing `return total`):
```python
percent = {'basic': 0, 'silver': 5, 'gold': 10}[tier]
total = subtotal_cents - subtotal_cents * percent // 100
if coupon == 'SAVE10' and subtotal_cents >= 5000:
    total = total - 1000
```

Preserved all module paths, the function signature, the four validation branches, their order, and the `return total` statement. The hole's `allowed_calls` list was empty; I introduced no new calls or imports (a dict literal indexing is used, no function calls).

Checks: ran my own behavioral test suite once. ALL PASS — covered R1 (TypeError for non-int/bool/float/str/None), R2 (negative ValueError, zero allowed), R3 (case-sensitive tier), R4 (case-sensitive coupon), R5 (order: bool+bad args -> TypeError first), R6 (floor-division tier discounts basic/silver/gold), R7 (further 1000 off only when coupon=='SAVE10' and ORIGINAL subtotal>=5000; ignored below 5000), R8 (int result, not bool).

No requirement conflicts found; the scaffold and requirements are consistent.
