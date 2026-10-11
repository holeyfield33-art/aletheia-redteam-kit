Done. Implemented the TODO in repo/pricing.py.

Files written in repo/:
- pricing.py (filled the single TODO in compute_total; preserved all four validation branches, signatures, imports, and the final `return total`)

Implementation of the TODO block:
```python
percent = {'basic': 0, 'silver': 5, 'gold': 10}[tier]
total = subtotal_cents - subtotal_cents * percent // 100
if coupon == 'SAVE10' and subtotal_cents >= 5000:
    total = total - 1000
```

This satisfies R6 (floor-division tier discount), R7 (extra 1000 off only when coupon is SAVE10 and ORIGINAL subtotal >= 5000, silently ignored below), and R8 (returns int). The scaffold's existing branches already cover R1-R5.

Checks: wrote and ran one behavioral test pass (ran checks once). All assertions passed (ALL PASS), covering R1 bool/float/str/None TypeError, R2 negative ValueError and zero allowed, R3/R4 case-sensitive validation, R5 ordering (non-int + bad tier -> TypeError first), R6 floor division, R7 both applied and ignored cases, R8 int return.

No requirement conflicts with the provided materials. The spec's allowed_calls for the TODO was empty; I used only a dict literal, subscript, arithmetic, and comparisons (no function calls), which is consistent with that constraint.
