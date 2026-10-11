Implemented the single TODO in repo/pricing.py (compute_total).

Files written in repo/: pricing.py (edited the TODO body only; preserved all validation branches, signature, imports, and statement order).

The filled-in logic:
    percent = {'basic': 0, 'silver': 5, 'gold': 10}[tier]
    total = subtotal_cents - subtotal_cents * percent // 100
    if coupon == 'SAVE10' and subtotal_cents >= 5000:
        total = total - 1000
    return total

This satisfies R6 (tier floor-division discount), R7 (SAVE10 subtracts 1000 only when original subtotal >= 5000, otherwise silently ignored), and R8 (returns int). The four validation branches R1-R5 were already present in the scaffold and are left unchanged.

Checks: wrote and ran one behavioral check script covering discounts, coupon threshold (above/below 5000), zero subtotal, and all five validation error paths (float, bool, negative, bad tier, bad coupon). All passed. Ran checks once.

No requirement conflicts with the provided materials.
