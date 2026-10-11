Completed. Filled the single TODO in repo/ledger.py (only file in repo/).

Implementation of the TODO body (within the per-transaction loop, using only the allowed calls isinstance and rejected.append):
- Invalid amount (not int / is bool / <= 0) -> rejected.append(index), balance unchanged (R4)
- Valid deposit -> current = current + amount (R5)
- Valid withdraw with amount <= current -> current = current - amount (R6)
- Withdraw exceeding current -> rejected.append(index), balance unchanged (R6; never negative)

All preserved from scaffold: R1 balance validation, R3 unknown-kind raise, R7 return shape, signatures, imports (none), branch/loop nesting, statement order.

Checks: wrote and ran one behavioral check script (1 run) covering R1 (float/bool/negative balance incl. False), R3 (unknown kind), R4 (0, negative, True, float amounts all rejected), R5, R6 (overdraw rejected, exact-balance withdraw allowed). All passed.

No requirement conflicts with the provided materials.
