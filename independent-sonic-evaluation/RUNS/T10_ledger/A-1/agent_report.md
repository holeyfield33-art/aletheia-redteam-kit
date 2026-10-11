Done. Wrote one file: repo/ledger.py containing exactly `apply_transactions(balance, transactions)`.

Implementation notes:
- R1: raises ValueError if balance is a bool, not an int, or negative.
- R3: validates all kinds up front (any kind not exactly 'deposit'/'withdraw' raises ValueError, failing the whole call before any processing).
- R4: amount that is a bool, not an int, or <= 0 is rejected (index recorded, balance unchanged).
- R5/R6: deposit adds; withdraw subtracts only if amount <= running balance, else rejected; balance never goes negative.
- R7: returns {'balance': final_balance, 'rejected': [increasing indices]}. Indices are appended in processing order so they are naturally increasing.

Checks: wrote/ran one inline check script covering R1, R3, R4, R5, R6, R7 — all passed (ran checks once). No conflicts found among the requirements.
