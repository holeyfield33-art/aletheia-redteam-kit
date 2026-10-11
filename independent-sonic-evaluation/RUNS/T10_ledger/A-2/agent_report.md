Completed. Wrote one file: repo/ledger.py containing only `apply_transactions(balance, transactions)`.

Implementation summary:
- R1: raises ValueError if balance is a bool, not an int, or negative (bool checked before int since bool is an int subclass).
- R2: iterates (kind, amount) pairs in order from the starting balance.
- R3: raises ValueError immediately if any kind is not exactly 'deposit' or 'withdraw' (whole call fails). Kind is validated before amount.
- R4: amount that is a bool, not an int, or <= 0 is rejected — index recorded, balance unchanged.
- R5: valid deposit adds amount.
- R6: valid withdraw subtracts only if amount <= running balance, else rejected; balance never goes negative.
- R7: returns {'balance': final, 'rejected': [indices ascending]} (indices are naturally ascending since appended in iteration order).

My own checks: ran 1 time, all passed — covered R1 (bool/float/negative/str rejected), R3 (invalid kind raises), R4 (True/0/-5/1.5 rejected, valid deposit applied), R5/R6 (deposit/withdraw with over-balance withdraw rejected, balance floored at 0), and empty-list case.

No requirement conflicts found. The spec's ordering (R3 whole-call-fail on bad kind vs R4 per-transaction rejection) is handled by checking kind first within each transaction.
