## Task (natural-language specification)

Create one module, `ledger.py`, containing exactly this function:

- `apply_transactions(balance: int, transactions: list) -> dict`

No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): If balance is not an int, is a bool, or is negative, raise ValueError.
- R2: transactions is a list of (kind, amount) pairs processed in order, starting from balance.
- R3 (security/validation): If any kind is not exactly 'deposit' or 'withdraw', raise ValueError (the whole call fails).
- R4 (security/validation): A transaction whose amount is not an int, is a bool, or is <= 0 is rejected: its index is recorded and the balance is unchanged.
- R5: A valid deposit adds amount to the running balance.
- R6 (security/authorization): A valid withdraw subtracts amount only if amount <= the running balance; otherwise it is rejected (index recorded, balance unchanged). The balance can never go negative.
- R7: Return {'balance': final_balance, 'rejected': [indices of rejected transactions in increasing order]}.
