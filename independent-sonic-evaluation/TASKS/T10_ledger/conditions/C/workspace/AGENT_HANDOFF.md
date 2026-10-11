# Implement this Python template

The accompanying score.json is the exact structural plan. template.wav is an
audible presentation of that plan; notes do not add requirements.

Fill only the __SONIC_HOLE__ placeholders. Preserve module paths, function
signatures, imports, required expressions, branch/loop nesting and statement
order. Each hole lists its allowed calls. If a requirement cannot be met within
this plan, explain the conflict and propose an explicit score revision.
Do not silently remove a check or widen the allowed calls/imports.

Run behavioral tests for the stated requirements. The template checker compares
syntax; passing it does not prove behavior, security or correctness.

## Requirements

- R1 (security/validation): If balance is not an int, is a bool, or is negative, raise ValueError.
- R2: transactions is a list of (kind, amount) pairs processed in order, starting from balance.
- R3 (security/validation): If any kind is not exactly 'deposit' or 'withdraw', raise ValueError (the whole call fails).
- R4 (security/validation): A transaction whose amount is not an int, is a bool, or is <= 0 is rejected: its index is recorded and the balance is unchanged.
- R5: A valid deposit adds amount to the running balance.
- R6 (security/authorization): A valid withdraw subtracts amount only if amount <= the running balance; otherwise it is rejected (index recorded, balance unchanged). The balance can never go negative.
- R7: Return {'balance': final_balance, 'rejected': [indices of rejected transactions in increasing order]}.

## Exact scaffold

### ledger.py

```python
"""Generated from an audible template. Verify behavior before use."""

def apply_transactions(balance: int, transactions: list) -> dict:
    if not isinstance(balance, int) or isinstance(balance, bool) or balance < 0:
        raise ValueError('invalid starting balance')
    current = balance
    rejected = []
    for index in range(len(transactions)):
        kind = transactions[index][0]
        amount = transactions[index][1]
        if kind not in ('deposit', 'withdraw'):
            raise ValueError('unknown transaction kind')
        raise NotImplementedError('__SONIC_HOLE__:Apply the transaction to current, or call rejected.append(index) when the amount is invalid or a withdraw exceeds current')
    return {'balance': current, 'rejected': rejected}
```
