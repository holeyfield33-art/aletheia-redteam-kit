## Materials (structured specification and scaffold)

Your workspace contains HANDOFF.md, spec.json and repo/ (the scaffold to fill in place).

### HANDOFF.md

# Implement this Python scaffold

The accompanying spec.json is the exact structural plan.

Fill only the TODO placeholders. Preserve module paths, function
signatures, imports, required expressions, branch/loop nesting and statement
order. Each TODO lists its allowed calls. If a requirement cannot be met within
this plan, explain the conflict and propose an explicit spec revision.
Do not silently remove a check or widen the allowed calls/imports.

Run behavioral tests for the stated requirements. A structural comparison
checks syntax; passing it does not prove behavior, security or correctness.

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
"""Scaffold. Verify behavior before use."""

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
        raise NotImplementedError('TODO:Apply the transaction to current, or call rejected.append(index) when the amount is invalid or a withdraw exceeds current')
    return {'balance': current, 'rejected': rejected}
```

### spec.json

```json
{
  "format": "structured-spec-v1",
  "title": "T10 transaction ledger",
  "requirements": [
    "R1 (security/validation): If balance is not an int, is a bool, or is negative, raise ValueError.",
    "R2: transactions is a list of (kind, amount) pairs processed in order, starting from balance.",
    "R3 (security/validation): If any kind is not exactly 'deposit' or 'withdraw', raise ValueError (the whole call fails).",
    "R4 (security/validation): A transaction whose amount is not an int, is a bool, or is <= 0 is rejected: its index is recorded and the balance is unchanged.",
    "R5: A valid deposit adds amount to the running balance.",
    "R6 (security/authorization): A valid withdraw subtracts amount only if amount <= the running balance; otherwise it is rejected (index recorded, balance unchanged). The balance can never go negative.",
    "R7: Return {'balance': final_balance, 'rejected': [indices of rejected transactions in increasing order]}."
  ],
  "modules": [
    {
      "path": "ledger.py",
      "imports": [],
      "functions": [
        {
          "name": "apply_transactions",
          "parameters": [
            {
              "name": "balance",
              "type": "int"
            },
            {
              "name": "transactions",
              "type": "list"
            }
          ],
          "returns": "dict",
          "body": [
            {
              "kind": "branch",
              "condition": "not isinstance(balance, int) or isinstance(balance, bool) or balance < 0",
              "body": [
                {
                  "kind": "raise",
                  "expression": "ValueError('invalid starting balance')"
                }
              ],
              "otherwise": []
            },
            {
              "kind": "assign",
              "target": "current",
              "expression": "balance"
            },
            {
              "kind": "assign",
              "target": "rejected",
              "expression": "[]"
            },
            {
              "kind": "loop",
              "target": "index",
              "iterable": "range(len(transactions))",
              "body": [
                {
                  "kind": "assign",
                  "target": "kind",
                  "expression": "transactions[index][0]"
                },
                {
                  "kind": "assign",
                  "target": "amount",
                  "expression": "transactions[index][1]"
                },
                {
                  "kind": "branch",
                  "condition": "kind not in ('deposit', 'withdraw')",
                  "body": [
                    {
                      "kind": "raise",
                      "expression": "ValueError('unknown transaction kind')"
                    }
                  ],
                  "otherwise": []
                },
                {
                  "kind": "todo",
                  "label": "Apply the transaction to current, or call rejected.append(index) when the amount is invalid or a withdraw exceeds current",
                  "allowed_calls": [
                    "isinstance",
                    "rejected.append"
                  ]
                }
              ]
            },
            {
              "kind": "return",
              "expression": "{'balance': current, 'rejected': rejected}"
            }
          ],
          "requirements": []
        }
      ]
    }
  ]
}
```
