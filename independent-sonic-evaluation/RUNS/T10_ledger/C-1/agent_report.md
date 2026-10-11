Done. Filled the single `__SONIC_HOLE__` in `repo/ledger.py` (the only deliverable file).

The hole was inside the per-transaction loop, after the kind-validation branch. Replacement (using only the allowed calls `isinstance` and `rejected.append`):

```python
if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
    rejected.append(index)
elif kind == 'deposit':
    current = current + amount
elif amount <= current:
    current = current - amount
else:
    rejected.append(index)
```

This preserves all surrounding structure, imports, signature, and statement order; only the placeholder was replaced.

Requirement coverage:
- R1: starting-balance validation was pre-existing in the scaffold (unchanged).
- R3: unknown-kind raise was pre-existing (whole call fails).
- R4: non-int / bool / <=0 amounts -> index appended, balance unchanged.
- R5: valid deposit adds amount.
- R6: withdraw subtracts only if amount <= current; otherwise index appended, balance unchanged; balance never goes negative.
- R7: returns {'balance': current, 'rejected': rejected} (pre-existing return; indices appended in increasing order since loop runs in order).

My own checks: ran 1 behavioral check script (one `python -c` run). All assertions passed:
- All invalid balances ('x', True, -1, 1.0) raised ValueError.
- f(100,[('deposit',50),('withdraw',30),('withdraw',200)]) -> {'balance':120,'rejected':[2]}.
- Unknown kind raised ValueError (whole call fails).
- f(100,[('deposit',0),('deposit',-5),('deposit',True),('deposit',1.5),('deposit',10)]) -> {'balance':110,'rejected':[0,1,2,3]}.
- Exact-boundary withdraw f(50,[('withdraw',50)]) -> {'balance':0,'rejected':[]}.

No requirement conflicts with the provided scaffold/score. The allowed_calls (`isinstance`, `rejected.append`) were sufficient to meet R4/R5/R6 without widening.
