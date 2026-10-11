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
