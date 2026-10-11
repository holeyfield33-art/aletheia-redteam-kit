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
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            rejected.append(index)
        elif kind == 'deposit':
            current = current + amount
        elif amount <= current:
            current = current - amount
        else:
            rejected.append(index)
    return {'balance': current, 'rejected': rejected}
