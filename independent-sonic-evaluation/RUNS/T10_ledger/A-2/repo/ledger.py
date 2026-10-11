def apply_transactions(balance: int, transactions: list) -> dict:
    if isinstance(balance, bool) or not isinstance(balance, int) or balance < 0:
        raise ValueError("balance must be a non-negative int")

    rejected = []
    for index, txn in enumerate(transactions):
        kind, amount = txn
        if kind not in ("deposit", "withdraw"):
            raise ValueError("invalid transaction kind: %r" % (kind,))

        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            rejected.append(index)
            continue

        if kind == "deposit":
            balance += amount
        else:  # withdraw
            if amount <= balance:
                balance -= amount
            else:
                rejected.append(index)

    return {"balance": balance, "rejected": rejected}
