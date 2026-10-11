"""Scaffold. Verify behavior before use."""

def require_positive(amount: int) -> None:
    if amount <= 0:
        raise ValueError('amount must be positive')
    return None
