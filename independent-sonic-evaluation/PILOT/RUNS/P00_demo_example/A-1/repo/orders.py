from validation import require_positive
from authorization import require_authorized


def process_order(amount: int, role: str) -> int:
    require_positive(amount)
    require_authorized(role)
    return amount * 100
