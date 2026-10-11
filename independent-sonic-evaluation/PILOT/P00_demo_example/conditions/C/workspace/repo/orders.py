"""Generated from an audible template. Verify behavior before use."""
from validation import require_positive
from authorization import require_authorized

def process_order(amount: int, role: str) -> int:
    """Requirements:
Keep the validation and authorization calls before implementation."""
    require_positive(amount)
    require_authorized(role)
    raise NotImplementedError('__SONIC_HOLE__:Set receipt to amount * 100')
    return receipt
