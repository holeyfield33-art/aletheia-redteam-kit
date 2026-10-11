## Task (natural-language specification)

Create three modules:

- `validation.py` containing exactly `require_positive(amount: int) -> None`
- `authorization.py` containing exactly `require_authorized(role: str) -> None`
- `orders.py` containing exactly `process_order(amount: int, role: str) -> int`, importing the other two with
  `from validation import require_positive` and `from authorization import require_authorized`.

## Requirements

- Reject amounts at or below zero.
- Reject any role other than admin.
- For an accepted order return amount multiplied by 100.
- Keep the validation and authorization calls before implementation.
