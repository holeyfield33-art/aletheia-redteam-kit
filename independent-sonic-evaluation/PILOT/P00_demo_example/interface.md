Create three modules:

- `validation.py` containing exactly `require_positive(amount: int) -> None`
- `authorization.py` containing exactly `require_authorized(role: str) -> None`
- `orders.py` containing exactly `process_order(amount: int, role: str) -> int`, importing the other two with
  `from validation import require_positive` and `from authorization import require_authorized`.
