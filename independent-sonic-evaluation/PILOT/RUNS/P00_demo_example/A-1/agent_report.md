Completed the task. Wrote three flat modules in repo/:

- validation.py — `require_positive(amount: int) -> None`, raises ValueError when amount <= 0.
- authorization.py — `require_authorized(role: str) -> None`, raises PermissionError for any role other than "admin".
- orders.py — `process_order(amount: int, role: str) -> int`, imports via `from validation import require_positive` and `from authorization import require_authorized`, calls both checks first (validation then authorization), then returns amount * 100.

My own checks: ran once (1 time). All passed — accepted order (5, 'admin') returns 500; amounts 0 and -1 are rejected; role 'user' is rejected.

No requirement conflicts with the provided materials. (Spec did not mandate specific exception types; I used ValueError and PermissionError.)
