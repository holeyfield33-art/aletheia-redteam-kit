Create two modules:

- `roles.py` containing exactly `permissions_for(role: str) -> set`
- `access.py` containing exactly `is_allowed(user: dict, action: str, owner: str) -> bool`
  and `perform(user: dict, action: str, owner: str, audit: list) -> str`.
  `access.py` must import `permissions_for` with `from roles import permissions_for`.

`user` is a dict that may contain the keys 'name', 'role' and 'active'.
No other modules, top-level statements or third-party dependencies are required.
