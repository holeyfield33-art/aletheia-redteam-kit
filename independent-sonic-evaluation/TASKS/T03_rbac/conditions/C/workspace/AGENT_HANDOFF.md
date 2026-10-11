# Implement this Python template

The accompanying score.json is the exact structural plan. template.wav is an
audible presentation of that plan; notes do not add requirements.

Fill only the __SONIC_HOLE__ placeholders. Preserve module paths, function
signatures, imports, required expressions, branch/loop nesting and statement
order. Each hole lists its allowed calls. If a requirement cannot be met within
this plan, explain the conflict and propose an explicit score revision.
Do not silently remove a check or widen the allowed calls/imports.

Run behavioral tests for the stated requirements. The template checker compares
syntax; passing it does not prove behavior, security or correctness.

## Requirements

- R1: permissions_for returns a NEW set on every call: 'admin' -> {'read', 'write', 'delete'}, 'editor' -> {'read', 'write'}, 'viewer' -> {'read'}, any other value (including None or '') -> empty set. It never raises. Mutating a returned set must not affect later calls.
- R2 (security/validation): is_allowed raises ValueError if action is not exactly one of 'read', 'write', 'delete'. This check happens first, even for inactive users.
- R3 (security/authorization): is_allowed returns False unless user.get('active') is exactly True (missing key, False, 1, 'yes' all deny).
- R4 (security/authorization): For an active user, is_allowed returns True if action is in permissions_for(user.get('role', '')).
- R5 (security/authorization): For an active user, is_allowed also returns True if user.get('name') == owner and action is 'read' or 'write'. Owners may NOT 'delete' unless their role grants it.
- R6: Otherwise is_allowed returns False. is_allowed always returns a bool.
- R7 (security/authorization): perform raises PermissionError('denied') if is_allowed(user, action, owner) is False, and must not modify audit in that case (ValueError from an unknown action also leaves audit unchanged).
- R8: On success perform appends exactly one string f"{user['name']}:{action}:{owner}" to audit and returns 'ok'.

## Exact scaffold

### roles.py

```python
"""Generated from an audible template. Verify behavior before use."""

def permissions_for(role: str) -> set:
    raise NotImplementedError('__SONIC_HOLE__:Set perms to a new set of the actions granted to role')
    return perms
```

### access.py

```python
"""Generated from an audible template. Verify behavior before use."""
from roles import permissions_for

def is_allowed(user: dict, action: str, owner: str) -> bool:
    if action not in ('read', 'write', 'delete'):
        raise ValueError('unknown action')
    if user.get('active') is not True:
        return False
    raise NotImplementedError("__SONIC_HOLE__:Set granted to True if action is in permissions_for(user.get('role', '')) or (user.get('name') == owner and action in ('read', 'write')), else False")
    return granted

def perform(user: dict, action: str, owner: str, audit: list) -> str:
    if not is_allowed(user, action, owner):
        raise PermissionError('denied')
    raise NotImplementedError('__SONIC_HOLE__:Append f"{user[\'name\']}:{action}:{owner}" to audit')
    return 'ok'
```
