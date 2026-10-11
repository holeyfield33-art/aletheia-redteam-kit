# Implement this Python scaffold

The accompanying spec.json is the exact structural plan.

Fill only the TODO placeholders. Preserve module paths, function
signatures, imports, required expressions, branch/loop nesting and statement
order. Each TODO lists its allowed calls. If a requirement cannot be met within
this plan, explain the conflict and propose an explicit spec revision.
Do not silently remove a check or widen the allowed calls/imports.

Run behavioral tests for the stated requirements. A structural comparison
checks syntax; passing it does not prove behavior, security or correctness.

## Requirements

- R1 (security/validation): check_password raises TypeError if password or username is not a str.
- R2: check_password returns a list of violation codes in this fixed order, each at most once: 'too_short' if len(password) < 12; 'no_digit' if no character is a digit (str.isdigit); 'no_upper' if no character is uppercase (str.isupper); 'no_lower' if no character is lowercase (str.islower); 'contains_username' if username is non-empty and username.lower() occurs in password.lower().
- R3: A password of exactly 12 characters is long enough. An empty username never triggers 'contains_username'.
- R4: check_password returns [] for a compliant password.
- R5 (security/validation): is_acceptable returns True only when check_password(password, username) returns an empty list; it must call check_password and propagate its TypeError.

## Exact scaffold

### policy.py

```python
"""Scaffold. Verify behavior before use."""

def check_password(password: str, username: str) -> list:
    if not isinstance(password, str) or not isinstance(username, str):
        raise TypeError('password and username must be str')
    violations = []
    raise NotImplementedError('TODO:Append the violation codes in the required order; iterate characters as ch, e.g. any(ch.isdigit() for ch in password)')
    return violations

def is_acceptable(password: str, username: str) -> bool:
    problems = check_password(password, username)
    return problems == []
```
