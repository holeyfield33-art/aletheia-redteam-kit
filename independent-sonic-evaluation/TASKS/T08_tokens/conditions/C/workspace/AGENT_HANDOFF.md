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

- R1: sign returns f"{username}.{expiry}.{signature}" where signature is the lowercase hex HMAC-SHA256 digest (hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()) of payload = f"{username}.{expiry}".
- R2 (security/validation): verify raises ValueError('malformed token') unless token split on '.' yields exactly 3 parts, the first part (username) is non-empty, and the second part (expiry) consists only of ASCII digits per str.isdigit.
- R3 (security/authentication): verify recomputes the signature for the given username and int(expiry) with secret and compares it with the token's signature using hmac.compare_digest; on mismatch raise PermissionError('bad signature').
- R4 (security/authentication): The signature check happens BEFORE the expiry check.
- R5 (security/authentication): If now >= int(expiry), raise PermissionError('token expired').
- R6: Otherwise verify returns the username.

## Exact scaffold

### tokens.py

```python
"""Generated from an audible template. Verify behavior before use."""
import hashlib
import hmac

def sign(username: str, expiry: int, secret: str) -> str:
    payload = f'{username}.{expiry}'
    raise NotImplementedError('__SONIC_HOLE__:Set signature to the hex HMAC-SHA256 of payload keyed by secret; first assign mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256), then signature = mac.hexdigest()')
    return f'{payload}.{signature}'

def verify(token: str, secret: str, now: int) -> str:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('malformed token')
    username = parts[0]
    expiry_text = parts[1]
    provided = parts[2]
    if not username or not expiry_text.isdigit():
        raise ValueError('malformed token')
    raise NotImplementedError("__SONIC_HOLE__:Set expected to the signature part of sign(username, int(expiry_text), secret); first assign expected_token = sign(...), then expected = expected_token.split('.')[2]")
    if not hmac.compare_digest(provided, expected):
        raise PermissionError('bad signature')
    if now >= int(expiry_text):
        raise PermissionError('token expired')
    return username
```
