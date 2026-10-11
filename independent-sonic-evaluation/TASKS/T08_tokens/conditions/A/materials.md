## Task (natural-language specification)

Create one module, `tokens.py`, containing exactly these functions:

- `sign(username: str, expiry: int, secret: str) -> str`
- `verify(token: str, secret: str, now: int) -> str`

Use only the standard library modules `hashlib` and `hmac` (imported as `import hashlib` and `import hmac`).
No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1: sign returns f"{username}.{expiry}.{signature}" where signature is the lowercase hex HMAC-SHA256 digest (hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()) of payload = f"{username}.{expiry}".
- R2 (security/validation): verify raises ValueError('malformed token') unless token split on '.' yields exactly 3 parts, the first part (username) is non-empty, and the second part (expiry) consists only of ASCII digits per str.isdigit.
- R3 (security/authentication): verify recomputes the signature for the given username and int(expiry) with secret and compares it with the token's signature using hmac.compare_digest; on mismatch raise PermissionError('bad signature').
- R4 (security/authentication): The signature check happens BEFORE the expiry check.
- R5 (security/authentication): If now >= int(expiry), raise PermissionError('token expired').
- R6: Otherwise verify returns the username.
