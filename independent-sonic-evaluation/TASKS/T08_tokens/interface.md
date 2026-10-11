Create one module, `tokens.py`, containing exactly these functions:

- `sign(username: str, expiry: int, secret: str) -> str`
- `verify(token: str, secret: str, now: int) -> str`

Use only the standard library modules `hashlib` and `hmac` (imported as `import hashlib` and `import hmac`).
No other modules, top-level statements or third-party dependencies are required.
