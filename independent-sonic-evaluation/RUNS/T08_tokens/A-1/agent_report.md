Done. Wrote one file: repo/tokens.py

Contents implement:
- sign(username, expiry, secret): returns f"{username}.{expiry}.{signature}" with signature = hmac.new(secret.encode(), f"{username}.{expiry}".encode(), hashlib.sha256).hexdigest() (R1).
- verify(token, secret, now): splits on '.', requires exactly 3 parts, non-empty username, digit-only expiry per str.isdigit, else ValueError('malformed token') (R2); recomputes signature for username and int(expiry), compares with hmac.compare_digest, else PermissionError('bad signature') (R3); signature check before expiry (R4); if now >= int(expiry) raise PermissionError('token expired') (R5); otherwise return username (R6).

Only hashlib and hmac imported. My own checks: I ran checks once (1 run) covering sign output, successful verify, malformed cases (2 parts, empty username, non-digit expiry), bad signature, and expiry — all passed.

No requirement conflicts found.
