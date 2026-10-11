Done. Wrote one file:

- /tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-15/repo/tokens.py

It contains exactly `sign(username, expiry, secret)` and `verify(token, secret, now)`, importing only `hashlib` and `hmac`.

Implementation notes mapped to requirements:
- R1: sign returns `f"{username}.{expiry}.{signature}"` with signature = `hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()` over `payload = f"{username}.{expiry}"`.
- R2: verify raises `ValueError('malformed token')` unless split('.') yields exactly 3 parts, username non-empty, and expiry all ASCII digits via `str.isdigit`.
- R3: signature recomputed for username and int(expiry), compared with `hmac.compare_digest`; mismatch raises `PermissionError('bad signature')`.
- R4: signature check precedes expiry check (verified with a tampered+expired token -> "bad signature").
- R5: `now >= int(expiry)` raises `PermissionError('token expired')`.
- R6: otherwise returns username.

My own checks: ran once (1 check run). All passed: valid round-trip returns username; malformed cases (2 parts, non-digit expiry, empty username) raise ValueError; bad signature raises PermissionError; expired raises PermissionError; and the sig-before-expiry ordering confirmed.

No requirement conflicts found. Total tool calls used: 3 (read prompt, write file, run checks).
