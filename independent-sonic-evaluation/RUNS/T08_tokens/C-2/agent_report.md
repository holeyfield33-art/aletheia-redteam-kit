Done. Filled the two `__SONIC_HOLE__` placeholders in `/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-25/repo/tokens.py`.

Files written in repo/:
- tokens.py (the only module)

What was filled:
- sign hole: `mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256)` then `signature = mac.hexdigest()`.
- verify hole: `expected_token = sign(username, int(expiry_text), secret)` then `expected = expected_token.split('.')[2]`.

All imports, signatures, statement order, branch nesting, and required expressions preserved exactly. Only allowed calls used in each hole.

Checks: ran my own behavioral checks once (1 run). All passed:
- sign returns `username.expiry.<hexdigest>`.
- verify returns username on a valid unexpired token.
- signature check runs before expiry check (an expired token with a tampered signature raises `PermissionError('bad signature')`, not 'token expired').
- expired token with valid signature raises `PermissionError('token expired')`.
- malformed tokens (wrong part count, empty username, non-digit expiry) raise `ValueError('malformed token')`.

No requirement conflicts with the provided materials; the scaffold and requirements are consistent.
