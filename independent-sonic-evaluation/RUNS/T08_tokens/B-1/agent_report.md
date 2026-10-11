Done. Filled the two TODOs in `/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-50/repo/tokens.py`, preserving all module paths, signatures, imports, statement order, and branch nesting from the scaffold.

Changes:
- `sign`: added `mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256)` then `signature = mac.hexdigest()` (allowed calls only).
- `verify`: added `expected_token = sign(username, int(expiry_text), secret)` then `expected = expected_token.split('.')[2]` (allowed calls only).

Checks: wrote and ran one behavioral check script (1 run). All passed:
- R1 sign produces `username.expiry.hexdigest`, verify returns username on valid token.
- R2 malformed cases (wrong part count, empty username, non-digit expiry) raise ValueError('malformed token').
- R3 bad signature raises PermissionError('bad signature').
- R4 signature check precedes expiry check — a token that is both expired and has a bad signature raises 'bad signature'.
- R5 good signature but expired raises PermissionError('token expired').
- R6 valid, unexpired token returns username.

No requirement conflicts with the provided materials. Only tokens.py was written to repo/.
