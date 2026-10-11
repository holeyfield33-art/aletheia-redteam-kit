Done. Filled the two TODO placeholders in repo/tokens.py, preserving all module paths, signatures, imports, statement order, and branch structure.

Files written in repo/:
- tokens.py — sign() now computes mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256) then signature = mac.hexdigest(); verify() now computes expected_token = sign(username, int(expiry_text), secret) then expected = expected_token.split('.')[2]. Only the allowed calls were used.

My own checks: PASSED. Ran checks 1 time (one behavioral test script). Verified R1 (HMAC-SHA256 hex signature matches reference), R2 (ValueError 'malformed token' for wrong part count, empty username, non-digit expiry), R3 (PermissionError 'bad signature' on tampered signature), R4 (signature check fires before expiry: a bad-signature token with now>=expiry raises 'bad signature'), R5 (PermissionError 'token expired' when now>=expiry with valid signature), and R6 (returns username on valid non-expired token).

No requirement conflicts with the provided materials. The scaffold's existing branch order already places the signature check before the expiry check (R4), so no spec revision was needed.
