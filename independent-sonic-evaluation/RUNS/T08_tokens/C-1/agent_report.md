Completed. Filled both __SONIC_HOLE__ placeholders in repo/tokens.py (the only file written in repo/), preserving all module paths, signatures, imports, branch/loop nesting, statement order, and required expressions.

Holes filled:
- sign: `mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256)` then `signature = mac.hexdigest()` (allowed calls only).
- verify: `expected_token = sign(username, int(expiry_text), secret)` then `expected = expected_token.split('.')[2]` (allowed calls only).

My own behavioral checks: ran 1 time, all passed. Verified R1 (correct HMAC-SHA256 hex signature), R2 (ValueError 'malformed token' for wrong part count, empty username, non-digit expiry), R3 (PermissionError 'bad signature' on mismatch via hmac.compare_digest), R4 (signature check precedes expiry — an expired token with a wrong signature yields 'bad signature'), R5 (PermissionError 'token expired' when now >= expiry with valid signature), and R6 (returns username on success).

No requirements conflicted with the provided materials; the scaffold and score.json were consistent and fully implementable within the plan.
