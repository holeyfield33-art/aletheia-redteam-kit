Completed T05 password policy implementation.

Files written in repo/:
- repo/policy.py — filled the single __SONIC_HOLE__ in check_password. Preserved module path, both function signatures, the TypeError guard, the `violations = []` assignment, and the final `return violations`. is_acceptable left as scaffolded (it already calls check_password and returns `problems == []`, which propagates the TypeError per R5).

Hole implementation appends violation codes in the required fixed order using only allowed calls (len, any, violations.append, ch.isdigit/isupper/islower, username.lower, password.lower):
- 'too_short' if len(password) < 12
- 'no_digit' if not any(ch.isdigit() ...)
- 'no_upper' if not any(ch.isupper() ...)
- 'no_lower' if not any(ch.islower() ...)
- 'contains_username' if username != '' and username.lower() in password.lower()

The empty-username check uses `username != ''` (a comparison, not a call) so it stays within allowed_calls. Exactly-12-char passwords pass the length check (R3), and empty username never triggers 'contains_username' (R3).

Checks: ran my own behavioral test suite once. All assertions passed (compliant->[], ordering, each code, TypeError on non-str for both functions and propagation through is_acceptable, empty-username and 12-char edge cases).

No requirement conflicts with the provided materials.
