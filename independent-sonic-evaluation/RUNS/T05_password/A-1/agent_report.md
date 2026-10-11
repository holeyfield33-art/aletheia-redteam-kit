Done. Wrote one file: /tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-03/repo/policy.py

It contains exactly check_password(password, username) -> list and is_acceptable(password, username) -> bool, no other top-level statements or dependencies.

Implementation notes:
- TypeError raised if either arg is not str (R1, R5 propagation via is_acceptable calling check_password).
- Violation codes appended in fixed order each at most once: too_short (len<12), no_digit, no_upper, no_lower, contains_username (only when username non-empty and username.lower() in password.lower()) (R2, R3).
- Returns [] for compliant passwords; is_acceptable returns check_password(...) == [] (R4, R5). 12-char passwords pass; empty username never triggers contains_username.

Checks: ran self-checks twice. First run failed only due to a bug in my own test assertion (a password I thought lacked the username actually contained it), not the module. Second run: ALL PASS covering compliant case, violations, ordering, contains_username, is_acceptable True/False, and TypeError for non-str on both functions.

No requirement conflicts with the provided materials.
