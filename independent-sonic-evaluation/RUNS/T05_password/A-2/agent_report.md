Done. Wrote one file: repo/policy.py containing check_password and is_acceptable (no other modules, no top-level statements, no third-party deps).

Implementation notes:
- check_password raises TypeError if password or username is not a str (R1).
- Returns violation codes in fixed order, each at most once: too_short (len<12), no_digit, no_upper, no_lower, contains_username (only when username non-empty and username.lower() in password.lower()) (R2/R3).
- Returns [] for compliant passwords; 12 chars counts as long enough (R3/R4).
- is_acceptable calls check_password and returns True only when it returns [], propagating TypeError (R5).

Checks: wrote and ran my own test suite once (1 run) covering all requirements including TypeError propagation and order/dedup behavior — ALL PASS.

No requirement conflicts with the materials.
