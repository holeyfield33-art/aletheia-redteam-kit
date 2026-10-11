Done. Filled the single `__SONIC_HOLE__` in `/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-04/repo/policy.py`.

Files written in repo/:
- policy.py — implemented the hole in check_password; is_acceptable was already complete in the scaffold and left untouched.

Implementation (hole only): appends violation codes in the required fixed order using only the allowed calls:
- `too_short` if `len(password) < 12`
- `no_digit` if `not any(ch.isdigit() for ch in password)`
- `no_upper` if `not any(ch.isupper() for ch in password)`
- `no_lower` if `not any(ch.islower() for ch in password)`
- `contains_username` if `username and username.lower() in password.lower()`

Preserved: module path, signatures, imports (none), the TypeError branch, the `violations = []` assign, and the `return violations` statement.

Checks: wrote and ran one behavioral check batch (1 run) covering R1–R5: compliant password -> [], ordering of codes, exactly-12-char not too_short, empty username never triggers contains_username, is_acceptable True/False, and TypeError propagation for non-str inputs. All passed ("OK").

No requirement conflicts with the provided materials.
