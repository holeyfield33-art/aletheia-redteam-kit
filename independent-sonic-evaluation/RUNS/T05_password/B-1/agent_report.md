Done. Filled the single TODO in /tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-01/repo/policy.py.

Files written in repo/: policy.py (only file). Implemented check_password's violation-collection logic; is_acceptable was already complete in the scaffold.

Implementation appends violation codes in the required fixed order using only allowed calls: too_short (len(password)<12), no_digit (not any ch.isdigit), no_upper (not any ch.isupper), no_lower (not any ch.islower), contains_username (username truthy and username.lower() in password.lower()). The isinstance TypeError guard and the final `return violations` were left intact per the spec. R1-R5 all satisfied, including 12-char = long enough and empty username never triggering contains_username.

My own checks: 1 run, all passed (order of codes, exactly-12-char boundary, empty username, compliant->[], is_acceptable True/False, TypeError propagation for non-str on both functions).

No requirements conflict with the provided materials.
