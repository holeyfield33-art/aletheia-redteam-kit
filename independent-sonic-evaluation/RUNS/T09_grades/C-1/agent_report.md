Done. Filled the three __SONIC_HOLE__ placeholders in repo/grades.py, preserving all signatures, imports, branch/loop nesting, statement order, and the required `return letter`/`return result`/`return counts`.

Files written:
- /tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-46/repo/grades.py

Holes filled:
- letter_for: if/elif band chain assigning letter ('A'>=90, 'B'>=80, 'C'>=70, 'D'>=60, else 'F'). No calls (allowed_calls empty).
- assign_grades: `result[name] = letter_for(scores[name])` (uses allowed call letter_for; builds new dict, preserves key order, propagates exceptions, does not mutate input).
- summarize: `counts[letter] += 1`.

Checks: ran my own behavioral test suite once covering R1-R5 (type/bool TypeError, range ValueError, all band boundaries, new-dict/order/non-mutation for assign_grades, correct counts and key order for summarize, and summarize ValueError on unknown letter). All passed.

Check runs: 1.

No requirement conflicts with the provided scaffold/score.
