Completed. Filled the three TODO placeholders in `/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-40/repo/grades.py`, preserving all signatures, imports, branch/loop nesting, statement order, and allowed-call constraints.

Implementations:
- letter_for: grade-band if/elif/else assigning `letter` (A>=90, B>=80, C>=70, D>=60, else F). No calls used (allowed_calls empty). Existing TypeError/ValueError guards left intact.
- assign_grades: loop body `result[name] = letter_for(scores[name])` (only letter_for called).
- summarize: loop body `counts[letter] += 1` after the unknown-letter ValueError check.

Checks: wrote and ran one behavioral check script covering R1-R5 (type/bool/range errors, all five bands incl. boundaries, new-dict + key-order + input-immutability for assign_grades, exact-key summarize incl. empty dict and unknown-letter ValueError). All passed. Ran checks 1 time.

No requirement conflicts with the provided materials.
