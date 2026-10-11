Done. Wrote one file: /tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-38/repo/grades.py

It contains exactly the three required functions (letter_for, assign_grades, summarize), no other modules, no top-level statements, stdlib only.

Coverage of requirements:
- R1: letter_for rejects bool (checked before int) and non-int with TypeError; out-of-range (<0 or >100) with ValueError.
- R2: boundary mapping A=90-100, B=80-89, C=70-79, D=60-69, F=0-59.
- R3: assign_grades builds a new dict in input key order, does not mutate input, calls letter_for per entry and propagates its exceptions.
- R4: summarize returns counts with keys A,B,C,D,F in that order, 0 for missing.
- R5: summarize raises ValueError on any value not in A-F.

Checks: ran my own check script once; all assertions passed (boundaries, bool/float/str/range rejection, order preservation, non-mutation, summarize counts and invalid-value rejection).

No requirement conflicts found.
