Done. Filled the three TODO placeholders in repo/grades.py (the only module), preserving all signatures, imports, branch/loop structure and statement order from the scaffold/spec.

Implementations:
- letter_for: if/elif/else band assignment (>=90 A, >=80 B, >=70 C, >=60 D, else F) setting `letter`, before the existing `return letter`. Replaced the TODO raise; the TypeError/ValueError guards above were left intact.
- assign_grades: `result[name] = letter_for(scores[name])` inside the existing loop. Returns a new dict, preserves input key order, does not mutate input.
- summarize: `counts[letter] += 1` after the existing unknown-letter ValueError guard.

Checks: wrote and ran one behavioral check script covering R1-R5 (bands/boundaries, TypeError on bool/float/str, ValueError out-of-range, new-dict/order/no-mutation for assign_grades, counts + empty-dict key order + unknown-letter ValueError for summarize). Ran checks 1 time: ALL PASS.

No requirement conflicts with the provided materials.
