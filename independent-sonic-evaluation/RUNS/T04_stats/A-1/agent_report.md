Done. Wrote one file: repo/stats.py containing summarize(readings: list) -> dict.

Implementation covers all requirements:
- R1: raises TypeError if readings is not a list.
- R2: None entries skipped.
- R3: raises TypeError for bool or non-int/float entries (checked bool before int since bool is a subclass of int).
- R4: raises ValueError if no numeric entries remain.
- R5: returns dict with exactly count, min, max, mean; mean rounded via round(value, 2); min/max are original unrounded values.
- R6: input list not modified (iterates without mutating; verified).

My own checks passed. I ran checks once (a single script covering valid input, non-modification, bad-type rejection, non-list input, empty/all-None ValueError). No conflicts between requirements and materials.
