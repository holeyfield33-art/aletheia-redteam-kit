Done. Wrote one file: repo/stats.py containing only summarize(readings: list) -> dict.

Implementation covers all requirements:
- R1: non-list input raises TypeError
- R2: None entries skipped
- R3: bool entries and non-int/float entries raise TypeError (checked bool before int since bool is a subclass of int)
- R4: ValueError when no numeric entries remain
- R5: returns dict with exactly keys count, min, max, mean; mean is round(value, 2); min/max are original unrounded values
- R6: input list is not mutated (iterated over a copy of references, builds a new list)

My own checks: passed. Ran checks once (a single script covering R1-R6, including list-not-modified verification). No requirement conflicts found.
