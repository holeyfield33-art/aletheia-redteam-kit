## Task (natural-language specification)

Create one module, `stats.py`, containing exactly this function:

- `summarize(readings: list) -> dict`

No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): If readings is not a list, raise TypeError.
- R2: Entries that are None are skipped.
- R3 (security/validation): Any entry that is not None and is a bool, or is not an int or float, raises TypeError (e.g. '3', True, [1]).
- R4 (security/validation): If no numeric entries remain after skipping None, raise ValueError.
- R5: Return a dict with exactly the keys 'count' (number of numeric entries), 'min', 'max' and 'mean'. 'mean' is the arithmetic mean rounded with round(value, 2). 'min' and 'max' are the original values (not rounded).
- R6: The input list must not be modified.
