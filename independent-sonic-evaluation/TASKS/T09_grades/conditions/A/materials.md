## Task (natural-language specification)

Create one module, `grades.py`, containing exactly these functions:

- `letter_for(score: int) -> str`
- `assign_grades(scores: dict) -> dict`
- `summarize(grades: dict) -> dict`

No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): letter_for raises TypeError if score is not an int or is a bool, and ValueError if score < 0 or score > 100.
- R2: letter_for returns 'A' for 90-100, 'B' for 80-89, 'C' for 70-79, 'D' for 60-69, and 'F' for 0-59.
- R3: assign_grades returns a NEW dict mapping each name in scores to letter_for(scores[name]), preserving the input's key order; it must call letter_for for every entry and propagate its exceptions. The input dict must not be modified.
- R4: summarize returns a dict with exactly the keys 'A', 'B', 'C', 'D', 'F' (in that order) giving how many values of grades equal each letter; letters with no students map to 0.
- R5 (security/validation): summarize raises ValueError if any value in grades is not one of 'A', 'B', 'C', 'D', 'F'.
