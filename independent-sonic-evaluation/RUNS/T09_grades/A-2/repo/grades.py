"""Letter grade assignment and summary utilities."""

_LETTERS = ("A", "B", "C", "D", "F")


def letter_for(score: int) -> str:
    """Return the letter grade for an integer score in [0, 100]."""
    if isinstance(score, bool) or not isinstance(score, int):
        raise TypeError("score must be an int (not bool)")
    if score < 0 or score > 100:
        raise ValueError("score must be between 0 and 100 inclusive")
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def assign_grades(scores: dict) -> dict:
    """Return a new dict mapping each name to letter_for(score), in input order."""
    result = {}
    for name, score in scores.items():
        result[name] = letter_for(score)
    return result


def summarize(grades: dict) -> dict:
    """Count how many grades equal each letter, in order A, B, C, D, F."""
    counts = {letter: 0 for letter in _LETTERS}
    for value in grades.values():
        if not isinstance(value, str) or value not in counts:
            raise ValueError("invalid grade: %r" % (value,))
        counts[value] += 1
    return counts
