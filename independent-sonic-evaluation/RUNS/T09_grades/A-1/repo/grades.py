"""Grade utilities: letter grades, grade assignment, and summarization."""


def letter_for(score: int) -> str:
    """Return the letter grade for an integer score in [0, 100].

    Raises TypeError if score is not an int (bool is rejected), and
    ValueError if score is out of the range 0..100.
    """
    if isinstance(score, bool) or not isinstance(score, int):
        raise TypeError("score must be an int (not a bool)")
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
    """Return a new dict mapping each name to its letter grade.

    Input key order is preserved; the input dict is not modified.
    letter_for is called for every entry and its exceptions propagate.
    """
    result = {}
    for name in scores:
        result[name] = letter_for(scores[name])
    return result


def summarize(grades: dict) -> dict:
    """Return counts of each letter grade.

    The returned dict has exactly the keys 'A', 'B', 'C', 'D', 'F' in that
    order, with 0 for letters that have no students.

    Raises ValueError if any value is not one of 'A', 'B', 'C', 'D', 'F'.
    """
    counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for value in grades.values():
        if value not in counts:
            raise ValueError("invalid grade value: {!r}".format(value))
        counts[value] += 1
    return counts
